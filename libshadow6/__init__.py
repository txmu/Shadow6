"""Python application facade for a locally managed Shadow6 deployment."""
from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import subprocess
from threading import RLock
from pathlib import Path

__all__ = ["Shadow6", "Shadow6Error", "Session", "CreditedSession",
           "WebrtcClientReflector", "run"]

from .webrtc_signal import WebrtcClientReflector

try:
    from Deployment.core_catalog import CoreCatalog
except ImportError:
    from core_catalog import CoreCatalog


class Shadow6Error(RuntimeError):
    """A local Shadow6 operation failed or is unavailable."""


class Session:
    """A capsule owned by a Shadow6 facade, with its application endpoint."""

    def __init__(self, owner: "Shadow6", token: str, core: str,
                 endpoint: dict, mode: str, protocol: str):
        self._owner = owner
        self.token = token
        self.core = core
        self.endpoint = endpoint
        self.mode = mode
        self.protocol = protocol
        self._closed = False

    def status(self) -> dict:
        if self._closed:
            raise Shadow6Error("session is closed")
        return self._owner._control("capsule.status", {"token": self.token})

    def pause(self) -> dict:
        if self._closed:
            raise Shadow6Error("session is closed")
        return self._owner._control("capsule.pause", {"token": self.token})

    def resume(self) -> dict:
        if self._closed:
            raise Shadow6Error("session is closed")
        return self._owner._control("capsule.resume", {"token": self.token})

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._owner._control("capsule.stop", {"token": self.token})
        finally:
            self._closed = True
            self._owner._sessions.discard(self)

    def __enter__(self) -> "Session":
        if self._closed:
            raise Shadow6Error("session is closed")
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


class CreditedSession:
    """One bounded application stream multiplexed over an S6NA endpoint."""
    def __init__(self, owner: "Shadow6", pool, stream: int, maximum: int = 64):
        from collections import deque
        if type(stream) is not int or not 0 <= stream < pool.endpoint.adapter.limits.max_streams:
            raise ValueError("invalid S6NA application stream")
        if type(maximum) is not int or not 1 <= maximum <= 64:
            raise ValueError("invalid S6NA receive window")
        self._owner, self._pool = owner, pool
        self.endpoint, self.stream, self.maximum = pool.endpoint, stream, maximum
        self._received = deque()
        self._stream_buffer = bytearray()
        self._closed = False

    def application_credit(self) -> int:
        self._ensure_open()
        return self.endpoint.adapter.application_credit()

    def send_record(self, data: bytes) -> int:
        self._ensure_open()
        try:
            self._pool.send(self, data)
        except Exception as error:
            if type(error).__name__ == "AdapterBackpressure":
                raise Shadow6Error("S6NA_BACKPRESSURE") from error
            raise
        return self.application_credit()

    def send(self, data: bytes) -> int:
        """Send application bytes without exposing the locked Profile choice."""
        self._ensure_open()
        if not isinstance(data, bytes) or not data:
            raise ValueError("S6NA application bytes must be non-empty")
        maximum = self.endpoint.adapter.limits.max_message
        payload = self.endpoint.adapter.codec.payload
        frames = sum((min(maximum, len(data) - offset) + payload - 1) // payload
                     for offset in range(0, len(data), maximum))
        if frames > self.application_credit():
            raise Shadow6Error("S6NA_BACKPRESSURE")
        for offset in range(0, len(data), maximum):
            self.send_record(data[offset:offset + maximum])
        return self.application_credit()

    def receive(self, size: int = 65536, timeout: float = 0.0) -> bytes:
        """Read a byte stream assembled from S6NA records; message users use receive_record."""
        self._ensure_open()
        if type(size) is not int or not 1 <= size <= 65536:
            raise ValueError("invalid S6NA receive bound")
        while not self._stream_buffer:
            record = self.receive_record(timeout)
            if record is None:
                return b""
            self._stream_buffer.extend(record)
        result = bytes(self._stream_buffer[:size])
        del self._stream_buffer[:len(result)]
        return result

    def receive_record(self, timeout: float = 0.0) -> bytes | None:
        import time
        self._ensure_open()
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 <= timeout <= 30:
            raise ValueError("S6NA receive timeout must be 0..30 seconds")
        if self._received:
            return self._received.popleft()
        deadline = time.monotonic() + timeout
        while True:
            wait = min(.2, max(0.0, deadline - time.monotonic())) if timeout else 0.0
            self._pool.poll(wait)
            if self._received:
                return self._received.popleft()
            if time.monotonic() >= deadline:
                return None

    def _ensure_open(self):
        if self._closed:
            raise Shadow6Error("S6NA_CLOSED")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._received.clear()
        self._stream_buffer.clear()
        self._pool.release(self)
        self._owner._attachments.discard(self)

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, *_exc):
        self.close()


class CreditedPool:
    """One pinned S6NA transport shared by bounded per-stream sessions."""
    def __init__(self, owner, endpoint, *, close_when_idle):
        from threading import RLock
        self.owner, self.endpoint = owner, endpoint
        self.close_when_idle = close_when_idle
        self.sessions = {}
        self.closed = False
        self._lock = RLock()

    def open(self, stream, maximum=64):
        with self._lock:
            if self.closed:
                raise Shadow6Error("S6NA_CLOSED")
            if type(stream) is not int or not 0 <= stream < self.endpoint.adapter.limits.max_streams:
                raise ValueError("invalid S6NA application stream")
            if stream in self.sessions:
                raise Shadow6Error("S6NA_STREAM_IN_USE")
            session = CreditedSession(self.owner, self, stream, maximum)
            self.sessions[stream] = session
            self.owner._attachments.add(session)
            return session

    def open_available(self, preferred=0, maximum=64):
        if type(preferred) is not int or preferred < 0:
            raise ValueError("invalid preferred S6NA stream")
        with self._lock:
            limit = self.endpoint.adapter.limits.max_streams
            for offset in range(limit):
                stream = (preferred + offset) % limit
                if stream not in self.sessions:
                    return self.open(stream, maximum)
        raise Shadow6Error("S6NA_STREAM_LIMIT")

    def send(self, session, data):
        with self._lock:
            if self.closed or self.sessions.get(session.stream) is not session:
                raise Shadow6Error("S6NA_CLOSED")
            self.endpoint.send_flow_controlled(session.stream, data)

    def poll(self, timeout):
        with self._lock:
            if self.closed:
                raise Shadow6Error("S6NA_CLOSED")
            completed, events = self.endpoint.poll(timeout)
            if events:
                self.close()
                raise Shadow6Error("S6NA_UNEXPECTED_EXTENSION")
            for stream, record in completed:
                session = self.sessions.get(stream)
                if session is None:
                    continue
                if len(session._received) >= session.maximum:
                    self.close()
                    raise Shadow6Error("S6NA_APPLICATION_WINDOW_VIOLATION")
                session._received.append(record)

    def release(self, session):
        with self._lock:
            if self.sessions.get(session.stream) is session:
                del self.sessions[session.stream]
            if not self.sessions and self.close_when_idle:
                self._close()

    def close(self):
        with self._lock:
            self._close()

    def _close(self):
        if self.closed:
            return
        self.closed = True
        self.endpoint.close()
        for session in tuple(self.sessions.values()):
            session._closed = True
            session._received.clear()
            self.owner._attachments.discard(session)
        self.sessions.clear()
        self.owner._attachment_pools.discard(self)
        for key, pool in tuple(self.owner._attachment_pool_map.items()):
            if pool is self:
                del self.owner._attachment_pool_map[key]
        for key, pool in tuple(getattr(self.owner, "_service_attachment_pools", {}).items()):
            if pool is self:
                del self.owner._service_attachment_pools[key]


def _cli() -> str:
    value = os.environ.get("SHADOW6_CLI") or shutil.which("shadow6")
    if not value:
        raise Shadow6Error("installed shadow6 CLI not found")
    return value


def run(*args: str, input: str | None = None, timeout: float = 30,
        cli: str | os.PathLike[str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run one fixed local Shadow6 CLI route and return its text result."""
    if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in args):
        raise ValueError("arguments must be non-empty strings without NUL")
    executable = str(cli) if cli is not None else _cli()
    result = subprocess.run([executable, *args], input=input, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise Shadow6Error(result.stderr.strip() or f"shadow6 exited {result.returncode}")
    return result


class Shadow6:
    """Discover compatible client boundaries and own their capsule lifecycle."""

    def __init__(self, cli: str | os.PathLike[str] | None = None):
        if cli is not None:
            self.cli = str(Path(cli).expanduser())
            if not Path(self.cli).is_file() or not os.access(self.cli, os.X_OK):
                raise Shadow6Error("configured Shadow6 CLI is not executable")
        else:
            self.cli = _cli()
        self._sessions: set[Session] = set()
        self._attachments: set[CreditedSession] = set()
        self._attachment_pools: set[CreditedPool] = set()
        self._attachment_pool_map: dict[tuple[str, str, str], CreditedPool] = {}
        self._service_attachment_pools: dict[str, CreditedPool] = {}
        self._attachment_lock = RLock()
        self._closed = False

    def _ensure_attachment_state(self):
        if not hasattr(self, "_attachments"):
            self._attachments = set()
        if not hasattr(self, "_attachment_pools"):
            self._attachment_pools = set()
        if not hasattr(self, "_attachment_pool_map"):
            self._attachment_pool_map = {}
        if not hasattr(self, "_service_attachment_pools"):
            self._service_attachment_pools = {}
        if not hasattr(self, "_attachment_lock"):
            self._attachment_lock = RLock()

    def call(self, *args: str, input: str | None = None, timeout: float = 30) -> str:
        return run(*args, input=input, timeout=timeout, cli=self.cli).stdout

    def json(self, *args: str, input: str | None = None, timeout: float = 30) -> dict:
        try: value = json.loads(self.call(*args, input=input, timeout=timeout))
        except json.JSONDecodeError as exc: raise Shadow6Error("invalid JSON response") from exc
        if not isinstance(value, dict): raise Shadow6Error("expected JSON object")
        return value

    def connection_plan(self, name: str) -> dict:
        """Resolve a named service through the same S6P1 connection pipeline."""
        return self.json('connect', name, '--json')

    def connect(self, name: str, *, adapter: str = "auto"):
        """Open a lock-selected application path without naming a Core or Profile.

        A locked S6NA application adapter is selected by default. Pass
        ``adapter="native"`` to attach directly to the local Core endpoint.
        """
        if adapter not in {"auto", "native", "s6na"}:
            raise ValueError("adapter must be auto, native, or s6na")
        plan = self.connection_plan(name)
        selected = plan.get("applicationAdapter", {}).get("provider", "native")
        if adapter == "s6na" and selected != "s6na":
            raise Shadow6Error("Named Service has no lock-bound S6NA application adapter")
        if adapter == "s6na" or (adapter == "auto" and selected == "s6na"):
            return self.open_credited_for_service(name)
        from Deployment.connection_plan import open_local_session
        return open_local_session(plan)

    def open_application(self, name: str):
        """Attach transparently through the Named Service's locked adapter."""
        return self.connect(name)

    def connect_native(self, name: str):
        """Attach directly to the Native Core endpoint, bypassing optional S6NA."""
        return self.connect(name, adapter="native")

    def webrtc_client_reflector(self, name: str, session_id: str, *, leg="E", timeout=15):
        """Create the small client shim for a locked S6EPE Name Service socket."""
        endpoint = self.json("service", "signal", name)
        if (endpoint.get("schema") != "shadow6.webrtc-signal-endpoint.v1" or
                endpoint.get("protocol") != "S6SG1"):
            raise Shadow6Error("Named Service returned an invalid WebRTC signal endpoint")
        return WebrtcClientReflector(endpoint.get("path"), session_id,
                                     leg=leg, timeout=timeout)

    def _credited_pool(self, config, *, _expected=None, close_when_idle=True):
        self._ensure_attachment_state()
        if self._closed:
            raise Shadow6Error("Shadow6 facade is closed")
        path = Path(config).expanduser().absolute()
        try:
            from Deployment.service_storage import private_read, strict_json
            config_bytes = private_read(path, limit=16384)
            value = strict_json(config_bytes)
        except (OSError, ValueError) as error:
            raise Shadow6Error("invalid private S6NA attachment config") from error
        config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
        if _expected is not None:
            if (not isinstance(_expected, dict) or _expected.get("configPath") != str(path)
                    or _expected.get("configDigest") != config_digest):
                raise Shadow6Error("S6NA attachment config differs from Named Service lock")
        fields = {"schema", "core", "key_file", "bind", "peer", "side", "stream", "limits"}
        if not isinstance(value, dict) or set(value) - fields or not {"schema", "core", "key_file", "bind", "peer"} <= set(value) or value["schema"] != "shadow6.s6na-attachment.v1":
            raise Shadow6Error("invalid S6NA attachment schema")
        if not isinstance(value["core"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value["core"]):
            raise Shadow6Error("invalid S6NA Profile family")
        if not isinstance(value["key_file"], str) or not Path(value["key_file"]).is_absolute():
            raise Shadow6Error("S6NA key_file must be absolute")
        preferred = value.get("stream", 0)
        if type(preferred) is not int or preferred < 0:
            raise Shadow6Error("invalid S6NA application stream")
        key_digest = _expected.get("keyDigest", "") if isinstance(_expected, dict) else ""
        cache_key = (str(path), config_digest, key_digest)
        with self._attachment_lock:
            existing = self._attachment_pool_map.get(cache_key)
            if existing is not None and not existing.closed:
                existing.close_when_idle = close_when_idle and existing.close_when_idle
                return existing, preferred
        key_path = Path(value["key_file"])
        module_roots = [CoreCatalog().root / "Network-Adapter"]
        for parent in Path(__file__).resolve().parents:
            module_roots.extend((parent / "Network-Adapter", parent / "share/shadow6/modules"))
        module = next((root for root in module_roots if (root / "shadow6_network.py").is_file()), None)
        if module is None:
            raise Shadow6Error("S6NA runtime module is unavailable")
        import sys
        if str(module) not in sys.path:
            sys.path.insert(0, str(module))
        from shadow6_network import DatagramEndpoint, Limits, load_key
        try:
            key = load_key(key_path)
            if _expected is not None and hashlib.sha256(key).hexdigest() != _expected.get("keyDigest", "").removeprefix("sha256:"):
                raise ValueError("S6NA attachment key differs from Named Service lock")
            bind, peer = value["bind"], value["peer"]
            if (not isinstance(bind, list) or len(bind) != 2 or not isinstance(peer, list) or len(peer) != 2
                    or not isinstance(bind[0], str) or not isinstance(peer[0], str)
                    or type(bind[1]) is not int or type(peer[1]) is not int):
                raise ValueError("invalid pinned S6NA endpoints")
            limits_value = value.get("limits", {})
            if not isinstance(limits_value, dict) or set(limits_value) - set(Limits.__dataclass_fields__):
                raise ValueError("invalid S6NA limits")
            side = value.get("side", 0)
            if type(side) is not int or side not in (0, 1):
                raise ValueError("invalid S6NA direction")
            endpoint = DatagramEndpoint(value["core"], key, tuple(bind), tuple(peer),
                side=side, limits=Limits(**limits_value))
            pool = CreditedPool(self, endpoint, close_when_idle=close_when_idle)
        except (OSError, TypeError, ValueError) as error:
            raise Shadow6Error("invalid S6NA attachment material") from error
        with self._attachment_lock:
            existing = self._attachment_pool_map.get(cache_key)
            if existing is not None and not existing.closed:
                endpoint.close()
                existing.close_when_idle = close_when_idle and existing.close_when_idle
                return existing, preferred
            self._attachment_pools.add(pool)
            self._attachment_pool_map[cache_key] = pool
        return pool, preferred

    def open_credited(self, config: str | os.PathLike[str], *, _expected=None,
                      stream: int | None = None) -> CreditedSession:
        """Open a Profile-aware S6NA application stream.

        Sessions opened from one locked config share its pinned UDP endpoint;
        each receives a distinct S6NA stream ID and bounded receive queue.
        """
        pool, preferred = self._credited_pool(config, _expected=_expected)
        return pool.open(preferred if stream is None else stream)

    def open_credited_for_service(self, name: str, *, stream: int | None = None) -> CreditedSession:
        """Open a multiplexed, lock-bound S6NA stream for a running service."""
        self._ensure_attachment_state()
        if not isinstance(name, str) or not name:
            raise ValueError("Named Service name is required")
        try:
            from Deployment.service_registry import ServiceRegistry
            from Deployment.credited_attachment import credited_core
            item, material = ServiceRegistry().credited_attachment(name)
        except (OSError, ValueError) as error:
            raise Shadow6Error(str(error)) from error
        attachment = material
        expected_core = credited_core(item.get("coreBinding", {}).get("core"), item.get("profileBinding"))
        if attachment.get("core") != expected_core:
            raise Shadow6Error("S6NA attachment Core differs from Named Service")
        pool = self._service_attachment_pools.get(name)
        if pool is None or pool.closed:
            pool, preferred = self._credited_pool(attachment["configPath"],
                _expected=attachment, close_when_idle=False)
            self._service_attachment_pools[name] = pool
        else:
            preferred = 0
        if stream is None:
            return pool.open_available(preferred)
        return pool.open(stream)

    def features(self, component: str | None = None) -> dict:
        args = ("features", "--format", "json")
        if component is not None:
            if not isinstance(component, str) or not component:
                raise ValueError("component must be a non-empty string")
            args += ("--component", component)
        result = self.json(*args)
        if component is None:
            return result
        reports = result.get("components")
        if not isinstance(reports, list) or len(reports) != 1 or not isinstance(reports[0], dict):
            raise Shadow6Error("invalid aggregate feature response")
        return reports[0]

    def _control(self, method: str, params: dict) -> dict:
        result = self.json("control", "call", method, "--params",
                           json.dumps(params, ensure_ascii=False, separators=(",", ":")))
        return result

    @staticmethod
    def _matches(boundary: dict, require: dict) -> bool:
        return all(boundary.get(key) == value for key, value in require.items())

    def resolve(self, require: dict, *, candidates: tuple[str, ...] | list[str] | None = None) -> dict:
        catalog = self._control("capsule.candidates", {})
        entries = catalog.get("candidates")
        if not isinstance(entries, list): raise Shadow6Error("invalid Core candidate catalog")
        allowed = set(candidates) if candidates is not None else None
        matches = [e for e in entries if isinstance(e, dict) and (allowed is None or e.get("core") in allowed)
                   and isinstance(e.get("boundary"), dict) and self._matches(e["boundary"], require)]
        if len(matches) > 1: raise Shadow6Error(json.dumps({"error":"AmbiguousCoreSelection","candidates":[e.get("core") for e in matches]}))
        return {"schema":"shadow6.core-resolution.v1", "candidates":matches}

    def open(self, require: dict, *, core: str | None = None, config: str | os.PathLike[str] | None = None,
             candidates: tuple[str, ...] | list[str] | None = None,
             protocol: str = "tcp", host: str = "127.0.0.1", port: int | None = None,
             ttl: int = 300) -> Session:
        """Select a matching client boundary and start an owned capsule.

        ``config`` defaults to ``SHADOW6_CONFIG``. Stream Core boundaries
        announce their endpoint; seqpacket boundaries require ``port``.
        """
        if self._closed:
            raise Shadow6Error("Shadow6 facade is closed")
        if not isinstance(require, dict) or not require:
            raise ValueError("require must be a non-empty boundary constraint object")
        allowed = {"kind", "mode", "ordered", "reliable", "full_duplex",
                   "message_preserving", "roles", "delivery"}
        if set(require) - allowed:
            raise ValueError("unsupported application-boundary requirement")
        config_path = os.fspath(config) if config is not None else os.environ.get("SHADOW6_CONFIG")
        if not config_path:
            raise ValueError("config is required (or set SHADOW6_CONFIG)")
        result = self.resolve(require, candidates=candidates)
        entries = result["candidates"]
        if core is not None:
            entries = [e for e in entries if e.get("core") == core]
        if len(entries) > 1:
            raise Shadow6Error(json.dumps({"error":"AmbiguousCoreSelection","candidates":[e.get("core") for e in entries]}))
        if not entries:
            raise Shadow6Error("no available Core satisfies the application boundary requirements")
        name, boundary = entries[0]["core"], entries[0]["boundary"]
        mode = boundary.get("mode")
        params = {"core": name, "config": config_path, "ttl": ttl,
                  "boundary_mode": mode}
        if boundary.get("mode") == "seqpacket-fd":
            if port is None:
                raise ValueError("seqpacket-fd boundary requires a loopback listener port")
            params.update(protocol=protocol, host=host, port=port)
        elif mode not in {"localhost-tcp-proxy", "localhost-udp-datagram-proxy"}:
            raise Shadow6Error("selected boundary has no supported capsule transport")
        response = self._control("capsule.start", params)
        token, endpoint = response.get("token"), response.get("endpoint")
        if endpoint is None and boundary.get("mode") == "seqpacket-fd":
            endpoint = {"host": response.get("host"), "port": response.get("port")}
        if (response.get("state") != "running" or not isinstance(token, str)
                or not isinstance(endpoint, dict)
                or endpoint.get("host") not in {"127.0.0.1", "::1"}
                or type(endpoint.get("port")) is not int
                or not 1 <= endpoint["port"] <= 65535):
            if isinstance(token, str):
                try:
                    self._control("capsule.stop", {"token": token})
                except Shadow6Error:
                    pass
            raise Shadow6Error("Control Center returned an invalid capsule endpoint")
        actual_mode = response.get("mode", mode)
        actual_protocol = protocol if actual_mode == "seqpacket-fd" else (
            "udp" if actual_mode == "localhost-udp-datagram-proxy" else "tcp")
        session = Session(self, token, name, endpoint, actual_mode, actual_protocol)
        self._sessions.add(session)
        return session

    def close(self) -> None:
        if self._closed:
            return
        errors = []
        for session in tuple(getattr(self, "_sessions", ())):
            try:
                session.close()
            except Shadow6Error as error:
                errors.append(error)
        for attachment in tuple(getattr(self, "_attachments", ())):
            attachment.close()
            self._attachments.discard(attachment)
        for pool in tuple(getattr(self, "_attachment_pools", ())):
            pool.close()
        self._closed = True
        if errors:
            raise Shadow6Error(f"failed to stop {len(errors)} owned capsule session(s)") from errors[0]

    def __enter__(self) -> "Shadow6":
        if self._closed:
            raise Shadow6Error("Shadow6 facade is closed")
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
