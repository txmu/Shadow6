"""Python application facade for a locally managed Shadow6 deployment."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

__all__ = ["Shadow6", "Shadow6Error", "Session", "run"]

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
        self._closed = False

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

    def connect(self, name: str):
        """Open a bounded local application session from actual ready state."""
        from Deployment.connection_plan import open_local_session
        return open_local_session(self.connection_plan(name))

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
        for session in tuple(self._sessions):
            try:
                session.close()
            except Shadow6Error as error:
                errors.append(error)
        self._closed = True
        if errors:
            raise Shadow6Error(f"failed to stop {len(errors)} owned capsule session(s)") from errors[0]

    def __enter__(self) -> "Shadow6":
        if self._closed:
            raise Shadow6Error("Shadow6 facade is closed")
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
