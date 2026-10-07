"""Compose a registered Core and a bounded loopback application-flow proxy."""
from __future__ import annotations

try:
    from Deployment.service_storage import strict_json as portable_json
except ImportError:
    import sys
    from pathlib import Path
    for _json_path in (Path(__file__).resolve().parents[1] / 'Deployment',
                       Path(__file__).resolve().parents[1] / 'deployment'):
        if (_json_path / 'service_storage.py').is_file():
            sys.path.insert(0, str(_json_path)); break
    from service_storage import strict_json as portable_json

import json
import os
import queue
import re
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


REGISTRY_FILE = Path(os.environ.get("SHADOW6_CAPSULE_REGISTRY", "/etc/shadow6/capsules.json"))
MAX_REGISTRY = 65536
MAX_FEATURE_REPORT = 65536
MAX_RECORD = 1172
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


def _strict_json(data: str | bytes) -> Any:
    return portable_json(data, limit=MAX_FEATURE_REPORT)


def capsule_registry() -> dict[str, dict[str, Any]]:
    try:
        metadata = REGISTRY_FILE.lstat()
    except FileNotFoundError:
        return {}
    if (not stat.S_ISREG(metadata.st_mode) or REGISTRY_FILE.is_symlink()
            or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            or metadata.st_size > MAX_REGISTRY):
        raise PermissionError("unsafe capsule registry")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(REGISTRY_FILE, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_ino != metadata.st_ino
                or opened.st_dev != metadata.st_dev or opened.st_uid != os.geteuid()
                or opened.st_mode & 0o077 or opened.st_size > MAX_REGISTRY):
            raise PermissionError("capsule registry changed while opening")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as source:
            raw = source.read(MAX_REGISTRY + 1)
    finally:
        os.close(fd)
    if len(raw.encode("utf-8")) > MAX_REGISTRY:
        raise ValueError("capsule registry is oversized")
    data = _strict_json(raw)
    if not isinstance(data, dict) or len(data) > 32:
        raise ValueError("invalid capsule registry")
    result: dict[str, dict[str, Any]] = {}
    for name, spec in data.items():
        if (not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(spec, dict)
                or set(spec) - {"binary", "max_record"}
                or not isinstance(spec.get("binary"), str) or not spec["binary"]):
            raise ValueError("invalid capsule entry")
        maximum = spec.get("max_record", MAX_RECORD)
        if type(maximum) is not int or not 1 <= maximum <= MAX_RECORD:
            raise ValueError("invalid capsule limits")
        result[name] = {"binary": spec["binary"], "max_record": maximum}
    return result


def _safe_config(path: str) -> Path:
    candidate = Path(path).expanduser()
    metadata = candidate.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or candidate.is_symlink() or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077 or metadata.st_size > 1_048_576):
        raise PermissionError("client config must be a bounded owner-only regular file")
    config = candidate.resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(config, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_ino != metadata.st_ino
                or opened.st_dev != metadata.st_dev or opened.st_uid != os.geteuid()
                or opened.st_mode & 0o077 or opened.st_size > 1_048_576):
            raise PermissionError("client config changed while opening")
    finally:
        os.close(fd)
    return config


def _client_application_boundaries(binary: Path) -> list[dict[str, Any]]:
    try:
        result = subprocess.run([str(binary), "--feature-report"], capture_output=True,
                                timeout=5, check=False, close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Core feature report unavailable") from error
    if result.returncode or len(result.stdout) > MAX_FEATURE_REPORT:
        raise ValueError("Core feature report unavailable or oversized")
    try:
        report = _strict_json(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Core feature report is invalid") from error
    raw_boundaries = report.get("application_boundaries") if isinstance(report, dict) else None
    if (not isinstance(raw_boundaries, list) or len(raw_boundaries) > 8
            or not isinstance(report.get("core"), str)):
        raise ValueError("Core does not declare application boundaries")
    choices = []
    for boundary in raw_boundaries:
        if not isinstance(boundary, dict):
            continue
        roles = boundary.get("roles")
        mode = boundary.get("mode")
        if not isinstance(roles, list) or "client" not in roles:
            continue
        if mode == "seqpacket-fd":
            maximum = boundary.get("max_record")
            if type(maximum) is int and 1 <= maximum <= MAX_RECORD:
                choices.append(dict(boundary))
        elif mode == "localhost-tcp-proxy" and boundary.get("listener_ownership") == "core":
            if boundary.get("endpoint_discovery") == "stdout-ready-jsonl-v1":
                choices.append(dict(boundary))
        elif (mode == "localhost-udp-datagram-proxy" and report["core"] == "shadow6-gleam"
              and boundary.get("kind") == "message" and boundary.get("roles") == ["client"]
              and boundary.get("message_preserving") is True and boundary.get("ordered") is False
              and boundary.get("reliable") is False and boundary.get("delivery") == "best-effort"
              and boundary.get("max_record") == 65465 and boundary.get("listener_ownership") == "core"
              and boundary.get("endpoint_discovery") == "stdout-ready-jsonl-v1"
              and boundary.get("listener_ready") == "bound-and-listening"):
            choices.append(dict(boundary))
    if not choices:
        raise ValueError("Core declares no supported client application boundary")
    return [{**choice, "core": report["core"]} for choice in choices]


def _client_application_boundary(binary: Path, mode: str | None = None) -> dict[str, Any]:
    choices = _client_application_boundaries(binary)
    if mode is not None:
        selected = next((item for item in choices if item["mode"] == mode), None)
    else:
        # Keep the existing Core-owned stream as the default when it is declared.
        selected = next((item for item in choices if item["mode"] == "localhost-tcp-proxy"), choices[0])
    if selected is None:
        raise ValueError("requested application boundary is not declared by Core")
    return selected


def candidates() -> dict[str, Any]:
    """Report only registered Cores with a supported client boundary."""
    registered = capsule_registry()
    available = []
    for name, spec in registered.items():
        try:
            binary = _resolved_executable(spec["binary"], "Core")
            boundaries = _client_application_boundaries(binary)
        except (OSError, ValueError, TimeoutError):
            continue
        available.extend({"core": name, "identity": boundary["core"], "boundary": boundary}
                         for boundary in boundaries)
        if len(available) > 64:
            raise ValueError("capsule candidate catalog exceeds its bound")
    return {"schema": "shadow6.capability-capsule-candidates.v1", "candidates": available}


def _boundary_ready(process: subprocess.Popen, expected_core: str, mode: str,
                    timeout: float = 15) -> dict[str, Any]:
    if process.stdout is None:
        raise ValueError("Core readiness stream unavailable")
    first_line: queue.Queue[bytes | None] = queue.Queue(maxsize=1)

    def drain() -> None:
        try:
            while line := process.stdout.readline(MAX_FEATURE_REPORT + 1):
                if first_line.empty():
                    first_line.put(line)
        except OSError:
            pass
        finally:
            if first_line.empty():
                first_line.put(None)

    threading.Thread(target=drain, name="shadow6-capsule-ready", daemon=True).start()
    try:
        line = first_line.get(timeout=timeout)
    except queue.Empty as error:
        raise TimeoutError("Core readiness event timed out") from error
    if line is None or len(line) > MAX_FEATURE_REPORT or not line.endswith(b"\n"):
        raise ValueError("Core readiness event is missing or oversized")
    try:
        event = _strict_json(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Core readiness event is invalid") from error
    expected_kind = "stream" if mode == "localhost-tcp-proxy" else "message"
    if (not isinstance(event, dict) or event.get("event") != "shadow6.ready"
            or type(event.get("schema")) is not int or event["schema"] != 1
            or event.get("core") != expected_core or event.get("role") != "client"):
        raise ValueError("Core readiness event does not match its feature report")
    boundary = event.get("application_boundary")
    endpoint = boundary.get("endpoint") if isinstance(boundary, dict) else None
    if (not isinstance(boundary, dict) or boundary.get("kind") != expected_kind
            or boundary.get("mode") != mode or not isinstance(endpoint, dict)
            or endpoint.get("host") not in {"127.0.0.1", "::1"}
            or type(endpoint.get("port")) is not int or not 1 <= endpoint["port"] <= 65535):
        raise ValueError("Core readiness endpoint is invalid")
    if process.poll() is not None:
        raise ValueError("Core exited after announcing readiness")
    return {"host": endpoint["host"], "port": endpoint["port"]}


def _proxy_ready(process: subprocess.Popen, read_fd: int, protocol: str, host: str, port: int,
                 timeout: float = 5) -> None:
    try:
        readable, _, _ = select.select([read_fd], [], [], timeout)
        if not readable:
            raise TimeoutError("application-flow proxy readiness timed out")
        line = os.read(read_fd, 4097)
        if len(line) > 4096 or not line.endswith(b"\n"):
            raise ValueError("application-flow proxy readiness event is invalid")
        event = _strict_json(line)
        if (not isinstance(event, dict) or event.get("event") != "shadow6.app-flow-proxy.ready"
                or type(event.get("schema")) is not int or event["schema"] != 1
                or event.get("protocol") != protocol or event.get("host") != host
                or event.get("port") != port):
            raise ValueError("application-flow proxy readiness event does not match request")
        if process.poll() is not None:
            raise ValueError("application-flow proxy exited after readiness")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("application-flow proxy readiness JSON is invalid") from error


def _resolved_executable(value: str, label: str) -> Path:
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise FileNotFoundError(f"{label} executable unavailable")
    return path


@dataclass
class Capsule:
    token: str
    core: str
    processes: tuple[subprocess.Popen, ...]
    created: float
    ttl: int
    mode: str = "seqpacket-fd"
    endpoint: dict[str, Any] | None = None
    paused: bool = False
    closed: bool = False
    state_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def close(self) -> None:
        with self.state_lock:
            if self.closed:
                return
            self.closed = True
            for process in self.processes:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        os.killpg(process.pid, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
            for process in self.processes:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
                stdout = getattr(process, "stdout", None)
                if stdout is not None:
                    stdout.close()

    def expired(self, now: float | None = None) -> bool:
        return (time.monotonic() if now is None else now) >= self.created + self.ttl


_CAPSULES: dict[str, Capsule] = {}
_LOCK = threading.RLock()
_REAPER_WAKE = threading.Event()
_REAPER: threading.Thread | None = None


def _reap_expired(now: float | None = None) -> int:
    current = time.monotonic() if now is None else now
    with _LOCK:
        expired = [token for token, capsule in _CAPSULES.items() if capsule.expired(current)]
        capsules = [_CAPSULES.pop(token) for token in expired]
    for capsule in capsules:
        capsule.close()
    return len(capsules)


def _reaper_loop() -> None:
    while True:
        with _LOCK:
            deadlines = [capsule.created + capsule.ttl for capsule in _CAPSULES.values()]
        delay = max(0.0, min(deadlines) - time.monotonic()) if deadlines else None
        if _REAPER_WAKE.wait(delay):
            _REAPER_WAKE.clear()
            continue
        _reap_expired()


def _ensure_reaper() -> None:
    global _REAPER
    with _LOCK:
        if _REAPER is None or not _REAPER.is_alive():
            _REAPER = threading.Thread(target=_reaper_loop, name="shadow6-capsule-reaper", daemon=True)
            _REAPER.start()
    _REAPER_WAKE.set()


def start(core: str, config: str, protocol: str | None = None, host: str | None = None,
          port: int | None = None,
          max_record: int | None = None, ttl: int = 300,
          boundary_mode: str | None = None) -> dict[str, Any]:
    registry = capsule_registry()
    spec = registry.get(core)
    if spec is None:
        raise ValueError("Core is not registered for capsule use")
    if type(ttl) is not int or not 30 <= ttl <= 300:
        raise ValueError("capsule bounds exceeded")
    binary = _resolved_executable(spec["binary"], "Core")
    boundary = _client_application_boundary(binary, boundary_mode)
    proxy: Path | None = None
    if boundary["mode"] == "seqpacket-fd":
        protocol = protocol or "tcp"
        host = host or "127.0.0.1"
        if (protocol not in {"tcp", "udp"} or host not in {"127.0.0.1", "::1"}
                or type(port) is not int or not 1 <= port <= 65535):
            raise ValueError("seqpacket capsule requires a loopback protocol and port")
        proxy_value = os.environ.get("SHADOW6_APP_FLOW_PROXY")
        if not proxy_value:
            raise ValueError("SHADOW6_APP_FLOW_PROXY is required")
        proxy = Path(proxy_value).expanduser().resolve(strict=True)
        if not proxy.is_file():
            raise FileNotFoundError("application-flow proxy unavailable")
    config_path = _safe_config(config)
    if boundary["mode"] == "seqpacket-fd":
        python = shutil.which(os.environ.get("PYTHON", "python3"))
        if not python:
            raise FileNotFoundError("Python executable unavailable")
        boundary_limit = min(spec["max_record"], boundary["max_record"])
        requested_limit = boundary_limit if max_record is None else max_record
        if type(requested_limit) is not int or not 1 <= requested_limit <= boundary_limit:
            raise ValueError("max-record exceeds the Core application boundary")
    else:
        if any(value is not None for value in (protocol, host, port, max_record)):
            raise ValueError("Core-owned application boundaries do not accept proxy parameters")
        requested_limit = None
    if boundary["mode"] == "seqpacket-fd" and not hasattr(socket, "SOCK_SEQPACKET"):
        raise ValueError("SOCK_SEQPACKET is unavailable on this platform")

    core_proc: subprocess.Popen | None = None
    proxy_proc: subprocess.Popen | None = None
    endpoint = None
    if boundary["mode"] == "seqpacket-fd":
        producer, consumer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        ready_read, ready_write = os.pipe()
        try:
            producer.set_inheritable(True)
            consumer.set_inheritable(True)
            os.set_inheritable(ready_write, True)
            env = dict(os.environ)
            env["SHADOW6_APP_FLOW_FD"] = str(consumer.fileno())
            core_proc = subprocess.Popen([str(binary), "--config", str(config_path)],
                                         pass_fds=(consumer.fileno(),), close_fds=True,
                                         env=env, start_new_session=True)
            proxy_proc = subprocess.Popen([python, str(proxy), "--fd", str(producer.fileno()),
                                           "--protocol", protocol, "--host", host, "--port", str(port),
                                           "--max-record", str(requested_limit), "--ready-fd", str(ready_write)],
                                          pass_fds=(producer.fileno(), ready_write), close_fds=True,
                                          start_new_session=True)
            os.close(ready_write)
            ready_write = -1
            _proxy_ready(proxy_proc, ready_read, protocol, host, port)
            ready_read = -1
        except BaseException:
            if proxy_proc is not None:
                Capsule("", core, (proxy_proc,), time.monotonic(), 1).close()
            if core_proc is not None:
                Capsule("", core, (core_proc,), time.monotonic(), 1).close()
            raise
        finally:
            producer.close()
            consumer.close()
            if ready_read >= 0:
                os.close(ready_read)
            if ready_write >= 0:
                os.close(ready_write)
    else:
        core_proc = subprocess.Popen([str(binary), "--config", str(config_path)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
        try:
            endpoint = _boundary_ready(core_proc, boundary["core"], boundary["mode"])
        except BaseException:
            Capsule("", core, (core_proc,), time.monotonic(), 1).close()
            if core_proc.stdout:
                core_proc.stdout.close()
            raise

    token = secrets.token_urlsafe(24)
    created = time.monotonic()
    processes = (core_proc, proxy_proc) if proxy_proc is not None else (core_proc,)
    capsule = Capsule(token, core, processes, created, ttl,
                      mode=boundary["mode"], endpoint=endpoint)
    with _LOCK:
        _CAPSULES[token] = capsule
    _ensure_reaper()
    result = {"schema": "shadow6.capability-capsule.v1", "token": token, "core": core,
              "state": "running", "mode": boundary["mode"], "pid": core_proc.pid,
              "expires_in": ttl}
    if proxy_proc is not None:
        result.update({"proxy_pid": proxy_proc.pid, "protocol": protocol, "host": host, "port": port})
    if endpoint is not None:
        result["endpoint"] = endpoint
    return result


def get(token: str) -> Capsule:
    with _LOCK:
        capsule = _CAPSULES.get(token)
        if capsule is None:
            raise ValueError("capsule unavailable")
        if not capsule.expired() and all(process.poll() is None for process in capsule.processes):
            return capsule
        _CAPSULES.pop(token, None)
    capsule.close()
    raise ValueError("capsule unavailable")


def status(token: str) -> dict[str, Any]:
    capsule = get(token)
    result = {"schema": "shadow6.capability-capsule-status.v1", "token": token,
              "core": capsule.core, "mode": capsule.mode,
              "state": "paused" if capsule.paused else "running",
              "pids": [p.pid for p in capsule.processes],
              "expires_in": max(0, int(capsule.created + capsule.ttl - time.monotonic()))}
    if capsule.endpoint is not None:
        result["endpoint"] = capsule.endpoint
    return result


def list_capsules() -> dict[str, Any]:
    _reap_expired()
    with _LOCK:
        entries = list(_CAPSULES.values())
    now = time.monotonic()
    return {"schema": "shadow6.capability-capsule-catalog.v1", "capsules": [
        {"core": capsule.core, "mode": capsule.mode,
         "state": "paused" if capsule.paused else "running",
         "pids": [process.pid for process in capsule.processes],
         "expires_in": max(0, int(capsule.created + capsule.ttl - now)),
         **({"endpoint": capsule.endpoint} if capsule.endpoint is not None else {})}
        for capsule in entries]}


def pause(token: str) -> dict[str, Any]:
    capsule = get(token)
    with capsule.state_lock:
        if capsule.closed:
            raise ValueError("capsule unavailable")
        if not capsule.paused:
            stopped = []
            try:
                for process in capsule.processes:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGSTOP)
                        stopped.append(process)
            except OSError:
                for process in stopped:
                    try:
                        os.killpg(process.pid, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
                raise
            capsule.paused = True
    return status(token)


def resume(token: str) -> dict[str, Any]:
    capsule = get(token)
    with capsule.state_lock:
        if capsule.closed:
            raise ValueError("capsule unavailable")
        if capsule.paused:
            resumed = []
            try:
                for process in capsule.processes:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGCONT)
                        resumed.append(process)
            except OSError:
                for process in resumed:
                    try:
                        os.killpg(process.pid, signal.SIGSTOP)
                    except ProcessLookupError:
                        pass
                raise
            capsule.paused = False
    return status(token)


def stop(token: str) -> dict[str, Any]:
    capsule = get(token)
    with _LOCK:
        _CAPSULES.pop(token, None)
    capsule.close()
    _REAPER_WAKE.set()
    return {"schema": "shadow6.capability-capsule-status.v1", "token": token, "state": "stopped"}
