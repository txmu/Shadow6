"""In-process capability capsules for bounded client application ingress."""
from __future__ import annotations
import os, secrets, signal, subprocess, time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORES = {
    "pony": ROOT / "Core-Pony" / "shadow6-pony",
    "hare": ROOT / "Core-Hare" / "shadow6-hare",
    "carp": ROOT / "Core-Carp" / "shadow6-carp",
    "idris": ROOT / "Core-Idris" / "shadow6-idris",
}
CAPSULE_REGISTRY = {
    **{name: {"binary": path, "mode": "seqpacket-fd", "max_record": 1172} for name, path in CORES.items()},
    "go": {"binary": ROOT / "Core-Go" / "shadow6-go", "mode": "stream", "max_record": 65536},
    "rust": {"binary": ROOT / "Core-Rust" / "shadow6-rust", "mode": "stream", "max_record": 65536},
    "gleam": {"binary": ROOT / "Core-Gleam" / "shadow6-gleam", "mode": "stream", "max_record": 65536},
    "nim": {"binary": ROOT / "Core-Nim" / "shadow6-nim", "mode": "stream", "max_record": 65536},
    "cpp": {"binary": ROOT / "Core-Cpp" / "shadow6-cpp", "mode": "stream", "max_record": 65536},
    "zig": {"binary": ROOT / "Core-Zig" / "shadow6-zig", "mode": "stream", "max_record": 65536},
    "ada": {"binary": ROOT / "Core-Ada" / "shadow6-ada", "mode": "stream", "max_record": 65536},
    "d": {"binary": ROOT / "Core-D" / "shadow6-d", "mode": "stream", "max_record": 65536},
}
PROXY = ROOT / "Tools" / "app_flow_proxy.py"

@dataclass
class Capsule:
    token: str; core: str; processes: tuple[subprocess.Popen, ...]; created: float; ttl: int
    def close(self):
        for process in self.processes:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError: pass
        for process in self.processes:
            try: process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
    def expired(self): return time.monotonic() >= self.created + self.ttl

_CAPSULES: dict[str, Capsule] = {}

def _safe_config(path: str) -> Path:
    config = Path(path).expanduser().resolve(strict=True)
    st = config.stat()
    if not config.is_file() or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise PermissionError("client config must be owner-only regular file")
    return config

def start(core: str, config: str, protocol: str, host: str, port: int, max_record: int = 1172, ttl: int = 300) -> dict:
    spec = CAPSULE_REGISTRY.get(core)
    if spec is None or spec["mode"] != "seqpacket-fd" or protocol not in {"tcp", "udp"} or host not in {"127.0.0.1", "::1"}:
        raise ValueError("unsupported capsule parameters")
    if not 1 <= port <= 65535 or not 1 <= max_record <= spec["max_record"] or not 30 <= ttl <= 300:
        raise ValueError("capsule bounds exceeded")
    config_path = _safe_config(config)
    binary = spec["binary"]
    if not binary.is_file() or not os.access(binary, os.X_OK): raise FileNotFoundError("Core executable unavailable")
    import socket
    producer, consumer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    producer.set_inheritable(True); consumer.set_inheritable(True)
    env = dict(os.environ); env["SHADOW6_APP_FLOW_FD"] = str(consumer.fileno())
    core_proc = subprocess.Popen([str(binary), "--config", str(config_path)], pass_fds=(consumer.fileno(),), close_fds=True, env=env, start_new_session=True)
    proxy_proc = subprocess.Popen([os.environ.get("PYTHON", "python3"), str(PROXY), "--fd", str(producer.fileno()), "--protocol", protocol, "--host", host, "--port", str(port), "--max-record", str(max_record)], pass_fds=(producer.fileno(),), close_fds=True, start_new_session=True)
    producer.close(); consumer.close()
    token = secrets.token_urlsafe(24); _CAPSULES[token] = Capsule(token, core, (core_proc, proxy_proc), time.monotonic(), ttl)
    return {"schema":"shadow6.capability-capsule.v1","token":token,"core":core,"state":"running","pid":core_proc.pid,"proxy_pid":proxy_proc.pid,"protocol":protocol,"host":host,"port":port,"expires_in":ttl}

def get(token):
    capsule = _CAPSULES.get(token)
    if not capsule or capsule.expired() or any(p.poll() is not None for p in capsule.processes):
        if capsule: capsule.close(); _CAPSULES.pop(token, None)
        raise ValueError("capsule unavailable")
    return capsule

def status(token):
    c=get(token); return {"schema":"shadow6.capability-capsule-status.v1","token":token,"core":c.core,"state":"running","pids":[p.pid for p in c.processes],"expires_in":max(0,int(c.created+c.ttl-time.monotonic()))}

def stop(token):
    c=get(token); c.close(); _CAPSULES.pop(token, None); return {"schema":"shadow6.capability-capsule-status.v1","token":token,"state":"stopped"}
