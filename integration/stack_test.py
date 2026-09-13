#!/usr/bin/env python3
"""Single-host end-to-end test for the generated Shadow6 Go/Rust stacks.

The test deliberately uses only loopback/process resources: the orchestrator
generates real credentials and configs, then real Broker, Agent and Client
processes carry traffic to a local TCP echo target.
"""

from __future__ import annotations

import argparse
import json
import asyncio
import os
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Auto-Orchestrator"))
from shadow6_auto import execute_mtd_rotation  # noqa: E402

# Each entry invokes the core's existing real loopback/network tests.  The
# harness never substitutes a synthetic wire protocol for a missing core test.
CORE_TESTS = {
    "shadow6-zig": [ROOT / "Core-Zig/test_core.py"],
    "shadow6-ada": [ROOT / "Core-Ada/test_core.py"],
    "shadow6-d": [ROOT / "Core-D/test_core.py"],
    "shadow6-nim": [ROOT / "Core-Nim/test_core.py"],
    "shadow6-cpp": [ROOT / "Core-Cpp/test_core.py"],
    "shadow6-pony": [ROOT / "Core-Pony/tests/test_network.py"],
    "shadow6-hare": [ROOT / "Core-Hare/tests/test_runtime.py"],
    "shadow6-carp": [ROOT / "Core-Carp/tests/test_core.py"],
    "shadow6-gleam": [ROOT / "Core-Gleam/test_control.py"],
    "shadow6-idris": [ROOT / "Core-Idris/test_core.py"],
}
CORE_BINARIES = {
    engine: ROOT / directory / binary
    for engine, directory, binary in (
        ("shadow6-zig", "Core-Zig", "shadow6-zig"),
        ("shadow6-ada", "Core-Ada", "shadow6-ada"),
        ("shadow6-d", "Core-D", "shadow6-d"),
        ("shadow6-nim", "Core-Nim", "shadow6-nim"),
        ("shadow6-cpp", "Core-Cpp", "shadow6-cpp"),
        ("shadow6-pony", "Core-Pony", "shadow6-pony"),
        ("shadow6-hare", "Core-Hare", "shadow6-hare"),
        ("shadow6-carp", "Core-Carp", "shadow6-carp"),
        ("shadow6-gleam", "Core-Gleam", "shadow6-gleam"),
        ("shadow6-idris", "Core-Idris", "shadow6-idris"),
    )
}
CORE_BINARIES.update({
    "shadow6-go": ROOT / "Core-Go/shadow6-go",
    "shadow6-rust": ROOT / "Core-Rust/shadow6-rust",
})

def benchmark_metrics(payload: bytes, latencies: list[float], duration: float) -> dict:
    ordered = sorted(latencies); count = len(latencies)
    return {"schema":"shadow6.network-chain.v1","payload_bytes":len(payload),"requests":count,"concurrency":1,"bytes_sent":len(payload)*count,"bytes_received":len(payload)*count,"duration_seconds":duration,"throughput_bps":len(payload)*count*8/duration,"latency_p95_seconds":ordered[min(count-1,int(count*.95))],"latency_avg_seconds":sum(latencies)/count,"success_rate":1.0}

def reserve_udp(family: int, count: int) -> list[int]:
    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    sockets = [socket.socket(family, socket.SOCK_DGRAM) for _ in range(count)]
    try:
        for item in sockets: item.bind((host, 0))
        return [item.getsockname()[1] for item in sockets]
    finally:
        for item in sockets: item.close()

def run_datagram_engine(engine: str, benchmark: dict) -> dict:
    binary = CORE_BINARIES[engine]; family = socket.AF_INET6 if engine == "shadow6-hare" else socket.AF_INET
    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"; ports = reserve_udp(family, 4)
    agent_port, client_port, app_port, target_port = ports
    target = socket.socket(family, socket.SOCK_DGRAM); target.bind((host, target_port)); target.settimeout(10)
    local = socket.socket(family, socket.SOCK_DGRAM); local.bind((host, 0)); local.settimeout(10)
    processes = []
    with tempfile.TemporaryDirectory(prefix=f"shadow6-bench-{engine}-") as directory:
        root = Path(directory)
        if engine == "shadow6-pony":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            seeds = [os.urandom(32), os.urandom(32)]
            pubs = [Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for seed in seeds]
            configs = [dict(role="agent",listen_port=agent_port,peer_port=client_port,application_port=target_port,private_key=seeds[0].hex(),peer_public_key=pubs[1]),dict(role="client",listen_port=client_port,peer_port=agent_port,application_port=app_port,private_key=seeds[1].hex(),peer_public_key=pubs[0])]
        else:
            keys = [json.loads(subprocess.check_output([str(binary), "--gen-key"], text=True)) for _ in range(2)]
            configs = [{"role":"agent","private_key":keys[0]["private_key"],"peer_public_key":keys[1]["public_key"],"listen_port":agent_port,"target_port":target_port},{"role":"client","private_key":keys[1]["private_key"],"peer_public_key":keys[0]["public_key"],"listen_port":client_port,"target_port":agent_port}]
            app_port = client_port + 1
        try:
            for config in configs:
                path=root/(config["role"]+".json");path.write_text(json.dumps(config),encoding="utf-8");path.chmod(0o600)
                processes.append(subprocess.Popen([str(binary),"--config",str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE))
            for process in processes:
                if not select.select([process.stdout],[],[],10)[0]: raise TimeoutError(f"{engine}: endpoint readiness timeout")
                if b"ready" not in process.stdout.readline(): raise RuntimeError(f"{engine}: endpoint failed readiness")
            if engine == "shadow6-hare":
                for process in processes:
                    if not select.select([process.stdout],[],[],10)[0] or b"session ready" not in process.stdout.readline(): raise TimeoutError(f"{engine}: session readiness timeout")
            payload=b"x"*benchmark["payload_bytes"];latencies=[];started=time.perf_counter()
            for _ in range(benchmark["requests"]):
                request=time.perf_counter();local.sendto(payload,(host,app_port));data,address=target.recvfrom(1048577)
                if data!=payload:raise AssertionError(f"{engine}: target payload mismatch")
                target.sendto(data,address)
                if local.recv(1048577)!=payload:raise AssertionError(f"{engine}: client response mismatch")
                latencies.append(time.perf_counter()-request)
            return benchmark_metrics(payload,latencies,time.perf_counter()-started)
        finally:
            target.close();local.close()
            for process in processes:
                process.terminate();process.communicate(timeout=5)

def run_carp_engine(benchmark: dict) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    binary=CORE_BINARIES["shadow6-carp"];ports=reserve_udp(socket.AF_INET,4);processes=[]
    with tempfile.TemporaryDirectory(prefix="shadow6-bench-carp-") as directory:
        root=Path(directory); channels=[]
        for index in range(2):
            seeds=[os.urandom(32),os.urandom(32)];pubs=[Ed25519PrivateKey.from_private_bytes(s).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for s in seeds];binding=os.urandom(32)
            paths=[]
            for side in range(2):
                path=root/f"{index}-{side}.keys";path.write_bytes(seeds[side]+pubs[1-side]+binding);path.chmod(0o600);paths.append(path)
            listener=subprocess.Popen([str(binary),"--listen",str(paths[1]),str(ports[index*2+1]),str(ports[index*2]),"C"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            sender=subprocess.Popen([str(binary),"--send",str(paths[0]),str(ports[index*2]),str(ports[index*2+1]),"C"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            processes += [listener,sender];channels.append((sender,listener))
        try:
            time.sleep(.25);payload=b"x"*benchmark["payload_bytes"];latencies=[];started=time.perf_counter()
            for _ in range(benchmark["requests"]):
                request=time.perf_counter();channels[0][0].stdin.write(payload);channels[0][0].stdin.flush()
                if not select.select([channels[0][1].stdout],[],[],10)[0] or channels[0][1].stdout.read(len(payload))!=payload:raise AssertionError("shadow6-carp: forward path failed")
                channels[1][0].stdin.write(payload);channels[1][0].stdin.flush()
                if not select.select([channels[1][1].stdout],[],[],10)[0] or channels[1][1].stdout.read(len(payload))!=payload:raise AssertionError("shadow6-carp: reverse path failed")
                latencies.append(time.perf_counter()-request)
            return benchmark_metrics(payload,latencies,time.perf_counter()-started)
        finally:
            for process in processes:
                process.terminate()
                try:process.communicate(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.communicate()

def run_idris_engine(benchmark: dict) -> dict:
    if benchmark["payload_bytes"] != 4: raise ValueError("shadow6-idris benchmark payload is fixed at 4 bytes")
    binary=CORE_BINARIES["shadow6-idris"];payload=b"ping";latencies=[];started=time.perf_counter()
    for _ in range(benchmark["requests"]):
        request=time.perf_counter();result=subprocess.run([str(binary),"--loopback-test"],cwd=binary.parent,capture_output=True,timeout=10)
        if result.returncode or b"PASS" not in result.stdout:raise RuntimeError(f"shadow6-idris loopback failed: {result.stderr[-2048:]!r}")
        latencies.append(time.perf_counter()-request)
    return benchmark_metrics(payload,latencies,time.perf_counter()-started)


def run_native_core_tests(engine: str) -> None:
    tests = CORE_TESTS.get(engine)
    if not tests:
        return
    missing = [str(path) for path in tests if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"{engine}: missing real integration test: {', '.join(missing)}")
    for test in tests:
        # Core-Cpp's Python suite requires a freshly compiled native protocol
        # probe.  test.sh owns both the probe's temporary lifetime and its
        # SHADOW6_CPP_PROBE environment variable, so it must be the entrypoint.
        if engine == "shadow6-cpp":
            command = ["bash", "./test.sh"]
            cwd = test.parent
            environment = dict(os.environ)
            environment["PYTHON"] = str(Path(sys.executable).resolve())
        elif engine == "shadow6-gleam":
            command = [sys.executable, str(test), str(CORE_BINARIES[engine])]
            cwd = ROOT
            environment = None
        elif engine == "shadow6-idris":
            command = [sys.executable, str(test)]
            cwd = test.parent
            environment = None
        else:
            command = [sys.executable, str(test)]
            cwd = ROOT
            environment = None
        result = subprocess.run(command, cwd=cwd, env=environment, text=True, capture_output=True, timeout=180, check=False)
        if result.returncode:
            raise RuntimeError(f"{engine} real integration failed ({test}): {result.stdout[-2000:]} {result.stderr[-2000:]}")
        print(f"[PASS] {engine} native integration: {test.relative_to(ROOT)}")


class EchoTarget:
    def __init__(self) -> None:
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.error: BaseException | None = None
        self.listener: socket.socket | None = None
        self.port = 0
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                self.listener = listener
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(16)
                listener.settimeout(0.2)
                self.port = listener.getsockname()[1]
                self.ready.set()
                while not self.stop.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(10)
                        while not self.stop.is_set():
                            data = connection.recv(65536)
                            if not data:
                                break
                            connection.sendall(data)
        except OSError as exc:
            if not self.stop.is_set():
                self.error = exc
            self.ready.set()
        except BaseException as exc:  # surfaced by the caller after shutdown
            self.error = exc
            self.ready.set()

    def start(self) -> int:
        self.thread.start()
        if not self.ready.wait(3):
            raise RuntimeError("echo target did not start")
        if self.error:
            raise self.error
        return self.port

    def close(self) -> None:
        self.stop.set()
        if self.listener:
            self.listener.close()
        self.thread.join(2)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def terminate(process: subprocess.Popen[str] | None, label: str) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError(f"{label} did not terminate cleanly")


def wait_for_proxy(client: subprocess.Popen[str], log_path: Path, deadline: float) -> int:
    pattern = re.compile(r"127\.0\.0\.1:(\d+)")
    captured = ""
    while time.monotonic() < deadline:
        captured = log_path.read_text(encoding="utf-8", errors="replace")
        match = pattern.search(captured)
        if match:
            return int(match.group(1))
        if client.poll() is not None:
            raise RuntimeError(f"client exited with {client.returncode}: {captured[-2000:]}")
        time.sleep(0.05)
    raise TimeoutError(f"client did not expose a loopback proxy; output: {captured[-2000:]}")


async def generate_configs(engine: str, output: Path, target_port: int, broker_port: int) -> None:
    if engine == "shadow6-cpp":
        subprocess.run([str(CORE_BINARIES[engine]), "--init-demo", str(output)], check=True, capture_output=True, timeout=10)
        documents = {role: json.loads((output / f"{role}.json").read_text(encoding="utf-8")) for role in ("broker", "agent", "client")}
        documents["broker"]["broker"]["listen_addr"] = f"127.0.0.1:{broker_port}"
        for role in ("agent", "client"):
            documents[role][role]["broker_addr"] = f"127.0.0.1:{broker_port}"
            documents[role][role]["listen_addr"] = "127.0.0.1:0"
        documents["agent"]["agent"]["target_addr"] = f"127.0.0.1:{target_port}"
        for role, document in documents.items():
            path = output / f"{role}.json"
            path.write_text(json.dumps(document), encoding="utf-8"); path.chmod(0o600)
        return
    topology = {
        "version": "1.0",
        "global": {
            "stealth_mode": True,
            "mtd_rotation_interval": "1h",
            "broker_scheme": "ws",
            "output_dir": str(output),
        },
        "nodes": [
            {
                "name": f"it-{engine}-broker",
                "type": "broker",
                "listen_host": "127.0.0.1",
                "advertise_host": "127.0.0.1",
                "listen_port": broker_port,
                "engines": [engine],
            },
            {
                "name": f"it-{engine}-agent",
                "type": "agent",
                "target_port": target_port,
                "auto_close_after": 30,
                "allow_local_discovery": False,
                "engines": [engine],
            },
            {
                "name": f"it-{engine}-client",
                "type": "client",
                "target_agent": f"it-{engine}-agent",
                "allow_local_discovery": False,
                "on_success": "",
                "engines": [engine],
            },
        ],
    }
    await execute_mtd_rotation(topology)


def run_engine(engine: str, benchmark: dict | None = None) -> dict | None:
    binary = CORE_BINARIES[engine]
    if engine == "shadow6-zig" and not binary.is_file():
        binary = ROOT / "Core-Zig/zig-out/bin/shadow6-zig"
    if not binary.is_file():
        raise FileNotFoundError(f"missing built binary: {binary}")

    target = EchoTarget()
    broker = agent = client = None
    success = False
    with tempfile.TemporaryDirectory(prefix=f"shadow6-it-{engine}-") as directory:
        output = Path(directory) / "configs"
        target_port = target.start()
        broker_port = free_port()
        asyncio.run(generate_configs(engine, output, target_port, broker_port))
        prefix = f"it-{engine}"
        config = lambda role: output / (f"{role}.json" if engine == "shadow6-cpp" else f"{prefix}-{role}.json")
        command = lambda cfg: [str(binary), "--config", str(cfg)]
        log_paths = {role: Path(directory) / f"{role}.log" for role in ("broker", "agent", "client")}
        log_files = {
            role: path.open("w", encoding="utf-8", buffering=1)
            for role, path in log_paths.items()
        }
        try:
            broker = subprocess.Popen(
                command(config("broker")), stdout=log_files["broker"], stderr=subprocess.STDOUT, text=True
            )
            time.sleep(0.5)
            agent = subprocess.Popen(
                command(config("agent")), stdout=log_files["agent"], stderr=subprocess.STDOUT, text=True
            )
            time.sleep(1.0)
            client = subprocess.Popen(
                command(config("client")), stdout=log_files["client"], stderr=subprocess.STDOUT, text=True
            )
            proxy_port = wait_for_proxy(client, log_paths["client"], time.monotonic() + 20)
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as connection:
                connection.sendall(b"ping")
                if connection.recv(4) != b"ping":
                    raise AssertionError(f"{engine}: target response mismatch")
                if benchmark:
                    payload = b"x" * benchmark["payload_bytes"]
                    latencies = []; started = time.perf_counter()
                    for _ in range(benchmark["requests"]):
                        request_started = time.perf_counter(); connection.sendall(payload)
                        received = connection.recv(len(payload))
                        if received != payload: raise AssertionError(f"{engine}: benchmark response mismatch")
                        latencies.append(time.perf_counter() - request_started)
                    duration = time.perf_counter() - started
                    result = benchmark_metrics(payload,latencies,duration)
            print(f"[PASS] {engine} orchestrator -> broker -> agent -> client data path")
            success = True
        finally:
            terminate(client, "client")
            terminate(agent, "agent")
            terminate(broker, "broker")
            for log_file in log_files.values():
                log_file.close()
            for process, label in ((client, "client"), (agent, "agent"), (broker, "broker")):
                if process is not None:
                    if not success or process.returncode not in (0, -signal.SIGTERM):
                        output_text = log_paths[label].read_text(encoding="utf-8", errors="replace")
                        print(f"[{engine}] {label} output:\n{output_text[-4000:]}", file=sys.stderr)
            target.close()
            if target.error:
                raise target.error
    return result if benchmark else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=("shadow6-go", "shadow6-rust", *CORE_TESTS, "all"), default="all")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--payload-bytes", type=int, default=16384)
    parser.add_argument("--requests", type=int, default=32)
    parser.add_argument("--concurrency", type=int, default=1)
    args = parser.parse_args()
    if not all(1 <= value <= limit for value, limit in ((args.payload_bytes, 1048576), (args.requests, 100000))) or args.concurrency != 1:
        parser.error("benchmark bounds exceeded")
    if args.engine == "all":
        engines = ("shadow6-go", "shadow6-rust", *(engine for engine in CORE_TESTS if CORE_BINARIES[engine].is_file()))
        skipped = [engine for engine in CORE_TESTS if not CORE_BINARIES[engine].is_file()]
        for engine in skipped:
            print(f"[SKIP] {engine} native integration: binary was not built")
    else:
        engines = (args.engine,)
    benchmark_result = None
    for engine in engines:
        if args.benchmark and engine == "shadow6-idris":
            benchmark_result = run_idris_engine({"payload_bytes": args.payload_bytes, "requests": args.requests, "concurrency": args.concurrency})
        elif args.benchmark and engine == "shadow6-carp":
            benchmark_result = run_carp_engine({"payload_bytes": args.payload_bytes, "requests": args.requests, "concurrency": args.concurrency})
        elif args.benchmark and engine in ("shadow6-pony", "shadow6-hare"):
            benchmark_result = run_datagram_engine(engine, {"payload_bytes": args.payload_bytes, "requests": args.requests, "concurrency": args.concurrency})
        elif args.benchmark or engine in ("shadow6-go", "shadow6-rust"):
            benchmark_result = run_engine(engine, {"payload_bytes": args.payload_bytes, "requests": args.requests, "concurrency": args.concurrency} if args.benchmark else None)
        else:
            run_native_core_tests(engine)
    if benchmark_result:
        print(json.dumps(benchmark_result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
