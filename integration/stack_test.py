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
        config = lambda role: output / f"{prefix}-{role}.json"
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
                    duration = time.perf_counter() - started; ordered = sorted(latencies)
                    result = {"schema":"shadow6.network-chain.v1","payload_bytes":len(payload),"requests":len(latencies),"concurrency":1,"bytes_sent":len(payload)*len(latencies),"bytes_received":len(payload)*len(latencies),"duration_seconds":duration,"throughput_bps":len(payload)*len(latencies)*8/duration,"latency_p95_seconds":ordered[min(len(ordered)-1,int(len(ordered)*.95))],"latency_avg_seconds":sum(latencies)/len(latencies),"success_rate":1.0}
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
        if args.benchmark or engine in ("shadow6-go", "shadow6-rust"):
            benchmark_result = run_engine(engine, {"payload_bytes": args.payload_bytes, "requests": args.requests, "concurrency": args.concurrency} if args.benchmark else None)
        else:
            run_native_core_tests(engine)
    if benchmark_result:
        print(json.dumps(benchmark_result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
