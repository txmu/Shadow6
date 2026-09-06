#!/usr/bin/env python3
"""Single-host end-to-end test for the generated Shadow6 Go/Rust stacks.

The test deliberately uses only loopback/process resources: the orchestrator
generates real credentials and configs, then real Broker, Agent and Client
processes carry traffic to a local TCP echo target.
"""

from __future__ import annotations

import argparse
import asyncio
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
                        connection.settimeout(3)
                        if connection.recv(4) == b"ping":
                            connection.sendall(b"pong")
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


def run_engine(engine: str) -> None:
    binary_name = "shadow6-go" if engine == "shadow6-go" else "shadow6-rust"
    binary = ROOT / ("Core-Go" if engine == "shadow6-go" else "Core-Rust") / binary_name
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
                if connection.recv(4) != b"pong":
                    raise AssertionError(f"{engine}: target response mismatch")
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=("shadow6-go", "shadow6-rust", "all"), default="all")
    args = parser.parse_args()
    engines = ("shadow6-go", "shadow6-rust") if args.engine == "all" else (args.engine,)
    for engine in engines:
        run_engine(engine)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
