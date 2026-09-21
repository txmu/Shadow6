#!/usr/bin/env python3
"""One application-level contract for all twelve native Shadow6 trios.

The test deliberately uses only loopback/process resources: the orchestrator
generates real credentials and configs, then real Broker, Agent and Client
processes carry traffic to a local TCP echo target.
"""

from __future__ import annotations

import argparse
import json
import ipaddress
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
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from native_configs import DATAGRAM_CORES, generate_commands
from companion import Adapter, BACKENDS, Channel, exchange


ROOT = Path(__file__).resolve().parents[1]
_BROKER_BIND_LOCK = threading.Lock()

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

def receive_exact(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise EOFError('target closed before complete benchmark response')
        result.extend(chunk)
    return bytes(result)



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
    def __init__(self, rtt_ms: int = 0, loss_percent: int = 0) -> None:
        if not 0 <= rtt_ms <= 2000 or not 0 <= loss_percent <= 50:
            raise ValueError("impairment bounds exceeded")
        self.rtt_ms = rtt_ms
        self.loss_percent = loss_percent
        self.responses = 0
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.error: BaseException | None = None
        self.listener: socket.socket | None = None
        self.port = 0
        self.connection_done = threading.Event()
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
                    try:
                        with connection:
                            connection.settimeout(10)
                            while not self.stop.is_set():
                                data = connection.recv(65536)
                                if not data:
                                    break
                                self.responses += 1
                                # Bounded deterministic userspace model: delay
                                # every response by the configured RTT and add
                                # one RTT of recovery cost at the requested loss
                                # cadence. It never changes host qdiscs/routes.
                                delay = self.rtt_ms / 1000
                                if self.loss_percent and self.responses % max(1, 100 // self.loss_percent) == 0:
                                    delay += self.rtt_ms / 1000
                                if delay:
                                    time.sleep(delay)
                                connection.sendall(data)
                    finally:
                        self.connection_done.set()
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

    def wait_for_connection_close(self, timeout: float) -> bool:
        return self.connection_done.wait(timeout)


class DatagramEchoTarget(EchoTarget):
    def __init__(self, family: int, **kwargs):
        self.family = family
        super().__init__(**kwargs)

    def _run(self):
        try:
            with socket.socket(self.family, socket.SOCK_DGRAM) as listener:
                self.listener = listener
                listener.bind(("::1" if self.family == socket.AF_INET6 else "127.0.0.1", 0))
                listener.settimeout(.2)
                self.port = listener.getsockname()[1]
                self.ready.set()
                while not self.stop.is_set():
                    try:
                        data, peer = listener.recvfrom(65536)
                    except socket.timeout:
                        continue
                    self.responses += 1
                    delay = self.rtt_ms / 1000
                    if self.loss_percent and self.responses % max(1, 100 // self.loss_percent) == 0:
                        delay += self.rtt_ms / 1000
                    if self.stop.wait(delay):
                        break
                    listener.sendto(data, peer)
        except BaseException as exc:
            if not self.stop.is_set():
                self.error = exc
        finally:
            self.ready.set()


class CompanionEchoTarget(EchoTarget):
    def __init__(self, family, datagram, backend, core, key_path, **kwargs):
        self.family, self.datagram = family, datagram
        self.backend, self.core, self.key_path = backend, core, key_path
        super().__init__(**kwargs)

    def _run(self):
        adapter = None
        try:
            adapter = Adapter(self.backend, self.core, self.key_path, 1)
            with socket.socket(self.family, socket.SOCK_DGRAM if self.datagram else socket.SOCK_STREAM) as listener:
                self.listener = listener
                listener.bind(("::1" if self.family == socket.AF_INET6 else "127.0.0.1", 0))
                listener.settimeout(.1)
                if not self.datagram:
                    listener.listen(1)
                self.port = listener.getsockname()[1]; self.ready.set()
                connection = listener
                if not self.datagram:
                    while not self.stop.is_set():
                        try:
                            connection, _ = listener.accept()
                            break
                        except socket.timeout:
                            continue
                    if self.stop.is_set():
                        return
                connection.settimeout(.1)
                channel = Channel(connection, self.datagram)
                try:
                    while not self.stop.is_set():
                        try:
                            if self.datagram and channel.peer is None:
                                frame, peer = connection.recvfrom(4097)
                                channel.peer = peer
                            else:
                                frame = channel.receive()
                        except socket.timeout:
                            frames, messages = adapter.call("tick")
                        except EOFError:
                            break
                        else:
                            frames, messages = adapter.call("receive", frame)
                        channel.send(frames)
                        for message in messages:
                            self.responses += 1
                            delay = self.rtt_ms / 1000
                            if self.loss_percent and self.responses % max(1, 100 // self.loss_percent) == 0:
                                delay += self.rtt_ms / 1000
                            if self.stop.wait(delay):
                                return
                            frames, extra = adapter.call("send", message)
                            channel.send(frames)
                finally:
                    if connection is not listener:
                        connection.close()
                    self.connection_done.set()
        except BaseException as exc:
            if not self.stop.is_set():
                self.error = exc
        finally:
            if adapter:
                adapter.close()
            self.ready.set()


def evaluate_application(connection: socket.socket, datagram: bool, options: dict, adapter=None) -> dict:
    """Identical bounded workload and assertions for every native transport.

    Application writes are 512 bytes for *every* family. This is ordinary
    application segmentation, not a synthetic Core protocol or a claim that
    bounded datagram cores carry a 1 MiB datagram or provide reliable streams.
    No retries here: corruption, loss, extra bytes, or timeout fail the run.
    """
    size = options["payload_bytes"]
    latencies = []
    channel = Channel(connection, datagram) if adapter else None
    started = time.perf_counter()
    for _ in range(options["requests"]):
        payload = os.urandom(size)
        request_started = time.perf_counter()
        for offset in range(0, size, 512):
            part = payload[offset:offset+512]
            if adapter:
                received = exchange(adapter, channel, part)
            else:
                connection.sendall(part)
                received = connection.recv(65536) if datagram else receive_exact(connection, len(part))
            if received != part:
                raise AssertionError("application response mismatch")
        latencies.append(time.perf_counter() - request_started)
    result = benchmark_metrics(payload, latencies, time.perf_counter() - started)
    result.update(application_chunk_bytes=min(size, 512),
                  application_transport="udp" if datagram else "tcp",
                  roles=["broker", "agent", "client"],
                  impairment={"model": "bounded-userspace-response-v1",
                              "rtt_ms": options.get("rtt_ms", 0),
                              "loss_percent": options.get("loss_percent", 0)})
    return result


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def captured_log(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def wait_until(predicate, process: subprocess.Popen[str], log_path: Path, deadline: float, failure: str) -> None:
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{failure}: exited with {process.returncode}: {captured_log(log_path)[-2000:]}")
        if predicate():
            return
        time.sleep(0.05)
    raise TimeoutError(f"{failure}: {captured_log(log_path)[-2000:]}")


def loopback_tcp_count(port: int, states: set[str], local_only: bool) -> int:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid loopback port")
    if not states or any(type(state) is not str or len(state) != 2 for state in states):
        raise ValueError("invalid tcp states")
    wanted = {state.upper() for state in states}
    needle = f"{port:04X}"
    count = 0
    for name in ("tcp", "tcp6"):
        path = Path("/proc/net") / name
        if not path.is_file():
            continue
        try:
            rows = path.read_text(encoding="ascii", errors="replace").splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            parts = row.split()
            if len(parts) < 4 or parts[3].upper() not in wanted:
                continue
            local = parts[1].rsplit(":", 1)
            remote = parts[2].rsplit(":", 1)
            if len(local) != 2 or len(remote) != 2:
                continue
            if local[1].upper() == needle or (not local_only and remote[1].upper() == needle):
                count += 1
    return count


def tcp_port_open(port: int) -> bool:
    if loopback_tcp_count(port, {"0A"}, True) >= 1:
        return True
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def established_loopback_count(port: int) -> int:
    return loopback_tcp_count(port, {"01"}, False)


def terminate(process: subprocess.Popen[str] | None, label: str) -> None:
    if process is None or process.poll() is not None:
        return
    def has_exited() -> bool:
        try:
            return process.poll() is not None
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) != 10054:
                raise
            # The Windows socket-reset race can also surface while Popen polls
            # its handle.  Ask the process handle directly before accepting it.
            import ctypes
            exit_code = ctypes.c_ulong()
            if ctypes.windll.kernel32.GetExitCodeProcess(
                ctypes.c_void_p(process._handle), ctypes.byref(exit_code)
            ) and exit_code.value != 259:  # STILL_ACTIVE
                process.returncode = exit_code.value
                return True
            return False
    def reap_after_reset() -> bool:
        """Reap a Windows child after a socket-reset race during termination.

        WSAECONNRESET can be raised by the Windows process wrapper while the
        child is tearing down its loopback sockets.  It is only accepted after
        repeated polling proves that the process exited; a live child remains
        a hard test failure.
        """
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if has_exited():
                return True
            time.sleep(0.05)
        return has_exited()
    try:
        process.terminate()
    except OSError as exc:
        if getattr(exc, "winerror", None) == 10054:
            if reap_after_reset():
                return
        raise
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError as exc:
            if getattr(exc, "winerror", None) != 10054 or not reap_after_reset():
                raise
        try:
            process.wait(timeout=5)
        except OSError as exc:
            if getattr(exc, "winerror", None) != 10054 or not reap_after_reset():
                raise
        raise RuntimeError(f"{label} did not terminate cleanly")
    except OSError as exc:
        if getattr(exc, "winerror", None) != 10054 or not reap_after_reset():
            raise


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
    from local_configs import generate_configs as generate_local_configs
    generate_local_configs(output, target_port, broker_port, engine)


def run_engine(engine: str, benchmark: dict | None = None, backend: str = "native") -> dict | None:
    binary = CORE_BINARIES[engine]
    if engine == "shadow6-zig" and not binary.is_file():
        binary = ROOT / "Core-Zig/zig-out/bin/shadow6-zig"
    if not binary.is_file():
        raise FileNotFoundError(f"missing built binary: {binary}")

    options = benchmark or {"payload_bytes": 16384, "requests": 4}
    datagram = engine in DATAGRAM_CORES
    family = socket.AF_INET6 if engine == "shadow6-hare" else socket.AF_INET
    impairment = {"rtt_ms": options.get("rtt_ms", 0), "loss_percent": options.get("loss_percent", 0)}
    target = DatagramEchoTarget(family, **impairment) if datagram else EchoTarget(**impairment)
    broker = agent = client = None
    success = False
    result = None
    with tempfile.TemporaryDirectory(prefix=f"shadow6-it-{engine}-") as directory:
        output = Path(directory) / "configs"
        key_path = Path(directory) / "adapter.key"
        if backend != "native":
            sys.path.insert(0, str(ROOT / 'Network-Adapter'))
            from shadow6_network import create_key
            create_key(key_path, os.urandom(32))
            target = CompanionEchoTarget(family, datagram, backend, engine.removeprefix("shadow6-"), key_path, **impairment)
        target_port = target.start()
        broker_port = free_port()
        if datagram:
            commands, endpoint = generate_commands(engine, binary, output, target_port)
        else:
            asyncio.run(generate_configs(engine, output, target_port, broker_port))
            prefix = f"it-{engine}"
            commands = {role: [str(binary), "--config", str(output / (
                f"{role}.json" if engine == "shadow6-cpp" else f"{prefix}-{role}.json"))]
                for role in ("broker", "agent", "client")}
        log_paths = {role: Path(directory) / f"{role}.log" for role in ("broker", "agent", "client")}
        log_files = {
            role: path.open("w", encoding="utf-8", buffering=1)
            for role, path in log_paths.items()
        }
        try:
            def start_role(role: str) -> subprocess.Popen[str]:
                popen_kwargs = {"stdout": log_files[role], "stderr": subprocess.STDOUT, "text": True}
                if engine == "shadow6-gleam":
                    environment = dict(os.environ)
                    environment["ERL_CRASH_DUMP"] = str(Path(directory) / f"{role}-erl_crash.dump")
                    popen_kwargs["cwd"] = directory
                    popen_kwargs["env"] = environment
                return subprocess.Popen(commands[role], **popen_kwargs)

            if engine == "shadow6-gleam":
                with _BROKER_BIND_LOCK:
                    broker = start_role("broker")
                    wait_until(lambda: tcp_port_open(broker_port), broker, log_paths["broker"],
                               time.monotonic() + 20, "gleam broker did not listen")
                agent = start_role("agent")
                wait_until(lambda: established_loopback_count(broker_port) >= 1, agent, log_paths["agent"],
                           time.monotonic() + 20, "gleam agent control handshake did not connect")
                settled = time.monotonic() + 1.0
                wait_until(lambda: time.monotonic() >= settled and established_loopback_count(broker_port) >= 1,
                           agent, log_paths["agent"], settled + 0.2, "gleam agent control session dropped")
                client = start_role("client")
            else:
                broker = start_role("broker")
                time.sleep(0.5)
                agent = start_role("agent")
                time.sleep(1.0)
                client = start_role("client")
            if datagram:
                deadline = time.monotonic() + 20
                marker = "ready:" if engine == "shadow6-pony" else "session ready"
                while time.monotonic() < deadline:
                    if any(p.poll() is not None for p in (broker, agent, client)):
                        raise RuntimeError("native role exited before session readiness")
                    if all(marker in log_paths[r].read_text(errors="replace") for r in ("agent", "client")):
                        break
                    time.sleep(.02)
                else:
                    raise TimeoutError("native session readiness timeout")
                connection = socket.socket(family, socket.SOCK_DGRAM)
                connection.connect(endpoint)
            else:
                proxy_wait = 30 if engine == "shadow6-gleam" else 20
                proxy_port = wait_for_proxy(client, log_paths["client"], time.monotonic() + proxy_wait)
                connection = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
            with connection:
                connection.settimeout(10)
                if any(p.poll() is not None for p in (broker, agent, client)):
                    raise RuntimeError("native role exited before application evaluation")
                adapter = None
                try:
                    if backend != "native":
                        adapter = Adapter(backend, engine.removeprefix("shadow6-"), key_path, 0)
                        connection.settimeout(.1)
                    result = evaluate_application(connection, datagram, options, adapter)
                    result["backend"] = backend
                finally:
                    if adapter:
                        adapter.close()
                # Complete the stream with an explicit FIN before the child
                # processes are torn down.  Abruptly closing a Windows TCP
                # handle while the echo target still has unread bytes causes
                # WSAECONNRESET and hides an otherwise real lifecycle bug.
                if not datagram:
                    connection.settimeout(10)
                    connection.shutdown(socket.SHUT_WR)
                    while connection.recv(65536):
                        pass
            if not datagram and not target.wait_for_connection_close(3):
                raise AssertionError(f"{engine}: target connection did not complete graceful close")
            success = True
            print(f"[PASS] {engine} backend={backend} native broker/agent/client application contract")
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

def run_external_proxy(endpoint: str, benchmark: dict) -> dict:
    host, separator, port_text = endpoint.rpartition(":")
    host = host.strip("[]")
    try: address = socket.getaddrinfo(host, int(port_text), type=socket.SOCK_STREAM)
    except (OSError, ValueError): raise ValueError("invalid external proxy endpoint")
    if not separator or not address or any(not ipaddress.ip_address(item[4][0]).is_loopback for item in address):
        raise ValueError("external proxy must resolve only to loopback addresses")
    payload=b"x"*benchmark["payload_bytes"]; latencies=[]; started=time.perf_counter()
    with socket.create_connection((host,int(port_text)),timeout=10) as connection:
        connection.settimeout(30)
        for _ in range(benchmark["requests"]):
            request=time.perf_counter(); connection.sendall(payload)
            if receive_exact(connection,len(payload)) != payload: raise AssertionError("external proxy response mismatch")
            latencies.append(time.perf_counter()-request)
    result=benchmark_metrics(payload,latencies,time.perf_counter()-started)
    result["impairment"]={"model":"external-network","rtt_ms":None,"loss_percent":None}
    return result


def run_parallel(engine, options, backend):
    count = options["concurrency"]
    if count == 1:
        return run_engine(engine, options, backend)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(run_engine, engine, options, backend) for _ in range(count)]
        results = [f.result() for f in futures]
    duration = time.perf_counter() - started
    result = dict(results[0])
    result.update(concurrency=count, concurrency_scope="independent-native-trios",
                  requests=sum(r["requests"] for r in results),
                  bytes_sent=sum(r["bytes_sent"] for r in results),
                  bytes_received=sum(r["bytes_received"] for r in results),
                  duration_seconds=duration,
                  throughput_bps=sum(r["bytes_sent"] for r in results)*8/duration,
                  latency_avg_seconds=sum(r["latency_avg_seconds"] for r in results)/count,
                  latency_p95_seconds=max(r["latency_p95_seconds"] for r in results),
                  latency_p95_aggregation="maximum-worker-p95",
                  duration_scope="includes-trio-startup-and-teardown")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=("shadow6-go", "shadow6-rust", *CORE_TESTS, "all"), default="all")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--backend", choices=(*BACKENDS, "all"))
    parser.add_argument("--payload-bytes", type=int, default=16384)
    parser.add_argument("--requests", type=int, default=32)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--rtt-ms", type=int, default=0)
    parser.add_argument("--loss-percent", type=int, default=0)
    parser.add_argument("--external-proxy")
    args = parser.parse_args()
    if not all(1 <= value <= limit for value, limit in ((args.payload_bytes, 1048576), (args.requests, 100000), (args.concurrency, 8))) or not 0 <= args.rtt_ms <= 2000 or not 0 <= args.loss_percent <= 50:
        parser.error("benchmark bounds exceeded")
    backend = args.backend or ("all" if args.benchmark and not args.external_proxy else "native")
    if args.external_proxy and (backend != "native" or args.concurrency != 1 or args.rtt_ms or args.loss_percent):
        parser.error("external endpoint requires native backend, concurrency 1, and zero local impairment")
    if args.engine == "all":
        engines = tuple(CORE_BINARIES)
    else:
        engines = (args.engine,)
    benchmark_result = None
    benchmark_results = {}
    failures = []
    backends = BACKENDS if backend == "all" else (backend,)
    for engine, backend in ((e, b) for e in engines for b in backends):
        result_key = engine if backend == "native" else f"{engine}@{backend}"
        benchmark_result = None
        try:
            if args.benchmark and args.external_proxy:
                benchmark_result = run_external_proxy(args.external_proxy, {"payload_bytes":args.payload_bytes,"requests":args.requests,"concurrency":1})
            else:
                benchmark_result = run_parallel(engine, {"payload_bytes": args.payload_bytes, "requests": args.requests,
                    "concurrency": args.concurrency, "rtt_ms": args.rtt_ms, "loss_percent": args.loss_percent}, backend)
        except Exception as exc:
            failures.append(f"{result_key}: {exc}")
            benchmark_results[result_key] = {"status": "failed", "reason": str(exc), "backend": backend}
            traceback.print_exc()
            print(f"[FAIL] {failures[-1]}", file=sys.stderr)
        else:
            if args.benchmark and benchmark_result is not None:
                benchmark_results[result_key] = benchmark_result
    if failures:
        print("Network contract failures:", file=sys.stderr)
        for failure in failures: print(f"  {failure}", file=sys.stderr)
    if benchmark_results:
        print(json.dumps({"schema": "shadow6.network-suite.v1", "results": benchmark_results}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
