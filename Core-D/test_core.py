"""Real Core-D broker/agent/client forwarding and bounded CLI tests."""
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BIN = Path(__file__).resolve().parent / "shadow6-d"


def keypair():
    private = Ed25519PrivateKey.generate()
    return private.private_bytes_raw().hex(), private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class EchoServer:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            connection, _ = self.listener.accept()
            with connection:
                while data := connection.recv(65536):
                    connection.sendall(data)
        except Exception as exc:
            self.error = exc

    def close(self):
        self.listener.close()
        self.thread.join(2)
        if self.error:
            raise self.error


class CoreDTests(unittest.TestCase):
    def call(self, *args):
        return subprocess.run([str(BIN), *args], capture_output=True, timeout=10)

    def test_cli_contract_and_nontrivial_native_path(self):
        result = self.call("--feature-report")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["core"], "shadow6-d")
        self.assertNotEqual(self.call("--unknown").returncode, 0)
        self.assertNotEqual(self.call("--check-config", "/nonexistent-shadow6-config").returncode, 0)
        benchmark = self.call("--benchmark-loopback", "1024", "32")
        self.assertEqual(benchmark.returncode, 0, benchmark.stderr)
        report = json.loads(benchmark.stdout)
        self.assertEqual(report["requests_completed"], 32)
        self.assertEqual(report["bytes_transferred"], 65536)

    def test_real_broker_agent_client_large_stream(self):
        broker_private, broker_public = keypair()
        agent_private, agent_public = keypair()
        client_private, client_public = keypair()
        broker_port = free_port()
        echo = EchoServer()
        processes = []
        with tempfile.TemporaryDirectory(prefix="shadow6-d-e2e.") as directory:
            root = Path(directory)

            def config(name, value):
                path = root / name
                path.write_text(json.dumps(value, separators=(",", ":")))
                path.chmod(0o600)
                return path

            broker = config("broker.json", {"role": "broker", "broker": {
                "listen_addr": f"127.0.0.1:{broker_port}", "private_key": broker_private,
                "agents": [{"id": "agent", "pubkey": agent_public}],
                "clients": [{"id": "client", "pubkey": client_public, "allowed_agents": ["agent"]}],
                "webhook_url": "", "stealth_mode": False}})
            agent = config("agent.json", {"role": "agent", "agent": {
                "id": "agent", "broker_addrs": [f"ws://127.0.0.1:{broker_port}/ws"],
                "broker_pubkey": broker_public, "private_key": agent_private,
                "target_port": echo.port, "auto_close_after": 30, "allow_local_discovery": False,
                "client_pubkeys": {"client": client_public}, "transport": "secure-stream", "sni": "", "alpn": ""}})
            client = config("client.json", {"role": "client", "client": {
                "id": "client", "broker_addrs": [f"ws://127.0.0.1:{broker_port}/ws"],
                "broker_pubkey": broker_public, "private_key": client_private,
                "target_agent": "agent", "agent_pubkey": agent_public, "on_success": "",
                "allow_local_discovery": False, "transport": "secure-stream", "sni": "", "alpn": ""}})
            for path in (broker, agent, client):
                checked = self.call("--config", str(path), "--check-config")
                self.assertEqual(checked.returncode, 0, checked.stderr)
            try:
                bp = subprocess.Popen([str(BIN), "--config", str(broker)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(bp)
                time.sleep(0.15)
                ap = subprocess.Popen([str(BIN), "--config", str(agent)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(ap)
                time.sleep(0.15)
                cp = subprocess.Popen([str(BIN), "--config", str(client)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(cp)
                deadline = time.time() + 10
                match = None
                while time.time() < deadline:
                    line = cp.stdout.readline()
                    match = re.search(r"proxy listening on 127\.0\.0\.1:(\d+)", line, re.I)
                    if match:
                        break
                    if cp.poll() is not None:
                        self.fail(cp.stderr.read())
                self.assertIsNotNone(match, "client did not publish its local proxy")
                payload = os.urandom(192 * 1024 + 37)
                with socket.create_connection(("127.0.0.1", int(match.group(1))), timeout=5) as app:
                    app.settimeout(10)
                    app.sendall(payload)
                    app.shutdown(socket.SHUT_WR)
                    received = bytearray()
                    while chunk := app.recv(65536):
                        received.extend(chunk)
                self.assertEqual(bytes(received), payload)
                self.assertEqual(cp.wait(timeout=5), 0, cp.stderr.read())
                self.assertEqual(ap.wait(timeout=5), 0, ap.stderr.read())
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=2)
                echo.close()


if __name__ == "__main__":
    unittest.main()
