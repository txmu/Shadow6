"""Real loopback WSS/SCTP tests; no other Shadow6 core is started."""
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import selectors
import socket
import socketserver
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parent
BINARY = Path(os.environ.get("SHADOW6_CPP_BINARY", ROOT / "shadow6-cpp"))
PROBE = Path(os.environ["SHADOW6_CPP_PROBE"])


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        while chunk := self.request.recv(8192):
            self.request.sendall(chunk)
        self.request.sendall(b"after-fin")


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shadow6-cpp-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run([str(BINARY), "--init-demo", str(self.root / "configs")], check=True, capture_output=True, timeout=10)
        self.cfg = {role: json.loads((self.root / "configs" / (role + ".json")).read_text())
                    for role in ("broker", "agent", "client")}
        self.processes = []
        self.addCleanup(self.stop_processes)

    def stop_processes(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                self.fail("C++ process did not stop within its I/O deadline")
            process.stdout.close()
            process.stderr.close()

    def write(self, role, data=None):
        path = self.root / "configs" / (role + ".json")
        path.write_text(json.dumps(data if data is not None else self.cfg[role]))
        path.chmod(0o600)
        return path

    def start(self, role):
        process = subprocess.Popen([str(BINARY), "--config", str(self.write(role))],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=12):
                self.fail(role + " did not become ready")
            line = process.stdout.readline()
        self.assertTrue(line, role + " exited before readiness")
        event = json.loads(line)
        self.assertEqual(event["type"], "ready")
        self.assertEqual(event["role"], role)
        return event["listen_addr"]

    def setup_stack(self, allow=True):
        self.cfg["broker"]["broker"]["listen_addr"] = "127.0.0.1:0"
        if not allow:
            self.cfg["broker"]["broker"]["clients"][0]["allowed_agents"] = []
        address = self.start("broker")
        self.cfg["agent"]["agent"]["broker_addr"] = address
        self.cfg["client"]["client"]["broker_addr"] = address
        self.cfg["agent"]["agent"]["listen_addr"] = "127.0.0.1:0"
        self.cfg["client"]["client"]["listen_addr"] = "127.0.0.1:0"
        echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        echo.daemon_threads = True
        thread = threading.Thread(target=echo.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(echo.server_close)
        self.addCleanup(echo.shutdown)
        self.cfg["agent"]["agent"]["target_addr"] = "127.0.0.1:" + str(echo.server_address[1])
        self.start("agent")
        return self.start("client")

    def exchange(self, address, payload):
        host, port = address.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=10) as sock:
            sock.settimeout(10)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            output = bytearray()
            while chunk := sock.recv(8192):
                output.extend(chunk)
            return bytes(output)

    def test_three_process_sctp_forwarding_and_half_close(self):
        address = self.setup_stack()
        payload = bytes(range(256)) * 1024
        self.assertEqual(self.exchange(address, payload), payload + b"after-fin")
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(lambda _: self.exchange(address, b"concurrent"), range(3)))
        self.assertEqual(results, [b"concurrentafter-fin"] * 3)

    def test_control_rejects_bad_schema_version_and_mask(self):
        self.setup_stack()
        for case in ("unknown", "version", "unmasked"):
            with self.subTest(case=case):
                subprocess.run([str(PROBE), "--probe", str(self.write("client")), case], check=True, timeout=10, capture_output=True)

    def test_broker_acl_denial(self):
        self.setup_stack(allow=False)
        subprocess.run([str(PROBE), "--probe", str(self.write("client")), "denied"], check=True, timeout=10, capture_output=True)

    def test_wrong_broker_pin_and_unknown_client_fail_tls(self):
        self.cfg["broker"]["broker"]["listen_addr"] = "127.0.0.1:0"
        self.cfg["client"]["client"]["broker_addr"] = self.start("broker")
        original = copy.deepcopy(self.cfg["client"])
        self.cfg["client"]["client"]["broker_pubkey"] = self.cfg["broker"]["broker"]["agents"][0]["pubkey"]
        subprocess.run([str(PROBE), "--probe", str(self.write("client")), "reject-tls"], check=True, timeout=10, capture_output=True)
        self.cfg["client"] = original
        keys = json.loads(subprocess.check_output([str(BINARY), "--keygen"], timeout=10))
        self.cfg["client"]["client"]["private_key"] = keys["private_key"]
        subprocess.run([str(PROBE), "--probe", str(self.write("client")), "reject-tls"], check=True, timeout=10, capture_output=True)

    def test_strict_config_and_file_contract(self):
        path = self.write("agent")
        for role in self.cfg:
            result = subprocess.run([str(BINARY), "--config", str(self.write(role)), "--check-config"], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0)
        for mode in (0o644, 0o700, 0o400):
            path.chmod(mode)
            result = subprocess.run([str(BINARY), "--check-config", str(path)], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
        path.chmod(0o600)
        link = self.root / "link"
        link.symlink_to(path)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        for invalid in (link, fifo, self.root):
            result = subprocess.run([str(BINARY), "--check-config", str(invalid)], capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
        for field, value in (("unknown", True), ("transport", "tcp"), ("target_addr", "192.0.2.1:22")):
            bad = copy.deepcopy(self.cfg["agent"])
            bad["agent"][field] = value
            result = subprocess.run([str(BINARY), "--check-config", str(self.write("agent", bad))], capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
