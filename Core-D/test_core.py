"""Real fixed CLI and authenticated UDP close-path integration for Core-D.

This validates the existing driver, not end-to-end forwarding or confidentiality.
"""
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BIN = Path(__file__).resolve().parent / "shadow6-d"


class CoreDTests(unittest.TestCase):
    def call(self, *args):
        return subprocess.run([str(BIN), *args], capture_output=True, timeout=5)

    def test_cli_contract_and_errors(self):
        result = self.call("--feature-report")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["core"], "shadow6-d")
        self.assertNotEqual(self.call("--unknown").returncode, 0)
        self.assertNotEqual(self.call("--check-config", "/nonexistent-shadow6-config").returncode, 0)

    def test_authenticated_client_broker_agent_target_benchmark(self):
        result = self.call("--benchmark-loopback", "4", "8")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["requests_completed"], 8)
        self.assertEqual(report["bytes_transferred"], 64)
        self.assertEqual(report["success_rate"], 1.0)

    def test_real_loopback_authenticated_close(self):
        seed = os.urandom(32)
        signer = Ed25519PrivateKey.from_private_bytes(seed)
        public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(json.dumps({"role": "broker", "broker": {
                "listen_addr": f"127.0.0.1:{port}", "private_key": seed.hex(), "agents": [], "clients": []}}))
            config.chmod(0o600)
            self.assertEqual(self.call("--check-config", str(config)).returncode, 0)
            process = subprocess.Popen([str(BIN), "--config", str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                header = (b"S6DUDP01" + bytes([3]) + hashlib.sha256(b"broker").digest()[:16]
                          + (0).to_bytes(4, "big") + int(time.time()).to_bytes(8, "big") + (17).to_bytes(2, "big"))
                # The current driver uses its public key here; do not claim secrecy.
                ciphertext = ChaCha20Poly1305(public).encrypt(bytes([3]) + bytes(11), b"\0", header)
                unsigned = header + ciphertext
                wire = unsigned + signer.sign(unsigned)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    for _ in range(5):
                        sender.sendto(wire[:-1] + bytes([wire[-1] ^ 1]), ("127.0.0.1", port))
                        time.sleep(0.04)
                        self.assertIsNone(process.poll(), "tampered close must not stop the driver")
                    for _ in range(30):
                        sender.sendto(wire, ("127.0.0.1", port))
                        try:
                            process.wait(timeout=0.1)
                            break
                        except subprocess.TimeoutExpired:
                            pass
                stdout, stderr = process.communicate(timeout=2)
                self.assertEqual(process.returncode, 0, stderr)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=2)


if __name__ == "__main__":
    unittest.main()
