"""Real fixed CLI and authenticated UDP close-path integration for Core-D.

This validates the bounded authenticated driver and its loopback forwarding path.
"""
import hashlib
import hmac
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
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
        client = Ed25519PrivateKey.generate()
        client_public = client.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text(json.dumps({"role": "broker", "broker": {
                "listen_addr": f"127.0.0.1:{port}", "private_key": seed.hex(), "agents": [],
                "clients": [{"id": "client", "pubkey": client_public.hex(), "allowed_agents": []}]}}))
            config.chmod(0o600)
            self.assertEqual(self.call("--check-config", str(config)).returncode, 0)
            process = subprocess.Popen([str(BIN), "--config", str(config)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                session = os.urandom(16)
                ephemeral = X25519PrivateKey.generate()
                hello = (b"S6DHEL02\x01" + session + int(time.time()).to_bytes(8, "big") + client_public
                         + ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) + public)
                hello += client.sign(hello)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.settimeout(0.1)
                    for _ in range(5):
                        sender.sendto(hello[:-1] + bytes([hello[-1] ^ 1]), ("127.0.0.1", port))
                        with self.assertRaises(socket.timeout): sender.recv(2048)
                    # Each rejected hello carries a valid signature: identity,
                    # intended target, freshness and X25519 checks are separate.
                    stranger = Ed25519PrivateKey.generate()
                    unknown = (hello[:33] + stranger.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                               + hello[65:129])
                    wrong_target = hello[:97] + bytes(32)
                    stale = hello[:25] + (int(time.time()) - 60).to_bytes(8, "big") + hello[33:129]
                    null_dh = hello[:65] + bytes(32) + hello[97:129]
                    for candidate, signing_key in ((unknown, stranger), (wrong_target, client),
                                                    (stale, client), (null_dh, client)):
                        sender.sendto(candidate + signing_key.sign(candidate), ("127.0.0.1", port))
                        with self.assertRaises(socket.timeout): sender.recv(2048)
                    sender.sendto(b"", ("127.0.0.1", port))
                    self.assertIsNone(process.poll(), "empty datagrams must not terminate the listener")
                    for _ in range(20):
                        sender.sendto(hello, ("127.0.0.1", port))
                        try:
                            response = sender.recv(2048)
                            break
                        except socket.timeout: pass
                    else: self.fail("signed hello did not establish a session")
                    self.assertEqual(response[:9], b"S6DHEL02\x02")
                    self.assertEqual(response[9:25], session)
                    self.assertEqual(response[97:129], hashlib.sha256(hello).digest())
                    signer.public_key().verify(response[129:], response[:129])
                    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(response[65:97]))
                    prk = hmac.digest(hashlib.sha256(hello + response).digest(), shared, "sha256")
                    tx = hmac.digest(prk, b"shadow6-d-v2/client-to-server\x01", "sha256")
                    rx = hmac.digest(prk, b"shadow6-d-v2/server-to-client\x01", "sha256")
                    self.assertNotEqual(tx, rx)

                    def frame(kind, sequence, payload, key=tx):
                        stamp = int(time.time())
                        header = (b"S6DUDP02" + bytes([kind]) + session + sequence.to_bytes(4, "big")
                                  + stamp.to_bytes(8, "big") + (len(payload)+16).to_bytes(2, "big"))
                        nonce = bytes([kind, 0, 0, 0]) + sequence.to_bytes(4, "big") + stamp.to_bytes(4, "big")
                        return header + ChaCha20Poly1305(key).encrypt(nonce, payload, header)

                    packet = frame(1, 0, b"\0hello")
                    # Public identity keys cannot authenticate the new data plane.
                    sender.sendto(frame(1, 0, b"\0bad", public), ("127.0.0.1", port))
                    with self.assertRaises(socket.timeout): sender.recv(2048)
                    sender.sendto(frame(1, 0, b"\0reflection", rx), ("127.0.0.1", port))
                    with self.assertRaises(socket.timeout): sender.recv(2048)
                    # A second source address cannot hijack an established session.
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                        other.settimeout(0.1)
                        other.sendto(packet, ("127.0.0.1", port))
                        with self.assertRaises(socket.timeout): other.recv(2048)
                    for _ in range(2):  # ACK loss/retransmit does not deliver twice.
                        sender.sendto(packet, ("127.0.0.1", port))
                        ack = sender.recv(2048)
                        self.assertEqual(ack[:9], b"S6DUDP02\x02")
                        nonce = b"\x02\0\0\0" + ack[25:29] + ack[33:37]
                        self.assertEqual(ChaCha20Poly1305(rx).decrypt(nonce, ack[39:], ack[:39]), b"\0")
                    wire = frame(3, 1, b"\0")
                    sender.sendto(wire[:-1] + bytes([wire[-1] ^ 1]), ("127.0.0.1", port))
                    time.sleep(0.05)
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
