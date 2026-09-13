"""Real loopback transport integration; no mocked crypto or sockets."""
import ctypes
import ctypes.util
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import unittest

BIN = str(Path(__file__).resolve().parents[1] / "shadow6-pony")


def public(seed):
    sodium = ctypes.CDLL(ctypes.util.find_library("sodium"))
    pk, sk = ctypes.create_string_buffer(32), ctypes.create_string_buffer(64)
    assert sodium.crypto_sign_seed_keypair(pk, sk, seed) == 0
    return pk.raw.hex()


class NetworkTests(unittest.TestCase):
    def test_roundtrip(self):
        sockets, processes = [], []
        try:
            for _ in range(5):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                except PermissionError as exc:
                    self.skipTest("loopback sockets unavailable: %s" % exc)
                sock.bind(("127.0.0.1", 0))
                sock.settimeout(3)
                sockets.append(sock)
            a, c, app, target_port, _ = [s.getsockname()[1] for s in sockets]
            for sock in sockets[:3]:
                sock.close()
            target, local = sockets[3:]
            seed_a, seed_c = bytes(range(32)), bytes(range(32, 64))
            with tempfile.TemporaryDirectory(prefix="shadow6-pony-") as directory:
                for role, listen, peer, application, seed, pin in (
                    ("agent", a, c, target_port, seed_a, seed_c),
                    ("client", c, a, app, seed_c, seed_a),
                ):
                    path = Path(directory) / (role + ".json")
                    config = dict(role=role, listen_port=listen, peer_port=peer,
                                  application_port=application, private_key=seed.hex(),
                                  peer_public_key=public(pin))
                    path.write_text(json.dumps(config))
                    path.chmod(0o600)
                    checked = subprocess.run([BIN, "--check-config", str(path)],
                                             capture_output=True, timeout=10)
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                    path.chmod(0o644)
                    checked = subprocess.run([BIN, "--check-config", str(path)],
                                             capture_output=True, timeout=10)
                    self.assertNotEqual(checked.returncode, 0)
                    path.chmod(0o600)
                    processes.append(subprocess.Popen([BIN, "--config", str(path)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE))
                for process in processes:
                    ready, _, _ = select.select([process.stdout], [], [], 8)
                    self.assertTrue(ready, "handshake readiness timeout")
                    self.assertIn(b"ready:", process.stdout.readline())
                for payload in (b"", b"hello", bytes(range(256)), b"x" * 1172):
                    local.sendto(payload, ("127.0.0.1", app))
                    data, address = target.recvfrom(2048)
                    self.assertEqual(data, payload)
                    target.sendto(data, address)
                    self.assertEqual(local.recvfrom(2048)[0], payload)
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            for sock in sockets:
                sock.close()


if __name__ == "__main__":
    unittest.main()
