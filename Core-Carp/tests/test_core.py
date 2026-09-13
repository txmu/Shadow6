import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import socket
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BIN = Path(__file__).resolve().parents[1] / "shadow6-carp"

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="shadow6-carp-test-")
        self.addCleanup(self.tmp.cleanup)
        self.key = Path(self.tmp.name) / "keys"
        self.call("--gen-key", str(self.key))

    def call(self, *args, data=b"", ok=True):
        result = subprocess.run([str(BIN), *args], input=data, capture_output=True, timeout=5)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        if not ok:
            self.assertEqual(result.stdout, b"")
        return result.stdout

    def test_features(self):
        report = json.loads(self.call("--feature-report"))
        self.assertEqual(report["crosed_max_level"], 0)
        self.assertEqual(report["crosed_capabilities"], [])

    def test_round_trip(self):
        for data in (b"", b"hello\x00world", os.urandom(994)):
            wire = self.call("--encode", str(self.key), data=data)
            self.assertEqual(len(wire), 1144)
            self.assertEqual(self.call("--decode", str(self.key), data=wire), data)
        self.call("--encode", str(self.key), data=b"x" * 995, ok=False)

    def test_tampering_and_lengths(self):
        wire = self.call("--encode", str(self.key), data=b"secret")
        for offset in (0, 23, 24, 39, 40, 63, 64, 79, 80, 103, 104, 119, 120, 1143):
            bad = bytearray(wire)
            bad[offset] ^= 1
            self.call("--decode", str(self.key), data=bad, ok=False)
        for bad in (b"", wire[:-1], wire + b"x"):
            self.call("--decode", str(self.key), data=bad, ok=False)

    def test_key_file(self):
        self.call("--gen-key", str(self.key), ok=False)
        self.key.chmod(0o644)
        self.call("--check-config", str(self.key), ok=False)
        self.key.chmod(0o600)
        link = Path(self.tmp.name) / "link"
        link.symlink_to(self.key)
        self.call("--check-config", str(link), ok=False)
        self.key.write_bytes(b"x" * 97)
        self.call("--check-config", str(self.key), ok=False)

    def test_udp_authenticated_session(self):
        seeds = [os.urandom(32), os.urandom(32)]
        pubs = [Ed25519PrivateKey.from_private_bytes(s).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for s in seeds]
        binding = os.urandom(32)
        paths = [Path(self.tmp.name) / name for name in ("sender", "receiver")]
        for i, path in enumerate(paths):
            path.write_bytes(seeds[i] + pubs[1-i] + binding)
            path.chmod(0o600)
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        ports = [sock.getsockname()[1] for sock in sockets]
        for sock in sockets:
            sock.close()
        for mode in ("A", "B", "C"):
            sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
            for sock in sockets:
                sock.bind(("127.0.0.1", 0))
            ports = [sock.getsockname()[1] for sock in sockets]
            for sock in sockets:
                sock.close()
            receiver = subprocess.Popen([str(BIN), "--listen", str(paths[1]), str(ports[1]), str(ports[0]), mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                time.sleep(.15)
                sender = subprocess.run([str(BIN), "--send", str(paths[0]), str(ports[0]), str(ports[1]), mode], input=(b"authenticated " + mode.encode()), capture_output=True, timeout=7)
                self.assertEqual(sender.returncode, 0, sender.stderr)
                import select
                self.assertTrue(select.select([receiver.stdout], [], [], 3)[0])
                self.assertEqual(os.read(receiver.stdout.fileno(), 128), b"authenticated " + mode.encode())
            finally:
                receiver.terminate()
                receiver.communicate(timeout=3)

    def test_unknown_mode_rejected(self):
        self.call("--send", str(self.key), "12001", "12002", "D", ok=False)

if __name__ == "__main__":
    unittest.main()
