"""Focused FFI regressions; optional Idris executables are tested in Actions."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent


class SecurityFFI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="shadow6-idris-security.")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.directory = Path(cls.tmp.name)
        lib = cls.directory / "security.so"
        flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "libsodium"], text=True).split()
        subprocess.run(["cc", "-D_GNU_SOURCE", "-std=c11", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                        str(ROOT / "ffi/sodium_ffi.c"), "-o", str(lib), "-pthread", *flags], check=True, timeout=30)
        cls.lib = ctypes.CDLL(str(lib))
        cls.lib.idris_crypto_hex.argtypes = [ctypes.c_int] + [ctypes.c_char_p] * 4
        cls.lib.idris_crypto_hex.restype = ctypes.c_char_p
        cls.lib.idris_random_hex.argtypes = [ctypes.c_uint]
        cls.lib.idris_random_hex.restype = ctypes.c_char_p
        cls.lib.idris_read_secure_hex.argtypes = [ctypes.c_char_p]
        cls.lib.idris_read_secure_hex.restype = ctypes.c_char_p
        cls.lib.idris_reserve_nonce.argtypes = [ctypes.c_char_p] * 3
        cls.lib.idris_socket_op.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        assert cls.lib.idris_sodium_init() >= 0

    def test_hash_and_signature(self):
        self.assertEqual(self.lib.idris_crypto_hex(0, b"", b"", b"616263", b"").decode(), hashlib.sha256(b"abc").hexdigest())
        key = b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        sig = b"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        self.assertEqual(self.lib.idris_crypto_hex(1, key, b"", b"", sig), b"ok")
        self.assertTrue(self.lib.idris_crypto_hex(1, key, b"", b"00", sig).startswith(b"!"))
        self.assertTrue(self.lib.idris_crypto_hex(0, b"", b"", b"zz", b"").startswith(b"!"))

    def test_aead(self):
        key, nonce = b"00" * 32, b"01" * 12
        ct = self.lib.idris_crypto_hex(2, key, nonce, b"616263", b"")
        if not self.lib.idris_aes256gcm_available():
            self.assertTrue(ct.startswith(b"!")); return
        self.assertEqual(self.lib.idris_crypto_hex(3, key, nonce, ct, b""), b"616263")
        bad = bytes([ord('1') if ct[0] == ord('0') else ord('0')]) + ct[1:]
        self.assertTrue(self.lib.idris_crypto_hex(3, key, nonce, bad, b"").startswith(b"!"))
        empty = self.lib.idris_crypto_hex(2, key, nonce, b"", b"")
        self.assertEqual(self.lib.idris_crypto_hex(3, key, nonce, empty, b""), b"")

    def test_secure_file(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            path = Path(directory) / "secret"
            path.write_bytes(b"secret"); path.chmod(0o600)
            read = lambda p: self.lib.idris_read_secure_hex(os.fsencode(p))
            self.assertEqual(read(path), b"736563726574")
            for mode in (0o644, 0o4600):
                path.chmod(mode); self.assertTrue(read(path).startswith(b"!"))
            path.chmod(0o600)
            link = Path(directory) / "link"; link.symlink_to(path)
            self.assertTrue(read(link).startswith(b"!"))
            link.unlink(); os.link(path, link)
            self.assertTrue(read(path).startswith(b"!")); link.unlink()
            fifo = Path(directory) / "fifo"; os.mkfifo(fifo, 0o600)
            self.assertTrue(read(fifo).startswith(b"!"))
            path.write_bytes(b"x" * 1048577)
            self.assertTrue(read(path).startswith(b"!"))

    def test_replay_and_capacity(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            path = Path(directory) / "replay"
            reserve = lambda n: self.lib.idris_reserve_nonce(os.fsencode(path), b"ab" * 32, n)
            self.assertEqual(reserve(b"ab" * 16), 0)
            self.assertNotEqual(reserve(b"AB" * 16), 0)
            for i in range(255):
                self.assertEqual(reserve(i.to_bytes(16, "big").hex().encode()), 0)
            self.assertNotEqual(reserve(b"cd" * 16), 0)
            path.write_bytes(b"corrupt")
            self.assertNotEqual(reserve(b"cd" * 16), 0)
            path.unlink(); path.symlink_to(Path(directory) / "elsewhere")
            self.assertNotEqual(reserve(b"cd" * 16), 0)

    def test_random(self):
        first = self.lib.idris_random_hex(32)
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, self.lib.idris_random_hex(32))
        self.assertTrue(self.lib.idris_random_hex(1048577).startswith(b"!"))

    def test_socket_lifecycle(self):
        handle = self.lib.idris_socket_create()
        self.assertGreater(handle, 0)
        self.assertNotEqual(self.lib.idris_socket_op(handle, 0, b"0.0.0.0", 0), 0)
        self.assertNotEqual(self.lib.idris_socket_op(handle, 1, b"", 1), 0)
        self.assertEqual(self.lib.idris_socket_op(handle, 0, b"127.0.0.1", 0), 0)
        self.assertNotEqual(self.lib.idris_socket_op(handle, 1, b"", 129), 0)
        self.assertEqual(self.lib.idris_socket_op(handle, 1, b"", 1), 0)
        self.assertEqual(self.lib.idris_socket_op(handle, 2, b"", 0), 0)
        self.assertNotEqual(self.lib.idris_socket_op(handle, 2, b"", 0), 0)
        handles = [self.lib.idris_socket_create() for _ in range(512)]
        self.assertTrue(all(h > 0 for h in handles))
        self.assertLess(self.lib.idris_socket_create(), 0)
        for h in handles:
            self.assertEqual(self.lib.idris_socket_op(h, 2, b"", 0), 0)

    def test_z_shutdown(self):
        h = self.lib.idris_socket_create()
        self.lib.idris_shutdown()
        self.assertLess(self.lib.idris_socket_create(), 0)
        self.assertNotEqual(self.lib.idris_socket_op(h, 2, b"", 0), 0)


class IdrisExecutables(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("IDRIS_SECURITY_BINARIES") != "1":
            raise unittest.SkipTest("Idris execution is restricted to the Actions job")

    def test_runtime_checks(self):
        for name in ("shadow6-idris", "shadow6-idris-crosed"):
            result = subprocess.run([str(ROOT / name), "--security-test"], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_authorization(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        with tempfile.TemporaryDirectory(prefix="shadow6-idris-auth.") as directory:
            base = Path(directory)
            key = Ed25519PrivateKey.generate()
            request = dict(version=1, mod_id="test", nonce="ab" * 16, issued_at=int(time.time()),
                           requested_level=1, capabilities=["observe.health"], source_domain="red", target_domain="red",
                           payload_hash=hashlib.sha256(b"{}").hexdigest())
            trust = dict(version=1, mod_id="test", pubkey=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                         max_level=5, capabilities=["observe.health"], allowed_domains=["red"], source_domain="red", target_domain="red",
                         domain_policies=[dict(source="red", target="red", allowed=True)], replay_path=str(base / "ledger"))
            def save():
                signed = ("{\"capabilities\":[" + ",".join('"' + c + '"' for c in sorted(request["capabilities"])) +
                          "],\"issued_at\":" + str(request["issued_at"]) +
                          ",\"mod_id\":\"" + request["mod_id"] +
                          ",\"nonce\":\"" + request["nonce"] +
                          "\",\"payload_hash\":\"" + request["payload_hash"] +
                          "\",\"requested_level\":" + str(request["requested_level"]) +
                          ",\"source_domain\":\"" + request["source_domain"] +
                          "\",\"target_domain\":\"" + request["target_domain"] +
                          "\",\"version\":1}")
                request["signature"] = key.sign(signed.encode()).hex()
                for name, doc in (("request", request), ("trust", trust)):
                    path = base / name; path.write_text(json.dumps(doc)); path.chmod(0o600)
            def run(binary, ok):
                result = subprocess.run([str(ROOT / binary), "--authorize", str(base / "request"), str(base / "trust")],
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
            save()
            run("shadow6-idris", False)
            run("shadow6-idris-crosed", True)
            run("shadow6-idris-crosed", False)
            self.assertEqual((base / "ledger").stat().st_size, 256 * 72)
            for changes in ({"nonce": "01" * 16, "issued_at": 1}, {"nonce": "02" * 16, "source_domain": "blue"},
                            {"nonce": "03" * 16, "mod_id": "other"}, {"nonce": "04" * 16, "capabilities": ["core.hook"]},
                            {"nonce": "05" * 16, "extra": True}):
                original = request.copy(); request.update(changes); save()
                run("shadow6-idris-crosed", False)
                request.clear(); request.update(original)


if __name__ == "__main__":
    unittest.main()
