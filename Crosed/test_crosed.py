import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from crosedctl import CrosedError, atomic_owner_write, build_request, inspect_binary, negotiate  # noqa: E402


class CrosedMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="shadow6-crosed-matrix-")
        cls.temp = Path(cls.directory.name)
        cls.go_core = cls.temp / "shadow6-go"
        subprocess.run(
            ["go", "build", "-buildvcs=false", "-tags", "crosed,crosed_l5,app_transport,qubes_isolation", "-o", str(cls.go_core), "."],
            cwd=ROOT / "Core-Go", check=True, timeout=120,
        )
        subprocess.run(
            ["cargo", "build", "--locked", "--features", "crosed-level-5,app-transport,qubes-isolation"],
            cwd=ROOT / "Core-Rust", check=True, timeout=180,
        )
        cls.rust_core = cls.temp / "shadow6-rust"
        shutil.copy2(ROOT / "Core-Rust" / "target" / "debug" / "shadow6-rust", cls.rust_core)
        os.chmod(cls.go_core, 0o755)
        os.chmod(cls.rust_core, 0o755)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_feature_matrix_and_signed_policy_negotiation(self):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        trust = {
            "mods": {
                "matrix-mod": {
                    "pubkey": public,
                    "max_level": 4,
                    "capabilities": ["observe.version", "transport.application", "identity.assert"],
                    "allowed_domains": ["chat-vm"],
                }
            }
        }
        trust_path = self.temp / "trust.json"
        request_path = self.temp / "request.json"
        atomic_owner_write(trust_path, json.dumps(trust, sort_keys=True, separators=(",", ":")).encode())
        request = build_request(
            "matrix-mod", 4, ["observe.version", "transport.application", "identity.assert"],
            {"text": "跨域 UTF-8"}, private, "work-vm", "chat-vm",
        )
        atomic_owner_write(request_path, json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        for core in (self.go_core, self.rust_core):
            report = inspect_binary(core)
            self.assertEqual(report["crosed_max_level"], 5)
            self.assertTrue(report["app_transport"])
            self.assertTrue(report["qubes_isolation"])
            self.assertTrue(report["utf8"])
            response = negotiate(core, request_path, trust_path)
            self.assertEqual(response["status"], "granted")
            self.assertEqual(response["granted_level"], 4)

        # A domain-less v1 request is portable across isolation-off and
        # isolation-on variants: both omitted domains mean the same local
        # default domain, not an unreviewed cross-domain transition.
        compatible = build_request(
            "matrix-mod", 1, ["observe.version"], {"compat": True}, private,
        )
        atomic_owner_write(request_path, json.dumps(compatible, sort_keys=True, separators=(",", ":")).encode())
        for core in (self.go_core, self.rust_core):
            self.assertEqual(negotiate(core, request_path, trust_path)["status"], "granted")

        denied = build_request("matrix-mod", 4, ["identity.assert"], {}, private, "work-vm", "vault-vm")
        atomic_owner_write(request_path, json.dumps(denied, sort_keys=True, separators=(",", ":")).encode())
        for core in (self.go_core, self.rust_core):
            self.assertEqual(negotiate(core, request_path, trust_path)["status"], "denied")

        denied["signature"] = "00" * 64
        atomic_owner_write(request_path, json.dumps(denied, sort_keys=True, separators=(",", ":")).encode())
        for core in (self.go_core, self.rust_core):
            with self.assertRaises(CrosedError):
                negotiate(core, request_path, trust_path)


if __name__ == "__main__":
    unittest.main()
