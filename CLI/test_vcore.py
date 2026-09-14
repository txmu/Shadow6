import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import shadow6_vcore as vcore
from vcore_adapters import ADAPTERS, translate


class VCoreTests(unittest.TestCase):
    def test_catalog_and_fixed_adapters_cover_twelve_cores(self):
        self.assertEqual(len(vcore.CORE_PATHS), 12)
        self.assertEqual(set(ADAPTERS), set(vcore.CORE_PATHS))
        for name in ADAPTERS:
            for operation in ("version", "feature-report", "status"):
                self.assertEqual(translate(name, operation), ["--feature-report"])
            with self.assertRaises(ValueError):
                translate(name, "exec", "/bin/true")
        with self.assertRaises(ValueError):
            translate("idris", "check-config", "/tmp/config")

    def test_unsigned_discovery_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / vcore.CORE_PATHS["go"]
            binary.parent.mkdir()
            binary.write_bytes(b"untrusted")
            with mock.patch.object(vcore, "_run", side_effect=AssertionError("must not execute")):
                result = vcore.discover(root)
            self.assertEqual(result["installed"], ["go"])
            self.assertEqual(result["cores"], {})
            self.assertIn("unsigned", result["errors"]["go"])

    def test_strict_protocol_rejects_ambiguous_inputs(self):
        for raw in (b'{"version":1,"version":1}', b'{"version":1.0}',
                    b'{"version":NaN}', b'{"version":9007199254740992}',
                    b'[' * 20 + b']' * 20, b'{"x":"e\\u0301"}', b'x' * 65537):
            with self.subTest(raw=raw[:40]), self.assertRaises((ValueError, vcore.SecurityError)):
                vcore.invoke(Path("/tmp"), raw, None, None)

    def test_selection_preserves_priority_and_constraints(self):
        discovery = {"cores": {"go": {"crosed_capabilities": []},
                               "rust": {"crosed_capabilities": ["observe.health"]}}}
        self.assertEqual(vcore.select(discovery, ["go", "rust"], ["rust"]),
                         {"selected": "rust", "fallback": ["go"]})
        self.assertEqual(vcore.select(discovery, capabilities=["observe.health"])["selected"], "rust")
        self.assertIsNone(vcore.select(discovery, capabilities=["core.hook"])["selected"])
        for bad in (["go", "go"], ["unknown"], "go", [True]):
            with self.assertRaises(ValueError):
                vcore.select(discovery, cores=bad)

    def test_native_signed_probe_and_tamper(self):
        # Real local native process, not a mock feature-report executable.
        source = Path(__file__).resolve().parents[1] / vcore.CORE_PATHS["go"]
        self.assertTrue(source.is_file(), "build Core-Go before running the integration suite")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / vcore.CORE_PATHS["go"]
            binary.parent.mkdir()
            import shutil
            shutil.copyfile(source, binary)
            binary.chmod(0o755)
            private, public, manifest = (root / n for n in ("key.pem", "key.json", "inventory.json"))
            from shadow6_security import generate_ledger_key
            generate_ledger_key(private, public)
            self.assertEqual(vcore.sign_inventory(root, private, manifest)["signed"], ["go"])
            found = vcore.discover(root, manifest=manifest, public_key=public)
            self.assertEqual(found["errors"], {})
            request = dict(version=1, operation="version", cores=["go"], priority=[],
                           capabilities=[], timeout=5, config=None)
            result = vcore.invoke(root, request, manifest, public)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["result"]["version"], found["cores"]["go"]["version"])
            request["operation"] = "check-config"
            request["config"] = str(root / "missing.json")
            self.assertFalse(vcore.invoke(root, request, manifest, public)["ok"])
            doc = json.loads(manifest.read_text())
            doc["cores"]["go"]["report"]["version"] = "99.0.0"
            manifest.write_bytes(vcore.canonical(doc))
            with self.assertRaisesRegex(ValueError, "signature"):
                vcore.discover(root, manifest=manifest, public_key=public)

    def test_resource_timeout_output_and_symlink_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link"
            link.symlink_to("/usr/bin/true")
            with self.assertRaises(ValueError), vcore._binary(link):
                pass
            with self.assertRaises(subprocess.TimeoutExpired):
                vcore.bounded_run(["/usr/bin/sleep", "2"], Path(tmp), 0.05)
            with self.assertRaises(vcore.SecurityError):
                vcore.bounded_run(["/usr/bin/yes"], Path(tmp), 2, 1024)
        for timeout in (True, 0, 31, 1.5, float("nan")):
            with self.assertRaises(ValueError):
                vcore.discover(Path("/tmp"), timeout)


if __name__ == "__main__":
    unittest.main()
