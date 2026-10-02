import json
import tempfile
import unittest
from pathlib import Path

from Deployment.shadow6_abi import decode_control, decode_data, encode_control, encode_data, s6ar_request
from shadow6_deployment import load_manifest, manifest_lock, plan_manifest
from Deployment.shadow6_acceptance import run_acceptance
from shadow6_driver import application_capability, ready_event, select_boundary


ROOT = Path(__file__).parent


class DeploymentTests(unittest.TestCase):
    def test_manifest_lock_and_plan(self):
        manifest = load_manifest(ROOT / "example.deployment.json")
        lock = manifest_lock(manifest)
        self.assertTrue(lock["manifestDigest"].startswith("sha256:"))
        self.assertFalse(plan_manifest(manifest)["requiresCoreBuild"])

    def test_unknown_and_float_rejected(self):
        data = json.loads((ROOT / "example.deployment.json").read_text())
        data["spec"]["unknown"] = True
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.json"
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): load_manifest(path)
        data = json.loads((ROOT / "example.deployment.json").read_text())
        data["spec"]["artifact"]["version"] = 1.5
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.json"
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): load_manifest(path)

    def test_abi_and_s6ar(self):
        control = encode_control("open", {"boundary": "stream"}, session="s")
        self.assertEqual(decode_control(control)["session"], "s")
        data = encode_data(b"hello", session="s", sequence=1, message=True)
        self.assertEqual(decode_data(data)["data"], b"hello")
        self.assertTrue(s6ar_request("deployment.validate", {"manifest": "x"}).startswith("S6AR1."))

    def test_acceptance_source_only(self):
        with tempfile.TemporaryDirectory() as d:
            result = run_acceptance(ROOT / "example.deployment.json", output=Path(d), source_only=True)
            self.assertEqual(result["status"], "pass")
            self.assertTrue((Path(d) / "acceptance.junit.xml").is_file())

    def test_driver_selects_declared_boundary(self):
        report = {"core": "shadow6-rust", "application_boundaries": [{"kind": "stream", "ordered": True, "reliable": True, "fullDuplex": True}]}
        selected = select_boundary(report, {"boundary": "stream", "ordered": True, "reliable": True, "fullDuplex": True})
        self.assertEqual(selected["kind"], "stream")
        self.assertEqual(application_capability(report, "rust", {"boundary": "stream"})["core"], "rust")
        self.assertEqual(ready_event('{"event":"ready","endpoint":"127.0.0.1:1234"}')['endpoint'], "127.0.0.1:1234")


if __name__ == "__main__":
    unittest.main()
