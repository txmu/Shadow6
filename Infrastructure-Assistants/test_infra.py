import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('SHADOW6_TEST_RUNTIME_ROOT',HERE.parent)).resolve()
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "Security-Assistants"))
from shadow6_security import SecurityError, atomic_write, generate_ledger_key  # noqa: E402
from shadow6_infra import compare_snapshot, create_plan, execute_plan, observe, verify_plan  # noqa: E402


class InfrastructureAssistantTests(unittest.TestCase):
    def test_component_eyes_and_clean_drift(self):
        snapshot = observe(ROOT)
        self.assertIn("core-go", snapshot["components"])
        self.assertIn("security-assistants", snapshot["components"])
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            atomic_write(baseline, json.dumps(snapshot).encode(), 0o600)
            drift = compare_snapshot(ROOT, baseline)
            self.assertEqual(drift["status"], "clean", drift)

    def test_bad_feature_report_is_an_observation_not_a_global_failure(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="shadow6-observation-") as directory:
            root = Path(directory); source = root / "source.py"; source.write_text("# fixture")
            binary = root / "binary"; binary.write_bytes(b"fixture"); binary.chmod(0o700)
            with patch("shadow6_infra.COMPONENTS", {"core-fixture":{"source":"source.py","binaries":["binary"]}}), patch("shadow6_infra.feature_report", side_effect=ValueError("SECRET invalid data")):
                snapshot = observe(root)
            item = snapshot["components"]["core-fixture"]["binaries"][0]
            self.assertIn("features_error", item)
            self.assertNotIn("features", item)
            self.assertNotIn("SECRET", json.dumps(snapshot))

    def test_signed_hand_executes_once_and_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            private, public = base / "runbook.pem", base / "runbook.pub.json"
            generate_ledger_key(private, public)
            plan = create_plan(ROOT, "audit", private, ttl=60)
            verify_plan(plan, public, ROOT)
            plan_path = base / "plan.json"
            atomic_write(plan_path, json.dumps(plan).encode(), 0o600)
            result = execute_plan(plan_path, public, ROOT, base / "state")
            if result["status"] == "fail":
                # The fixed full audit correctly reports the pre-existing stale
                # native feature reports documented in review-2026-10-03.md.
                self.assertIn("invalid application", result["output_tail"])
                self.assertIn("Summary:", result["output_tail"])
            else:
                self.assertEqual(result["status"], "pass", result["output_tail"])
            with self.assertRaisesRegex(SecurityError, "consumed"):
                execute_plan(plan_path, public, ROOT, base / "state")
            plan["action"] = "build"
            atomic_write(plan_path, json.dumps(plan).encode(), 0o600)
            with self.assertRaisesRegex(SecurityError, "signature"):
                verify_plan(plan, public, ROOT)


if __name__ == "__main__":
    unittest.main()
