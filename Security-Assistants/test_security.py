import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from shadow6_security import (  # noqa: E402
    SecurityError, append_event, doctor, evaluate_policy, generate_ledger_key,
    generate_sbom, verify_ledger,
)


class SecurityAssistantTests(unittest.TestCase):
    def test_doctor_and_offline_sbom(self):
        report = doctor(ROOT)
        self.assertEqual(report["status"], "pass", report)
        sbom = generate_sbom(ROOT)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertGreater(len(sbom["components"]), 20)
        purls = [item["purl"] for item in sbom["components"]]
        self.assertEqual(purls, sorted(set(purls)))

    def test_signed_ledger_detects_tamper_and_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            private, public, ledger = base / "ledger.pem", base / "ledger.pub.json", base / "events.jsonl"
            generate_ledger_key(private, public)
            first = append_event(ledger, private, "build.complete", "test-suite", {"result": "通过"})
            second = append_event(ledger, private, "audit.complete", "test-suite", {"passed": 32})
            self.assertEqual((first["sequence"], second["sequence"]), (1, 2))
            verified = verify_ledger(ledger, public)
            self.assertEqual(verified["sequence"], 2)

            original = ledger.read_bytes()
            ledger.write_bytes(original.replace(b"audit.complete", b"audit.failed__", 1))
            os.chmod(ledger, 0o600)
            with self.assertRaises(SecurityError):
                verify_ledger(ledger, public)
            ledger.write_bytes(original.splitlines(keepends=True)[0])
            os.chmod(ledger, 0o600)
            with self.assertRaisesRegex(SecurityError, "checkpoint"):
                verify_ledger(ledger, public)

    def test_maximum_policy_checks_full_component_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            policy_path = base / "policy.json"
            private, public, ledger = base / "ledger.pem", base / "ledger.pub.json", base / "events.jsonl"
            generate_ledger_key(private, public)
            append_event(ledger, private, "release.candidate", "test-suite", {"status": "ready"})
            policy = {
                "version": 1,
                "profile": "maximum",
                "core": {
                    "default_crosed_max_level": 0,
                    "variant_min_level": 5,
                    "require_app_transport": True,
                    "require_qubes_isolation": True,
                    "require_utf8": True,
                },
                "plugins": {
                    "require_signatures": True,
                    "allowed_signers": ["shadow6-release"],
                    "allowed_capabilities": ["game.local"],
                },
                "audit": {"require_ledger": True, "ledger_path": str(ledger), "public_key": str(public)},
            }
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            os.chmod(policy_path, 0o644)
            result = evaluate_policy(ROOT, policy_path)
            self.assertEqual(result["status"], "pass", result)


if __name__ == "__main__":
    unittest.main()
