import os
import tempfile
import unittest
from pathlib import Path

from shadow6_easybuild import EasyBuildError, _secure_regular, generate_identities, termux_capabilities, verify_package_trust, write_profile
from shadow6_pkg import keygen


class EasyBuildTests(unittest.TestCase):
    def test_secrets_and_safe_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identities = root / "identities.json"
            generate_identities(identities)
            self.assertEqual(identities.stat().st_mode & 0o777, 0o600)
            profile = root / "profile.json"
            write_profile(profile, False, False, "/usr/local")
            text = profile.read_text()
            self.assertIn('"crosed_level": 5', text)
            self.assertIn('"qubes_style_isolation": false', text)
            self.assertIn('"compliance_applied": false', text)
            self.assertIn('"suite": "public6"', text)

    def test_termux_profile_always_contains_both_cores(self):
        profile = termux_capabilities()
        self.assertEqual(profile["core-go"], "included")
        self.assertEqual(profile["core-rust"], "included")
        self.assertIn("included", profile["control-center-mcp-lsp-openai"])
        self.assertIn("Public6", profile["public6"])

    def test_local_signing_material_requires_secure_complete_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private, trust = root / "key.pem", root / "trust.json"
            keygen(private, trust, "local-owner")
            verify_package_trust(private, trust)
            trust.chmod(0o666)
            with self.assertRaises(EasyBuildError):
                verify_package_trust(private, trust)

    def test_secure_state_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("x")
            link = root / "state"
            link.symlink_to(target)
            with self.assertRaises(EasyBuildError):
                _secure_regular(link, 10)


if __name__ == "__main__":
    unittest.main()
