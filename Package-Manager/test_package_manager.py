import tempfile
import unittest
from pathlib import Path

from shadow6_pkg import PackageError, activate, build_package, install_package, keygen, list_packages, verify_package


class PackageManagerTests(unittest.TestCase):
    def test_signed_install_and_version_switch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private, trust, store = root / "key.pem", root / "trust.json", root / "store"
            keygen(private, trust, "local-owner")
            for version, content in (("1.0.0", b"first"), ("1.1.0", b"second")):
                payload = root / f"payload-{version}"; payload.mkdir(); (payload / "app.bin").write_bytes(content)
                package = root / f"app-{version}.s6pkg"
                build_package(payload, package, private, "local-owner", "app", "sample-app", version)
                manifest, source = verify_package(package, trust); source.close()
                self.assertEqual(manifest["version"], version)
                install_package(package, trust, store, True)
            activate(store, "app", "sample-app", "1.0.0")
            rows = list_packages(store)
            self.assertEqual([row["version"] for row in rows if row["active"]], ["1.0.0"])

    def test_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); payload = root / "payload"; payload.mkdir(); (payload / "mod.py").write_text("safe")
            keygen(root / "key.pem", root / "trust.json", "owner")
            build_package(payload, root / "mod.s6pkg", root / "key.pem", "owner", "crosed-mod", "sample-mod", "1.0.0")
            (payload / "mod.py").write_text("changed")
            with self.assertRaises(PackageError):
                build_package(payload, root / "mod.s6pkg", root / "key.pem", "owner", "crosed-mod", "sample-mod", "1.0.0")


if __name__ == "__main__":
    unittest.main()
