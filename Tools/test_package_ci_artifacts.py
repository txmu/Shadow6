import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys_path = str(Path(__file__).resolve().parent)
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)
from package_ci_artifacts import package, target_for
from install_platform_payload import _verify_payload


class CiArtifactBundleTests(unittest.TestCase):
    def test_known_platform_artifacts_are_grouped_by_architecture(self):
        self.assertEqual(target_for("shadow6-linux-release"), ("linux", "x86_64"))
        self.assertEqual(target_for("shadow6-linux-arm64-components"), ("linux", "arm64"))
        self.assertEqual(target_for("shadow6-macos-arm64-components"), ("macos", "arm64"))
        self.assertEqual(target_for("shadow6-windows-amd64-components"), ("windows", "x86_64"))
        self.assertEqual(target_for("shadow6-android-debug"), ("android", "multi-abi"))
        self.assertEqual(target_for("shadow6-dragonflybsd-x86-64-components"), ("dragonflybsd", "x86_64"))
        self.assertEqual(target_for("shadow6-omnios-x86-64-components"), ("omnios", "x86_64"))
        self.assertEqual(target_for("shadow6-deployment-acceptance"), ("reports", "workflow"))
        self.assertEqual(target_for("shadow6-gleam-aarch64"), ("linux", "arm64"))
        self.assertEqual(target_for("shadow6-linux-qemu-riscv64-components"), ("linux-qemu", "riscv64"))
        self.assertEqual(target_for("shadow6-linux-qemu-s390x64-components"), ("linux-qemu", "s390x64"))
        self.assertEqual(target_for("shadow6-idris-ubuntu-latest-X64"), ("linux", "x86_64"))
        self.assertEqual(target_for("shadow6-idris-ubuntu-24.04-arm-ARM64"), ("linux", "arm64"))
        self.assertEqual(target_for("shadow6-idris-macos-latest-ARM64"), ("macos", "arm64"))
        self.assertEqual(target_for("shadow6-idris-macos-latest-X64"), ("macos", "x86_64"))
        with self.assertRaisesRegex(ValueError, "lacks runner architecture"):
            target_for("shadow6-idris-macos-latest")

    def test_unknown_shadow6_artifact_name_requires_an_explicit_group(self):
        with self.assertRaisesRegex(ValueError, "no platform/architecture mapping"):
            target_for("shadow6-future-unmapped-output")

    def test_package_has_per_target_archive_installers_and_source_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incoming = root / "incoming"
            linux = incoming / "shadow6-linux-release" / "ci-artifacts" / "linux"
            linux.mkdir(parents=True)
            (linux / "Shadow6.tar.gz").write_bytes(b"fixture release bytes")
            android = incoming / "shadow6-android-debug"
            android.mkdir(parents=True)
            (android / "app-debug.apk").write_bytes(b"fixture apk")
            output = root / "all-artifacts.zip"
            source_commit = "a" * 40
            report = package(incoming, output, run_id="123456", commit=source_commit)
            self.assertEqual(report["commit"], source_commit)
            self.assertEqual({(item["platform"], item["architecture"]) for item in report["groups"]},
                             {("linux", "x86_64"), ("android", "multi-abi")})
            with zipfile.ZipFile(output) as bundle:
                manifest = json.loads(bundle.read("Shadow6-artifact-bundle/manifest.json"))
                self.assertEqual(manifest["runId"], "123456")
                self.assertEqual(manifest["commit"], source_commit)
                for platform_name, arch in (("linux", "x86_64"), ("android", "multi-abi")):
                    base = f"Shadow6-artifact-bundle/platforms/{platform_name}/{arch}/"
                    payload = bundle.read(base + "artifacts.tar.gz")
                    group = next(item for item in manifest["groups"]
                                 if item["platform"] == platform_name and item["architecture"] == arch)
                    self.assertEqual(hashlib.sha256(payload).hexdigest(), group["payloadSha256"])
                    self.assertIn(base + "install.sh", bundle.namelist())
                    self.assertIn(base + "install.ps1", bundle.namelist())
                    self.assertIn(base + "README.md", bundle.namelist())
                    self.assertIn(base + "manifest.json", bundle.namelist())
                    standalone = root / f"{platform_name}-{arch}"
                    standalone.mkdir()
                    (standalone / "manifest.json").write_bytes(bundle.read(base + "manifest.json"))
                    (standalone / "artifacts.tar.gz").write_bytes(payload)
                    _verify_payload(standalone, standalone / "artifacts.tar.gz", platform_name,
                                    arch, source_commit)
                    damaged = standalone / "damaged.tar.gz"
                    damaged.write_bytes(payload[:-1] + bytes([payload[-1] ^ 1]))
                    with self.assertRaisesRegex(ValueError, "SHA-256 verification failed"):
                        _verify_payload(standalone, damaged, platform_name, arch, source_commit)

    def test_symbolic_link_payload_is_rejected_without_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incoming = root / "incoming" / "shadow6-linux-release"
            incoming.mkdir(parents=True)
            secret = root / "secret"
            secret.write_text("not to package")
            (incoming / "linked").symlink_to(secret)
            output = root / "out.zip"
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                package(root / "incoming", output, run_id="9", commit="b" * 40)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
