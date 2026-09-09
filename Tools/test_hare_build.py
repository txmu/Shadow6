"""Exercise optional and explicitly required Hare builds without a toolchain."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAKE = shutil.which("make")


class HareBuildTests(unittest.TestCase):
    def run_build(self, *settings):
        with tempfile.TemporaryDirectory(prefix="shadow6-hare-build-") as directory:
            (Path(directory) / "echo").symlink_to(shutil.which("echo"))
            env = dict(os.environ, PATH=directory)
            env.pop("BUILD_HARE", None)
            return subprocess.run([MAKE, "-f", str(ROOT / "Makefile"), "core-hare", *settings],
                                  cwd=directory, env=env, text=True,
                                  capture_output=True, timeout=10)

    def test_missing_optional_toolchain_disables_build(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Core-Hare disabled", result.stdout)

    def test_required_missing_toolchain_fails_early(self):
        result = self.run_build("BUILD_HARE=1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BUILD_HARE=1 requires", result.stderr)

    def test_explicit_disable(self):
        result = self.run_build("BUILD_HARE=0")
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
