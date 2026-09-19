import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import archive_preflight


class ArchivePreflightTests(unittest.TestCase):
    def test_tar_requires_core_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                archive.addfile(tarfile.TarInfo("README.md"))
            with self.assertRaisesRegex(ValueError, "missing required binaries"):
                archive_preflight.check_tar(str(path))

    def test_tar_accepts_project_root_prefix_and_required_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                archive.addfile(tarfile.TarInfo("Shadow6/README.md"))
                for name in archive_preflight.REQUIRED_TAR_FILES:
                    archive.addfile(tarfile.TarInfo(f"Shadow6/{name}"))
            archive_preflight.check_tar(str(path))

    def test_tar_rejects_parent_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                archive.addfile(tarfile.TarInfo("../escape"))
            with self.assertRaisesRegex(ValueError, "unsafe archive member path"):
                archive_preflight.check_tar(str(path))

    def test_zip_rejects_generated_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Shadow6/config.mk.txt", "BUILD_GO=1\n")
            with self.assertRaisesRegex(ValueError, "forbidden zip member"):
                archive_preflight.check_zip(str(path))


if __name__ == "__main__":
    unittest.main()
