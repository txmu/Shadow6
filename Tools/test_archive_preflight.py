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

    def test_zip_rejects_ci_toolchain_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(
                    "Shadow6/.nim_runtime/dist/atlas/config.nims.txt",
                    "generated = true\n",
                )
            with self.assertRaisesRegex(ValueError, "forbidden zip directory"):
                archive_preflight.check_zip(str(path))

    def test_zip_rejects_test_and_tool_caches(self):
        cache_paths = (
            ".pytest_cache/v/cache/nodeids.txt",
            ".mypy_cache/3.12/module.meta.txt",
            ".ruff_cache/0.1/cache.txt",
            ".hypothesis/examples/example.txt",
            ".tox/py312/log.txt",
            ".nox/test/log.txt",
            ".cache/tool/state.txt",
        )
        for cache_path in cache_paths:
            with self.subTest(cache_path=cache_path):
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "release.zip"
                    with zipfile.ZipFile(path, "w") as archive:
                        archive.writestr(f"Shadow6/{cache_path}", "generated\n")
                    with self.assertRaisesRegex(ValueError, "forbidden zip directory"):
                        archive_preflight.check_zip(str(path))


if __name__ == "__main__":
    unittest.main()
