import copy
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from prepare_netbsd_go import MAX_ARCHIVE, save_archive, select_archive

ROOT = Path(__file__).resolve().parents[1]


class NetBSDToolchainTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"test archive bytes"
        self.item = dict(filename="go1.25.0.netbsd-amd64.tar.gz", os="netbsd",
                         arch="amd64", kind="archive", size=len(self.payload),
                         sha256=hashlib.sha256(self.payload).hexdigest())
        self.metadata = [dict(version="go1.25.0", files=[self.item])]

    def test_exact_platform_and_version_selection(self):
        self.assertEqual(select_archive(self.metadata, "go1.25.0"), self.item)
        for version in ("go1.25", "go1.25.0/../../x", "go1.25.0rc1", "go1.26.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                select_archive(self.metadata, version)
        for field, value in (("os", "linux"), ("arch", "arm64"), ("kind", "source"),
                             ("filename", "../go.tar.gz"), ("sha256", "f" * 63),
                             ("size", True), ("size", -1), ("size", MAX_ARCHIVE + 1)):
            metadata = copy.deepcopy(self.metadata)
            metadata[0]["files"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                select_archive(metadata, "go1.25.0")

    def test_ambiguous_metadata_is_rejected(self):
        self.metadata[0]["files"].append(dict(self.item))
        with self.assertRaises(ValueError):
            select_archive(self.metadata, "go1.25.0")

    def test_only_verified_download_is_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            save_archive(io.BytesIO(self.payload), root, self.item)
            self.assertEqual((root / "go.tar.gz").read_bytes(), self.payload)
            for payload in (self.payload[:-1], self.payload + b"x", b"x" * len(self.payload)):
                with self.subTest(payload=payload), self.assertRaises(ValueError):
                    save_archive(io.BytesIO(payload), root, self.item)
                self.assertEqual((root / "go.tar.gz").read_bytes(), self.payload)
                self.assertEqual([p.name for p in root.iterdir()], ["go.tar.gz"])

    def test_interrupted_download_cleans_partial_archive(self):
        class Interrupted(io.BytesIO):
            def read(self, count):
                if self.tell():
                    raise OSError("connection reset")
                return super().read(1)

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                save_archive(Interrupted(self.payload), directory, self.item)
            self.assertEqual(list(Path(directory).iterdir()), [])


class NetBSDRunnerTests(unittest.TestCase):
    def run_guest_script(self, fail_component="", python=sys.executable):
        """Exercise the real shell/build scripts with a local stand-in compiler."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for component in ("Core-Go", "Guard", "Gate"):
                (root / component).mkdir()
            shutil.copy2(ROOT / "Core-Go/compile.sh", root / "Core-Go/compile.sh")
            tools = root / "fake-bin"
            tools.mkdir()
            # Optional host toolchains must not leak into this Go runner test.
            # Native C++/Zig/Nim behavior is covered by their own suites.
            for component in ("Core-Cpp", "Core-Zig", "Core-Nim"):
                (root / component).mkdir()
            for script in ("compile.sh", "test.sh"):
                (root / "Core-Cpp" / script).write_text("#!/bin/sh\nexit 0\n")
            for name in ("zig", "nim"):
                tool = tools / name
                tool.write_text("#!/bin/sh\nexit 0\n")
                tool.chmod(0o700)
            (tools / "uname").write_text("#!/bin/sh\nprintf '%s\\n' NetBSD\n")
            (tools / "uname").chmod(0o700)
            compiler = root / "go"
            compiler.write_text("#!" + sys.executable + "\n" + '''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["SHADOW6_TEST_GO_LOG"], "a") as log:
    log.write(json.dumps([pathlib.Path.cwd().name, args,
                         os.environ.get("GOTOOLCHAIN"),
                         os.environ.get("CROSED_LEVEL")]) + "\\n")
if args[0] == "test" and pathlib.Path.cwd().name == os.environ["SHADOW6_TEST_FAIL"]:
    sys.exit(7)
if args[0] == "env":
    print("amd64" if args[1] == "GOARCH" else "netbsd")
if args[0] == "build":
    output = pathlib.Path(args[args.index("-o") + 1])
    output.write_text("#!/bin/sh\\nexit 0\\n# level=" + os.environ["CROSED_LEVEL"])
''')
            compiler.chmod(0o700)
            archive = root / ".tmp/netbsd-go/go.tar.gz"
            archive.parent.mkdir(parents=True)
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(compiler, arcname="go/bin/go")
            log = root / "go.log"
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                       PYTHON=python,
                       SHADOW6_TEST_GO_LOG=str(log), SHADOW6_TEST_FAIL=fail_component)
            result = subprocess.run(["bash", str(ROOT / "Tools/test_netbsd.sh")],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=15)
            import json
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            outputs = {p.name: p.read_text() for p in (root / "Core-Go").glob("shadow6-go*")}
            return result, calls, outputs

    def test_success_keeps_default_and_crosed_artifacts(self):
        result, calls, outputs = self.run_guest_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        tests = [call for call in calls if call[1][0] == "test"]
        self.assertEqual([call[0] for call in tests], ["Core-Go", "Guard", "Gate"])
        for call in tests:
            self.assertIn("-timeout=5m", call[1])
            self.assertEqual(call[2], "local")
        self.assertIn("level=0", outputs["shadow6-go"])
        self.assertIn("level=5", outputs["shadow6-go-crosed"])

    def test_native_test_failure_stops_before_build(self):
        result, calls, outputs = self.run_guest_script("Guard")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertFalse(outputs)
        self.assertFalse(any(call[1][0] == "build" for call in calls))
        self.assertFalse(any(call[0] == "Gate" for call in calls))

    def test_missing_python_fails_before_any_build(self):
        result, calls, outputs = self.run_guest_script(python="/nonexistent/shadow6-test-python")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shadow6-test-python", result.stderr)
        self.assertFalse(calls)
        self.assertFalse(outputs)


if __name__ == "__main__":
    unittest.main()
