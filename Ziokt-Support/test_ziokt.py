"""Native Ziokt support must work without the Ziokt checkout."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shadow6-ziokt-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = {**os.environ, "HOME": str(self.base), "PYTHONDONTWRITEBYTECODE": "1"}
        for name in ("SHADOW6_ROOT", "SHADOW6_SERVICE_REGISTRY", "SHADOW6_CORE_DESCRIPTORS", "PYTHONPATH"):
            self.env.pop(name, None)
        self.config = self.base / "ziokt.json"

    def invoke(self, *args, data=None, script=None):
        return subprocess.run([sys.executable, str(script or ROOT / "CLI/shadow6.py"),
                               "ziokt", *args] if script is None else
                              [sys.executable, str(script), *args],
                              input=data, capture_output=True, text=True, env=self.env, timeout=10)

    def enable(self):
        self.config.write_text(json.dumps({"schema": "ziokt.provider.v1", "enabled": True,
                                          "federation_id": "test", "provider_id": "s6"}))
        self.config.chmod(0o600)

    def request(self, method="status.get"):
        return json.dumps({"protocol": "zfcp/1", "request_id": "native-test", "federation_id": "test",
                           "provider_id": "s6", "method": method, "params": {}, "nonce": "a" * 32,
                           "deadline_ms": time.time_ns() // 1_000_000 + 20_000}) + "\n"

    def test_disabled_default_creates_no_state(self):
        result = self.invoke("capabilities")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["enabled"])
        self.assertEqual(list(self.base.iterdir()), [])

    def test_opt_in_rpc_and_rejection_of_mutations(self):
        self.enable()
        for method, success in (("status.get", True), ("operation.commit", False)):
            result = self.invoke("--config", str(self.config), "rpc", "--stdio", data=self.request(method))
            self.assertEqual(json.loads(result.stdout)["ok"], success)
        self.assertEqual([p.name for p in self.base.iterdir()], ["ziokt.json"])

    def test_strict_framing_duplicate_keys_and_missing_eof(self):
        self.enable()
        for data in ('{"protocol":"zfcp/1","protocol":"zfcp/1"}\n',
                     self.request() + self.request(), self.request().rstrip("\n"), "x" * 65538 + "\n"):
            result = self.invoke("--config", str(self.config), "rpc", "--stdio", data=data)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(json.loads(result.stdout)["ok"])

    def test_private_config_and_unknown_fields(self):
        self.enable(); self.config.chmod(0o644)
        result = self.invoke("--config", str(self.config), "status")
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "UNSAFE_FILE")
        self.config.chmod(0o600)
        self.config.write_text('{"schema":"ziokt.provider.v1","enabled":true,"unknown":1}')
        self.assertEqual(self.invoke("--config", str(self.config), "status").returncode, 2)

    def test_installed_entrypoint_resolves_its_own_vendored_runtime(self):
        prefix = self.base / "prefix"
        bindir = prefix / "bin"; bindir.mkdir(parents=True)
        modules = prefix / "share/shadow6/modules"; modules.mkdir(parents=True)
        tree = prefix / "share/shadow6/tree"; tree.mkdir(); (tree / "Makefile").write_text("")
        shutil.copyfile(ROOT / "Ziokt-Support/shadow6_ziokt.py", bindir / "shadow6-ziokt")
        shutil.copyfile(ROOT / "Ziokt-Support/zfcp_runtime.py", modules / "zfcp_runtime.py")
        shutil.copyfile(ROOT / "Crosed/install_layout.py", modules / "install_layout.py")
        result = self.invoke("capabilities", script=bindir / "shadow6-ziokt")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["enabled"])


if __name__ == "__main__":
    unittest.main()
