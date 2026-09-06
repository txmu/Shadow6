import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from shadow6_plugins import (  # noqa: E402
    DEFAULT_PLUGIN_ROOT,
    DEFAULT_TRUST_STORE,
    PluginError,
    PluginRegistry,
    dispatch_hook,
    run_plugin,
)


class PluginSystemTests(unittest.TestCase):
    def setUp(self):
        self.registry = PluginRegistry()

    def test_bundled_plugins_are_signed_and_discoverable(self):
        self.assertEqual(
            self.registry.discover(),
            ["maze-runner", "number-guess", "rock-paper-scissors"],
        )
        for plugin_id in self.registry.discover():
            manifest = self.registry.load(plugin_id)
            self.assertEqual(manifest.signer, "shadow6-release")
            self.assertEqual(manifest.capabilities, frozenset({"game.local"}))

    def test_games_execute_in_isolated_processes(self):
        number = self.registry.load("number-guess")
        response = run_plugin(number, {"action": "new", "state": {}})
        secret = response["state"]["secret"]
        response["state"]["input"] = str(secret)
        won = run_plugin(number, {"action": "play", "state": response["state"]})
        self.assertTrue(won["done"])

        rps = self.registry.load("rock-paper-scissors")
        result = run_plugin(rps, {"action": "play", "state": {"input": "石头"}})
        self.assertTrue(result["done"])

        maze = self.registry.load("maze-runner")
        response = run_plugin(maze, {"action": "new", "state": {}})
        for move in "ssddwwddss":
            response["state"]["input"] = move
            response = run_plugin(maze, {"action": "play", "state": response["state"]})
        self.assertTrue(response["done"])

    def test_modified_code_and_manifest_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "plugins"
            shutil.copytree(DEFAULT_PLUGIN_ROOT, root)
            code = root / "number-guess" / "main.py"
            code.write_text(code.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "digest mismatch"):
                PluginRegistry(root, DEFAULT_TRUST_STORE).load("number-guess")

            shutil.rmtree(root)
            shutil.copytree(DEFAULT_PLUGIN_ROOT, root)
            manifest_path = root / "maze-runner" / "plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["signature"] = "00" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(PluginError, "signature verification failed"):
                PluginRegistry(root, DEFAULT_TRUST_STORE).load("maze-runner")

    def test_capabilities_are_deny_by_default_at_policy_boundary(self):
        registry = PluginRegistry(granted_capabilities=frozenset())
        with self.assertRaisesRegex(PluginError, "not granted"):
            registry.load("rock-paper-scissors")

    def test_plugin_symlink_and_oversized_request_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "plugins"
            root.mkdir()
            (root / "number-guess").symlink_to(DEFAULT_PLUGIN_ROOT / "number-guess")
            with self.assertRaisesRegex(PluginError, "must not be a symlink"):
                PluginRegistry(root, DEFAULT_TRUST_STORE).load("number-guess")
        manifest = self.registry.load("number-guess")
        with self.assertRaisesRegex(PluginError, "exceeds"):
            run_plugin(manifest, {"payload": "x" * 70_000})

    def test_signed_hook_dispatch_has_no_host_network(self):
        code = b"""import json, socket, sys
request = json.loads(sys.stdin.buffer.readline())
blocked = False
try:
    sock = socket.socket()
    sock.settimeout(0.1)
    sock.connect((\"127.0.0.1\", 9))
except OSError:
    blocked = True
print(json.dumps({\"event\": request.get(\"event\"), \"network_blocked\": blocked}))
"""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "plugins"
            plugin_dir = root / "test-hook"
            plugin_dir.mkdir(parents=True)
            entrypoint = plugin_dir / "main.py"
            entrypoint.write_bytes(code)
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            trust_store = base / "trusted.json"
            trust_store.write_text(
                json.dumps({"signers": {"test-signer": public_key.hex()}}), encoding="utf-8"
            )
            document = {
                "schema_version": 1,
                "id": "test-hook",
                "name": "Test Hook",
                "version": "1.0.0",
                "runtime": "python3",
                "entrypoint": "main.py",
                "capabilities": ["hook.mtd.after"],
                "hooks": ["hook.mtd.after"],
                "timeout_seconds": 3,
                "max_output_bytes": 65536,
                "sha256": hashlib.sha256(code).hexdigest(),
                "signer": "test-signer",
            }
            payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            document["signature"] = private_key.sign(payload).hex()
            (plugin_dir / "plugin.json").write_text(json.dumps(document), encoding="utf-8")
            for path in (entrypoint, trust_store, plugin_dir / "plugin.json"):
                os.chmod(path, 0o644)
            registry = PluginRegistry(
                root, trust_store, granted_capabilities=frozenset({"hook.mtd.after"})
            )
            result = dispatch_hook(registry, "hook.mtd.after", {"epoch": 7})
            self.assertEqual(result["test-hook"]["event"], "hook.mtd.after")
            self.assertTrue(result["test-hook"]["network_blocked"])


if __name__ == "__main__":
    unittest.main()
