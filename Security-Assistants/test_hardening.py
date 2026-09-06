"""Isolated security regressions; no compiled products, network, or host actions."""

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import shadow6_security as security


class SecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shadow6-security-regression-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def write(self, relative, content, mode=0o600):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def keys(self):
        private, public = self.base / "private.pem", self.base / "public.json"
        security.generate_ledger_key(private, public)
        return private, public

    def test_strict_json_rejects_ambiguous_and_nonportable_inputs(self):
        bad_inputs = [b'{"x":1,"x":2}', b'{"a":{"x":1,"x":1}}', b'1.0', b'1e0',
                      b'NaN', b'Infinity', b'-Infinity', b'9007199254740992', b'"\\ud800"',
                      b'"\\u0000"', '"e\u0301"', b'\xff', b'[' * 10000 + b']' * 10000,
                      b'"' + b'x' * 65537 + b'"', '{"e\u0301":1}']
        for raw in bad_inputs:
            with self.subTest(raw=repr(raw)[:60]), self.assertRaises(security.SecurityError):
                security.strict_json_loads(raw)

    def test_strict_json_size_is_utf8_bytes_and_roundtrips(self):
        value = {"text": "通过é", "n": 9007199254740991, "list": [True, None, -2]}
        self.assertEqual(security.strict_json_loads(security.canonical(value)), value)
        with self.assertRaises(security.SecurityError):
            security.strict_json_loads('"通过"', limit=7)
        self.assertEqual(security.strict_json_loads('"通过"', limit=8), "通过")
        self.assertEqual(security.strict_json_loads('"{[\\\"\\\\]}"'), '{["\\]}')

    def test_canonical_rejects_nonportable_objects(self):
        for value in (1.0, float("nan"), {1: "x"}, (1,), {"bad": "e\u0301"}, {"bad": "\ud800"}):
            with self.subTest(value=repr(value)), self.assertRaises(security.SecurityError):
                security.canonical(value)

    def test_secure_read_rechecks_opened_mode_and_owner(self):
        path = self.write("secret", b"secret")
        real_open = os.open

        def chmod_during_open(target, flags, *args, **kwargs):
            os.chmod(target, 0o644)
            return real_open(target, flags, *args, **kwargs)

        with mock.patch.object(security.os, "open", side_effect=chmod_during_open):
            with self.assertRaisesRegex(security.SecurityError, "0600"):
                security.secure_read(path, secret=True)
        path.chmod(0o600)
        original = os.fstat

        def changed_owner(fd):
            metadata = original(fd)
            return mock.Mock(st_mode=metadata.st_mode, st_uid=metadata.st_uid + 1, st_size=metadata.st_size)

        with mock.patch.object(security.os, "fstat", side_effect=changed_owner):
            with self.assertRaisesRegex(security.SecurityError, "owner-controlled"):
                security.secure_read(path, secret=True)

    def test_secure_read_fifo_race_uses_nonblocking_open(self):
        path = self.write("swapped", b"safe")
        real_open = os.open

        def replace_during_open(target, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NONBLOCK)
            path.unlink()
            os.mkfifo(path, 0o600)
            return real_open(target, flags, *args, **kwargs)

        started = time.monotonic()
        with mock.patch.object(security.os, "open", side_effect=replace_during_open):
            with self.assertRaises(security.SecurityError):
                security.secure_read(path)
        self.assertLess(time.monotonic() - started, 1)

    def test_secure_read_rejects_symlink_size_and_nonexact_secret_mode(self):
        path = self.write("data", b"12345")
        link = self.base / "link"
        link.symlink_to(path)
        for target, limit in ((link, 10), (path, 4)):
            with self.assertRaises(security.SecurityError):
                security.secure_read(target, limit)
        path.chmod(0o400)
        with self.assertRaisesRegex(security.SecurityError, "0600"):
            security.secure_read(path, secret=True)

    def test_secure_read_detects_growth_after_stat(self):
        path = self.write("growing", b"small")
        real_read = os.read
        grown = False

        def grow_then_read(fd, count):
            nonlocal grown
            if not grown:
                path.write_bytes(b"x" * 100)
                grown = True
            return real_read(fd, count)

        with mock.patch.object(security.os, "read", side_effect=grow_then_read):
            with self.assertRaisesRegex(security.SecurityError, "exceeds"):
                security.secure_read(path, 10)

    def test_atomic_write_refuses_dangling_symlink(self):
        link = self.base / "link"
        link.symlink_to(self.base / "missing")
        with self.assertRaises(security.SecurityError):
            security.atomic_write(link, b"new", 0o600)
        self.assertTrue(link.is_symlink())

    def test_bounded_run_returns_completed_process_with_env_and_exit_status(self):
        result = security.bounded_run([sys.executable, "-c",
            "import os,sys;print(os.environ['REGRESSION']);print('err',file=sys.stderr);sys.exit(3)"],
            self.base, 3, env={"REGRESSION": "通过"})
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, "通过\n", "err\n"))

    def test_bounded_run_combines_stream_limits_and_kills_own_group(self):
        with mock.patch.object(security.os, "killpg", wraps=os.killpg) as kill:
            with self.assertRaisesRegex(security.SecurityError, "output exceeds"):
                security.bounded_run([sys.executable, "-c",
                    "import os,time;os.write(1,b'x'*700);os.write(2,b'y'*700);time.sleep(5)"], self.base, 3, 1024)
            self.assertEqual(kill.call_count, 1)
            self.assertNotEqual(kill.call_args.args[0], os.getpgrp())
            self.assertEqual(kill.call_args.args[1], signal.SIGKILL)
        result = security.bounded_run([sys.executable, "-c", "import os;os.write(1,b'x'*1024)"], self.base, 3, 1024)
        self.assertEqual(len(result.stdout), 1024)

    def test_bounded_run_timeout_with_closed_streams(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            security.bounded_run([sys.executable, "-c", "import os,time;os.close(1);os.close(2);time.sleep(5)"], self.base, 0.2)
        self.assertLess(time.monotonic() - started, 1.5)

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "Linux descendant state check")
    def test_bounded_run_timeout_kills_descendant_holding_pipe(self):
        pid_file = self.base / "descendant.pid"
        script = ("import os,sys,time;pid=os.fork();"
                  "open(sys.argv[1],'w').write(str(pid)) if pid else None;"
                  "time.sleep(5) if not pid else None")
        with self.assertRaises(subprocess.TimeoutExpired):
            security.bounded_run([sys.executable, "-c", script, str(pid_file)], self.base, 0.3)
        child_pid = int(pid_file.read_text())
        state = Path(f"/proc/{child_pid}/stat")
        deadline = time.monotonic() + 1
        while state.exists() and state.read_text().split()[2] != "Z" and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(not state.exists() or state.read_text().split()[2] == "Z")

    def test_bounded_run_rejects_invalid_utf8_and_invalid_limits(self):
        with self.assertRaisesRegex(security.SecurityError, "UTF-8"):
            security.bounded_run([sys.executable, "-c", "import os;os.write(1,b'\\xff')"], self.base, 3)
        for timeout in (0, -1, True, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(security.SecurityError):
                security.bounded_run([sys.executable], self.base, timeout)

    def test_append_refuses_truncation_missing_or_tampered_checkpoint(self):
        private, public = self.keys()
        ledger = self.base / "events.jsonl"
        security.append_event(ledger, private, "first", "test", {})
        security.append_event(ledger, private, "second", "test", {})
        original = ledger.read_bytes()
        checkpoint_path = security.checkpoint_path(ledger)
        checkpoint = checkpoint_path.read_bytes()
        for data in (original.splitlines(keepends=True)[0], b""):
            ledger.write_bytes(data)
            with self.assertRaisesRegex(security.SecurityError, "checkpoint"):
                security.append_event(ledger, private, "third", "test", {})
            self.assertEqual(ledger.read_bytes(), data)
            self.assertEqual(checkpoint_path.read_bytes(), checkpoint)
        ledger.write_bytes(original)
        checkpoint_path.unlink()
        with self.assertRaisesRegex(security.SecurityError, "checkpoint"):
            security.append_event(ledger, private, "third", "test", {})
        checkpoint_path.write_bytes(checkpoint.replace(b'"sequence":2', b'"sequence":1'))
        checkpoint_path.chmod(0o600)
        with self.assertRaisesRegex(security.SecurityError, "checkpoint"):
            security.append_event(ledger, private, "third", "test", {})
        checkpoint_path.write_bytes(checkpoint)
        self.assertEqual(security.verify_ledger(ledger, public)["sequence"], 2)

    def test_ledger_rejects_duplicate_keys_and_boolean_sequence(self):
        private, public = self.keys()
        ledger = self.base / "events.jsonl"
        security.append_event(ledger, private, "first", "test", {})
        raw = ledger.read_bytes()
        ledger.write_bytes(raw.replace(b'"sequence":1', b'"sequence":1,"sequence":1'))
        with self.assertRaisesRegex(security.SecurityError, "duplicate"):
            security.verify_ledger(ledger, public)
        event = security.strict_json_loads(raw)
        event["sequence"] = True
        event.pop("signature")
        event["signature"] = security.load_private(private)[0].sign(security.canonical(event)).hex()
        ledger.write_bytes(security.canonical(event) + b"\n")
        with self.assertRaisesRegex(security.SecurityError, "schema"):
            security.verify_ledger(ledger, public)

    def test_public_key_rejects_boolean_version_and_duplicate_fields(self):
        _, public = self.keys()
        raw = public.read_bytes()
        for changed in (raw.replace(b'"version":1', b'"version":true'), raw.replace(b'"version":1', b'"version":1,"version":1')):
            public.write_bytes(changed)
            with self.assertRaises(security.SecurityError):
                security.load_public(public)

    def plugin_fixture(self):
        private_path, public_path = self.keys()
        private, _ = security.load_private(private_path)
        public = security.strict_json_loads(public_path.read_bytes())["public_key"]
        self.write("Plugin-System/trusted_signers.json", security.canonical({"signers": {"test-signer": public}}))
        code = b"print('fixture; never executed')\n"
        self.write("plugins/test-plugin/main.py", code)
        manifest = {"schema_version": 1, "id": "test-plugin", "name": "Test", "version": "1.0.0",
                    "runtime": "python3", "entrypoint": "main.py", "capabilities": ["game.local"], "hooks": [],
                    "timeout_seconds": 3, "max_output_bytes": 1024, "sha256": hashlib.sha256(code).hexdigest(), "signer": "test-signer"}
        manifest["signature"] = private.sign(security.canonical(manifest)).hex()
        path = self.write("plugins/test-plugin/plugin.json", security.canonical(manifest))
        policy = {"version": 1, "profile": "maximum", "core": {"default_crosed_max_level": 0,
                  "variant_min_level": 5, "require_app_transport": True, "require_qubes_isolation": True, "require_utf8": True},
                  "plugins": {"require_signatures": True, "allowed_signers": ["test-signer"], "allowed_capabilities": ["game.local"]},
                  "audit": {"require_ledger": False, "ledger_path": "", "public_key": ""}}
        policy_path = self.write("policy.json", security.canonical(policy))
        return path, manifest, policy_path, policy

    def policy_result(self, path):
        def features(binary, root):
            variant = binary.name.endswith("-crosed")
            return {"crosed_max_level": 5 if variant else 0, "utf8": True,
                    "app_transport": variant, "qubes_isolation": variant}
        with mock.patch.object(security, "feature_report", side_effect=features):
            return security.evaluate_policy(self.base, path)

    def test_policy_verifies_actual_signature_and_entrypoint_digest(self):
        path, manifest, policy_path, _ = self.plugin_fixture()
        self.assertEqual(self.policy_result(policy_path)["status"], "pass")
        changed = dict(manifest, name="Forged display name")
        path.write_bytes(security.canonical(changed))
        report = self.policy_result(policy_path)
        self.assertEqual(report["status"], "fail")
        self.assertIn("signature", str(report))
        path.write_bytes(security.canonical(manifest))
        (path.parent / "main.py").write_bytes(b"tampered")
        report = self.policy_result(policy_path)
        self.assertEqual(report["status"], "fail")
        self.assertIn("digest", str(report))

    def test_policy_rejects_wrong_field_types_and_unknown_fields(self):
        _, _, path, policy = self.plugin_fixture()
        edits = [("core", "require_utf8", "false"), ("core", "variant_min_level", True),
                 ("plugins", "allowed_capabilities", "game.local"), ("plugins", "allowed_signers", [[]]),
                 ("audit", "require_ledger", 0), ("audit", "public_key", []), ("core", "extra", True)]
        for section, key, value in edits:
            changed = copy.deepcopy(policy)
            changed[section][key] = value
            path.write_bytes(security.canonical(changed))
            with self.subTest(section=section, key=key), self.assertRaises(security.SecurityError):
                self.policy_result(path)

    def test_policy_rejects_duplicate_manifest_fields(self):
        path, _, policy_path, _ = self.plugin_fixture()
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'))
        self.assertEqual(self.policy_result(policy_path)["status"], "fail")

    def test_sbom_has_standard_uuid_and_gate_inventory(self):
        self.write("Core-Go/go.mod", b"module core\nrequire example.org/mod v1.2.3\n")
        self.write("Guard/go.mod", b"module guard\n")
        self.write("Gate/go.mod", b"module gate\nrequire example.org/gate v2.0.0\n")
        self.write("Core-Rust/Cargo.lock", b"version = 4\n")
        self.write("requirements.txt", b"example==1.0.0\n")
        self.write("requirements-ml.txt", b"")
        self.write("Gate/main.go", b"package main\n")
        self.write("Gate/shadow6-gate", b"fixture binary; not executable")
        report = security.generate_sbom(self.base)
        serial = uuid.UUID(report["serialNumber"])
        self.assertEqual(serial.version, 5)
        self.assertEqual(report["serialNumber"], serial.urn)
        names = {component["name"] for component in report["components"]}
        self.assertTrue({"example.org/gate", "example.org/mod", "shadow6-gate"} <= names)
        binary = json.loads(report["properties"][0]["value"])[0]
        self.assertEqual(binary["path"], "Gate/shadow6-gate")
        self.assertEqual(binary["mode"], "0600")
        self.assertIn("uid", binary)
        self.assertEqual(security.generate_sbom(self.base)["serialNumber"], report["serialNumber"])


if __name__ == "__main__":
    unittest.main()
