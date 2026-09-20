"""Small source-level regression harness; builds only the NIF and Erlang modules.

No embedded OTP/Core rebuild, dependency downloads, or public listeners.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]


class GleamSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.erl = shutil.which("erl") or str(ROOT / ".tools/gleam/otp/bin/erl")
        cls.erlc = shutil.which("erlc") or str(ROOT / ".tools/gleam/otp/bin/erlc")
        if not Path(cls.erl).is_file() or not Path(cls.erlc).is_file():
            raise unittest.SkipTest("Erlang toolchain unavailable; no downloads attempted")
        cls.tmp = tempfile.TemporaryDirectory(prefix="shadow6-gleam-security.")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.build = Path(cls.tmp.name)
        include = ROOT / ".tools/gleam/otp/lib/erlang/usr/include"
        if not (include / "erl_nif.h").is_file():
            include = Path("/usr/lib/erlang/usr/include")
        subprocess.run(["cc", "-shared", "-fPIC", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
                        "-I" + str(include), str(ROOT / "Core-Gleam/c_src/shadow6_sodium.c"),
                        "-o", str(cls.build / "shadow6_sodium.so"), "-lsodium", "-lcrypto"], check=True, timeout=30)
        (cls.build / "shadow6_build.erl").write_text(
            '-module(shadow6_build).\n-export([crosed_level/0,app_transport/0,qubes_isolation/0]).\n'
            'crosed_level()->5.\napp_transport()->true.\nqubes_isolation()->true.\n')
        modules = [ROOT / "Core-Gleam/src" / (name + ".erl") for name in
                   ("shadow6_sodium", "shadow6_crosed", "shadow6_secure_file", "shadow6_json",
                    "shadow6_config", "shadow6_forward", "shadow6_control")]
        # Test-only exports allow direct negative tests without exposing them in production.
        subprocess.run([cls.erlc, "+export_all", "-o", str(cls.build), *map(str, modules),
                        str(cls.build / "shadow6_build.erl")], check=True, timeout=30,
                       env={**os.environ, "ERL_FLAGS": "+S 2:2 +SDcpu 1 +SDio 1"})

    def setUp(self):
        self.state = tempfile.TemporaryDirectory(prefix="state-", dir=self.build)
        self.addCleanup(self.state.cleanup)
        self.root = Path(self.state.name)
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.request = {"version": 1, "mod_id": "test-mod", "nonce": "ab" * 16,
                        "issued_at": int(time.time()), "requested_level": 1,
                        "capabilities": ["observe.health"], "source_domain": "default",
                        "target_domain": "default", "payload": {"message": "ok"}}
        self.trust = {"mods": {"test-mod": {"pubkey": public, "max_level": 5,
                                          "capabilities": ["observe.health"], "allowed_domains": []}}}
        self.save()

    def save(self):
        r = self.request
        digest = hashlib.sha256(json.dumps(r["payload"], separators=(",", ":")).encode()).hexdigest()
        signed = "\n".join(["1", r["mod_id"], r["nonce"], str(r["issued_at"]), str(r["requested_level"]),
                             ",".join(sorted(r["capabilities"])), digest, r["source_domain"], r["target_domain"]])
        r["signature"] = self.key.sign(signed.encode()).hex()
        for name, value in (("request", r), ("trust", self.trust)):
            path = self.root / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)

    def erl_eval(self, expression):
        result = subprocess.run([self.erl, "+S", "2:2", "+SDcpu", "1", "+SDio", "1", "-noshell",
                                 "-pa", str(self.build), "-eval",
                                 'ok=shadow6_sodium:load(), ' + expression + ', halt().'],
                                cwd=self.build, capture_output=True, text=True, timeout=8,
                                env={**os.environ, "LD_LIBRARY_PATH": str(self.build)})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def grant(self, accepted):
        expression = 'shadow6_crosed:request(<<"' + str(self.root / "request") + '">>,<<"' + str(self.root / "trust") + '">>)'
        if accepted:
            self.erl_eval('#{status := <<"granted">>} = ' + expression)
        else:
            self.erl_eval('true = (try ' + expression + ' of _ -> false catch _:_ -> true end)')

    def test_replay_persists_across_vm_restarts_and_hex_case(self):
        self.grant(True)
        self.grant(False)
        self.request["nonce"] = self.request["nonce"].upper()
        self.save()
        self.grant(False)
        self.assertEqual((self.root / "trust.replay").stat().st_size, 256 * 72)

    def test_domain_binding(self):
        self.request["source_domain"] = self.request["target_domain"] = "other"
        self.save()
        self.grant(False)
        self.assertFalse((self.root / "trust.replay").exists())
        self.trust["domain"] = "other"
        self.trust["mods"]["test-mod"]["source_domain"] = "other"
        self.save()
        self.grant(True)

    def test_bad_signature_does_not_consume_nonce(self):
        path = self.root / "request"
        raw = json.loads(path.read_text()); raw["signature"] = "00" * 64
        path.write_text(json.dumps(raw))
        self.grant(False)
        self.assertFalse((self.root / "trust.replay").exists())
        self.save(); self.grant(True)

    def test_ledger_corruption_and_symlink_fail_closed(self):
        ledger = self.root / "trust.replay"
        ledger.write_bytes(b"corrupt"); ledger.chmod(0o600)
        self.grant(False)
        ledger.unlink(); ledger.symlink_to(self.root / "request")
        self.grant(False)

    def test_empty_capabilities_denied(self):
        self.request["capabilities"] = []; self.save(); self.grant(False)

    def test_fifo_and_special_modes_rejected(self):
        fifo = self.root / "fifo"; os.mkfifo(fifo, 0o600)
        self.erl_eval('{error,unsafe_file}=shadow6_sodium:read_secure("' + str(fifo) + '")')
        path = self.root / "request"
        self.erl_eval('{ok,_}=shadow6_sodium:read_secure("' + str(path) + '")')
        for mode in (0o644, 0o4600):
            path.chmod(mode)
            self.erl_eval('{error,unsafe_file}=shadow6_sodium:read_secure("' + str(path) + '")')

    def test_control_identity_bound_to_session(self):
        peer = '#{kind=>client,id=><<"caller">>,allowed=>[<<"agent">>],public=><<0:256>>}'
        message = '#{<<"type">>=><<"access">>,<<"target">>=><<"agent">>,<<"ephemeral">>=>binary:copy(<<"00">>,32),<<"signature">>=>binary:copy(<<"00">>,64)}'
        call = 'shadow6_control:handle_message(self(),' + peer + ',' + message + ',#{},#{})'
        self.erl_eval('true=(try ' + call + ' of _ -> false catch _:_ -> true end)')


if __name__ == "__main__":
    unittest.main()
