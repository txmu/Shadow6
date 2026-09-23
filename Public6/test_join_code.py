"""Portable invitation framing and strict profile contracts."""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest

from join_code import decode, install_peer, issue, peer_public, provision, resolve, validate_profile
from virtual_peer import load_config as load_peer


class JoinCodeTests(unittest.TestCase):
    def test_android_wire_vector(self):
        code = "A8YzZAoBuwABAgMEBQYHCAkKCwwNDg8QERITFBUW"
        self.assertEqual(decode(code)["lookup_id"], "29ba43311f908fa99653084749d2078ded0d30252704a1c7f5cd3f082a03b082")
        from join_code import peer_seed
        self.assertEqual(peer_seed(code, "gate").hex(), "947f4e6ac07bd4c002398dddbd985317363a8b80473fd39760ae819ba9c16cb7")

    def test_three_modes_and_separate_keys(self):
        for mode in ("directory", "manual", "ipv4-https"):
            with self.subTest(mode=mode):
                code = issue(mode, "198.51.100.10" if mode == "ipv4-https" else None,
                             443 if mode == "ipv4-https" else None)
                self.assertEqual(len(code), 40)
                info = decode(code)
                self.assertEqual(info["mode"], mode)
                self.assertEqual(len(info["lookup_id"]), 64)
                self.assertNotEqual(peer_public(code, "gate"), peer_public(code, "admission"))
                if mode == "ipv4-https":
                    self.assertEqual((info["https_host"], info["https_port"]), ("198.51.100.10", 443))
        with self.assertRaises(ValueError):
            decode("A" * 40)
        with self.assertRaises(ValueError):
            decode("A" * 39 + "=")
        with self.assertRaises(ValueError):
            issue("ipv4-https", "127.0.0.1", 443)

    def test_manual_profile_is_bounded_owned_and_bound_to_code(self):
        code = issue("manual")
        route = {"core": "go", "transport": "tcp", "gate_host": "198.51.100.10",
                 "gate_public_key": "a" * 64, "gate_port": 5443,
                 "native_broker_public_key": "b" * 64,
                 "native_client_public_key": peer_public(code, "core:go:client"),
                 "native_agent_public_key": peer_public(code, "core:go:agent"),
                 "default_agent_id": "", "default_agent_public_key": ""}
        value = {"schema": "shadow6.public-node-profile.v1", "lookup_id": decode(code)["lookup_id"],
                 "admission_public_key": peer_public(code, "admission"),
                 "tenant": "example", "routes": [route]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "profile.json"
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            self.assertEqual(resolve(code, manual_profile=path, manual_pin="a" * 64), value)
            with self.assertRaises(ValueError):
                resolve(code, manual_profile=path)
            route["gate_public_key"] = "bad"
            with self.assertRaises(ValueError):
                validate_profile(json.dumps(value).encode(), code)
            route["gate_public_key"] = "a" * 64
            value["lookup_id"] = "0" * 64
            with self.assertRaises(ValueError):
                validate_profile(json.dumps(value).encode(), code)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                resolve(code, manual_profile=path, manual_pin="a" * 64)

    def test_provision_and_install_binds_gate_and_broker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            identity = root / "identity"
            identity.write_bytes(os.urandom(32))
            identity.chmod(0o600)
            broker = {"schema": "shadow6.virtual-broker.v1", "listen": {"host": "127.0.0.1", "port": 7443},
                      "identity_key_file": str(identity), "cores": {"go": {"host": "127.0.0.1", "port": 7444}},
                      "tenants": [{"id": "tenant", "public_keys": [base64.b64encode(os.urandom(32)).decode()],
                                   "approval": "approval-required", "max_connections": 4, "bytes_per_second": 4096,
                                   "burst_bytes": 8192}],
                      "routes": [{"tenant": "tenant", "core": "go", "host": "127.0.0.1", "port": 7444}],
                      "approvals": [], "guard": {"required": True}, "gate": {"required": True},
                      "c11relay": {"control_socket": "/run/shadow6/c11relay.sock"},
                      "limits": {"max_frame": 4096, "handshake_seconds": 5, "idle_seconds": 30}}
            broker_path = root / "broker.json"
            broker_path.write_text(json.dumps(broker))
            broker_path.chmod(0o600)
            gate = {"version": 1, "enabled": True, "role": "server", "private_key": os.urandom(32).hex(),
                    "peer_public_keys": [os.urandom(32).hex()], "protocol": ["tcp"],
                    "upstream": "127.0.0.1:7443", "mtd": {"enabled": False, "min_port": 5443}}
            gate_path = root / "gate.json"
            gate_path.write_text(json.dumps(gate))
            gate_path.chmod(0o600)
            bundle = root / "bundle"
            result = provision("ipv4-https", "tenant", broker_path, [f"go={gate_path}"],
                               bundle, "198.51.100.10", "198.51.100.10", 443,
                               ["go=" + "b" * 64], ["go=nas-1:" + "c" * 64])
            code = (bundle / "code.txt").read_text().strip()
            self.assertEqual(len(code), 40)
            profile = json.loads(Path(result["profile_file"]).read_text())
            self.assertEqual(profile["routes"][0]["gate_port"], 5443)
            self.assertEqual(profile["routes"][0]["default_agent_id"], "nas-1")
            self.assertEqual(profile["routes"][0]["native_client_public_key"], peer_public(code, "core:go:client"))
            self.assertTrue((bundle / "native-authorizations.json").is_file())
            updated_broker = json.loads((bundle / "virtual-broker.json").read_text())
            self.assertIn(base64.b64encode(bytes.fromhex(peer_public(code, "admission"))).decode(),
                          updated_broker["tenants"][0]["public_keys"])
            self.assertEqual(len(updated_broker["approvals"]), 2)
            self.assertIn(peer_public(code, "gate"), json.loads((bundle / "gate-go.json").read_text())["peer_public_keys"])
            client = root / "client"
            install_peer(code, profile, "go", "client", client)
            config, _, _, _ = load_peer(client / "virtual-peer.json")
            self.assertEqual(config["identity"], updated_broker["approvals"][0]["client"])
            with self.assertRaises(FileExistsError):
                install_peer(code, profile, "go", "client", client)


if __name__ == "__main__":
    unittest.main()
