#!/usr/bin/env python3
"""
Unit tests for Shadow6-Auto Orchestrator
"""

import os
import stat
import time
import json
import unittest
import ipaddress
import urllib.request
import asyncio
import tempfile
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
from shadow6_auto import (
    generate_ed25519_keypair, 
    generate_spa_packet, 
    PluginACL, 
    generate_init_script,
    secure_file,
    parse_interval,
    generate_random_sni,
    execute_mtd_rotation,
    format_host_port,
    load_topology_file,
    validate_topology,
)

class TestShadow6Auto(unittest.TestCase):

    def test_ada_rotation_binds_domains_and_cell_transport(self):
        with tempfile.TemporaryDirectory(prefix="shadow6-ada-auto-") as directory:
            topology = {"version": "1.0", "global": {"broker_scheme": "ws", "output_dir": directory}, "nodes": [
                {"name": "broker", "type": "broker", "engines": ["shadow6-ada"], "listen_host": "127.0.0.1"},
                {"name": "agent", "type": "agent", "engines": ["shadow6-ada"], "domain": "vault-vm"},
                {"name": "client", "type": "client", "engines": ["shadow6-ada"], "domain": "work-vm", "allowed_agents": ["agent"]},
            ]}
            asyncio.run(execute_mtd_rotation(topology))
            agent = json.loads(Path(directory, "agent.json").read_text())["agent"]
            client = json.loads(Path(directory, "client.json").read_text())["client"]
            self.assertEqual(agent["transport"], "cell-relay")
            self.assertEqual(client["transport"], "cell-relay")
            self.assertEqual(agent["client_domains"], {"client": "work-vm"})
            self.assertEqual(client["target_domain"], "vault-vm")
            self.assertEqual(agent["domain"], "vault-vm")

    def test_ed25519_keygen(self):
        pub, priv = generate_ed25519_keypair()
        self.assertEqual(len(pub), 64)   # 32 bytes hex
        self.assertEqual(len(priv), 64)  # 32 bytes hex

    def test_spa_packet_generation(self):
        secret = "s" * 32
        ip = "192.0.2.1"
        pkt = generate_spa_packet(secret, ip)
        self.assertEqual(len(pkt), 40) # 8 bytes TS + 32 bytes HMAC

    def test_parse_interval(self):
        self.assertEqual(parse_interval("24h"), 86400)
        self.assertEqual(parse_interval("60m"), 3600)
        self.assertEqual(parse_interval("30s"), 30)
        self.assertEqual(parse_interval("60"), 60)
        with self.assertRaises(ValueError):
            parse_interval("0s")

    def test_ipv6_host_formatting(self):
        self.assertEqual(format_host_port("::1", 4433), "[::1]:4433")
        self.assertEqual(format_host_port("broker.example", 4433), "broker.example:4433")
        with self.assertRaises(ValueError):
            format_host_port("bad..example", 4433)

    def test_topology_loader_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "topology.yaml"
            source.write_text("version: '1.0'\nnodes: []\n", encoding="utf-8")
            link = Path(directory) / "link.yaml"
            link.symlink_to(source)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                load_topology_file(str(link))

    def test_secure_file_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "secret"
            target.write_text("secret", encoding="utf-8")
            link = Path(directory) / "secret-link"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                secure_file(str(link))

    def test_openrc_arguments_are_shell_quoted_as_one_value(self):
        script = generate_init_script(
            "openrc", "s6", "/bin/s6", "/etc/$(touch /tmp/shadow6-injected) config.json"
        )
        assignment = next(line for line in script.splitlines() if line.startswith("command_args="))
        value = shlex.split(assignment.split("=", 1)[1])[0]
        self.assertEqual(shlex.split(value), ["--config", "/etc/$(touch /tmp/shadow6-injected) config.json"])

    def test_generate_random_sni(self):
        sni = generate_random_sni()
        self.assertTrue(sni.endswith(".shadow6.invalid"))
        self.assertTrue(6 <= len(sni) - len(".shadow6.invalid") <= 10)

    def test_plugin_acl_ipv4_and_e_class(self):
        acl = PluginACL(allowed_ips=["192.168.1.0/24", "240.0.0.1"], allowed_domains=[])
        self.assertTrue(acl.is_allowed("192.168.1.15"))
        self.assertTrue(acl.is_allowed("240.0.0.1")) # E-Class allowed
        self.assertFalse(acl.is_allowed("8.8.8.8"))

    def test_plugin_acl_domains(self):
        acl = PluginACL(allowed_ips=[], allowed_domains=["vitalik.eth", "hidden.onion", "ipfs://Qhash"])
        self.assertTrue(acl.is_allowed("vitalik.eth"))
        self.assertTrue(acl.is_allowed("ipfs://Qhash"))
        self.assertFalse(acl.is_allowed("google.com"))

    def test_init_script_generation(self):
        sysd = generate_init_script("systemd", "s6", "/bin/s6", "/etc/s6.json")
        self.assertIn('ExecStart="/bin/s6"', sysd)
        
        openrc = generate_init_script("openrc", "s6", "/bin/s6", "/etc/s6.json")
        self.assertIn("#!/sbin/openrc-run", openrc)

        rcd = generate_init_script("rc.d", "s6", "/usr/local/bin/s6", "/usr/local/etc/s6.json")
        self.assertIn("# REQUIRE: NETWORKING", rcd)
        self.assertIn(": ${s6_s6_enable:=NO}", rcd)

        procd = generate_init_script("procd", "s6", "/usr/bin/s6", "/etc/s6.json")
        self.assertIn("USE_PROCD=1", procd)
        self.assertIn("procd_set_param command", procd)

        launchd = generate_init_script("launchd", "s6", "/opt/s6&bin", "/etc/s6<conf>.json")
        ET.fromstring(launchd)
        self.assertIn("/opt/s6&amp;bin", launchd)
        self.assertIn("/etc/s6&lt;conf&gt;.json", launchd)

        guix = generate_init_script("guixsd", "s6", "/gnu/store/s6", '/etc/a"b\\c.json')
        self.assertIn("shepherd-service", guix)
        self.assertIn('a\\"b\\\\c.json', guix)

    def test_new_init_generators_treat_paths_as_data(self):
        hostile = "/etc/$(touch /tmp/shadow6-init-injected) config.json"
        for system in ("rc.d", "procd"):
            with self.subTest(system=system):
                script = generate_init_script(system, "s6", "/bin/s6", hostile)
                self.assertIn("'", script)
                self.assertIn("$(touch /tmp/shadow6-init-injected)", script)

    def test_init_generator_rejects_unsafe_inputs(self):
        with self.assertRaises(ValueError):
            generate_init_script("launchd", "../bad", "/bin/s6", "/etc/s6.json")
        with self.assertRaises(ValueError):
            generate_init_script("procd", "s6", "relative", "/etc/s6.json")

    def test_file_security(self):
        with tempfile.TemporaryDirectory() as directory:
            test_file = Path(directory) / "test_sec.txt"
            test_file.write_text("test")
            secure_file(test_file)
            self.assertEqual(stat.S_IMODE(test_file.stat().st_mode), 0o600)

    def test_topology_rejects_mixed_core_protocols(self):
        topology = {
            "version": "1.0",
            "global": {"broker_scheme": "ws"},
            "nodes": [
                {"name": "broker", "type": "broker", "advertise_host": "127.0.0.1", "engines": ["shadow6-go"]},
                {"name": "agent", "type": "agent", "engines": ["shadow6-rust"]},
            ],
        }
        with self.assertRaisesRegex(ValueError, "same core engine"):
            validate_topology(topology)

    def test_broker_may_attach_zig_bridge_to_uniform_rust_stack(self):
        topology = {
            "version": "1.0", "global": {"broker_scheme": "ws"},
            "nodes": [
                {"name": "broker", "type": "broker", "advertise_host": "127.0.0.1", "engines": ["shadow6-rust", "shadow6-zig"]},
                {"name": "agent", "type": "agent", "engines": ["shadow6-rust"]},
                {"name": "client", "type": "client", "engines": ["shadow6-rust"], "allowed_agents": ["agent"]},
            ],
        }
        self.assertEqual(validate_topology(topology), topology)

    def test_loopback_staging_deployment_is_tightly_scoped(self):
        topology = {
            "version": "1.0",
            "global": {"broker_scheme": "ws"},
            "nodes": [
                {
                    "name": "broker",
                    "type": "broker",
                    "advertise_host": "127.0.0.1",
                    "ssh_host": "127.0.0.1",
                    "ssh_port": 2222,
                    "known_hosts": "/tmp/known-hosts",
                    "deploy_root": "/tmp/shadow6-stage",
                    "init_system": "none",
                    "engines": ["shadow6-go"],
                }
            ],
        }
        self.assertEqual(validate_topology(topology), topology)
        topology["nodes"][0]["ssh_host"] = "192.0.2.10"
        with self.assertRaisesRegex(ValueError, "loopback"):
            validate_topology(topology)

    def test_engine_specific_config_generation(self):
        for engine, transport in (("shadow6-go", "kcp"), ("shadow6-rust", "quic"), ("shadow6-zig", "enet")):
            with self.subTest(engine=engine), tempfile.TemporaryDirectory() as directory:
                topology = {
                    "version": "1.0",
                    "global": {"broker_scheme": "ws", "output_dir": directory, "mtd_rotation_interval": "60"},
                    "nodes": [
                        {"name": "broker", "type": "broker", "advertise_host": "127.0.0.1", "listen_host": "127.0.0.1", "engines": [engine]},
                        {"name": "agent", "type": "agent", "target_port": 22, "engines": [engine]},
                        {"name": "client", "type": "client", "target_agent": "agent", "engines": [engine]},
                    ],
                }
                asyncio.run(execute_mtd_rotation(topology))
                agent = json.loads((Path(directory) / "agent.json").read_text())
                client = json.loads((Path(directory) / "client.json").read_text())
                self.assertEqual(agent["agent"]["transport"], transport)
                self.assertEqual(client["client"]["transport"], transport)
                if engine != "shadow6-rust":
                    self.assertNotIn("sni", agent["agent"])
                    self.assertNotIn("alpn", agent["agent"])
                else:
                    self.assertTrue(agent["agent"]["sni"].endswith(".shadow6.invalid"))

if __name__ == '__main__':
    unittest.main()
