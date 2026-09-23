"""Loopback contracts for both Virtual Peer roles and native carriers."""
import asyncio
import base64
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from virtual_broker import Broker, Config, Tenant
from virtual_peer import VirtualPeer, load_config


class VirtualPeerTests(unittest.TestCase):
    def fixture(self, role="client", transport="tcp", core="go"):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        seed = os.urandom(32)
        secret = root / "key"
        secret.write_bytes(seed)
        secret.chmod(0o600)
        document = {"schema": "shadow6.virtual-peer.v1", "role": role, "core": core,
                    "tenant": "tenant", "identity": role + "-1", "private_key_file": str(secret),
                    "transport": transport, "listen": {"host": "127.0.0.1", "port": 7441},
                    "gate": {"host": "127.0.0.1", "port": 7442},
                    "max_connections": 4, "idle_seconds": 5}
        path = root / "peer.json"
        path.write_text(json.dumps(document))
        path.chmod(0o600)
        return path, document

    def broker(self, peer, endpoint):
        public = base64.b64decode(peer.public)
        tenant = Tenant("tenant", (public,), "default-approved", 4, 1024 * 1024, 1024 * 1024)
        cfg = Config("127.0.0.1", 7443, os.urandom(32), {peer.config["core"]: endpoint},
                     {"tenant": tenant}, {("tenant", peer.config["core"]): endpoint},
                     True, True, "/run/shadow6/c11relay.sock", frozenset(), 4096, 5, 5)
        return Broker(cfg)

    def test_strict_config_and_key(self):
        path, document = self.fixture()
        config, listen, gate, key = load_config(path)
        self.assertEqual((config["role"], listen, gate), ("client", ("127.0.0.1", 7441), ("127.0.0.1", 7442)))
        self.assertIsInstance(key, Ed25519PrivateKey)
        document["extra"] = True
        path.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            load_config(path)
        del document["extra"]
        document["gate"]["host"] = "0.0.0.0"
        path.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            load_config(path)
        document["gate"]["host"] = "127.0.0.1"
        path.write_text(json.dumps(document))
        Path(document["private_key_file"]).chmod(0o644)
        with self.assertRaises(ValueError):
            load_config(path)

    def test_tcp_admission_for_client_and_agent(self):
        async def exercise(role):
            path, _ = self.fixture(role=role)
            config, listen, gate, key = load_config(path)
            peer = VirtualPeer(config, listen, gate, key)

            async def echo(reader, writer):
                writer.write(await reader.readexactly(4))
                await writer.drain()
                writer.close()

            upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
            target = ("127.0.0.1", upstream.sockets[0].getsockname()[1])
            broker = self.broker(peer, target)
            ingress = await asyncio.start_server(broker.handle, "127.0.0.1", 0)
            peer.gate = ("127.0.0.1", ingress.sockets[0].getsockname()[1])
            front = await asyncio.start_server(peer.handle_tcp, "127.0.0.1", 0)
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", front.sockets[0].getsockname()[1])
                writer.write(b"ping")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(4), 3), b"ping")
                writer.close()
                await writer.wait_closed()
            finally:
                for server in (front, ingress, upstream):
                    server.close()
                    await server.wait_closed()

        for role in ("client", "agent"):
            with self.subTest(role=role):
                asyncio.run(exercise(role))

    def test_fresh_admission_and_udp_frame(self):
        path, _ = self.fixture(role="agent", transport="udp", core="hare")
        config, listen, gate, key = load_config(path)
        peer = VirtualPeer(config, listen, gate, key)
        broker = self.broker(peer, ("127.0.0.1", 7444))
        first, second = peer.admission(), peer.admission()
        self.assertNotEqual(first, second)
        self.assertEqual(broker.admit(first)[0].tenant_id, "tenant")
        self.assertEqual(broker.admit(second)[0].tenant_id, "tenant")
        with self.assertRaises(PermissionError):
            broker.admit(first)

    def test_gate_virtual_broker_tcp_chain(self):
        binary = Path(__file__).resolve().parents[1] / "Gate/shadow6-gate"
        if sys.platform != "linux" or not binary.is_file():
            self.skipTest("built Linux Gate binary is unavailable")

        async def exercise():
            path, _ = self.fixture()
            config, listen, gate, key = load_config(path)
            peer = VirtualPeer(config, listen, gate, key)

            async def echo(reader, writer):
                writer.write(await reader.readexactly(4))
                await writer.drain()
                writer.close()

            upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
            target = ("127.0.0.1", upstream.sockets[0].getsockname()[1])
            broker = self.broker(peer, target)
            ingress = await asyncio.start_server(broker.handle, "127.0.0.1", 0)
            broker_port = ingress.sockets[0].getsockname()[1]

            def free_port():
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    return sock.getsockname()[1]

            server_port, client_port = free_port(), free_port()
            server_key, client_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
            public = lambda item: item.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            shared = {"version": 1, "enabled": True, "listen_host": "127.0.0.1",
                      "upstreams": [], "remote_hosts": [], "load_balance": "round_robin",
                      "protocol": ["tcp"], "open_mode": "unconditional", "allowed_cidrs": [], "windows": [],
                      "mtd": {"enabled": False, "period_seconds": 300, "min_port": server_port,
                              "max_port": server_port + 1, "grace_seconds": 15},
                      "limits": {"max_connections": 32, "max_frame_bytes": 65507, "idle_seconds": 30}}
            gate_paths = []
            processes = []
            front = None
            try:
                for role, private, peer_public, local, remote, upstream_address in (
                    ("server", server_key, public(client_key), server_port, "", f"127.0.0.1:{broker_port}"),
                    ("client", client_key, public(server_key), client_port, "127.0.0.1", "127.0.0.1:4433"),
                ):
                    gate_config = dict(shared, role=role, listen_port=local, remote_host=remote,
                                       upstream=upstream_address,
                                       private_key=private.private_bytes_raw().hex(), peer_public_keys=[peer_public])
                    config_path = path.parent / f"gate-{role}.json"
                    config_path.write_text(json.dumps(gate_config))
                    config_path.chmod(0o600)
                    gate_paths.append(config_path)
                    checked = subprocess.run([str(binary), "--config", str(config_path), "--check-config"],
                                             capture_output=True, timeout=5)
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                for config_path in gate_paths:
                    processes.append(subprocess.Popen([str(binary), "--config", str(config_path)],
                                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                peer.gate = ("127.0.0.1", client_port)
                front = await asyncio.start_server(peer.handle_tcp, "127.0.0.1", 0)
                await asyncio.sleep(0.15)
                reader, writer = await asyncio.open_connection("127.0.0.1", front.sockets[0].getsockname()[1])
                writer.write(b"ping")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(4), 5), b"ping")
                writer.close()
                await writer.wait_closed()
            finally:
                if front is not None:
                    front.close()
                    await front.wait_closed()
                ingress.close()
                upstream.close()
                await ingress.wait_closed()
                await upstream.wait_closed()
                for process in processes:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
