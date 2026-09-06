"""Loopback-only Core-Zig contract and real three-role transport tests."""
import base64
import contextlib
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "Core-Zig/shadow6-zig"


def identity():
    key = Ed25519PrivateKey.generate()
    return key, key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed(domain, *fields):
    return domain.encode() + b"".join(struct.pack("!I", len(x)) + x for x in fields)


class WS:
    def __init__(self, port, key, peer, broker_key, rust_endpoint=False):
        self.rust = False
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.sock.settimeout(10)
        nonce = base64.b64encode(os.urandom(16)).decode()
        path = "/ws?control=rust" if rust_endpoint else "/ws"
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {nonce}\r\n\r\n").encode())
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            header += self.exact(1)
            if len(header) > 8192:
                raise ValueError("oversize HTTP response")
        assert header.startswith(b"HTTP/1.1 101")
        challenge = self.recv()
        domain = "shadow6-rust-control-auth-v1" if self.rust else "shadow6-control-auth-v1"
        self.send({"version": 1, "type": "auth", "peer_id": peer, "signature": base64.b64encode(key.sign(signed(domain, peer.encode(), base64.b64decode(challenge["nonce"])))).decode()})
        challenge = os.urandom(32)
        self.send({"version": 1, "type": "challenge", "nonce": base64.b64encode(challenge).decode()})
        response = self.recv()
        assert response["peer_id"] == "broker"
        broker_key.public_key().verify(base64.b64decode(response["signature"]), signed(domain, b"broker", challenge))

    def exact(self, n):
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n-len(out))
            if not chunk:
                raise EOFError()
            out += chunk
        return out

    def send(self, message):
        opcode = 1
        if self.rust:
            if message["type"] == "auth":
                message = {"id": message["peer_id"], "signature": message["signature"]}
            elif message["type"] == "challenge":
                opcode = 2
                raw = base64.b64decode(message["nonce"])
            else:
                params = dict(message["params"])
                for old, new in (("ip", "ipv6"), ("client_ip", "client_ipv6"), ("client_sig", "client_signature")):
                    if old in params: params[new] = params.pop(old)
                message = {"jsonrpc": "2.0", "id": message["id"], "method": message["method"], "params": params}
        if opcode == 1:
            raw = json.dumps(message).encode()
        mask = os.urandom(4)
        head = bytes((0x80 | opcode, 0x80 | len(raw))) if len(raw) < 126 else bytes((0x80 | opcode, 0xfe)) + struct.pack("!H", len(raw))
        self.sock.sendall(head + mask + bytes(x ^ mask[i % 4] for i, x in enumerate(raw)))

    def recv(self):
        head = self.exact(2)
        n = head[1] & 127
        if n == 126:
            n = struct.unpack("!H", self.exact(2))[0]
        if n == 127:
            n = struct.unpack("!Q", self.exact(8))[0]
        if n > 65536:
            raise ValueError("oversize websocket")
        raw = self.exact(n)
        if head[0] & 15 == 2:
            self.rust = True
            return {"nonce": base64.b64encode(raw).decode()}
        result = json.loads(raw)
        if self.rust and "signature" in result:
            result["peer_id"] = result.pop("id")
        return result


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="shadow6-zig-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.broker_key, self.bpriv, self.bpub = identity()
        self.agent_key, self.apriv, self.apub = identity()
        self.client_key, self.cpriv, self.cpub = identity()
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.broker = {"role": "broker", "broker": {"listen_addr": f"127.0.0.1:{self.port}", "private_key": self.bpriv, "agents": [{"id": "agent", "pubkey": self.apub}], "clients": [{"id": "client", "pubkey": self.cpub, "allowed_agents": ["agent"]}], "stealth_mode": True, "webhook_url": ""}}

    def config(self, name, value):
        path = self.path / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def start(self, binary, config):
        log = (self.path / f"{config.name}-{binary.name}.log").open("w+")
        process = subprocess.Popen([str(binary), "--config", str(config)], stdout=log, stderr=log)
        def cleanup():
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
            log.close()
        self.addCleanup(cleanup)
        return process, log

    def ready(self, process, log, pattern, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            log.seek(0); text = log.read()
            match = re.search(pattern, text)
            if match:
                return match
            if process.poll() is not None:
                self.fail(text)
            time.sleep(.05)
        self.fail(f"Timed out waiting for {pattern}: {text}")

    def test_feature_key_and_l0_contract(self):
        report = json.loads(subprocess.check_output([str(BIN), "--feature-report"]))
        self.assertEqual(report["core"], "shadow6-zig")
        for binary in [ROOT / "Core-Go/shadow6-go", ROOT / "Core-Rust/shadow6-rust"]:
            expected = json.loads(subprocess.check_output([str(binary), "--feature-report"]))
            expected["core"] = "shadow6-zig"
            self.assertEqual(report, expected)
        key = subprocess.check_output([str(BIN), "--gen-key"], text=True)
        private = bytes.fromhex(re.search(r"Private Key \(Hex\):\s*(\w+)", key)[1])
        public = bytes.fromhex(re.search(r"Public Key \(Hex\):\s*(\w+)", key)[1])
        self.assertEqual(Ed25519PrivateKey.from_private_bytes(private[:32]).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), public)
        response = json.loads(subprocess.check_output([str(BIN), "--crosed-request", "absent", "--crosed-trust", "absent"]))
        self.assertEqual(response["status"], "denied")
        self.assertEqual(response["granted_level"], 0)
        self.assertEqual(response["granted_capabilities"], [])

    def test_strict_configuration(self):
        path = self.config("broker.json", self.broker)
        def check():
            return subprocess.run([str(BIN), "--config", str(path), "--check-config"], capture_output=True, timeout=10)
        self.assertEqual(check().returncode, 0)
        for mode in (0o644, 0o400, 0o660):
            path.chmod(mode); self.assertNotEqual(check().returncode, 0)
        path.chmod(0o600)
        raw = path.read_text()
        for bad in ('{"role":"broker","role":"agent"}', raw.replace('"stealth_mode": true', '"stealth_mode": 1'), raw.replace('"role": "broker"', '"role": "broker", "unknown": 2'), raw.replace('"stealth_mode": true', '"stealth_mode": 1.0'), '['*33+'0'+']'*33):
            path.write_text(bad); self.assertNotEqual(check().returncode, 0)
        path.unlink(); target = self.config("target.json", self.broker); path.symlink_to(target)
        self.assertNotEqual(check().returncode, 0)

    def test_control_interoperability(self):
        for binary, rust_endpoint in ((BIN, False), (BIN, True), (ROOT / "Core-Go/shadow6-go", False), (ROOT / "Core-Rust/shadow6-rust", False)):
            with self.subTest(core=binary.name):
                process, log = self.start(binary, self.config(binary.name+".json", self.broker))
                deadline = time.monotonic()+10
                while True:
                    try:
                        agent = WS(self.port, self.agent_key, "agent", self.broker_key, rust_endpoint)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() > deadline: raise
                        time.sleep(.05)
                try:
                    agent.send({"version":1,"type":"request","id":1,"method":"Broker.UpdateIP","params":{"agent_id":"agent","ip":"127.0.0.1"}})
                    self.assertTrue(agent.recv()["result"]["success"])
                finally:
                    agent.sock.close()
                client = WS(self.port, self.client_key, "client", self.broker_key, rust_endpoint)
                try:
                    client.send({"version":1,"type":"request","id":1,"method":"Broker.UpdateIP","params":{"agent_id":"agent","ip":"127.0.0.1"}})
                    self.assertTrue(client.recv()["error"])
                finally:
                    client.sock.close()
                process.terminate(); process.wait(timeout=5)

    def test_enet_three_role_tcp_roundtrip(self):
        self.roundtrip()

    def test_enet_rust_control_dialect(self):
        self.roundtrip("?control=rust")

    def test_native_rust_broker_rejects_enet_grant(self):
        self.roundtrip(broker_binary=ROOT / "Core-Rust/shadow6-rust", reject_grant=True)

    def roundtrip(self, control_suffix="", broker_binary=BIN, reject_grant=False):
        stop = threading.Event()
        echo = socket.socket(); echo.bind(("127.0.0.1", 0)); echo.listen(8); echo.settimeout(.2)
        self.addCleanup(echo.close); self.addCleanup(stop.set)
        def serve():
            while not stop.is_set():
                try: conn, _ = echo.accept()
                except socket.timeout: continue
                except OSError: return
                def copy(conn):
                    with conn:
                        conn.settimeout(5)
                        try:
                            while data := conn.recv(65536): conn.sendall(data)
                        except (OSError, TimeoutError): pass
                threading.Thread(target=copy, args=(conn,), daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        b, bl = self.start(broker_binary, self.config("broker.json", self.broker))
        self.ready(b, bl, "control plane listening|Listening on")
        agent = {"role":"agent","agent":{"id":"agent","broker_addrs":[f"ws://127.0.0.1:{self.port}/ws{control_suffix}"],"broker_pubkey":self.bpub,"private_key":self.apriv,"target_port":echo.getsockname()[1],"auto_close_after":30,"client_pubkeys":{"client":self.cpub},"transport":"enet"}}
        ag, al = self.start(BIN, self.config("agent.json", agent))
        time.sleep(.5)
        client = {"role":"client","client":{"id":"client","broker_addrs":[f"ws://127.0.0.1:{self.port}/ws{control_suffix}"],"broker_pubkey":self.bpub,"private_key":self.cpriv,"target_agent":"agent","agent_pubkey":self.apub,"transport":"enet"}}
        cl, log = self.start(BIN, self.config("client.json", client))
        if reject_grant:
            self.assertNotEqual(cl.wait(timeout=15), 0)
            log.seek(0)
            self.assertIn("invalid QUIC access response", log.read())
            return
        match = self.ready(cl, log, r"local proxy listening on 127\.0\.0\.1:(\d+)")
        port = int(match[1])
        for size in (1, 1144, 70000):
            with socket.create_connection(("127.0.0.1",port),timeout=10) as sock:
                sock.settimeout(10); data = os.urandom(size); sock.sendall(data)
                received = b""
                while len(received) < size:
                    chunk = sock.recv(size-len(received))
                    if not chunk: break
                    received += chunk
                self.assertEqual(received, data)
                sock.shutdown(socket.SHUT_WR)
                self.assertEqual(sock.recv(1), b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
