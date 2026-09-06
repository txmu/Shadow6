"""Offline, loopback-only tests for the standalone Ada stack and signed policy."""
import base64
import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "Core-Ada/shadow6-ada"
L5 = ROOT / "Core-Ada/shadow6-ada-crosed"
sys.path.insert(0, str(ROOT / "Crosed"))
from crosedctl import build_request


def identity():
    key = Ed25519PrivateKey.generate()
    return (key, key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption()).hex(),
            key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class WS:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.settimeout(5)
        nonce = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {nonce}\r\n\r\n").encode())
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            header += self.exact(1)
            if len(header) > 8192:
                raise ValueError("oversize header")
        expected = base64.b64encode(hashlib.sha1((nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert expected in header and header.startswith(b"HTTP/1.1 101")

    def exact(self, n):
        out = b""
        while len(out) < n:
            block = self.sock.recv(n - len(out))
            if not block:
                raise EOFError
            out += block
        return out

    def send(self, obj):
        self.raw(json.dumps(obj).encode())

    def raw(self, raw, opcode=1):
        mask = os.urandom(4)
        head = bytes([0x80 | opcode, 0x80 | len(raw)]) if len(raw) < 126 else bytes([0x80 | opcode, 0xfe]) + struct.pack("!H", len(raw))
        self.sock.sendall(head + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(raw)))

    def recv(self):
        h = self.exact(2)
        n = h[1] & 127
        if n == 126:
            n = struct.unpack("!H", self.exact(2))[0]
        assert n != 127 and h[0] == 0x81
        return json.loads(self.exact(n))

    def auth(self, key, peer, broker_key):
        challenge = self.recv()["params"]["nonce"]
        own = os.urandom(32).hex()
        signed = f"shadow6-ada-control-v1\n{peer}\n{challenge}".encode()
        self.send({"jsonrpc": "2.0", "id": 1, "method": "Auth.Response", "params": {
            "id": peer, "nonce": own, "signature": key.sign(signed).hex()}})
        result = self.recv()
        broker_key.public_key().verify(bytes.fromhex(result["result"]["signature"]),
                                       f"shadow6-ada-control-v1\nbroker\n{own}".encode())


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="shadow6-ada-", dir="/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.env = os.environ.copy()
        self.bkey, self.bpriv, self.bpub = identity()
        self.akey, self.apriv, self.apub = identity()
        self.ckey, self.cpriv, self.cpub = identity()
        self.port = free_port()
        self.broker = {"role": "broker", "broker": {"listen_addr": f"127.0.0.1:{self.port}",
            "private_key": self.bpriv, "agents": [{"id": "agent", "pubkey": self.apub}],
            "clients": [{"id": "client", "pubkey": self.cpub, "allowed_agents": ["agent"]}],
            "webhook_url": "", "stealth_mode": True}}

    def config(self, name, value):
        path = self.path / name
        path.write_text(json.dumps(value, ensure_ascii=False))
        path.chmod(0o600)
        return path

    def run_core(self, *args, binary=BIN):
        return subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=15)

    def start(self, config):
        log = (self.path / (config.name + ".log")).open("w+")
        process = subprocess.Popen([str(BIN), "--config", str(config)], stdout=log, stderr=log, env=self.env)
        def cleanup():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            log.close()
        self.addCleanup(cleanup)
        return process, log

    def wait_log(self, process, log, pattern):
        deadline = time.monotonic() + 10
        text = ""
        while time.monotonic() < deadline:
            log.seek(0)
            text = log.read()
            match = re.search(pattern, text)
            if match:
                return match
            if process.poll() is not None:
                self.fail(f"core exited {process.returncode}: {text}")
            time.sleep(.03)
        self.fail(f"timeout: {text}")

    def start_broker(self):
        process, log = self.start(self.config("broker.json", self.broker))
        self.wait_log(process, log, "control listening")
        return process

    def test_features_keys_and_config_boundaries(self):
        report = json.loads(self.run_core("--feature-report").stdout)
        self.assertEqual(report["core"], "shadow6-ada")
        self.assertEqual(report["crosed_max_level"], 0)
        self.assertFalse(report["qubes_isolation"])
        self.assertEqual(report["cell_size"], 512)
        self.assertRegex(self.run_core("--gen-key").stdout, r"Private Key \(Hex\): [a-f0-9]{128}")
        p = self.config("check.json", self.broker)
        self.assertEqual(self.run_core("--config", p, "--check-config").returncode, 0)
        for raw in ['{"role":"broker","role":"client"}', p.read_text().replace('"stealth_mode": true', '"stealth_mode": 1.0'),
                    p.read_text().replace('"role":', '"unknown":0,"role":'), '{"role":"broker"} trailing',
                    '{"role":"\\ud800"}', '{"role":"e\\u0301"}']:
            p.write_text(raw)
            self.assertNotEqual(self.run_core("--config", p, "--check-config").returncode, 0)
        p = self.config("safe.json", self.broker)
        p.chmod(0o644)
        self.assertNotEqual(self.run_core("--config", p, "--check-config").returncode, 0)
        p.chmod(0o600)
        alias = self.path / "alias.json"
        alias.symlink_to(p)
        self.assertNotEqual(self.run_core("--config", alias, "--check-config").returncode, 0)

    def test_authenticated_jsonrpc_and_malformed_peer_isolation(self):
        broker = self.start_broker()
        with contextlib.closing(WS(self.port).sock):
            pass
        ws = WS(self.port)
        self.addCleanup(ws.sock.close)
        ws.auth(self.ckey, "client", self.bkey)
        ws.send({"jsonrpc": "2.0", "id": 3, "method": "Core.Features", "params": {}})
        self.assertEqual(ws.recv()["result"]["core"], "shadow6-ada")
        ws.send({"jsonrpc": "2.0", "id": 4, "method": "unknown", "params": {}})
        self.assertEqual(ws.recv()["error"]["code"], -32601)
        ws.raw(b'{"jsonrpc":"2.0","id":5,"id":6,"method":"Core.Features","params":{}}')
        with self.assertRaises((EOFError, ConnectionResetError)):
            ws.recv()
        self.assertIsNone(broker.poll())
        good = WS(self.port)
        self.addCleanup(good.sock.close)
        good.auth(self.ckey, "client", self.bkey)

    def test_crosed_levels_domains_unicode_tamper_and_persistent_replay(self):
        key, _, pub = identity()
        caps = ["observe.version", "policy.request", "transport.application", "identity.assert", "core.lifecycle"]
        trust = self.config("trust.json", {"domain": "vault-vm", "mods": {"mod": {"pubkey": pub, "max_level": 5,
            "capabilities": caps, "source_domain": "work-vm", "allowed_domains": ["vault-vm"]}}})
        for level in range(1, 6):
            request = build_request("mod", level, caps[:level], {"text": "跨域 UTF-8", "n": 9007199254740991}, key, "work-vm", "vault-vm")
            path = self.config("request.json", request)
            args = ("--crosed-request", path, "--crosed-trust", trust)
            response = self.run_core(*args, binary=L5)
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertEqual(json.loads(response.stdout)["granted_level"], level)
            self.assertEqual(json.loads(self.run_core(*args, binary=L5).stdout)["status"], "denied")
            self.assertEqual(json.loads(self.run_core(*args).stdout)["status"], "denied")
        for source, target in [("other-vm", "vault-vm"), ("work-vm", "other-vm"), ("work-vm", "work-vm")]:
            request = build_request("mod", 1, caps[:1], {}, key, source, target)
            path = self.config("request.json", request)
            response = self.run_core("--crosed-request", path, "--crosed-trust", trust, binary=L5)
            self.assertEqual(json.loads(response.stdout)["status"], "denied")
        request["signature"] = "00" * 64
        path = self.config("request.json", request)
        self.assertNotEqual(self.run_core("--crosed-request", path, "--crosed-trust", trust, binary=L5).returncode, 0)

    def tls_config(self, correct_name=True):
        key = Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Ada loopback test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(
                    "127.0.0.1" if correct_name else "127.0.0.2"))]), critical=False).sign(key, None))
        cp, kp = self.path / "tls-cert.pem", self.path / "tls-key.pem"
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        kp.chmod(0o600)
        self.broker["broker"].update(tls_cert=str(cp), tls_key=str(kp))
        self.env["SSL_CERT_FILE"] = str(cp)

    def test_tls_wrong_hostname_fails_closed(self):
        self.tls_config(correct_name=False)
        broker = self.start_broker()
        cfg = self.config("bad-tls.json", {"role": "client", "client": {
            "id": "client", "private_key": self.cpriv, "broker_pubkey": self.bpub,
            "broker_addrs": [f"wss://127.0.0.1:{self.port}/ws"], "transport": "cell-relay",
            "target_agent": "agent", "agent_pubkey": self.apub, "on_success": ""}})
        process, _ = self.start(cfg)
        self.assertNotEqual(process.wait(timeout=10), 0)
        self.assertIsNone(broker.poll())

    def test_real_three_role_cell_relay(self):
        self.three_role(False)

    def test_tls_three_role_cell_relay(self):
        self.tls_config()
        self.three_role(True)

    def three_role(self, tls):
        echo = socket.socket()
        echo.bind(("127.0.0.1", 0))
        echo.listen(1)
        echo.settimeout(15)
        self.addCleanup(echo.close)
        errors = []
        def serve():
            try:
                with echo.accept()[0] as peer:
                    peer.settimeout(15)
                    while True:
                        block = peer.recv(16384)
                        if not block:
                            break
                        peer.sendall(block)
            except (OSError, TimeoutError) as exc:
                errors.append(exc)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.broker["broker"]["agents"][0]["domain"] = "vault-vm"
        self.broker["broker"]["clients"][0]["domain"] = "work-vm"
        self.start_broker()
        common = {"broker_addrs": [f"{'wss' if tls else 'ws'}://127.0.0.1:{self.port}/ws"], "broker_pubkey": self.bpub,
                  "allow_local_discovery": False, "transport": "cell-relay"}
        agent = {"role": "agent", "agent": dict(common, id="agent", private_key=self.apriv,
            target_port=echo.getsockname()[1], auto_close_after=30, client_pubkeys={"client": self.cpub},
            domain="vault-vm", client_domains={"client": "work-vm"})}
        ap, al = self.start(self.config("agent.json", agent))
        time.sleep(.2)
        client = {"role": "client", "client": dict(common, id="client", private_key=self.cpriv,
            target_agent="agent", agent_pubkey=self.apub, on_success="", domain="work-vm", target_domain="vault-vm")}
        cp, cl = self.start(self.config("client.json", client))
        match = self.wait_log(cp, cl, r"proxy listening on 127\.0\.0\.1:(\d+)")
        with socket.create_connection(("127.0.0.1", int(match[1])), timeout=10) as sock:
            sock.settimeout(10)
            for size in (1, 475, 476, 477, 512, 16384, 48000):
                payload = os.urandom(size)
                sock.sendall(payload)
                result = b""
                while len(result) < size:
                    chunk = sock.recv(size - len(result))
                    self.assertTrue(chunk)
                    result += chunk
                self.assertEqual(result, payload)
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(sock.recv(1), b"")
        thread.join(3)
        self.assertFalse(errors)
        self.assertEqual(cp.wait(timeout=5), 0)
        self.assertIsNone(ap.poll())


if __name__ == "__main__":
    unittest.main(verbosity=2)
