"""Core-Nim actual binary, cross-language Crosed and loopback WebRTC tests."""
import json
import os
import re
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "Core-Nim/shadow6-nim"
sys.path.insert(0, str(ROOT / "Crosed"))
from crosedctl import build_request
from feature_contract import validate_feature_report
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="shadow6-nim-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        path.chmod(0o600)
        return path

    def key(self):
        return json.loads(subprocess.check_output([BIN,"--gen-key"]))

    def test_report_and_owner_checks(self):
        validate_feature_report(json.loads(subprocess.check_output([BIN,"--feature-report"])), "shadow6-nim")
        path = self.write("invalid.json", {})
        path.chmod(0o644)
        self.assertNotEqual(subprocess.run([BIN,"--config",path,"--check-config"], capture_output=True).returncode, 0)
        path.chmod(0o600)
        link = self.root / "link"
        link.symlink_to(path)
        self.assertNotEqual(subprocess.run([BIN,"--config",link,"--check-config"], capture_output=True).returncode, 0)

    def test_crosed_l5_python_signatures_and_replay(self):
        variant = ROOT / "Core-Nim/shadow6-nim-crosed"
        self.assertTrue(variant.is_file(), "build nim-crosed-variant before this test")
        key = Ed25519PrivateKey.generate()
        trust = self.write("trust.json", {"mods":{"test-mod":{
            "pubkey":key.public_key().public_bytes_raw().hex(), "max_level":5,
            "capabilities":["observe.version","transport.application"], "allowed_domains":["vault"],
            "source_domain":"work"}}, "domain":"vault"})
        for level in range(1,6):
            cap = "observe.version" if level < 3 else "transport.application"
            request = build_request("test-mod",level,[cap],{"unicode":"你好"},key,"work","vault")
            path = self.write("request.json",request)
            args = [variant,"--crosed-request",path,"--crosed-trust",trust]
            report = json.loads(subprocess.check_output(args))
            self.assertEqual(report["granted_level"],level)
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
        request["target_domain"] = "work"
        path = self.write("request.json",request)
        self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)

    def start(self, cfg):
        path = self.write(cfg["role"]+".json",cfg)
        proc = subprocess.Popen([BIN,"--config",path],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        def cleanup():
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            proc.stdout.close()
        self.addCleanup(cleanup)
        return proc

    def line(self, proc, pattern, timeout=30):
        end = time.monotonic()+timeout
        data = b""
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ)
            while time.monotonic() < end:
                if selector.select(0.1):
                    chunk = os.read(proc.stdout.fileno(),65536)
                    if not chunk: break
                    data += chunk
                    found = re.search(pattern,data.decode(errors="replace"))
                    if found: return found
        self.fail(f"expected {pattern}: {data.decode(errors='replace')}")

    def test_actual_webrtc_loopback_relay(self):
        keys = {role:self.key() for role in ("broker","agent","client")}
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1",0)); port = reserve.getsockname()[1]
        listener = socket.socket()
        listener.bind(("127.0.0.1",0)); listener.listen(1); listener.settimeout(30)
        self.addCleanup(listener.close)
        def echo():
            try:
                conn,_ = listener.accept()
                with conn:
                    conn.settimeout(20)
                    while data := conn.recv(16384): conn.sendall(data)
            except OSError: pass
        worker = threading.Thread(target=echo,daemon=True); worker.start()
        broker = self.start({"role":"broker","broker":{
            "listen_addr":f"127.0.0.1:{port}","private_key":keys["broker"]["private_key"],
            "agents":[{"id":"agent","pubkey":keys["agent"]["public_key"]}],
            "clients":[{"id":"client","pubkey":keys["client"]["public_key"],"allowed_agents":["agent"]}]}})
        self.line(broker,"Broker ready")
        common = {"broker_addrs":[f"ws://127.0.0.1:{port}/ws"],
                  "broker_pubkey":keys["broker"]["public_key"],"transport":"webrtc"}
        agent = self.start({"role":"agent","agent":{**common,"id":"agent",
            "private_key":keys["agent"]["private_key"],"target_port":listener.getsockname()[1],
            "client_pubkeys":{"client":keys["client"]["public_key"]},"auto_close_after":60}})
        self.line(agent,"Control authenticated")
        client = self.start({"role":"client","client":{**common,"id":"client",
            "private_key":keys["client"]["private_key"],"target_agent":"agent",
            "agent_pubkey":keys["agent"]["public_key"]}})
        proxy = int(self.line(client,r"Local proxy listening on 127\.0\.0\.1:(\d+)").group(1))
        payload = bytes(range(256))*512
        with socket.create_connection(("127.0.0.1",proxy),timeout=20) as conn:
            conn.sendall(payload)
            received = b""
            while len(received) < len(payload):
                part = conn.recv(16384)
                self.assertTrue(part)
                received += part
            self.assertEqual(received,payload)
        worker.join(timeout=2)

if __name__ == "__main__": unittest.main()
