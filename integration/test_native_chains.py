"""Broker admission/route regressions against compiled native Core processes."""
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_configs import generate_commands

ROOT = Path(__file__).resolve().parents[1]


class NativeBrokerTests(unittest.TestCase):
    def check_broker(self, name):
        engine = "shadow6-" + name
        binary = ROOT / ("Core-" + name.capitalize()) / engine
        if not binary.is_file():
            self.skipTest(f"{engine} binary unavailable; Actions must run this case")
        family = socket.AF_INET6 if name == "hare" else socket.AF_INET
        host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        with tempfile.TemporaryDirectory(prefix="shadow6-broker-negative-") as directory:
            root = Path(directory)
            with socket.socket(family, socket.SOCK_DGRAM) as target:
                target.bind((host, 0))
                commands, _ = generate_commands(engine, binary, root, target.getsockname()[1])
            if name == "hare":
                config = json.loads((root / "broker.config").read_text())
                broker, client, agent = config["listen_port"], config["client_port"], config["target_port"]
                seeds = [bytes.fromhex(json.loads((root / f"{r}.config").read_text())["private_key"]) for r in ("client", "agent")]
            else:
                command = commands["broker"]
                broker, client, agent = map(int, command[3:6] if name == "carp" else (command[4], command[6], command[8]))
                seeds = [(root / f"{r}.config").read_bytes()[:32] for r in ("client", "agent")]
            with socket.socket(family, socket.SOCK_DGRAM) as c, socket.socket(family, socket.SOCK_DGRAM) as a, socket.socket(family, socket.SOCK_DGRAM) as stranger:
                c.bind((host, client)); a.bind((host, agent))
                c.settimeout(.15); a.settimeout(.15)
                with (root / "broker.log").open("w+") as log:
                    process = subprocess.Popen(commands["broker"], stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 3
                        while "broker ready" not in (root / "broker.log").read_text():
                            self.assertIsNone(process.poll())
                            if time.monotonic() >= deadline:
                                self.fail("broker readiness timeout")
                            time.sleep(.01)
                        prefix = b"S6I3" if name == "idris" else b"S6W2"
                        hello = prefix + os.urandom(64 - len(prefix))
                        signed = hello + Ed25519PrivateKey.from_private_bytes(seeds[0]).sign(hello)
                        for rejected in (bytes(len(signed)), signed[:-1]+bytes([signed[-1]^1]), signed+b"x"):
                            c.sendto(rejected, (host, broker))
                            with self.assertRaises(socket.timeout): a.recv(2048)
                        stranger.sendto(signed, (host, broker))
                        with self.assertRaises(socket.timeout): a.recv(2048)
                        c.sendto(signed, (host, broker))
                        self.assertEqual(a.recv(2048), signed)
                        reply_message = bytearray(hello + os.urandom(64))
                        reply_message[len(hello):len(hello) + 4] = prefix
                        reply = bytes(reply_message)
                        reply += Ed25519PrivateKey.from_private_bytes(seeds[1]).sign(reply)
                        a.sendto(reply[:-1]+bytes([reply[-1]^1]), (host, broker))
                        with self.assertRaises(socket.timeout): c.recv(2048)
                        a.sendto(reply, (host, broker))
                        self.assertEqual(c.recv(2048), reply)
                        # No second admission or replayed hello once established.
                        c.sendto(signed, (host, broker))
                        with self.assertRaises(socket.timeout): a.recv(2048)
                    finally:
                        process.terminate()
                        process.wait(timeout=3)

    def test_hare_admission(self): self.check_broker("hare")
    def test_carp_admission(self): self.check_broker("carp")
    def test_idris_admission(self): self.check_broker("idris")


if __name__ == "__main__":
    unittest.main()
