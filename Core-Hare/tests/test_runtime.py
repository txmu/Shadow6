import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import unittest

BIN = Path(__file__).resolve().parents[1] / "shadow6-hare"

class RuntimeTests(unittest.TestCase):
    def test_bidirectional_session(self):
        with tempfile.TemporaryDirectory(prefix="shadow6-hare-runtime-") as directory:
            keys = [json.loads(subprocess.check_output([str(BIN), "--gen-key"])) for _ in range(2)]
            reservations = [socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) for _ in range(3)]
            for s in reservations:
                s.bind(("::1", 0))
            agent_port, client_port, target_port = [s.getsockname()[1] for s in reservations]
            for s in reservations[:2]:
                s.close()
            target = reservations[2]
            target.settimeout(3)
            self.addCleanup(target.close)
            processes = []
            try:
                for i, role in enumerate(("agent", "client")):
                    config = {"role": role, "private_key": keys[i]["private_key"],
                              "peer_public_key": keys[1-i]["public_key"],
                              "listen_port": agent_port if i == 0 else client_port,
                              "target_port": target_port if i == 0 else agent_port}
                    path = Path(directory) / (role + ".json")
                    path.write_text(json.dumps(config)); path.chmod(0o600)
                    p = subprocess.Popen([str(BIN), "--config", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    processes.append(p)
                    self.assertTrue(select.select([p.stdout], [], [], 3)[0])
                    self.assertEqual(p.stdout.readline(), b"control ready\n")
                for p in processes:
                    self.assertTrue(select.select([p.stdout], [], [], 3)[0])
                    line = p.stdout.readline()
                    self.assertEqual(line, b"session ready\n", p.stderr.read() if not line else b"")
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    for payload in (b"hello", os.urandom(978), b"", b"after-empty"):
                        client.sendto(payload, ("::1", client_port + 1))
                        data, address = target.recvfrom(2048)
                        self.assertEqual(data, payload)
                        target.sendto(data, address)
                        self.assertEqual(client.recv(2048), payload)
            finally:
                for p in processes:
                    p.terminate()
                    p.communicate(timeout=3)

if __name__ == "__main__":
    unittest.main()
