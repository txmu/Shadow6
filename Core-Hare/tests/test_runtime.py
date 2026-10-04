import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time
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

    def test_seqpacket_attachment_round_trip_and_eof_drain(self):
        with tempfile.TemporaryDirectory(prefix="shadow6-hare-flow-") as directory:
            keys = [json.loads(subprocess.check_output([str(BIN), "--gen-key"])) for _ in range(2)]
            reservations = [socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) for _ in range(3)]
            for sock in reservations:
                sock.bind(("::1", 0))
            agent_port, client_port, target_port = [sock.getsockname()[1] for sock in reservations]
            for sock in reservations[:2]:
                sock.close()
            target = reservations[2]
            target.settimeout(3)
            self.addCleanup(target.close)
            flow, child_flow = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            flow.settimeout(3)
            self.addCleanup(flow.close)
            processes = []

            def next_line(process, deadline):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    return None
                return process.stdout.readline()

            def wait_line(process, expected, seconds):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    line = next_line(process, deadline)
                    if line is None:
                        return False
                    if not line:
                        self.fail("Hare exited before readiness: " + process.stderr.read().decode(errors="replace"))
                    if line == expected:
                        return True
                return False

            try:
                for i, role in enumerate(("agent", "client")):
                    config = {"role": role, "private_key": keys[i]["private_key"],
                              "peer_public_key": keys[1-i]["public_key"],
                              "listen_port": agent_port if i == 0 else client_port,
                              "target_port": target_port if i == 0 else agent_port}
                    path = Path(directory) / (role + ".json")
                    path.write_text(json.dumps(config)); path.chmod(0o600)
                    env = os.environ.copy()
                    kwargs = {}
                    if role == "client":
                        env["SHADOW6_APP_FLOW_FD"] = str(child_flow.fileno())
                        kwargs["pass_fds"] = (child_flow.fileno(),)
                    process = subprocess.Popen([str(BIN), "--config", str(path)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, **kwargs)
                    processes.append(process)
                    child_flow.close() if role == "client" else None
                    if not wait_line(process, b"control ready\n", 8):
                        self.fail("Hare readiness deadline expired")
                # Wait until both native roles finish their authenticated exchange.
                for process in processes:
                    if not wait_line(process, b"session ready\n", 8):
                        self.fail("Hare session readiness deadline expired")
                for payload in (b"attachment-round-trip", os.urandom(978)):
                    flow.send(payload)
                    data, address = target.recvfrom(2048)
                    self.assertEqual(data, payload)
                    target.sendto(data, address)
                    self.assertEqual(flow.recv(979), payload)
                flow.send(b"")
                client = processes[1]
                self.assertEqual(client.wait(timeout=5), 0,
                    client.stderr.read().decode(errors="replace"))
            finally:
                child_flow.close()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                    process.communicate(timeout=3)

if __name__ == "__main__":
    unittest.main()
