"""Loopback fault injection for each native datagram Core's three-role path."""
import select
import socket
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from native_configs import generate_commands

ROOT = Path(__file__).resolve().parents[1]


class NativeReliabilityTests(unittest.TestCase):
    def check_loss(self, name):
        binary = ROOT / f"Core-{name.capitalize()}" / f"shadow6-{name}"
        self.assertTrue(binary.is_file(),f"required native binary unavailable: {binary}")
        family = socket.AF_INET6 if name == "hare" else socket.AF_INET
        host = "::1" if name == "hare" else "127.0.0.1"
        with tempfile.TemporaryDirectory(prefix="shadow6-native-loss-") as directory:
            reservations = {}
            with socket.socket(family, socket.SOCK_DGRAM) as target:
                target.bind((host, 0)); target.settimeout(8)
                commands, (_, app_port) = generate_commands(
                    f"shadow6-{name}", binary, Path(directory), target.getsockname()[1], reservations)
                ports = {role: sockets[0].getsockname()[1] for role, sockets in reservations.items()}
                for sock in reservations["broker"]: sock.close()
                relay = socket.socket(family, socket.SOCK_DGRAM)
                relay.bind((host, ports["broker"])); relay.settimeout(.1)
                stop = threading.Event()
                dropped = {"client": False, "agent": False}

                def forward():
                    while not stop.is_set():
                        try: frame, source = relay.recvfrom(2048)
                        except socket.timeout: continue
                        side = "client" if source[1] == ports["client"] else "agent" if source[1] == ports["agent"] else None
                        if side is None: continue
                        data_frame = len(frame) == (1024 if name == "hare" else 1144 if name == "carp" else 0)
                        if name == "idris": data_frame = frame.startswith(b"S6I1")
                        if data_frame and not dropped[side]:
                            dropped[side] = True
                            continue
                        other = "agent" if side == "client" else "client"
                        relay.sendto(frame, (host, ports[other]))

                worker = threading.Thread(target=forward, daemon=True); worker.start()
                processes = []
                try:
                    for role in ("agent", "client"):
                        for sock in reservations[role]: sock.close()
                        process = subprocess.Popen(commands[role], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
                        processes.append(process)
                        self.assertTrue(select.select([process.stdout], [], [], 4)[0])
                        self.assertEqual(process.stdout.readline(), b"control ready\n")
                    for process in processes:
                        self.assertTrue(select.select([process.stdout], [], [], 4)[0])
                        self.assertEqual(process.stdout.readline(), b"session ready\n")
                    with socket.socket(family, socket.SOCK_DGRAM) as application:
                        application.settimeout(8)
                        # A second transaction cannot start until the first
                        # lost ACK has been recovered. It also exposes any
                        # duplicate delivery of the retransmitted first data.
                        for payload in (b"native-loss-recovery",bytes(range(256))*3,b"after-lost-ack"):
                            application.sendto(payload, (host, app_port))
                            data, source = target.recvfrom(2048)
                            self.assertEqual(data, payload)
                            target.sendto(data, source)
                            self.assertEqual(application.recvfrom(2048)[0], payload)
                    self.assertEqual(dropped, {"client": True, "agent": True})
                finally:
                    stop.set(); worker.join(1); relay.close()
                    for sockets in reservations.values():
                        for sock in sockets: sock.close()
                    for process in processes:
                        process.terminate()
                        process.communicate(timeout=3)

    def test_hare(self): self.check_loss("hare")
    def test_carp(self): self.check_loss("carp")
    def test_idris(self): self.check_loss("idris")


if __name__ == "__main__": unittest.main()
