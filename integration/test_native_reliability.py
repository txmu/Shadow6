"""Loopback fault injection for each native datagram Core's three-role path."""
import os
import signal
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
                reordered = {"held": None, "done": False}

                def forward():
                    while not stop.is_set():
                        try: frame, source = relay.recvfrom(2048)
                        except socket.timeout: continue
                        side = "client" if source[1] == ports["client"] else "agent" if source[1] == ports["agent"] else None
                        if side is None: continue
                        data_frame = len(frame) == (1024 if name == "hare" else 1144 if name == "carp" else 0)
                        if name == "idris": data_frame = frame.startswith(b"S6I2")
                        if data_frame and side == "client" and not reordered["done"]:
                            if reordered["held"] is None:
                                reordered["held"] = frame
                                continue
                            # Send sequence two first, then lose sequence one.
                            relay.sendto(frame, (host, ports["agent"]))
                            reordered["held"] = None
                            reordered["done"] = True
                            dropped["client"] = True
                            continue
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
                        process = subprocess.Popen(commands[role], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
                        processes.append(process)
                        self.assertTrue(select.select([process.stdout], [], [], 4)[0])
                        self.assertEqual(process.stdout.readline(), b"control ready\n")
                    for process in processes:
                        self.assertTrue(select.select([process.stdout], [], [], 4)[0])
                        self.assertEqual(process.stdout.readline(), b"session ready\n")
                    with socket.socket(family, socket.SOCK_DGRAM) as application:
                        application.settimeout(8)
                        # Multiple transactions may overlap in the transport
                        # window. The relay reverses the first two frames and
                        # drops sequence one plus the first ACK from the agent.
                        payloads = (b"native-loss-recovery", bytes(range(256))*3,
                                    b"after-lost-ack", b"window-four", b"window-five")
                        for payload in payloads:
                            application.sendto(payload, (host, app_port))
                        observed = []
                        for _ in payloads:
                            data, source = target.recvfrom(2048)
                            observed.append((data, source))
                        self.assertEqual([data for data, _ in observed], list(payloads))
                        for data, source in observed:
                            target.sendto(data, source)
                        self.assertEqual([application.recvfrom(2048)[0] for _ in payloads], list(payloads))
                        application.settimeout(.5)
                        with self.assertRaises(socket.timeout):
                            application.recvfrom(2048)
                    self.assertEqual(dropped, {"client": True, "agent": True})
                    self.assertTrue(reordered["done"])
                finally:
                    stop.set(); worker.join(1); relay.close()
                    for sockets in reservations.values():
                        for sock in sockets: sock.close()
                    for process in processes:
                        # Idris/Chez launchers may leave a child holding pipes.
                        # Signal only the isolated process group created above.
                        try: os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError: pass
                        try: process.communicate(timeout=3)
                        except subprocess.TimeoutExpired:
                            try: os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError: pass
                            process.communicate(timeout=3)

    def test_hare(self): self.check_loss("hare")
    def test_carp(self): self.check_loss("carp")
    def test_idris(self): self.check_loss("idris")


if __name__ == "__main__": unittest.main()
