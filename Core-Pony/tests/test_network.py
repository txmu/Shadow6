"""Real loopback transport integration; no mocked crypto or sockets."""
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import unittest

BIN = str(Path(__file__).resolve().parents[1] / "shadow6-pony")


def public(seed):
    sodium = ctypes.CDLL(ctypes.util.find_library("sodium"))
    pk, sk = ctypes.create_string_buffer(32), ctypes.create_string_buffer(64)
    assert sodium.crypto_sign_seed_keypair(pk, sk, seed) == 0
    return pk.raw.hex()


class NetworkTests(unittest.TestCase):
    def test_external_addresses_require_explicit_operator_opt_in(self):
        with tempfile.TemporaryDirectory(prefix="shadow6-pony-config-") as directory:
            path = Path(directory) / "external.json"
            config = dict(
                role="client", listen_port=41001, peer_port=41002,
                application_port=41003, private_key=bytes(range(32)).hex(),
                peer_public_key=public(bytes(range(32, 64))),
                bind_host="192.0.2.10", peer_host="198.51.100.20",
                application_host="127.0.0.1", allow_external=False,
            )
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            denied = subprocess.run([BIN, "--check-config", str(path)], timeout=10)
            self.assertNotEqual(denied.returncode, 0)
            config["allow_external"] = True
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            accepted = subprocess.run([BIN, "--check-config", str(path)], timeout=10)
            self.assertEqual(accepted.returncode, 0)

    def test_roundtrip(self):
        sockets, processes = [], []
        try:
            for _ in range(5):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                except PermissionError as exc:
                    self.skipTest("loopback sockets unavailable: %s" % exc)
                sock.bind(("127.0.0.1", 0))
                # CI runners can pause the Pony scheduler during the encrypted
                # UDP round trip; allow retransmission timers to fire without
                # changing the protocol or accepting a missing response.
                sock.settimeout(8)
                sockets.append(sock)
            a, c, app, target_port, _ = [s.getsockname()[1] for s in sockets]
            for sock in sockets[:3]:
                sock.close()
            target, local = sockets[3:]
            seed_a, seed_c = bytes(range(32)), bytes(range(32, 64))
            with tempfile.TemporaryDirectory(prefix="shadow6-pony-") as directory:
                for role, listen, peer, application, seed, pin in (
                    ("agent", a, c, target_port, seed_a, seed_c),
                    ("client", c, a, app, seed_c, seed_a),
                ):
                    path = Path(directory) / (role + ".json")
                    config = dict(role=role, listen_port=listen, peer_port=peer,
                                  application_port=application, private_key=seed.hex(),
                                  peer_public_key=public(pin))
                    path.write_text(json.dumps(config))
                    path.chmod(0o600)
                    checked = subprocess.run([BIN, "--check-config", str(path)],
                                             capture_output=True, timeout=10)
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                    path.chmod(0o644)
                    checked = subprocess.run([BIN, "--check-config", str(path)],
                                             capture_output=True, timeout=10)
                    self.assertNotEqual(checked.returncode, 0)
                    path.chmod(0o600)
                    command = [BIN, "--config", str(path)]
                    if os.environ.get("SHADOW6_PONY_DEBUG") == "1":
                        command.append("--debug")
                    processes.append(subprocess.Popen(command,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE))
                for process in processes:
                    ready, _, _ = select.select([process.stdout], [], [], 8)
                    self.assertTrue(ready, "handshake readiness timeout")
                    self.assertIn(b"ready:", process.stdout.readline())
                for payload in (b"", b"hello", bytes(range(256)), b"x" * 1172):
                    local.sendto(payload, ("127.0.0.1", app))
                    data, address = target.recvfrom(2048)
                    self.assertEqual(data, payload)
                    target.sendto(data, address)
                    try:
                        echoed = local.recvfrom(2048)[0]
                    except TimeoutError as exc:
                        diagnostics = []
                        for process in processes:
                            ready, _, _ = select.select([process.stderr], [], [], 0)
                            if ready:
                                diagnostics.append(process.stderr.read1(4096).decode(errors="replace"))
                        raise AssertionError(f"Pony application response timeout payload={len(payload)} stderr={diagnostics}") from exc
                    self.assertEqual(echoed, payload)
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            for sock in sockets:
                sock.close()

    def test_three_party_broker_relay(self):
        """A and C authenticate end-to-end while B only relays ciphertext."""
        reservations, processes = [], []
        try:
            for _ in range(7):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                reservations.append(sock)
            client_port, broker_client_port, broker_agent_port, agent_port, app_port, target_port, _ = (
                sock.getsockname()[1] for sock in reservations
            )
            for sock in reservations[:5]:
                sock.close()
            reservations[6].close()
            target = reservations[5]
            target.settimeout(8)
            seed_a, seed_b, seed_c = bytes(range(32)), bytes(range(64, 96)), bytes(range(32, 64))
            with tempfile.TemporaryDirectory(prefix="shadow6-pony-broker-") as directory:
                specs = (
                    ("broker", broker_client_port, agent_port, broker_agent_port, seed_b, seed_a),
                    ("agent", agent_port, broker_agent_port, target_port, seed_a, seed_c),
                    ("client", client_port, broker_client_port, app_port, seed_c, seed_a),
                )
                for role, listen, peer, application, seed, pin in specs:
                    path = Path(directory) / f"{role}.json"
                    path.write_text(json.dumps(dict(
                        role=role, listen_port=listen, peer_port=peer,
                        application_port=application, private_key=seed.hex(),
                        peer_public_key=public(pin), bind_host="127.0.0.1",
                        peer_host="127.0.0.1", application_host="127.0.0.1",
                        allow_external=False,
                    )))
                    path.chmod(0o600)
                    command = [BIN, "--config", str(path)]
                    if os.environ.get("SHADOW6_PONY_DEBUG") == "1":
                        command.append("--debug")
                    processes.append(subprocess.Popen(
                        command, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ))
                for process in processes:
                    ready, _, _ = select.select([process.stdout], [], [], 8)
                    self.assertTrue(ready, "three-party readiness timeout")
                    self.assertIn(b"ready:", process.stdout.readline())
                local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                local.settimeout(8)
                local.sendto(b"through-broker", ("127.0.0.1", app_port))
                try:
                    payload, address = target.recvfrom(2048)
                except TimeoutError as exc:
                    diagnostics = [process.stderr.read1(8192).decode(errors="replace") for process in processes]
                    raise AssertionError(f"three-party payload timeout: {diagnostics}") from exc
                self.assertEqual(payload, b"through-broker")
                target.sendto(payload, address)
                self.assertEqual(local.recvfrom(2048)[0], payload)
                local.close()
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            for sock in reservations:
                sock.close()


if __name__ == "__main__":
    unittest.main()
