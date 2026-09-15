"""Real Pony listener tests driven by independent, signed UDP tenants.

The driver uses the native protocol library for credentials/AEAD, and real
loopback sockets against the compiled actor runtime. No mocked network state.
"""
import ctypes as C
import hashlib
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time
import unittest

from test_crypto import SessionTests, buf

BIN = str(Path(__file__).resolve().parents[1] / "shadow6-pony")


class Peer:
    def __init__(self, lib, seed, agent_pk, endpoint):
        self.lib = lib
        self.seed, self.pin = buf(seed), agent_pk
        self.keys, self.state, self.hello = buf(96), buf(236), buf(140)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.25)
        self.endpoint = endpoint
        if lib.s6p_start(self.seed, 32, self.pin, 32, self.state, 236,
                         self.hello, 140, int(time.time())) != 0:
            raise AssertionError("client hello failed")

    def connect(self, timeout=5):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            self.sock.sendto(bytes(self.hello), self.endpoint)
            try:
                response, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            if len(response) != 172:
                continue
            attempt = buf(bytes(self.state))
            if self.lib.s6p_finish(attempt, 236, buf(response), len(response),
                                   self.keys, 96, int(time.time())) == 0:
                break
        else:
            raise TimeoutError("signed tenant handshake timed out")
        while time.monotonic() < until:
            self.send(b"", 1, 0)
            try:
                kind, seq, _ = self.receive()
                if (kind, seq) == (1, 1):
                    return
            except socket.timeout:
                pass
        raise TimeoutError("tenant key confirmation timed out")

    def seal(self, payload, seq, kind=2):
        frame = buf(1200)
        frame[12:12 + len(payload)] = payload
        if self.lib.s6p_seal(frame, 1200, len(payload) + 12, self.keys, 96, seq, kind) != 0:
            raise AssertionError("seal failed")
        return bytes(frame[:28 + len(payload)])

    def send(self, payload, seq, kind=2):
        self.sock.sendto(self.seal(payload, seq, kind), self.endpoint)

    def receive(self):
        until = time.monotonic() + 3
        while time.monotonic() < until:
            data, address = self.sock.recvfrom(2048)
            if address != self.endpoint:
                continue
            packet = buf(data)
            if self.lib.s6p_open(packet, len(packet), self.keys, 96) == 0:
                return packet[3], int.from_bytes(data[4:12], "big"), bytes(packet[12:-16])
        raise TimeoutError("authenticated response timed out")

    def data(self):
        until = time.monotonic() + 5
        while time.monotonic() < until:
            try:
                kind, seq, payload = self.receive()
                if kind == 2:
                    self.send(b"", seq, 3)
                    return payload
            except socket.timeout:
                pass
        raise TimeoutError("application response timed out")


class TenantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse just the compiler harness, not its unittest assertions.
        SessionTests.setUpClass()
        cls.lib = SessionTests.lib
        cls.addClassCleanup(SessionTests.doClassCleanups)

    def _listener(self, count, broker=False):
        directory = tempfile.TemporaryDirectory(prefix="shadow6-pony-tenants-")
        self.addCleanup(directory.cleanup)
        seeds = [hashlib.sha256(f"tenant-{i}".encode()).digest() for i in range(count)]
        seed_a = hashlib.sha256(b"agent").digest()
        ap = buf(32)
        self.assertEqual(self.lib.s6p_public(buf(seed_a), 32, ap, 32), 0)
        pins = []
        for seed in seeds:
            pk = buf(32)
            self.assertEqual(self.lib.s6p_public(buf(seed), 32, pk, 32), 0)
            pins.append(bytes(pk).hex())
        target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target.bind(("127.0.0.1", 0)); target.settimeout(5)
        self.addCleanup(target.close)
        reservations = []
        for _ in range(4):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0)); reservations.append(sock)
        agent_port, unused, broker_port, broker_app = [s.getsockname()[1] for s in reservations]
        for sock in reservations:
            sock.close()
        config = dict(role="agent", listen_port=agent_port, peer_port=unused,
                      application_port=target.getsockname()[1], private_key=seed_a.hex(),
                      peer_public_key=pins[0], peer_public_keys=pins[1:])
        self._start(Path(directory.name) / "agent.json", config)
        endpoint = ("127.0.0.1", agent_port)
        if broker:
            self._start(Path(directory.name) / "broker.json", dict(
                role="broker", listen_port=broker_port, peer_port=agent_port,
                application_port=broker_app, private_key=seed_a.hex(),
                peer_public_key=bytes(ap).hex()))
            endpoint = ("127.0.0.1", broker_port)
        return seeds, ap, endpoint, target

    def _start(self, path, config):
        path.write_text(json.dumps(config)); path.chmod(0o600)
        process = subprocess.Popen([BIN, "--config", str(path)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        def close():
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate()
        self.addCleanup(close)
        ready, _, _ = select.select([process.stdout], [], [], 8)
        self.assertTrue(ready, "Pony listener readiness timed out")
        line = process.stdout.readline()
        self.assertIn(b"ready:", line)
        return process

    def _peer(self, seed, ap, endpoint):
        peer = Peer(self.lib, seed, ap, endpoint)
        self.addCleanup(peer.sock.close)
        peer.connect()
        return peer

    def test_256_distinct_tenants_and_capacity(self):
        seeds, ap, endpoint, target = self._listener(256)
        peers = [self._peer(seed, ap, endpoint) for seed in seeds]
        destinations = set()
        for number, peer in enumerate(peers):
            payload = f"tenant-{number}".encode()
            peer.send(payload, 2)
            data, address = target.recvfrom(2048)
            self.assertEqual(data, payload)
            destinations.add(address)
            target.sendto(data, address)
            self.assertEqual(peer.data(), payload)
        self.assertEqual(len(destinations), 256, "tenants shared an application socket")
        overflow = Peer(self.lib, seeds[0], ap, endpoint)
        self.addCleanup(overflow.sock.close)
        with self.assertRaises(TimeoutError):
            overflow.connect(timeout=0.5)
        # Capacity exhaustion may not evict any existing tenant.
        peers[0].send(b"still alive", 3)
        data, address = target.recvfrom(2048)
        self.assertEqual(data, b"still alive")
        target.sendto(data, address)
        self.assertEqual(peers[0].data(), data)

    def test_broker_tenant_isolation_reorder_duplicate_and_loss(self):
        seeds, ap, endpoint, target = self._listener(2, broker=True)
        first, second = [self._peer(seed, ap, endpoint) for seed in seeds]
        # A valid packet under tenant 1's key cannot authenticate on tenant 2's
        # source route. The legitimate seq 2 must remain available afterward.
        second.sock.sendto(first.seal(b"cross-tenant", 2), endpoint)
        target.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            target.recvfrom(2048)
        target.settimeout(5)
        # Reordering buffers seq 3 until seq 2; duplicate seq 2 never redelivers.
        first.send(b"third", 3)
        first.send(b"second", 2)
        packets = [target.recvfrom(2048), target.recvfrom(2048)]
        self.assertEqual([packet[0] for packet in packets], [b"second", b"third"])
        first.send(b"second", 2)
        second.send(b"independent", 2)
        data, second_address = target.recvfrom(2048)
        self.assertEqual(data, b"independent")
        self.assertNotEqual(second_address, packets[0][1])
        # Do not ACK the first server DATA: retransmission must be byte-identical.
        target.sendto(b"retry-me", packets[0][1])
        until = time.monotonic() + 5
        wires = []
        while time.monotonic() < until and len(wires) < 2:
            try:
                wire, _ = first.sock.recvfrom(2048)
                if len(wire) >= 28 and wire[:4] == b"S6E\x02":
                    wires.append(wire)
            except socket.timeout:
                pass
        self.assertEqual(len(wires), 2, "server did not retransmit unacknowledged DATA")
        self.assertEqual(wires[0], wires[1])
        first.send(b"", int.from_bytes(wires[0][4:12], "big"), 3)
        target.sendto(b"own-response", second_address)
        self.assertEqual(second.data(), b"own-response")


if __name__ == "__main__":
    unittest.main()
