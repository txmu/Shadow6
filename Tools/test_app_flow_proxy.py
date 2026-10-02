from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import app_flow_proxy


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(hasattr(socket, "SOCK_SEQPACKET"), "AF_UNIX SOCK_SEQPACKET is unavailable")
class AppFlowProxyTests(unittest.TestCase):
    def start_proxy(self, protocol: str, port: int):
        receiver, inherited = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "Tools/app_flow_proxy.py"), "--fd", str(inherited.fileno()),
             "--protocol", protocol, "--host", "127.0.0.1", "--port", str(port)],
            pass_fds=(inherited.fileno(),), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        inherited.close()
        self.addCleanup(self.stop_proxy, process, receiver)
        receiver.settimeout(3)
        return process, receiver

    @staticmethod
    def stop_proxy(process: subprocess.Popen, receiver: socket.socket) -> None:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        receiver.close()
        if process.stderr:
            process.stderr.close()

    @staticmethod
    def free_port(protocol: str) -> int:
        kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, kind) as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def connect_tcp(self, port: int) -> socket.socket:
        deadline = time.monotonic() + 3
        last_error = None
        while time.monotonic() < deadline:
            try:
                peer = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                peer.settimeout(3)
                return peer
            except OSError as error:
                last_error = error
                time.sleep(0.02)
        self.fail(f"TCP proxy did not start: {last_error}")

    def test_tcp_forwards_existing_peer_records(self):
        port = self.free_port("tcp")
        _, flow = self.start_proxy("tcp", port)
        with self.connect_tcp(port) as peer:
            peer.sendall(b"first-record")
            self.assertEqual(flow.recv(64), b"first-record")
            peer.sendall(b"second-record")
            self.assertEqual(flow.recv(64), b"second-record")

    def test_udp_forwards_datagrams(self):
        port = self.free_port("udp")
        _, flow = self.start_proxy("udp", port)
        flow.settimeout(0.1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                peer.sendto(b"datagram", ("127.0.0.1", port))
                try:
                    self.assertEqual(flow.recv(64), b"datagram")
                    return
                except TimeoutError:
                    continue
            self.fail("UDP proxy did not forward a datagram")

    def test_tcp_pending_queue_stops_and_resumes_peer_reads(self):
        port = self.free_port("tcp")
        flow, inherited = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        inherited.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2048)
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "Tools/app_flow_proxy.py"), "--fd", str(inherited.fileno()),
             "--protocol", "tcp", "--host", "127.0.0.1", "--port", str(port)],
            pass_fds=(inherited.fileno(),), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        inherited.close()
        self.addCleanup(self.stop_proxy, process, flow)
        peer = self.connect_tcp(port)
        self.addCleanup(peer.close)
        payload = bytes(index % 251 for index in range(262144))
        send_errors = []

        def send_large_stream():
            try:
                peer.sendall(payload)
            except OSError as error:
                send_errors.append(error)

        sender = threading.Thread(target=send_large_stream, daemon=True)
        sender.start()
        # Leave the inherited Core FD unread until the proxy has filled its
        # 64-record queue and must pause this already-accepted TCP peer.
        time.sleep(0.2)
        received = bytearray()
        flow.settimeout(1)
        deadline = time.monotonic() + 5
        while len(received) < len(payload) and time.monotonic() < deadline:
            try:
                received.extend(flow.recv(1172))
            except TimeoutError:
                continue
        sender.join(timeout=2)
        self.assertFalse(sender.is_alive(), "TCP sender remained blocked after Core backpressure cleared")
        self.assertEqual(send_errors, [])
        self.assertEqual(bytes(received), payload)

    def test_loopback_and_record_limits_fail_closed(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with self.assertRaisesRegex(ValueError, "loopback"):
            app_flow_proxy.run(left.detach(), "0.0.0.0", 0, "tcp", 100)
        with self.assertRaisesRegex(ValueError, "max-record"):
            app_flow_proxy.run(right.detach(), "127.0.0.1", 0, "tcp", app_flow_proxy.MAX_RECORD + 1)


if __name__ == "__main__":
    unittest.main()
