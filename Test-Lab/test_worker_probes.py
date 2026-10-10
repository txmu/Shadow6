"""Loss evidence must continue without retransmission or false correctness."""
import hashlib
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from worker import echo_probes, run


class WorkerProbeTests(unittest.TestCase):
    def test_first_record_loss_keeps_later_probes_and_exact_byte_accounting(self):
        client, remote = socket.socketpair(type=socket.SOCK_DGRAM)
        with client, remote:
            client.settimeout(.1); remote.settimeout(1)
            arrivals = []; errors = []
            def echo():
                try:
                    for index in range(4):
                        data = remote.recv(512); arrivals.append(data)
                        if index: remote.send(data)
                except Exception as error: errors.append(error)
            thread = threading.Thread(target=echo); thread.start()
            try:
                session = SimpleNamespace(socket=client, boundary=SimpleNamespace(kind='message', max_record=512))
                sent, received, latencies, digest, failures = echo_probes(session, b'abcd', 2, 2)
            finally: thread.join(timeout=2)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
            self.assertEqual(arrivals, [b'ab', b'cd', b'ab', b'cd'])
            self.assertEqual((sent, received, len(latencies)), (8, 6, 1))
            self.assertEqual(digest, hashlib.sha256(b'abcd').hexdigest())
            self.assertEqual(failures, [{'request': 0, 'offset': 0, 'reason': 'TimeoutError: timed out'}])

    def test_total_record_loss_is_bounded_and_has_no_verified_requests(self):
        connection = Mock(); connection.send.return_value = 2
        connection.recvmsg.side_effect = socket.timeout
        session = SimpleNamespace(socket=connection, boundary=SimpleNamespace(kind='message', max_record=512))
        sent, received, latencies, digest, failures = echo_probes(session, b'abcd', 2, 2)
        self.assertEqual((sent, received, latencies, digest), (8, 0, [], None))
        self.assertEqual(len(failures), 4)
        self.assertEqual(connection.send.call_count, 4)

    def test_stream_eof_still_fails_immediately(self):
        connection = Mock(); connection.recv.return_value = b''
        session = SimpleNamespace(socket=connection, boundary=SimpleNamespace(kind='stream'))
        with self.assertRaises(EOFError): echo_probes(session, b'abcd', 2, 4)
        self.assertEqual(connection.sendall.call_count, 1)

    def test_partial_record_loss_never_becomes_a_pass(self):
        result = {'probe_failures': [{'request': 0, 'offset': 0, 'reason': 'TimeoutError: timed out'}],
            'success_rate': .5, 'bytes_sent': 8, 'bytes_received': 6,
            'exact_echo': {'byte_for_byte': False, 'verified_requests': 1, 'record_bytes': 2,
                'payload_sha256': 'a' * 64, 'received_sha256': 'a' * 64},
            'duration_seconds': .1, 'throughput_bps': 320, 'latency_p95_seconds': .01,
            'latency_avg_seconds': .01, 'pacing_ms': 0, 'application_abi': {},
            'runtime_observation': {}, 'application_game': None}
        with tempfile.TemporaryDirectory(prefix='s6-probe-test-') as temporary:
            binary = Path(temporary) / 'fixture'; binary.write_bytes(b'fixture')
            with patch('worker.named_workload', return_value=result):
                report = run('idris', 'idris-udp', binary, 4, 2, 0)
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['correctness']['status'], 'FAIL')
        self.assertFalse(report['correctness']['byteForByte'])
        self.assertEqual(report['correctness']['successRate'], .5)


if __name__ == '__main__':
    unittest.main()
