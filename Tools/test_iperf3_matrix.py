import socket
import unittest
from pathlib import Path
from unittest.mock import patch

from iperf3_matrix import free_port, metric, run_case_with_timeout_retry, specs, udp_rate


class MatrixTests(unittest.TestCase):
    def test_tcp_port_allocator_retries_transient_bind_collisions(self):
        class CollisionSocket:
            calls = 0
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def setsockopt(self, *_): pass
            def bind(self, _):
                type(self).calls += 1
                if type(self).calls < 4:
                    raise OSError(10048, "address already in use")
            def getsockname(self): return ("127.0.0.1", 45678)

        with patch("iperf3_matrix.socket.socket", side_effect=lambda *_args: CollisionSocket()):
            self.assertEqual(free_port(4), 45678)
        self.assertEqual(CollisionSocket.calls, 4)

    def test_udp_matrix_port_is_bindable_by_both_tcp_and_udp(self):
        port = free_port(4, udp=True)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
            stream.bind(("127.0.0.1", port))
            datagram.bind(("127.0.0.1", port))

    def test_full_matrix_and_stream_bound(self):
        rows = specs(12, (4, 6))
        self.assertEqual(len(rows), 32)
        self.assertEqual({(r["family"], r["direction"], r["protocol"]) for r in rows},
                         {(family, direction, protocol)
                          for family in (4, 6) for direction in ("forward", "reverse")
                          for protocol in ("tcp", "udp")})
        self.assertLessEqual(max(r["streams"] for r in rows), 12)
        with self.assertRaises(ValueError):
            specs(13, (4,))

    def test_rejects_nonfinite_or_missing_throughput(self):
        for value in (float("nan"), float("inf"), True, 0, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                metric({"end": {"sum_received": {"bits_per_second": value}}}, "tcp")

    def test_udp_rate_is_bounded_by_tcp_and_fixed_cap(self):
        rows = [dict(family=4, direction="forward", protocol="tcp", status="ok", throughput_bps=26e9)]
        self.assertEqual(udp_rate(rows, 4, "forward", 2000), 2_000_000_000)
        self.assertEqual(udp_rate(rows, 4, "reverse", 2000), 100_000_000)

    def test_only_timeouts_get_one_retry_and_keep_both_outcomes(self):
        timeout = dict(status="failed", reason="client timed out", timed_out=True, elapsed_seconds=36)
        success = dict(status="ok", elapsed_seconds=7)
        with patch("iperf3_matrix.run_case", side_effect=[timeout, success]) as run:
            row = run_case_with_timeout_retry("iperf3", {}, 6, None, Path("raw"), 1)
            self.assertEqual(row["status"], "ok")
            self.assertEqual([attempt["status"] for attempt in row["attempts"]], ["failed", "ok"])
            self.assertEqual(run.call_count, 2)
        with patch("iperf3_matrix.run_case", return_value=timeout) as run:
            row = run_case_with_timeout_retry("iperf3", {}, 6, None, Path("raw"), 1)
            self.assertEqual(row["status"], "failed")
            self.assertEqual(run.call_count, 2)
        with patch("iperf3_matrix.run_case", return_value=dict(status="failed", reason="bad data", elapsed_seconds=1)) as run:
            row = run_case_with_timeout_retry("iperf3", {}, 6, None, Path("raw"), 1)
            self.assertEqual(row["status"], "failed")
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
