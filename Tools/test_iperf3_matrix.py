import unittest

from iperf3_matrix import metric, specs, udp_rate


class MatrixTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
