"""Receiver accounting must never promote sender rate or high-loss UDP."""
import unittest
from iperf_chain import receiver_result


class ReceiverTests(unittest.TestCase):
    def report(self, bps=1_100_000_000, loss=0):
        return {'end': {'sum_sent': {'bits_per_second': 10_000_000_000, 'sender': True},
                        'sum_received': {'bits_per_second': bps, 'lost_percent': loss, 'sender': False,
                                         'packets': 10000, 'lost_packets': round(loss * 100)}}}

    def test_receiver_rate_and_loss_are_both_required(self):
        self.assertTrue(receiver_result(self.report(), True, reverse=True)[1])
        self.assertFalse(receiver_result(self.report(bps=500_000_000), True, reverse=True)[1])
        self.assertFalse(receiver_result(self.report(loss=10), True, reverse=True)[1])

    def test_missing_receiver_never_falls_back_to_sender(self):
        with self.assertRaises(KeyError):
            receiver_result({'end': {'sum': {'bits_per_second': 10_000_000_000, 'sender': True}}}, True, reverse=True)

    def test_invalid_metrics_fail_closed(self):
        for bps in (float('nan'), float('inf'), True, -1, 0):
            with self.subTest(bps=bps), self.assertRaises(ValueError):
                receiver_result(self.report(bps=bps), True, reverse=True)
        report = self.report(); report['end']['sum_received']['sender'] = True
        with self.assertRaises(ValueError): receiver_result(report, True, reverse=True)
        report = self.report(); del report['end']['sum_received']['lost_percent']
        with self.assertRaises(ValueError): receiver_result(report, True, reverse=True)

    def test_iperf_failure_is_not_a_measurement(self):
        report = self.report(); report['error'] = 'unable to connect'
        with self.assertRaises(ValueError): receiver_result(report, False, reverse=True)

    def test_forward_tcp_uses_server_report(self):
        report = self.report()
        report['end']['sum_received']['sender'] = True
        report['server_output_json'] = self.report(bps=2_866_916_922)
        receiver, passed = receiver_result(report, False, reverse=False)
        self.assertEqual(receiver['bits_per_second'], 2_866_916_922)
        self.assertTrue(passed)

    def test_forward_udp_uses_receiver_loss_denominator(self):
        report = self.report(loss=0.01)
        report['server_output_json'] = self.report(loss=97.82)
        receiver, passed = receiver_result(report, True, reverse=False)
        self.assertEqual(receiver['lost_percent'], 97.82)
        self.assertFalse(passed)

    def test_forward_requires_successful_server_evidence(self):
        report = self.report()
        with self.assertRaises(KeyError):
            receiver_result(report, False, reverse=False)
        report['server_output_json'] = {'error': 'server failed'}
        with self.assertRaises(ValueError):
            receiver_result(report, False, reverse=False)

    def test_reverse_uses_client_report(self):
        report = self.report(bps=2_751_063_742)
        report['server_output_json'] = self.report(bps=0)
        receiver, passed = receiver_result(report, False, reverse=True)
        self.assertEqual(receiver['bits_per_second'], 2_751_063_742)
        self.assertTrue(passed)

    def test_udp_loss_uses_receiver_packet_counts(self):
        report = self.report(loss=0.01)
        report['end']['sum_received'].update(packets=1604, lost_packets=1571)
        receiver, passed = receiver_result(report, True, reverse=True)
        self.assertAlmostEqual(receiver['lost_percent'], 100 * 1571 / 1604)
        self.assertEqual(receiver['reported_lost_percent'], 0.01)
        self.assertFalse(passed)

    def test_invalid_udp_packet_counts_fail_closed(self):
        for packets, lost in [(0, 0), (True, 0), (10, -1), (10, 11), (10, 1.0), (None, 0)]:
            report = self.report()
            report['end']['sum_received'].update(packets=packets, lost_packets=lost)
            with self.subTest(packets=packets, lost=lost), self.assertRaises(ValueError):
                receiver_result(report, True, reverse=True)


if __name__ == '__main__': unittest.main()
