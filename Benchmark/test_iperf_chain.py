"""Receiver accounting must never promote sender rate or high-loss UDP."""
import unittest
from iperf_chain import receiver_result


class ReceiverTests(unittest.TestCase):
    def report(self, bps=1_100_000_000, loss=0):
        return {'end': {'sum_sent': {'bits_per_second': 10_000_000_000, 'sender': True},
                        'sum_received': {'bits_per_second': bps, 'lost_percent': loss, 'sender': False}}}

    def test_receiver_rate_and_loss_are_both_required(self):
        self.assertTrue(receiver_result(self.report(), True)[1])
        self.assertFalse(receiver_result(self.report(bps=500_000_000), True)[1])
        self.assertFalse(receiver_result(self.report(loss=10), True)[1])

    def test_missing_receiver_never_falls_back_to_sender(self):
        with self.assertRaises(KeyError):
            receiver_result({'end': {'sum': {'bits_per_second': 10_000_000_000, 'sender': True}}}, True)

    def test_invalid_metrics_fail_closed(self):
        for bps in (float('nan'), float('inf'), True, -1, 0):
            with self.subTest(bps=bps), self.assertRaises(ValueError):
                receiver_result(self.report(bps=bps), True)
        report = self.report(); report['end']['sum_received']['sender'] = True
        with self.assertRaises(ValueError): receiver_result(report, True)
        report = self.report(); del report['end']['sum_received']['lost_percent']
        with self.assertRaises(ValueError): receiver_result(report, True)

    def test_iperf_failure_is_not_a_measurement(self):
        report = self.report(); report['error'] = 'unable to connect'
        with self.assertRaises(ValueError): receiver_result(report, False)


if __name__ == '__main__': unittest.main()
