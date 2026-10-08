"""Receiver accounting must never promote sender rate or high-loss UDP."""
import unittest
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from iperf_chain import iperf_document, portable_json, receiver_result, measure


class IperfDocumentTests(unittest.TestCase):
    rate = 1_100_000_000

    def document(self, fields=None, extra=''):
        if fields is None:
            fields = f'"target_bitrate":{self.rate},"target_bitrate":{self.rate}'
        return ('{"server_output_json":{"start":{' + fields + '},'
                '"end":{"sum_received":{"sender":false,"bits_per_second":1100000000,'
                '"lost_percent":0,"packets":10000,"lost_packets":0}}}' + extra + '}')

    def test_iperf_316_udp_metadata_preserves_forward_receiver(self):
        raw = self.document().encode()
        with self.assertRaisesRegex(ValueError, 'duplicate JSON field'):
            portable_json(raw, allow_measurement_floats=True)
        document = iperf_document(raw, udp_rate=self.rate)
        self.assertEqual(document['server_output_json']['start']['target_bitrate'], self.rate)
        receiver, passed = receiver_result(document, True, reverse=False)
        self.assertEqual(receiver['bits_per_second'], self.rate)
        self.assertTrue(passed)

    def test_udp_measure_accepts_known_duplicate_and_preserves_raw_evidence(self):
        raw = self.document(extra=',"end":{"sum_sent":{}}').encode()
        with tempfile.TemporaryDirectory() as directory:
            target = SimpleNamespace(datagram=True, server_port=12345, host='127.0.0.1',
                                     directory=Path(directory))
            result = SimpleNamespace(returncode=0, stdout=raw, stderr=b'')
            with patch('iperf_chain.subprocess.run', return_value=result):
                row = measure(('127.0.0.1', 12345), target, (), 1, False, self.rate, True)
            self.assertEqual(row['status'], 'ok')
            self.assertEqual(row['receiver_bps'], self.rate)
            self.assertEqual((target.directory / 'client.json').read_bytes(), raw)

    def test_duplicate_rate_requires_udp_workload_and_exact_integer_value(self):
        for rate in (None, float(self.rate), True):
            with self.subTest(rate=rate), self.assertRaisesRegex(ValueError, 'duplicate JSON field'):
                iperf_document(self.document(), udp_rate=rate)
        for fields in (
                f'"target_bitrate":{self.rate},"target_bitrate":{self.rate + 1}',
                '"target_bitrate":1,"target_bitrate":1',
                f'"target_bitrate":{self.rate},"target_bitrate":{self.rate}.0',
                f'"target_bitrate":{self.rate}.0,"target_bitrate":{self.rate}',
                '"target_bitrate":true,"target_bitrate":true',
                f'"target_bitrate":{self.rate},"target_bitrate":{self.rate},"target_bitrate":{self.rate}'):
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, 'duplicate JSON field'):
                iperf_document(self.document(fields), udp_rate=self.rate)

    def test_other_duplicate_fields_and_paths_remain_rejected(self):
        documents = (
            self.document('"version":"iperf 3.16","version":"iperf 3.16"'),
            self.document(extra=',"receiver_bps":1,"receiver_bps":2'),
            self.document().replace('"bits_per_second":1100000000',
                                    '"bits_per_second":1100000000,"bits_per_second":1100000000'),
            '{"start":{"target_bitrate":1100000000,"target_bitrate":1100000000}}',
            '{"end":{"target_bitrate":1100000000,"target_bitrate":1100000000}}',
        )
        for raw in documents:
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'duplicate JSON field'):
                iperf_document(raw, udp_rate=self.rate)

    def test_known_duplicate_does_not_relax_json_bounds(self):
        for extra in (',"x":NaN', ',"x":1e999', ',"x":9007199254740992',
                      ',"x":"e\\u0301"', ',"x":"\\u0000"',
                      ',"x":"' + 'a' * 65537 + '"',
                      ',"x":' + '[' * 18 + '0' + ']' * 18,
                      ',"x":"' + 'a' * 1048576 + '"'):
            with self.subTest(extra=extra[:40]), self.assertRaises(ValueError):
                iperf_document(self.document(extra=extra), udp_rate=self.rate)


class ReceiverTests(unittest.TestCase):
    def test_ten_gbps_requires_receiver_rate_and_low_loss(self):
        for rate, loss, expected in ((10_000_000_000, 0, True),
                                     (9_999_999_999, 0, False),
                                     (12_000_000_000, 2, False)):
            with self.subTest(rate=rate, loss=loss), tempfile.TemporaryDirectory() as directory:
                target = SimpleNamespace(datagram=True, server_port=12345, host='127.0.0.1',
                                         directory=Path(directory))
                result = SimpleNamespace(returncode=0, stderr=b'',
                                         stdout=json.dumps(self.report(rate, loss)).encode())
                with patch('iperf_chain.subprocess.run', return_value=result):
                    row = measure(('127.0.0.1', 12345), target, (), 1, True, 1_100_000_000, True)
                self.assertIs(row['ten_gbps_target_met'], expected)

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
