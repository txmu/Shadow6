import unittest
from privacy_envelope import EnvelopeMetrics, compatibility

class PrivacyEnvelopeTests(unittest.TestCase):
    def test_metrics_are_aggregate_only(self):
        value = EnvelopeMetrics(preauth_rejections=2).public()
        self.assertEqual(value["preauth_rejection_count"], 2)
        self.assertNotIn("payload", value)
        self.assertNotIn("token", value)
    def test_transport_matrix_marks_datagram_limits(self):
        self.assertTrue(compatibility("rust")["supported"])
        self.assertTrue(compatibility("hare")["supported"])


class ObservationTests(unittest.TestCase):
    def test_missing_metrics_are_not_zero_observations(self):
        from privacy_envelope import read_metrics
        self.assertEqual(read_metrics()['observation'], 'not-configured')
        self.assertNotIn('sessions', read_metrics())

    def test_actual_private_metrics_fresh_stale_and_rejection(self):
        import json, tempfile, time
        from pathlib import Path
        from privacy_envelope import read_metrics
        with tempfile.TemporaryDirectory(prefix='shadow6-metrics-') as directory:
            path = Path(directory)/'metrics'
            self.assertEqual(read_metrics(path)['observation'], 'unavailable')
            value = {**EnvelopeMetrics(sessions=4).public(), 'observed_at':int(time.time())}
            path.write_text(json.dumps(value)); path.chmod(0o600)
            self.assertEqual(read_metrics(path)['sessions'],4)
            self.assertEqual(read_metrics(path)['observation'],'current')
            value['observed_at'] -= 60; path.write_text(json.dumps(value))
            self.assertEqual(read_metrics(path)['observation'],'stale')
            value['payload']='secret'; path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): read_metrics(path)
            path.chmod(0o644)
            with self.assertRaises(ValueError): read_metrics(path)

    def test_future_timestamp_remains_stale_without_clock_tolerance(self):
        import json, tempfile
        from pathlib import Path
        from unittest.mock import patch
        from privacy_envelope import read_metrics
        with tempfile.TemporaryDirectory(prefix='shadow6-clock-') as directory:
            path=Path(directory)/'metrics'
            value={**EnvelopeMetrics().public(),'observed_at':1791010001}
            path.write_text(json.dumps(value));path.chmod(0o600)
            with patch('privacy_envelope.time.time',return_value=1791010000.9):
                self.assertEqual(read_metrics(path)['observation'],'stale')
                value['observed_at']=1791010000;path.write_text(json.dumps(value))
                self.assertEqual(read_metrics(path)['observation'],'current')

    def test_unsupported_or_unknown_core_does_not_claim_compatibility(self):
        self.assertFalse(compatibility('nim')['supported'])
        with self.assertRaises(ValueError): compatibility('unknown')

if __name__ == "__main__": unittest.main()
