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

    def test_tls_carrier_observation_is_strict_and_aggregate(self):
        import json, tempfile, time
        from pathlib import Path
        from privacy_envelope import read_metrics
        with tempfile.TemporaryDirectory(prefix='shadow6-tls-metrics-') as directory:
            path=Path(directory)/'metrics'
            value={**EnvelopeMetrics().public(),'schema':'shadow6.privacy-envelope-status.v3',
                   'observed_at':int(time.time()),'records_in':1,'records_out':1,'timeout_count':0,
                   'shaping_overhead_bytes':0,'shaping_enabled':False,'carrier':'tls',
                   'wire_appearance':'standard-tls13'}
            path.write_text(json.dumps(value));path.chmod(0o600)
            self.assertEqual(read_metrics(path)['carrier'],'tls')
            self.assertEqual(read_metrics(path)['observation'],'current')
            for key,replacement in (('carrier','webrtc'),('wire_appearance','DPI-proof'),('extra',True)):
                bad={**value,key:replacement};path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):read_metrics(path)

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

    def test_sctp_observation_requires_bounded_failure_counters(self):
        import json, tempfile, time
        from pathlib import Path
        from privacy_envelope import read_metrics
        with tempfile.TemporaryDirectory(prefix='shadow6-sctp-metrics-') as directory:
            path=Path(directory)/'metrics'
            value={**EnvelopeMetrics().public(),'schema':'shadow6.privacy-envelope-status.v4',
                   'observed_at':int(time.time()),'records_in':1,'records_out':1,'timeout_count':0,
                   'shaping_overhead_bytes':0,'shaping_enabled':False,'carrier':'sctp',
                   'wire_appearance':'standard-sctp','native_send_abandonment_count':2,
                   'session_rejection_count':1}
            path.write_text(json.dumps(value));path.chmod(0o600)
            self.assertEqual(read_metrics(path)['native_send_abandonment_count'],2)
            for field,replacement in (('carrier','webrtc'),('wire_appearance','camouflaged'),
                                      ('native_send_abandonment_count',True),('session_rejection_count',-1)):
                with self.subTest(field=field):
                    path.write_text(json.dumps({**value,field:replacement}))
                    with self.assertRaises(ValueError):read_metrics(path)

    def test_webrtc_observation_names_standard_datachannel_and_bounds_counters(self):
        import json, tempfile, time
        from pathlib import Path
        from privacy_envelope import read_metrics
        with tempfile.TemporaryDirectory(prefix='shadow6-webrtc-metrics-') as directory:
            path=Path(directory)/'metrics'
            value={**EnvelopeMetrics().public(),'schema':'shadow6.privacy-envelope-status.v6',
                   'observed_at':int(time.time()),'records_in':1,'records_out':1,'timeout_count':0,
                   'shaping_overhead_bytes':0,'shaping_enabled':False,'carrier':'webrtc',
                   'wire_appearance':'standard-webrtc-datachannel','native_send_abandonment_count':0,
                   'session_rejection_count':0,'active_sessions':0}
            path.write_text(json.dumps(value));path.chmod(0o600)
            self.assertEqual(read_metrics(path)['carrier'],'webrtc')
            for field,replacement in (('wire_appearance','camouflaged'),('native_send_abandonment_count',True),
                                      ('session_rejection_count',-1)):
                with self.subTest(field=field):
                    path.write_text(json.dumps({**value,field:replacement}))
                    with self.assertRaises(ValueError):read_metrics(path)

    def test_legacy_envelope_is_reported_unavailable_without_relabeling_it(self):
        from privacy_envelope import feature_availability
        current={'schema':'shadow6.privacy-envelope.v1','wire_version':3,
                 'payload_encryption':True,'mode':'encrypted-authenticated-envelope'}
        self.assertTrue(feature_availability(current)['available'])
        for report in ({**current,'wire_version':2},{**current,'payload_encryption':False},
                       {**current,'wire_version':True},{**current,'mode':'authenticated-envelope'}):
            result=feature_availability(report)
            self.assertFalse(result['available'])
            self.assertEqual(result['diagnostics'][0]['code'],'OutdatedEnvelopeContract')

    def test_message_carriers_and_unknown_core(self):
        for core, carrier in (('nim', 'webrtc'), ('cpp', 'sctp')):
            result = compatibility(core)
            self.assertTrue(result['supported'])
            self.assertEqual(result['mode'], 'message')
            self.assertEqual(result['carriers'], [carrier])
            self.assertEqual(result['evidence'], 'source-contract-only')
        with self.assertRaises(ValueError): compatibility('unknown')

if __name__ == "__main__": unittest.main()
