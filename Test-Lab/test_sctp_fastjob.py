"""Control-flow tests for the bounded FastJob; no native builds or netns."""
from contextlib import ExitStack
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import sctp_fastjob


class SCTPFastJobTests(unittest.TestCase):
    def run_driver(self, outcomes, *, caps=None, repeats=2):
        with tempfile.TemporaryDirectory(prefix='s6-fastjob-test-') as temporary, ExitStack() as mocks:
            native = {'availability': 'AVAILABLE', 'featureReport': {
                'crosed_max_level': 0, 'app_transport': False, 'qubes_isolation': False}}
            mocks.enter_context(patch('sctp_fastjob._current_feature_report', return_value=native))
            mocks.enter_context(patch('sctp_fastjob.validate_feature_report'))
            mocks.enter_context(patch('sctp_fastjob.feature_report', return_value={
                'schema': 'shadow6.privacy-envelope.v1', 'wire_version': 3,
                'payload_encryption': True, 'mode': 'encrypted-authenticated-envelope'}))
            mocks.enter_context(patch('sctp_fastjob.SCTPCarrier.admit'))
            mocks.enter_context(patch('sctp_fastjob.capabilities', return_value=caps or {
                'netnsNetem': True, 'namespaceCapture': True}))
            mocks.enter_context(patch('sctp_fastjob.sha256_file', return_value='a' * 64))
            runner = mocks.enter_context(patch('sctp_fastjob.case', side_effect=outcomes))
            report = sctp_fastjob.reproduce(Path(temporary), repeats)
            stored = json.loads((Path(temporary) / 'report.json').read_text())
            self.assertEqual(stored, report)
            self.assertTrue((Path(temporary) / 'summary.md').is_file())
            return report, runner.call_args_list

    def test_eof_survives_outer_capture_error_and_stops_after_evidence_case(self):
        passed = {'status': 'PASS', 'scenario': 'clean', 'stages': {'correctness': {'status': 'PASS'}}}
        eof = {'status': 'FAIL', 'scenario': 'lan', 'reason': 'capture ownership failure',
            'stages': {'correctness': {'status': 'FAIL', 'reason': 'RuntimeError: EOFError: game stream EOF'}}}
        report, calls = self.run_driver([passed, eof])
        self.assertEqual(report['status'], 'FAIL')
        self.assertTrue(report['eofReproduced'])
        self.assertEqual(len(calls), 2)
        self.assertEqual([call.args[4] for call in calls], ['clean', 'lan'])

    def test_no_eof_executes_one_baseline_and_every_bounded_wan_attempt(self):
        scenarios = ['clean', *sctp_fastjob.WAN_SCENARIOS, *sctp_fastjob.WAN_SCENARIOS]
        rows = [{'status': 'PASS', 'scenario': scenario} for scenario in scenarios]
        report, calls = self.run_driver(copy.deepcopy(rows))
        self.assertEqual(report['status'], 'PASS')
        self.assertFalse(report['eofReproduced'])
        self.assertEqual([call.args[4] for call in calls], scenarios)
        self.assertTrue(all(call.kwargs['worker_timeout'] == 90 for call in calls))
        self.assertEqual([row['attempt'] for row in report['results']], [0, 1, 1, 1, 2, 2, 2])

    def test_missing_namespace_permission_is_blocked_and_never_passes(self):
        report, calls = self.run_driver([], caps={
            'netnsNetem': False, 'namespaceCapture': False, 'reason': 'CAP_NET_ADMIN unavailable'})
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertEqual(calls, [])
        self.assertIn('CAP_NET_ADMIN', report['reason'])

    def test_non_eof_regression_is_retained_and_fails_the_job(self):
        scenarios = ['clean', *sctp_fastjob.WAN_SCENARIOS]
        rows = [{'status': 'FAIL' if scenario == 'lan' else 'PASS', 'scenario': scenario,
                 'reason': 'byte accounting mismatch' if scenario == 'lan' else None} for scenario in scenarios]
        report, calls = self.run_driver(rows, repeats=1)
        self.assertEqual(report['status'], 'FAIL')
        self.assertFalse(report['eofReproduced'])
        self.assertEqual(len(calls), 4)


if __name__ == '__main__':
    unittest.main()
