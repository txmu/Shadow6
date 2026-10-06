"""Admission diagnostics never equate artifact existence with a usable Profile."""
import unittest
from unittest.mock import patch
from Deployment.core_catalog import CoreCatalog
from Deployment.profile_availability import inspect_profile, installed_profiles
import Crosed.test_feature_contract as feature_fixtures


class ProfileAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.catalog = CoreCatalog()
        # These tests exercise admission contracts independently of the host;
        # the explicit degradation test supplies a different platform below.
        platform = patch('Deployment.profile_availability.sys.platform', 'linux')
        platform.start(); self.addCleanup(platform.stop)
        pidfd = patch('Deployment.profile_availability.os.pidfd_open', create=True)
        pidfd.start(); self.addCleanup(pidfd.stop)

    def report(self, core):
        return feature_fixtures.FeatureContractTests().with_modes('shadow6-' + core)

    def test_installed_binary_does_not_require_a_compiler(self):
        with patch('shutil.which', side_effect=AssertionError('compiler discovery during runtime admission')):
            result = inspect_profile(self.catalog, 'go', 'go-kcp', report=self.report('go'))
        self.assertTrue(result['available'])
        self.assertEqual(result['diagnostics'], [])
        self.assertEqual(result['buildPrerequisites'], ['go'])

    def test_unknown_profile_and_wrong_family_do_not_fall_back(self):
        for core, profile in [('go', 'rust-quic'), ('gleam', 'gleam-unknown')]:
            with self.assertRaises(ValueError): inspect_profile(self.catalog, core, profile)

    def test_missing_binary_has_actionable_fixed_profile_diagnostic(self):
        with patch('Deployment.service_runtime.feature_report', side_effect=FileNotFoundError):
            result = inspect_profile(self.catalog, 'pony', 'pony-udp')
        self.assertFalse(result['available'])
        self.assertEqual(result['diagnostics'][0]['code'], 'NativeArtifactMissing')
        self.assertIn('Core-Pony/shadow6-pony', result['diagnostics'][0]['action'])

    def test_wrong_or_undeclared_boundary_is_unavailable(self):
        for report in ({}, self.report('rust')):
            self.assertFalse(inspect_profile(self.catalog, 'go', report=report)['available'])
        report = self.report('gleam'); report['application_boundaries'].pop()
        self.assertFalse(inspect_profile(self.catalog, 'gleam', 'gleam-micro-mux', report=report)['available'])

    def test_catalog_probes_one_artifact_for_both_gleam_profiles(self):
        def probe(path):
            if path.endswith('shadow6-gleam'): return self.report('gleam')
            raise ValueError('fixture artifact unavailable')
        with patch('Deployment.service_runtime.feature_report', side_effect=probe) as bounded_probe:
            result = installed_profiles(self.catalog)
        self.assertEqual(len(result['profiles']), 13)
        self.assertEqual(bounded_probe.call_count, 12)
        self.assertEqual(result['availableProfiles'], ['gleam-secure-stream', 'gleam-micro-mux'])

    def test_sctp_and_webrtc_prerequisite_diagnostics_are_explicit(self):
        with patch('Deployment.profile_availability.socket.socket',side_effect=OSError('SCTP unavailable')):
            result=inspect_profile(self.catalog,'cpp','cpp-sctp-tls13',report=self.report('cpp'))
        self.assertFalse(result['available'])
        self.assertEqual(result['diagnostics'][0]['code'],'KernelSCTPUnavailable')
        self.assertIn('operator',result['diagnostics'][0]['action'])
        with patch('Deployment.service_runtime.feature_report',side_effect=ValueError('libdatachannel unavailable')):
            result=inspect_profile(self.catalog,'nim','nim-webrtc')
        self.assertFalse(result['available'])
        self.assertIn('libdatachannel',result['diagnostics'][0]['action'])

    def test_supervisor_degradation_is_explicit_and_unavailable(self):
        with patch('Deployment.profile_availability.sys.platform', 'darwin'):
            result = inspect_profile(self.catalog, 'go', report=self.report('go'))
        self.assertFalse(result['available'])
        self.assertEqual(result['diagnostics'][0]['code'], 'NamedSupervisorUnavailable')


if __name__ == '__main__': unittest.main()
