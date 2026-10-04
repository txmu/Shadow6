"""Architecture contracts for the shared registry, without Native Core builds."""
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_profiles import (CORE_IDS, application_boundaries, artifact_map,
    profile_digest, profiles, select_profile, transport_map)
from feature_contract import (APP_TRANSPORT_MODES, CORE_PATHS, SEQPACKET_MAX_RECORD,
    STREAM_CONNECTION_LIMIT, TRANSPORTS)


class NativeProfileTests(unittest.TestCase):
    def test_complete_unique_profiles(self):
        items = profiles()
        self.assertEqual(len(items), 13)
        self.assertEqual(len(CORE_IDS), 12)
        self.assertEqual(len({p['id'] for p in items}), 13)
        self.assertEqual(sum(p['applicationBoundary']['kind'] == 'stream' for p in items), 8)
        self.assertEqual(sum(p['applicationBoundary']['kind'] == 'message' for p in items), 5)
        for p in items:
            with self.subTest(profile=p['id']):
                self.assertEqual(select_profile(p['core'], p['id']), p)
                self.assertEqual(p['roles'], ['broker', 'agent', 'client'])
                self.assertFalse(p['composition']['nativeTranslation'])
                self.assertFalse(p['readiness']['processAliveSufficient'])
                self.assertEqual(p['attachment']['kind'], p['applicationBoundary']['kind'])
                self.assertRegex(profile_digest(p), '^sha256:[0-9a-f]{64}$')
                self.assertNotIn('available', p)

    def test_all_core_profile_pairs(self):
        # Every legal and illegal pair, rather than merely counting 13 records.
        for core in CORE_IDS:
            for p in profiles():
                with self.subTest(core=core, profile=p['id']):
                    if core == p['core']:
                        self.assertEqual(select_profile(core, p['id']), p)
                    else:
                        with self.assertRaisesRegex(ValueError, 'InvalidCoreProfileBinding'):
                            select_profile(core, p['id'])

    def test_explicit_gleam_contracts(self):
        stream = select_profile('gleam', 'gleam-secure-stream')
        message = select_profile('gleam', 'gleam-micro-mux')
        self.assertEqual(stream['attachment']['kind'], 'stream')
        self.assertEqual(message['attachment']['kind'], 'message')
        self.assertFalse(message['applicationBoundary']['reliable'])
        self.assertEqual(message['limits']['max_record'], 65465)
        self.assertEqual(select_profile('gleam')['id'], stream['id'])

    def test_unknown_never_falls_back(self):
        for core, profile in [('unknown', None), ('go', 'unknown'), ('gleam', ''),
                              ([], None), ('go', []), (None, None)]:
            with self.subTest(core=core, profile=profile), self.assertRaises(ValueError):
                select_profile(core, profile)

    def test_detached_records_and_drift(self):
        p = select_profile('go')
        original = profile_digest(p)
        p['roles'].clear()
        self.assertEqual(select_profile('go')['roles'], ['broker', 'agent', 'client'])
        with self.assertRaisesRegex(ValueError, 'NativeProfileContractDrift'):
            profile_digest(p)
        for key, value in [('primary', 1), ('unknown', True)]:
            p = select_profile('go'); p[key] = value
            with self.assertRaisesRegex(ValueError, 'NativeProfileContractDrift'):
                profile_digest(p)
        self.assertEqual(profile_digest(select_profile('go')), original)

    def test_boundary_numeric_types_do_not_coerce(self):
        from test_feature_contract import FeatureContractTests
        from feature_contract import validate_feature_report
        for value in (64.0, True):
            report = FeatureContractTests().with_modes('shadow6-go')
            report['application_boundaries'][0]['local_connection_limit'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'boundary'):
                validate_feature_report(report, 'shadow6-go')

    def test_shared_feature_and_artifact_facts(self):
        self.assertEqual(CORE_PATHS, artifact_map())
        self.assertEqual(TRANSPORTS, transport_map())
        self.assertEqual(transport_map(configuration=True)['shadow6-cpp'], 'sctp')
        self.assertEqual(TRANSPORTS['shadow6-cpp'], 'sctp-tls13')
        for core in CORE_IDS:
            for b in application_boundaries(core):
                if b['kind'] == 'stream':
                    self.assertEqual(STREAM_CONNECTION_LIMIT['shadow6-' + core], b['local_connection_limit'])
                elif b['mode'] == 'seqpacket-fd':
                    self.assertEqual(SEQPACKET_MAX_RECORD['shadow6-' + core], b['max_record'])
                    self.assertEqual(APP_TRANSPORT_MODES['shadow6-' + core], ['udp', 'seqpacket-fd'])
        self.assertEqual(len(artifact_map(benchmark=True)), 13)


if __name__ == '__main__':
    unittest.main()
