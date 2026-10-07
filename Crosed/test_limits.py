import copy
import unittest
from limits import HostBudget, LimitResolver, validate_policy, S6SG1_PROTOCOL_LIMITS
from native_profiles import profiles

class LimitsTests(unittest.TestCase):
    def test_webrtc_signalling_capacity_uses_operator_sessions_and_host_fd_budget(self):
        config = {'envelope': {'carrier': 'webrtc', 'max_sessions': '7', 'max_preauth': '2',
                               'max_frame': '4096', 'idle_timeout': '30'}}
        result = self.resolver.resolve_components(config, host=self.host, process_fds=512)
        envelope = result['components']['envelope']
        self.assertEqual(envelope['signalling_client_limit'], 28)
        self.assertEqual(envelope['estimated_fds'], 16 + 14 + 1 + 28)
        self.assertEqual(envelope['estimated_memory_bytes'], 2 * 7 * 4096 + 28 * S6SG1_PROTOCOL_LIMITS['sdp_bytes'])
        self.assertIn('S6SG1 bounded semaphore', envelope['enforced_by'])
        with self.assertRaisesRegex(ValueError, 'ComponentLimitExceedsProcessFds'):
            self.resolver.resolve_components(config, host=self.host, process_fds=32)

    def setUp(self):
        self.host = HostBudget(512 * 1024 * 1024, 4096, 2, 'linux')
        self.resolver = LimitResolver()

    def test_all_profiles_all_modes(self):
        for profile in profiles():
            for mode in ('safe', 'elastic', 'custom'):
                with self.subTest(profile=profile['id'], mode=mode):
                    policy = dict(mode=mode, operator_overrides={})
                    result = self.resolver.resolve(profile, policy, self.host).to_dict()
                    self.resolver.validate(result, profile, policy)
                    for row in result['dimensions'].values():
                        self.assertGreater(row['effective'], 0)
                        self.assertLessEqual(row['effective'], row['host_derived_ceiling'])
                        if row['hard_protocol_limit'] is not None:
                            self.assertLessEqual(row['effective'], row['hard_protocol_limit'])

    def test_elastic_uses_cpu_recommendation_with_finite_host_ceiling(self):
        result = self.resolver.resolve(profiles()[0], dict(mode='elastic', operator_overrides={}), self.host)
        self.assertEqual(result.to_dict()['effective_limits']['process_fds'],2048)

    def test_invalid_operator_inputs(self):
        profile = profiles()[0]
        for value in (0, -1, True, 1.5, 2**53, '256'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.resolver.resolve(profile, dict(mode='custom', operator_overrides={'process_fds':value}), self.host)
        for policy in ({'mode':'safe','operator_overrides':{'process_fds':512}},
                       {'mode':'custom','operator_overrides':{'unknown':1}},
                       {'mode':'elastic','operator_overrides':{},'extra':1}):
            with self.assertRaises(ValueError): self.resolver.resolve(profile, policy, self.host)

    def test_protocol_and_host_ceilings(self):
        profile = next(p for p in profiles() if p['core'] == 'carp')
        for overrides in ({'max_record':987}, {'process_fds':4096}, {'local_connection_limit':1}):
            with self.assertRaises(ValueError):
                self.resolver.resolve(profile, dict(mode='custom', operator_overrides=overrides), self.host)
        result = self.resolver.resolve(profile, dict(mode='custom', operator_overrides={'max_record':128}), self.host)
        self.assertEqual(result.to_dict()['effective_limits']['max_record'],128)

    def test_tampering_and_frozen_host(self):
        profile = profiles()[0]
        original = self.resolver.resolve(profile, host=self.host).to_dict()
        changed = copy.deepcopy(original); changed['effective_limits']['process_fds'] = 999
        with self.assertRaises(ValueError): self.resolver.validate(changed, profile)
        changed = copy.deepcopy(original); changed['host_budget']['extra'] = 1
        with self.assertRaises(ValueError): self.resolver.validate(changed, profile)
        with self.assertRaisesRegex(ValueError,'HostBudgetDrift'):
            self.resolver.validate(original, profile, check_host=True)
        self.assertEqual(original['effective_limits']['process_fds'],512)

    def test_low_host_cannot_change_immutable_native_capacity(self):
        with self.assertRaises(ValueError):
            self.resolver.resolve(profiles()[0], host=HostBudget(1024,128,1,'linux'))

    def test_gate_and_envelope_limits_are_bounded_and_drift_checked(self):
        inputs = {
            'gate': {'limits': {'max_connections': 64, 'max_frame_bytes': 8192, 'idle_seconds': 60}},
            'envelope': {'max_sessions': '24', 'max_preauth': '8', 'max_frame': '4096', 'idle_timeout': '30'},
            'guard': {'role':'broker_guard', 'broker_shield': {'enabled':True, 'max_conn_per_ip':32}},
        }
        limits = self.resolver.resolve_components(inputs, host=self.host, process_fds=1024)
        self.assertEqual(limits['components']['gate']['estimated_fds'], 144)
        self.assertEqual(limits['components']['envelope']['estimated_memory_bytes'], 196608)
        self.assertEqual(limits['components']['guard']['max_active_connections'], 256)
        self.assertEqual(limits['components']['guard']['max_active_datagram_workers'], 0)
        self.assertEqual(limits['components']['guard']['estimated_fds'], 529)
        self.assertEqual(limits['components']['guard']['max_connections_per_ip'], 32)
        self.assertEqual(limits['components']['guard']['estimated_memory_bytes'],
            256 * 96 * 1024 + 256 * 512)
        self.assertEqual(limits['estimated_peak_process_fds'], 529)
        self.assertEqual(limits['estimated_total_fds'], 737)
        self.assertEqual(limits['estimated_total_memory_bytes'],
            196608 + 64 * 8192 + 256 * 96 * 1024 + 256 * 512)
        self.resolver.validate_components(limits, inputs, host=self.host, process_fds=1024)
        changed = copy.deepcopy(inputs); changed['gate']['limits']['max_connections'] = 65
        with self.assertRaisesRegex(ValueError, 'ComponentLimitsDrift'):
            self.resolver.validate_components(limits, changed, host=self.host, process_fds=1024)
        with self.assertRaisesRegex(ValueError, 'ComponentLimitExceedsProcessFds'):
            self.resolver.resolve_components({'gate': {'limits': {'max_connections': 300}}}, host=self.host, process_fds=512)
        with self.assertRaisesRegex(ValueError, 'EnvelopePreauthExceedsSessions'):
            self.resolver.resolve_components({'envelope': {'max_sessions': '4', 'max_preauth': '5'}}, host=self.host, process_fds=512)
        with self.assertRaisesRegex(ValueError, 'InvalidGuardLimitConfig'):
            self.resolver.resolve_components({'guard': {'role':'client_guard'}}, host=self.host, process_fds=512)
        agent = {'role':'agent_guard',
            'spa_config': {'enabled':True}, 'lpd_limiter': {'enabled':True},
            'anti_probe': {'enabled':True}}
        resolved = self.resolver.resolve_components({'guard':agent}, host=self.host, process_fds=1024)
        guard_limits = resolved['components']['guard']
        self.assertEqual(guard_limits['tracked_state_entries'], 300_000)
        self.assertEqual(guard_limits['max_active_connections'], 256)
        self.assertEqual(guard_limits['max_active_datagram_workers'], 256)
        self.assertEqual(guard_limits['estimated_fds'], 789)
        self.assertEqual(guard_limits['estimated_memory_bytes'],
            300_000 * 512 + 256 * 80 * 1024 + 256 * 16 * 1024)
        with self.assertRaisesRegex(ValueError, 'ComponentLimitExceedsProcessFds'):
            self.resolver.resolve_components({'guard':agent}, host=self.host, process_fds=512)
        small_fd_host = HostBudget(self.host.memory_bytes, 700, self.host.cpu_units, 'linux')
        combined = {'gate':{'limits':{'max_connections':100}}, 'guard':inputs['guard']}
        with self.assertRaisesRegex(ValueError, 'ComponentLimitExceedsHostFds'):
            self.resolver.resolve_components(combined, host=small_fd_host, process_fds=700)
        with self.assertRaisesRegex(ValueError, 'InvalidGuardLimitConfig'):
            self.resolver.resolve_components({'guard': {'role':'broker_guard',
                'broker_shield': {'enabled':True, 'unexpected':1}}}, host=self.host, process_fds=1024)

    def test_credited_attachment_limits_are_bounded_and_host_admitted(self):
        config = {'schema':'shadow6.s6na-attachment.v1','core':'go',
            'key_file':'/private/key','bind':['127.0.0.1',41000],
            'peer':['127.0.0.1',41001], 'limits':{
                'max_message':4096,'max_inflight':8192,'max_streams':8,
                'max_window':16,'payload_bytes':128,'window_frames':8}}
        result = self.resolver.resolve_components({'credited':config},
            host=self.host, process_fds=512)
        row = result['components']['credited']
        self.assertEqual(row['estimated_fds'],17)
        self.assertEqual(row['max_message'],4096)
        self.assertEqual(row['window_frames'],8)
        self.assertEqual(row['estimated_memory_bytes'],
            2 * 8192 + 8 * (128 + 128) + 8192 * 512 + 8 * 256)
        self.resolver.validate_components(result, {'credited':config},
            host=self.host, process_fds=512)
        with self.assertRaisesRegex(ValueError,'InvalidCreditedLimitConfig'):
            self.resolver.resolve_components({'credited':{**config,
                'limits':{**config['limits'],'unexpected':1}}}, host=self.host, process_fds=512)
        with self.assertRaisesRegex(ValueError,'ComponentLimitExceedsHostMemory'):
            self.resolver.resolve_components({'credited':{**config,
                'limits':{**config['limits'],'max_inflight':256 * 1024 * 1024,
                          'max_message':256 * 1024 * 1024}}},
                host=HostBudget(512 * 1024 * 1024, 4096, 2, 'linux'), process_fds=512)

if __name__ == '__main__': unittest.main()
