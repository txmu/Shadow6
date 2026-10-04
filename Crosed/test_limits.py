import copy
import unittest
from limits import HostBudget, LimitResolver, validate_policy
from native_profiles import profiles

class LimitsTests(unittest.TestCase):
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
        self.assertEqual(original['effective_limits']['process_fds'],256)

    def test_low_host_cannot_change_immutable_native_capacity(self):
        with self.assertRaises(ValueError):
            self.resolver.resolve(profiles()[0], host=HostBudget(1024,128,1,'linux'))

if __name__ == '__main__': unittest.main()
