"""Profile normalization at the fleet/native configuration boundary."""
import unittest
from Deployment.native_realization import realize_native_node
from Deployment.profile_registry import topology_profile


class ProfileRealizationTests(unittest.TestCase):
    def realize(self, settings, *, family='gleam', override=None):
        nodes = [{'name': role, 'type': role, 'engines': ['shadow6-' + family]}
                 for role in ('broker', 'agent', 'client')]
        return realize_native_node(topo={'global': settings, 'nodes': nodes},
            node=nodes[2], core_engine='shadow6-' + family,
            broker_pub='broker-public', broker_priv='broker-private',
            agents_data=[], clients_data=[], agent_keys={'agent': ('agent-public', 'agent-private')},
            client_keys={'client': ('client-public', 'client-private')},
            broker_url='ws://127.0.0.1:4433/ws', native_configs=override or {}, sni=None)

    def test_explicit_profiles_realize_distinct_contracts(self):
        for transport in ('secure-stream', 'micro-mux'):
            explicit = self.realize({'native_profile': 'gleam-' + transport})
            legacy = self.realize({'gleam_transport': transport})
            self.assertEqual(explicit, legacy)
            self.assertEqual(explicit['client']['transport'], transport)

    def test_conflicts_never_fall_back(self):
        for settings in ({'native_profile': 'rust-quic'},
                         {'native_profile': 'gleam-unknown'},
                         {'native_profile': 'gleam-secure-stream', 'gleam_transport': 'micro-mux'}):
            with self.subTest(settings=settings), self.assertRaisesRegex(ValueError, 'InvalidCoreProfileBinding'):
                self.realize(settings)

    def test_override_cannot_change_locked_profile_transport(self):
        with self.assertRaisesRegex(ValueError, 'ProfileConfigMismatch'):
            self.realize({'native_profile': 'gleam-secure-stream'},
                override={'client': {'role': 'client', 'client': {'transport': 'micro-mux'}}})

    def test_legacy_gleam_selector_cannot_select_other_family(self):
        with self.assertRaisesRegex(ValueError, 'only to Gleam'):
            topology_profile('go', {'gleam_transport': 'micro-mux'})


if __name__ == '__main__':
    unittest.main()
