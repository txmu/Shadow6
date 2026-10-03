import copy
import json
import unittest
from pathlib import Path

from Deployment.topology_contract import check_topology, selected_engine
from Deployment.shadow6_deployment import validate_manifest, node_context
from Deployment.protocol_context import check_binding, minimal_context
from Deployment.core_catalog import CoreCatalog


class TopologyContractTests(unittest.TestCase):
    def test_same_family_and_no_implicit_translation(self):
        for engine in ('go', 'rust', 'zig', 'ada', 'd', 'nim', 'cpp', 'pony', 'hare', 'carp', 'gleam', 'idris'):
            bindings = [{'core': engine, 'role': role} for role in ('broker', 'agent', 'client')]
            self.assertFalse(check_topology(bindings)['nativeTranslation'])
            bindings[1]['core'] = 'rust' if engine != 'rust' else 'go'
            with self.assertRaisesRegex(ValueError, 'same core engine'):
                check_topology(bindings)

    def test_zig_control_exception_is_explicit_and_broker_only(self):
        for family in ('go', 'rust'):
            self.assertEqual(selected_engine(['shadow6-zig', 'shadow6-' + family], 'broker'), family)
            for role in ('agent', 'client'):
                with self.assertRaises(ValueError): selected_engine([family, 'zig'], role)
        for family in ('ada', 'nim', 'cpp', 'hare'):
            with self.assertRaises(ValueError): selected_engine([family, 'zig'], 'broker')
        with self.assertRaises(ValueError): selected_engine(['go', 'go'], 'broker')

    def test_deployment_cannot_bind_a_different_native_family(self):
        value = json.loads((Path(__file__).parent / 'example.deployment.json').read_text())
        validate_manifest(value)
        for role in ('broker', 'agent', 'client'):
            changed = copy.deepcopy(value)
            node = next(n for n in changed['spec']['nodes'] if n['role'] == role)
            node['core'] = 'go'
            with self.assertRaisesRegex(ValueError, 'CoreBinding conflicts'):
                validate_manifest(changed)
            with self.assertRaisesRegex(ValueError, 'CoreBinding conflicts'):
                node_context(changed, node)

    def test_portable_route_engine_restricts_broad_core_scope(self):
        context = minimal_context()
        context['routes'] = [{'kind': 'broker_set', 'id': 'pool', 'engine': 'rust',
                             'policy': 'priority', 'members': [{'identity': 'broker', 'endpoint': 'wss://example.invalid/ws'}]}]
        check_binding(context, 'rust', CoreCatalog())
        with self.assertRaisesRegex(ValueError, 'CoreBinding conflicts'):
            check_binding(context, 'go', CoreCatalog())

    def test_malformed_bindings_are_rejected(self):
        for bindings in ([], [{}], [None], [{'core': 'go', 'role': 'unknown'}]):
            with self.assertRaises(ValueError): check_topology(bindings)


if __name__ == '__main__':
    unittest.main()
