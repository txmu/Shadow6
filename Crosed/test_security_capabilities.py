"""Source inventory checks without compiling or executing any Native Core."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from feature_contract import CORE_PATHS, TRANSPORTS
from security_capabilities import CONTROLS, ROOT, load_matrix, markdown, validate_matrix


class NativeSecurityMatrixTests(unittest.TestCase):
    def setUp(self):
        self.matrix = load_matrix()

    def rejects(self, mutate):
        value = copy.deepcopy(self.matrix)
        mutate(value)
        with self.assertRaises(ValueError):
            validate_matrix(value)

    def test_all_twelve_source_contracts_match_current_sources(self):
        matrix = load_matrix(source_root=ROOT)
        self.assertEqual({row['core'] for row in matrix['cores']}, set(CORE_PATHS))
        self.assertEqual(len(matrix['cores']), 12)
        for row in matrix['cores']:
            self.assertEqual(row['transport'], TRANSPORTS[row['core']])
            self.assertEqual(set(row['capabilities']), CONTROLS)

    def test_unknown_fields_rejected_at_every_object_level(self):
        accessors = [lambda m: m, lambda m: m['outer_domain'],
                     lambda m: m['cores'][0],
                     lambda m: m['cores'][0]['capabilities']['encryption'],
                     lambda m: m['cores'][0]['evidence'][0],
                     lambda m: m['cores'][2]['legacy_modes'][0]]
        for accessor in accessors:
            with self.subTest(accessor=accessor):
                self.rejects(lambda m: accessor(m).update(unknown=True))

    def test_incomplete_duplicate_and_transport_mismatched_inventory_rejected(self):
        self.rejects(lambda m: m['cores'].pop())
        self.rejects(lambda m: m['cores'].__setitem__(1, m['cores'][0]))
        self.rejects(lambda m: m['cores'][0].update(transport='quic'))
        self.rejects(lambda m: m['cores'][0]['capabilities'].pop('persistent_replay'))
        self.rejects(lambda m: m['cores'][0]['capabilities']['rekey'].update(status='guaranteed'))

    def test_outer_domain_flags_are_exact_booleans(self):
        for key in ('independent', 'mandatory_encryption', 'native_protocol_translation'):
            self.rejects(lambda m: m['outer_domain'].update({key: 1 if key != 'native_protocol_translation' else 0}))
        self.rejects(lambda m: m.update(security_domain='all-components'))

    def test_source_references_cannot_escape_or_cross_core_families(self):
        for name in ('/etc/passwd', '../Core-Go/data.go', 'Core-Go/../Core-Rust/src/main.rs',
                     'Core-Go//data.go', 'Core-Rust/src/main.rs', 'Core-Go\\data.go'):
            self.rejects(lambda m: m['cores'][0]['evidence'][0].update(path=name))
        self.rejects(lambda m: m['cores'][0].update(evidence=[]))
        self.rejects(lambda m: m['cores'][0]['evidence'].append(m['cores'][0]['evidence'][0]))

    def test_changed_or_unavailable_source_evidence_fails(self):
        value = copy.deepcopy(self.matrix)
        value['cores'][0]['evidence'][0]['contains'] = 'source assertion deliberately missing'
        with self.assertRaises(ValueError):
            validate_matrix(value, source_root=ROOT)
        with tempfile.TemporaryDirectory(prefix='shadow6-matrix-') as directory:
            with self.assertRaises(ValueError):
                validate_matrix(self.matrix, source_root=directory)

    def test_document_parser_rejects_duplicates_numbers_and_excessive_input(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-matrix-') as directory:
            path = Path(directory) / 'matrix.json'
            for text in ('{"schema":"x","schema":"y"}', '{"x":1.0}', '{"x":1}',
                         '{"x":NaN}', '{"x":Infinity}', '[' * 2000 + ']' * 2000,
                         ' ' * 65537):
                with self.subTest(text=text[:40]):
                    path.write_text(text)
                    with self.assertRaises(ValueError):
                        load_matrix(path)

    def test_not_declared_is_distinct_from_negative_security_guarantee(self):
        rows = {row['core']: row for row in self.matrix['cores']}
        self.assertEqual(rows['shadow6-go']['capabilities']['replay']['status'], 'limited')
        self.assertEqual(rows['shadow6-rust']['capabilities']['encryption']['status'], 'transport')
        self.assertEqual(rows['shadow6-nim']['capabilities']['rekey']['status'], 'not-declared')
        self.assertEqual(rows['shadow6-carp']['capabilities']['replay']['status'], 'mode-dependent')
        for row in rows.values():
            persistent = row['capabilities']['persistent_replay']
            self.assertEqual(persistent['status'], 'not-declared')
            self.assertIn('Crosed', persistent['detail'])

    def test_published_table_is_generated_from_matrix(self):
        text = (ROOT / 'docs/native-security-capabilities.md').read_text()
        table = text.split('<!-- matrix:start -->\n', 1)[1].split('\n<!-- matrix:end -->', 1)[0]
        self.assertEqual(table, markdown(self.matrix))


if __name__ == '__main__':
    unittest.main()
