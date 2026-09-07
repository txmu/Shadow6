import unittest
from feature_contract import TRANSPORTS, validate_feature_report

class FeatureContractTests(unittest.TestCase):
    def report(self, core):
        return dict(core=core, version="1.1.0", crosed_compiled=False,
            crosed_max_level=0, app_transport=False, qubes_isolation=False,
            gate_compiled=False, gate_enabled_by_default=False, utf8=True,
            crosed_capabilities=[], transport=TRANSPORTS[core])

    def test_every_core_and_its_specific_fields(self):
        for core in TRANSPORTS:
            report = self.report(core)
            report.update({"shadow6-ada": {"cell_size": 512}, "shadow6-d": {"better_c": True},
                           "shadow6-nim": {"memory_model": "arc"}}.get(core, {}))
            self.assertEqual(validate_feature_report(report, core), report)

    def test_unknown_missing_mistyped_and_contradictory_fields(self):
        for patch in ({"unknown": True}, {"crosed_max_level": True},
                      {"crosed_capabilities": ["core.hook"]}, {"transport": "quic"},
                      {"gate_enabled_by_default": True}, {"crosed_compiled": True},
                      {"crosed_capabilities": [[], []]}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                validate_feature_report(dict(self.report("shadow6-nim"), **patch))
        report = self.report("shadow6-ada")
        del report["gate_compiled"]
        with self.assertRaises(ValueError): validate_feature_report(report)

    def test_family_fields_cannot_leak_to_other_cores(self):
        with self.assertRaises(ValueError):
            validate_feature_report(dict(self.report("shadow6-go"), better_c=True))
        with self.assertRaises(ValueError):
            validate_feature_report(self.report("shadow6-d"), "shadow6-nim")
