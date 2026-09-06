import json
import unittest
from pathlib import Path

from shadow6_public import Public6Error, decode_offer, negotiate, offer_from_feature_report, suite_profile


def offer(family="shadow6-go", version="1.1.0", *, applications=None, dimensions=None, extensions=None):
    return {
        "schema_version": 1,
        "suite": "public6",
        "core": {"family": family, "version": version},
        "applications": applications or {},
        "dimensions": dimensions or {},
        "extensions": extensions or {},
    }


class Public6Tests(unittest.TestCase):
    def test_only_core_identity_is_mandatory(self):
        local = offer(
            applications={"shadow.chat": [1, 2]},
            dimensions={"crosed.level": ["5"], "transport.optional": ["quic"]},
            extensions={"org.example.alpha": [1, 2]},
        )
        peer = offer(
            applications={"shadow.files": [7]},
            dimensions={"crosed.level": ["0"], "transport.optional": ["kcp"]},
            extensions={"org.example.beta": [9]},
        )
        result = negotiate(local, peer)
        self.assertTrue(result["compatible"])
        self.assertEqual(result["applications"], {})
        self.assertEqual(result["dimensions"], {})
        self.assertEqual(result["extensions"], {})

    def test_optional_intersections_choose_compatible_values(self):
        local = offer(
            applications={"shadow.chat": [1, 2]},
            dimensions={"transport.optional": ["kcp", "quic"]},
            extensions={"org.example.codec": [1, 3]},
        )
        peer = offer(
            applications={"shadow.chat": [1]},
            dimensions={"transport.optional": ["quic", "tcp"]},
            extensions={"org.example.codec": [1, 2]},
        )
        result = negotiate(local, peer)
        self.assertEqual(result["applications"], {"shadow.chat": 1})
        self.assertEqual(result["dimensions"], {"transport.optional": ["quic"]})
        self.assertEqual(result["extensions"], {"org.example.codec": 1})

    def test_core_family_or_version_mismatch_fails(self):
        self.assertFalse(negotiate(offer(), offer(version="1.2.0"))["compatible"])
        self.assertFalse(negotiate(offer(), offer(family="shadow6-rust"))["compatible"])

    def test_strict_bounded_portable_offer(self):
        invalid = offer()
        invalid["unknown"] = True
        with self.assertRaises(Public6Error):
            decode_offer(json.dumps(invalid).encode())
        with self.assertRaises(Public6Error):
            decode_offer(b'{"value":1.5}')

    def test_feature_report_differences_are_optional(self):
        base = {
            "core": "shadow6-go", "version": "1.1.0", "crosed_compiled": False,
            "crosed_max_level": 0, "app_transport": False, "qubes_isolation": False,
            "gate_compiled": True, "gate_enabled_by_default": False,
            "utf8": True, "crosed_capabilities": [],
        }
        full = dict(base, crosed_compiled=True, crosed_max_level=5, app_transport=True,
                    qubes_isolation=True, crosed_capabilities=["observe.version"])
        self.assertTrue(negotiate(offer_from_feature_report(base), offer_from_feature_report(full))["compatible"])

    def test_profile_enables_everything_except_compliance(self):
        profile = suite_profile()
        self.assertEqual(profile["core_engines"], ["shadow6-go", "shadow6-rust"])
        self.assertEqual(profile["components"], "all")
        self.assertFalse(profile["compliance"])


if __name__ == "__main__":
    unittest.main()
