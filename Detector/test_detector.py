import json
import os
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from detector_core import RF_FEATURES, RF_FORMAT, SafeRandomForestModel, TrafficFeatures
from watch import ShadowSentinel, clean_output


def leaf_model():
    return {
        "format": RF_FORMAT,
        "features": RF_FEATURES,
        "classes": [0, 1],
        "estimators": [
            {
                "children_left": [-1],
                "children_right": [-1],
                "feature": [-2],
                "threshold": [-2.0],
                "value": [[[0.0, 3.0]]],
            }
        ],
    }


def ipv4_udp_packet(source: bytes, destination: bytes, source_port: int, destination_port: int, payload: bytes):
    ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
    total_length = 20 + 8 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        17,
        0,
        source,
        destination,
    )
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    return ethernet + ipv4 + udp + payload


class DetectorCoreTests(unittest.TestCase):
    def test_threat_event_preserves_direction(self):
        packet = ipv4_udp_packet(b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01", 5000, 4321, b"probe")
        identity = ShadowSentinel._alert_identity(TrafficFeatures.threat_event(packet))
        self.assertEqual(identity, ("10.0.0.2", 4321))
        self.assertIsNone(TrafficFeatures.threat_event(b"short"))

    def test_sentinel_output_is_bounded_and_sanitized(self):
        cleaned = clean_output("\x1b[31mALERT\x1b[0m\n" + "x" * 5000)
        self.assertFalse("\x1b" in cleaned)
        self.assertFalse("\n" in cleaned)
        self.assertEqual(len(cleaned), 4096)

    def test_udp_features_and_bidirectional_flow_key(self):
        payload = b"AAAA"
        forward = ipv4_udp_packet(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 1234, 4321, payload)
        reverse = ipv4_udp_packet(b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01", 4321, 1234, payload)
        length, entropy, is_tcp, payload_size = TrafficFeatures.extract_features(forward)
        self.assertEqual(length, len(forward))
        self.assertEqual(entropy, 0.0)
        self.assertEqual(is_tcp, 0)
        self.assertEqual(payload_size, len(payload))
        self.assertEqual(TrafficFeatures.flow_key(forward), TrafficFeatures.flow_key(reverse))

    def test_truncated_and_non_ip_packets_are_safe(self):
        for packet in (b"", b"\x00" * 13, b"\x00" * 14, b"\x00" * 33):
            result = TrafficFeatures.extract_features(packet)
            self.assertEqual(len(result), 4)
            self.assertGreaterEqual(result[0], 0)

    def test_safe_forest_predicts_valid_leaf(self):
        model = SafeRandomForestModel(leaf_model())
        self.assertEqual(model.predict([[128, 1.0, 1, 74, 0.001]]), [1])
        with self.assertRaisesRegex(ValueError, "five finite"):
            model.predict([[1, 2]])
        with self.assertRaisesRegex(ValueError, "five finite"):
            model.predict([[128, float("nan"), 1, 74, 0.001]])

    def test_safe_forest_rejects_invalid_documents(self):
        cases = []
        unknown = leaf_model()
        unknown["unexpected"] = True
        cases.append(unknown)

        bad_votes = leaf_model()
        bad_votes["estimators"][0]["value"] = [[[1.0]]]
        cases.append(bad_votes)

        bad_leaf = leaf_model()
        bad_leaf["estimators"][0]["children_left"] = [0]
        bad_leaf["estimators"][0]["children_right"] = [0]
        cases.append(bad_leaf)

        cycle = leaf_model()
        cycle["estimators"][0] = {
            "children_left": [1, 0],
            "children_right": [1, 0],
            "feature": [0, 0],
            "threshold": [1.0, 1.0],
            "value": [[[1.0, 0.0]], [[0.0, 1.0]]],
        }
        cases.append(cycle)

        for document in cases:
            with self.subTest(document=document), self.assertRaises(ValueError):
                SafeRandomForestModel(document)

    def test_model_loader_rejects_writable_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "model.json"
            model_path.write_text(json.dumps(leaf_model()), encoding="utf-8")
            os.chmod(model_path, 0o600)
            self.assertEqual(SafeRandomForestModel.load(model_path).classes, [0, 1])

            os.chmod(model_path, 0o622)
            with self.assertRaises(PermissionError):
                SafeRandomForestModel.load(model_path)
            os.chmod(model_path, 0o600)

            link_path = Path(directory) / "model-link.json"
            link_path.symlink_to(model_path)
            with self.assertRaises(ValueError):
                SafeRandomForestModel.load(link_path)
            self.assertEqual(stat.S_IMODE(model_path.stat().st_mode), 0o600)


class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.sentinel = ShadowSentinel(["detector"], "/tmp/orchestrator", "/tmp/topology", 300)
        self.sentinel.log = lambda *args: None

    def event(self, source=1, port=1000):
        return "SHADOW6_THREAT " + json.dumps({"version": 1, "source": f"192.0.2.{source}", "port": port})

    def test_single_source_and_duplicates_cannot_rotate(self):
        for port in range(1000, 1100):
            self.assertFalse(self.sentinel._allow_rotation(self.event(port=port)))
        for _ in range(20):
            self.assertFalse(self.sentinel._allow_rotation(self.event()))
        self.assertEqual(len(self.sentinel.alert_history), 100)

    def test_global_rotation_requires_multiple_sources_and_ports(self):
        self.assertFalse(self.sentinel._allow_rotation(self.event(1, 1000)))
        self.assertFalse(self.sentinel._allow_rotation(self.event(2, 1001)))
        self.assertTrue(self.sentinel._allow_rotation(self.event(3, 1002)))
        self.sentinel.alert_pending.clear()
        for source in range(4, 10):
            self.assertFalse(self.sentinel._allow_rotation(self.event(source, 1000 + source)))

    def test_unstructured_unknown_and_duplicate_fields_never_count(self):
        for reason in (
            "MALICIOUS PROBE DETECTED",
            'SHADOW6_THREAT {"version":1,"source":"192.0.2.1","port":80,"extra":1}',
            'SHADOW6_THREAT {"version":1,"version":1,"source":"192.0.2.1","port":80}',
            'SHADOW6_THREAT {"version":true,"source":"192.0.2.1","port":80}',
            'SHADOW6_THREAT {"version":1,"source":"not-an-ip","port":80}',
        ):
            self.assertFalse(self.sentinel._allow_rotation(reason))
        self.assertEqual(self.sentinel.alert_history, {})

    def test_failure_and_timeout_consume_cooldown(self):
        import subprocess
        for outcome in (subprocess.CompletedProcess([], 1), subprocess.TimeoutExpired([], 120), OSError("failed")):
            with self.subTest(outcome=outcome):
                self.setUp()
                with patch("watch.time.monotonic", side_effect=[100.0, 101.0]), patch("watch.subprocess.run") as run:
                    if isinstance(outcome, Exception):
                        run.side_effect = outcome
                    else:
                        run.return_value = outcome
                    self.sentinel.trigger_rotation("test")
                    self.sentinel.trigger_rotation("test")
                    self.assertEqual(run.call_count, 1)
                    self.assertEqual(self.sentinel.last_attempt, 100)
                    self.assertEqual(self.sentinel.failure_backoff, 300)

    def test_expired_votes_cannot_accumulate(self):
        with patch("watch.time.monotonic", side_effect=[100, 161, 162]):
            self.assertFalse(self.sentinel._allow_rotation(self.event(1, 1000)))
            self.assertFalse(self.sentinel._allow_rotation(self.event(2, 1001)))
            self.assertFalse(self.sentinel._allow_rotation(self.event(3, 1002)))


if __name__ == "__main__":
    unittest.main()
