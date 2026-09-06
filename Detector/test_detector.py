import json
import os
import stat
import struct
import tempfile
import unittest
from pathlib import Path

from detector_core import RF_FEATURES, RF_FORMAT, SafeRandomForestModel, TrafficFeatures
from watch import clean_output


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


if __name__ == "__main__":
    unittest.main()
