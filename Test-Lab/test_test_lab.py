from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import tarfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "Crosed"))
import artifacts
from fingerprint import analyze
from network import SCENARIOS, netem_argv, netem_veth_argv, symmetric_loopback_settings
from native_profiles import CORE_IDS, profiles, profile_digest
from shadow6_test_lab import _core_coverage, _s6epe_matrix


def ipv4_packet(protocol, payload, source, target):
    src = ipaddress.IPv4Address(source).packed
    dst = ipaddress.IPv4Address(target).packed
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, protocol, 0, src, dst)
    return b"\x00" * 12 + b"\x08\x00" + header + payload


def tcp_frame(source_port, target_port, payload, *, syn_flags=0x18):
    header = struct.pack("!HHLLBBHHH", source_port, target_port, 1, 0,
                         5 << 4, syn_flags, 65535, 0, 0)
    source, target = (("192.0.2.10", "198.51.100.20") if source_port != 443
                      else ("198.51.100.20", "192.0.2.10"))
    return ipv4_packet(6, header + payload, source, target)


def pcap_bytes(frames):
    result = bytearray(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    for seconds, microseconds, frame in frames:
        result.extend(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
        result.extend(frame)
    return bytes(result)


class FingerprintTests(unittest.TestCase):
    def test_extracts_tcp_flow_tls_observation_and_timing_without_identity_inference(self):
        hello = b"\x16\x03\x03\x00\x04\x01\x00\x00\x00"
        frames = [(10, 0, tcp_frame(41000, 443, b"", syn_flags=0x02)),
                  (10, 1000, tcp_frame(443, 41000, b"", syn_flags=0x12)),
                  (10, 2000, tcp_frame(41000, 443, b"", syn_flags=0x10)),
                  (10, 3000, tcp_frame(41000, 443, hello))]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.pcap"
            path.write_bytes(pcap_bytes(frames))
            result = analyze(path, run_id="fixture-1", core="test", profile="test-profile")
        self.assertEqual(result["schema"], "shadow6.wan-pcap-fingerprint.v1")
        self.assertEqual(len(result["flows"]), 1)
        self.assertEqual(result["flows"][0]["transport"], "tcp")
        self.assertIn("tls-record-observed", result["classification"]["observed"])
        self.assertAlmostEqual(result["flows"][0]["tcpHandshakeSeconds"], 0.002)
        self.assertEqual(result["capture"]["runId"], "fixture-1")
        self.assertIn("no DPI-resistance inference", result["classification"]["meaning"])

    def test_explicit_plaintext_fixture_fails_leak_scan_without_echoing_secret(self):
        marker = b"fixture-private-test-value"
        frame = tcp_frame(443, 4444, marker)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.pcap"
            path.write_bytes(pcap_bytes([(10, 0, frame)]))
            report = analyze(path, forbidden_literals=[marker])
        self.assertEqual(report["leakScan"]["status"], "detected")
        self.assertEqual(report["leakScan"]["explicitForbiddenLiteralDigests"],
                         [hashlib.sha256(marker).hexdigest()])
        self.assertNotIn(marker.decode(), json.dumps(report))

    def test_truncated_capture_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.pcap"
            path.write_bytes(b"\xd4\xc3\xb2\xa1")
            with self.assertRaisesRegex(ValueError, "truncated"):
                analyze(path)


class NetworkScenarioTests(unittest.TestCase):
    def test_scenarios_are_bounded_and_directional_presets_differ(self):
        self.assertEqual(SCENARIOS["good-wan"]["kind"], "simulated")
        self.assertNotEqual(SCENARIOS["good-wan"]["a_to_b"], SCENARIOS["good-wan"]["b_to_a"])
        self.assertEqual(netem_argv({"latency_ms": 30, "jitter_ms": 4, "loss_percent": 1})[:7],
                         ["tc", "qdisc", "replace", "dev", "lo", "root", "netem"])
        self.assertEqual(netem_veth_argv("s6tl-a", SCENARIOS["good-wan"]["a_to_b"])[4], "s6tl-a")

    def test_unknown_unbounded_and_arbitrary_interface_inputs_are_rejected(self):
        for settings in ({"command": "sh -c true"}, {"loss_percent": 101}, {"latency_ms": True}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                netem_argv(settings)
        with self.assertRaises(ValueError):
            netem_veth_argv("eth0", {"latency_ms": 1})

    def test_loopback_keeps_directional_intent_as_a_conservative_symmetric_bound(self):
        effective = symmetric_loopback_settings(
            {"latency_ms": 20, "loss_percent": 1, "rate_kbit": 2048, "queue_limit": 100},
            {"latency_ms": 45, "loss_percent": 2, "rate_kbit": 1024, "queue_limit": 80},
        )
        self.assertEqual(effective, {"latency_ms": 45, "loss_percent": 2,
                                     "rate_kbit": 1024, "queue_limit": 80})


class ArtifactManifestTests(unittest.TestCase):
    def test_linux_idris_companion_uses_explicit_architecture_name_and_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = root / "shadow6-idris-ubuntu-latest-X64"
            current.mkdir()
            self.assertEqual(artifacts.locate_linux_idris_artifact(root), current)
            legacy = root / "shadow6-idris-ubuntu-latest"
            legacy.mkdir()
            with self.assertRaisesRegex(ValueError, "multiple Linux Idris"):
                artifacts.locate_linux_idris_artifact(root)

    def make_artifacts(self, root):
        for relative in artifacts.expected_files():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x7fELF-test-artifact-" + relative.encode())
            path.chmod(0o755)

    def test_registry_drives_exact_twelve_binary_manifest_and_digest_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_artifacts(root)
            manifest_path = root / artifacts.MANIFEST
            manifest = artifacts.write_manifest(root, manifest_path, commit="a" * 40,
                                                run_id="12345", workflow="multiplatform")
            self.assertEqual(len(manifest["files"]), 12)
            inventory = artifacts.verify_inventory(root, manifest_path=manifest_path,
                                                    expected_commit="a" * 40)
            self.assertEqual(inventory["available"], 12)
            self.assertEqual(inventory["denominator"], 12)
            self.assertTrue(all(item["integrity"] == "manifest-verified" for item in inventory["cores"]))
            path = root / manifest["files"][0]["path"]
            path.write_bytes(b"tampered")
            changed = artifacts.verify_inventory(root, manifest_path=manifest_path)
            self.assertTrue(any(item["integrity"] == "failed" for item in changed["cores"]))

    def test_manifest_rejects_commit_drift_and_duplicate_json_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_artifacts(root)
            path = root / artifacts.MANIFEST
            artifacts.write_manifest(root, path, commit="b" * 40)
            with self.assertRaisesRegex(ValueError, "does not match"):
                artifacts.verify_inventory(root, manifest_path=path, expected_commit="c" * 40)
            path.write_text('{"schema":"wrong","schema":"shadow6.test-lab-artifacts.v1"}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                artifacts.load_manifest(path)

    def test_github_zip_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "unsafe.zip"
            import zipfile
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("../escaped", b"bad")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                artifacts._safe_extract(archive, root / "extract")

    def test_idris_runtime_tar_is_bounded_extracted_and_file_digests_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "shadow6-idris").write_text("#!/bin/sh\nexit 0\n")
            digest = hashlib.sha256((source / "shadow6-idris").read_bytes()).hexdigest()
            (source / "SHA256SUMS").write_text(
                f"{hashlib.sha256(b'').hexdigest()}  ./SHA256SUMS\n{digest}  ./shadow6-idris\n")
            archive = root / "runtime.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(source / "SHA256SUMS", arcname="./SHA256SUMS")
                output.add(source / "shadow6-idris", arcname="./shadow6-idris")
            extracted = root / "Core-Idris"
            artifacts._safe_extract_runtime_tar(archive, extracted)
            artifacts._verify_idris_checksums(extracted)
            self.assertEqual((extracted / "shadow6-idris").read_text(), "#!/bin/sh\nexit 0\n")
            (extracted / "shadow6-idris").write_text("tampered")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                artifacts._verify_idris_checksums(extracted)

    def test_nested_runtime_tar_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                import io
                member = tarfile.TarInfo("../../escaped")
                member.size = 4
                output.addfile(member, io.BytesIO(b"oops"))
            with self.assertRaisesRegex(ValueError, "path traversal"):
                artifacts._safe_extract_runtime_tar(archive, root / "extract")

    def test_nim_native_provider_is_taken_from_same_release_bundle_not_s6epe_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / "Core-Nim"
            core.mkdir()
            native_binary = b"nim-core-same-run"
            (core / "shadow6-nim").write_bytes(native_binary)
            (core / "shadow6-nim").chmod(0o755)
            package = root / "ci-artifacts" / "linux" / "Shadow6.tar.gz"
            package.parent.mkdir(parents=True)
            with tarfile.open(package, "w:gz") as output:
                for name, data in (("Shadow6/Core-Nim/shadow6-nim", native_binary),
                                   ("Shadow6/Core-Nim/libdatachannel.so.0.23", b"native websocket provider")):
                    import io
                    member = tarfile.TarInfo(name)
                    member.mode = 0o755
                    member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
            package.chmod(0o644)
            companion = root / "companions" / "shadow6-s6epe-linux-runtime"
            (companion / "lib").mkdir(parents=True)
            s6epe_library = companion / "lib" / "libdatachannel.so.0.23"
            s6epe_library.write_bytes(b"standard carrier provider")
            s6epe_library.chmod(0o644)
            missing = artifacts.merge_runtime_companions(root, idris_artifact=None,
                                                          s6epe_artifact=companion)
            self.assertEqual(missing, [])
            self.assertEqual((core / "libdatachannel.so.0.23").read_bytes(), b"native websocket provider")
            self.assertEqual((root / "runtime-artifacts" / "shadow6-s6epe-linux-runtime" / "lib" /
                              "libdatachannel.so.0.23").read_bytes(), b"standard carrier provider")


class RegistryCoverageTests(unittest.TestCase):
    def test_registry_has_twelve_cores_and_all_registered_profiles(self):
        self.assertEqual(len(CORE_IDS), 12)
        self.assertEqual(len({profile["id"] for profile in profiles()}), 13)
        self.assertEqual(len(_s6epe_matrix()), 16)

    def test_android_and_six_epe_statuses_remain_explicitly_not_run(self):
        self.assertTrue(all(row["status"] == "NOT-RUN" for row in _s6epe_matrix()))


if __name__ == "__main__":
    unittest.main()
