"""Lightweight adversarial checks for artifact admission and report truthfulness."""
import os
import json
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch, Mock
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(HERE), str(ROOT / 'Deployment'), str(ROOT / 'Crosed')]
import artifacts
from service_storage import strict_json
import test_test_lab as fixtures
from shadow6_test_lab import _core_coverage, _scenario_case, _worker
import network
from native_profiles import profiles


class ArtifactTrustTests(unittest.TestCase):
    def test_path_parser_rejects_normalization_aliases_and_wrong_types(self):
        for value in ('a/../b', 'a/./b', 'a//b', '/a', 'a\\b', 'a\0b', [], None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                artifacts._safe_relative(value)

    def test_hash_rejects_ancestor_symlinks_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'real').mkdir()
            source = root / 'real' / 'binary'
            source.write_bytes(b'artifact')
            source.chmod(0o600)
            (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaises(OSError): artifacts.sha256_file(root / 'alias' / 'binary')
            os.link(source, root / 'hardlink')
            with self.assertRaises(ValueError): artifacts.sha256_file(source)

    def test_hash_detects_same_size_rewrite_and_path_replacement(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / 'binary'
                source.write_bytes(b'original')
                source.chmod(0o600)
                original_read = os.read
                changed = False
                def rewrite(fd, size):
                    nonlocal changed
                    data = original_read(fd, size)
                    if data and not changed:
                        changed = True
                        previous = source.stat()
                        target = source.with_suffix('.new') if replacement else source
                        target.write_bytes(b'modified')
                        target.chmod(0o600)
                        os.utime(target, ns=(previous.st_atime_ns, previous.st_mtime_ns + 1_000_000))
                        if replacement: os.replace(target, source)
                    return data
                with patch.object(artifacts.os, 'read', side_effect=rewrite), self.assertRaisesRegex(ValueError, 'changed'):
                    artifacts.sha256_file(source)

    def test_only_actions_0644_to_manifest_0755_mode_restoration_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures.ArtifactManifestTests().make_artifacts(root)
            manifest = root / artifacts.MANIFEST
            artifacts.write_manifest(root, manifest, commit='a' * 40)
            binary = root / next(iter(artifacts.expected_files()))
            binary.chmod(0o644)
            accepted = artifacts.verify_inventory(root, manifest_path=manifest)
            self.assertTrue(accepted['cores'][0]['actionsModeRestored'])
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
            binary.chmod(0o740)
            rejected = artifacts.verify_inventory(root, manifest_path=manifest)
            self.assertEqual(rejected['cores'][0]['integrity'], 'failed')

    def test_manifest_rejects_workflow_run_attempt_platform_and_architecture_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures.ArtifactManifestTests().make_artifacts(root)
            manifest = root / artifacts.MANIFEST
            artifacts.write_manifest(root, manifest, commit='a' * 40, run_id='123',
                                     run_attempt='2', platform='linux', architecture='x86_64')
            for key, value in (('expected_workflow', 'other'), ('expected_run_id', '124'),
                    ('expected_run_attempt', '1'), ('expected_platform', 'windows'),
                    ('expected_architecture', 'aarch64')):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'identity'):
                    artifacts.verify_inventory(root, manifest_path=manifest, **{key: value})

    def test_archives_reject_links_special_files_and_write_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, mode in enumerate((stat.S_IFLNK | 0o777, stat.S_IFSOCK | 0o600, stat.S_IFREG | 0o666)):
                archive = root / f'{index}.zip'
                with zipfile.ZipFile(archive, 'w') as output:
                    info = zipfile.ZipInfo('binary')
                    info.external_attr = mode << 16
                    output.writestr(info, b'x')
                with self.assertRaises(ValueError): artifacts._safe_extract(archive, root / f'out{index}')
            archive = root / 'links.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                info = tarfile.TarInfo('alias')
                info.type = tarfile.SYMTYPE
                info.linkname = 'binary'
                output.addfile(info)
            with self.assertRaisesRegex(ValueError, 'link'):
                artifacts._safe_extract_runtime_tar(archive, root / 'tar-out')


class PortableJSONTests(unittest.TestCase):
    def test_shared_portable_conformance_corpus(self):
        import crosedctl
        corpus = json.loads((ROOT / 'Tools/strict_json_conformance.json').read_text())
        self.assertEqual(corpus['schema'], 'shadow6.strict-json-conformance.v1')
        for parser in (strict_json, artifacts._strict_json, crosedctl.strict_json):
            for case in corpus['cases']:
                with self.subTest(parser=parser.__module__, case=case['id']):
                    try: parser(case['input'].encode('utf-8'))
                    except (ValueError, RuntimeError): accepted = False
                    else: accepted = True
                    self.assertEqual(accepted, case['accepted'])

    def test_rejects_non_utf8_ambiguity_and_resource_overflow(self):
        inputs = (b'{"x":1,"x":2}', b'{"x":1,"\\u0078":2}', b'{"x":NaN}',
            b'{"x":Infinity}', b'{"x":1.5}', b'{} {}', b'{"x":"\\ud800"}',
            b'{"x":9007199254740992}', ('[' * 80 + '0' + ']' * 80).encode(),
            '{}'.encode('utf-16'), b'{"x":"\\u0000"}')
        for parser in (strict_json, artifacts._strict_json):
            for value in inputs:
                with self.subTest(parser=parser.__name__, value=value[:80]), self.assertRaises(ValueError):
                    parser(value)
        with self.assertRaisesRegex(ValueError, 'size'):
            strict_json('"你好"', limit=6)

    def test_floats_require_explicit_measurement_policy_and_still_reject_nonfinite(self):
        self.assertEqual(strict_json('{"rtt":0.25}', allow_measurement_floats=True), {'rtt': 0.25})
        for value in ('{"rtt":1e999}', '{"rtt":NaN}', '{"rtt":Infinity}'):
            with self.assertRaises(ValueError): strict_json(value, allow_measurement_floats=True)


class ReportEvidenceTests(unittest.TestCase):
    def test_worker_pass_requires_matching_structured_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'worker.py').write_text('print(\'{"status":"PASS"}\')\n')
            with patch('shadow6_test_lab.HERE', root), self.assertRaisesRegex(ValueError, 'readiness'):
                _worker(profiles()[0], Path('/unused'), payload_bytes=4096, requests=2, namespace=None)

    def test_requested_capture_cannot_pass_without_namespace_evidence(self):
        profile = profiles()[0]
        with tempfile.TemporaryDirectory() as directory, \
                patch('shadow6_test_lab.Namespace.create', side_effect=PermissionError('denied')), \
                patch('shadow6_test_lab._worker', return_value={'status': 'PASS', 'correctness': {'status': 'PASS'}}):
            row = _scenario_case(profile, Path('/unused'), 'clean', Path(directory), 'fixture',
                                 capture_enabled=True, payload_bytes=4096, requests=2)
        self.assertEqual(row['status'], 'BLOCKED')
        self.assertEqual(row['correctness']['status'], 'PASS')
        inventory = {'cores': [{'core': p['core'], 'available': True} for p in profiles() if p['primary']]}
        coverage = _core_coverage([profile], [row], inventory)
        self.assertEqual(coverage['executed'], 1)
        self.assertEqual(coverage['counts']['PASS'], 0)

    def test_pair_uses_resolved_tc_and_keeps_directional_parameters_distinct(self):
        pair = network.NamespacePair()
        pair.ip = '/trusted/ip'
        pair.created = [pair.a, pair.b]
        pair._run = Mock()
        with patch.object(network, 'system_tool', return_value='/trusted/tc'):
            pair.apply({'latency_ms': 1}, {'latency_ms': 7, 'queue_limit': 100})
        calls = [call.args[0] for call in pair._run.call_args_list]
        self.assertEqual(calls[0][4], '/trusted/tc')
        self.assertEqual(calls[0][2:4], ['exec', pair.a])
        self.assertEqual(calls[1][2:4], ['exec', pair.b])
        self.assertIn('1ms', calls[0])
        self.assertIn('7ms', calls[1])
        self.assertIn('100', calls[1])

    def test_failure_recovery_is_scheduled_after_workload_ready(self):
        namespace = Mock(name='namespace')
        namespace.name = 'fixture-owned-namespace'
        phases = []
        namespace.apply.side_effect = lambda settings: phases.append(settings)
        class ImmediateThread:
            def __init__(self, *, target, args, daemon): self.target, self.args = target, args
            def start(self): self.target(*self.args)
            def join(self, timeout): pass
        def worker(*args, **kwargs):
            self.assertEqual(len(phases), 1)
            kwargs['on_ready']()
            self.assertEqual(len(phases), 3)
            return {'status': 'PASS', 'correctness': {'status': 'PASS'}}
        with tempfile.TemporaryDirectory() as directory, \
                patch('shadow6_test_lab.Namespace.create', return_value=namespace), \
                patch('shadow6_test_lab._worker', side_effect=worker), \
                patch('shadow6_test_lab.threading.Thread', ImmediateThread), \
                patch('shadow6_test_lab.time.sleep'):
            row = _scenario_case(profiles()[0], Path('/unused'), 'failure-recovery', Path(directory),
                                 'fixture', capture_enabled=False, payload_bytes=4096, requests=2)
        self.assertEqual(row['failureInjection']['status'], 'applied')
        self.assertIn('not inferred', row['failureInjection']['reconnectClaim'])


if __name__ == '__main__': unittest.main()
