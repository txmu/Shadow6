"""Profile-driven service/lock admission; no Native Core compilation.

The thirteen-Profile lock matrix uses fixture artifacts to test authority and
material admission. It does not claim real native trio/lifecycle coverage.
"""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Deployment.core_catalog import CoreCatalog
from Deployment.protocol_context import minimal_context
from Deployment.profile_registry import (bind_profile, profiles,
    validate_profile_binding)
from Deployment.service_registry import ServiceRegistry
from Deployment.service_storage import atomic_write, strict_json
from Deployment import service_runtime

ROOT = Path(__file__).resolve().parents[1]


class ProfileBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='shadow6-profile-lock-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.catalog = CoreCatalog(ROOT)
        binary = self.directory / 'fixture'
        binary.write_text('#!/bin/false\n'); binary.chmod(0o700)
        for item in self.catalog.list(): item['executable'] = str(binary)
        self.registry = ServiceRegistry(self.directory / 'services.json', self.catalog)

    def create(self, profile, *, native=None, context=None, name='test/profile'):
        path = self.directory / (profile['id'] + '.json')
        if native is None:
            if profile['realization']['launcher'] == 'native-files':
                from Deployment.test_message_attachment import native_config
                native = native_config(profile['core'])
            else:
                native = {'role': 'client', 'client': {'transport': profile['configTransport']}}
        atomic_write(path, json.dumps(native).encode())
        return self.registry.create(name, core=profile['core'], profile=profile['id'],
            config={'config_path': str(path)}, context=context)

    def test_all_profiles_bind_lock_apply_and_export_exact_material(self):
        for profile in profiles():
            with self.subTest(profile=profile['id']):
                name = 'test/' + profile['id']
                item = self.create(profile, name=name)
                expected = bind_profile(profile['core'], profile['id'])
                self.assertEqual(item['profileBinding'], expected)
                lock = self.registry.lock(name)
                self.assertEqual(lock['profileBinding'], expected)
                self.assertEqual(self.registry.apply(name)['state'], 'applied')
                _, plan = self.registry.launch_plan(name)
                self.assertEqual(plan['profileBinding'], expected)
                service_runtime.verify_launch_material(plan)
                altered = copy.deepcopy(plan)
                altered['componentLimits']['process_fds'] += 1
                with self.assertRaisesRegex(ValueError, 'InvalidComponentLimitsSchema|ComponentLimitsDrift|deployment drift before launch: componentLimits'):
                    service_runtime.verify_launch_material(altered)
                self.assertNotIn('profileBinding', item['protocolContext'])
                self.assertNotIn('config_path', json.dumps(item['protocolContext']))
                self.registry.remove(name)
        self.assertEqual(self.registry.list(), [])

    def test_run_requires_preexisting_lock_and_never_creates_one(self):
        self.create(profiles('go')[0])
        with patch('Deployment.service_registry.runtime.start') as start:
            with self.assertRaisesRegex(ValueError, 'DeploymentLock required'):
                self.registry.run('test/profile')
            start.assert_not_called()
        self.assertNotIn('deploymentLock', self.registry.inspect('test/profile'))

    def test_legacy_record_requires_explicit_profile_reconfiguration(self):
        profile = profiles('gleam')[1]
        self.create(profile)
        self.registry.lock('test/profile')
        value = strict_json(self.registry.path.read_bytes())
        item = value['services']['test/profile']
        item.pop('profileBinding'); item['deploymentLock'].pop('profileBinding')
        atomic_write(self.registry.path, json.dumps(value).encode())
        with self.assertRaisesRegex(ValueError, 'ProfileBinding required'):
            self.registry.run('test/profile')
        # Loading or attempting run has not guessed the primary Profile.
        self.assertNotIn('profileBinding', strict_json(self.registry.path.read_bytes())['services']['test/profile'])
        self.registry.stop('test/profile')
        self.registry.configure('test/profile', core='gleam', profile=profile['id'],
            config=item['coreBinding']['config'])
        self.assertEqual(self.registry.lock('test/profile')['profileBinding']['profile'], profile['id'])

    def test_profile_drift_does_not_refresh_or_replace_lock(self):
        profile = profiles('go')[0]
        self.create(profile); self.registry.lock('test/profile')
        value = strict_json(self.registry.path.read_bytes())
        item = value['services']['test/profile']
        item['profileBinding']['contractDigest'] = 'sha256:' + '0' * 64
        atomic_write(self.registry.path, json.dumps(value).encode())
        before = self.registry.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'ProfileBindingDrift'):
            self.registry.apply('test/profile')
        self.assertEqual(self.registry.path.read_bytes(), before)
        self.registry.stop('test/profile')  # Drift must not prevent safe cleanup.

    def test_wrong_profile_unknown_fields_and_types_are_rejected(self):
        original = bind_profile('go')
        for change in ({'core': 'rust'}, {'profile': 'rust-quic'},
                       {'extra': True}, {'contractDigest': 1}, {'profile': None}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_profile_binding({**original, **change}, core='go')

    def test_native_config_and_portable_boundary_mismatch_fail_before_spawn(self):
        profile = profiles('gleam')[1]
        for native in ({'role': 'client', 'client': {'transport': 'secure-stream'}},
                       {'role': 'client'}, {'role': 'client', 'core': 'go'}):
            self.create(profile, native=native)
            with self.assertRaisesRegex(ValueError, 'ProfileConfigMismatch'):
                self.registry.lock('test/profile')
            self.registry.remove('test/profile')
        context = minimal_context('gleam')
        context['routes'] = [{'boundary': 'stream', 'endpoint': 'tcp://127.0.0.1:1234'}]
        self.create(profile, context=context)
        with self.assertRaisesRegex(ValueError, 'ProfileCapabilityMismatch'):
            self.registry.lock('test/profile')

    def test_failed_reconfiguration_preserves_original_lock_and_service(self):
        profile = profiles('go')[0]
        item = self.create(profile); self.registry.lock('test/profile')
        before = self.registry.path.read_bytes()
        for kwargs in ({'profile': 'rust-quic'}, {'spec': {'unknown': True}},
                       {'privacy': 'unknown'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.registry.configure('test/profile', core='go',
                    config=item['coreBinding']['config'], **kwargs)
            self.assertEqual(self.registry.path.read_bytes(), before)

    def test_failed_native_replacement_does_not_destroy_previous_lock(self):
        profile = profiles('gleam')[0]
        item = self.create(profile); self.registry.lock('test/profile')
        path = self.directory / 'replacement.json'
        atomic_write(path, b'{"role":"client","client":{"transport":"micro-mux"}}')
        before = self.registry.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'ProfileConfigMismatch'):
            self.registry.configure('test/profile', core='gleam', profile=profile['id'],
                config={'config_path': str(path)})
        self.assertEqual(self.registry.path.read_bytes(), before)
        self.assertEqual(self.registry.apply('test/profile')['state'], 'applied')

    def test_upgrade_commits_replacement_lock_without_starting_service(self):
        old = profiles('go')[0]
        self.create(old); self.registry.lock('test/profile')
        path = self.directory / 'upgrade-gleam.json'
        atomic_write(path, json.dumps({'role':'client','client':{'transport':'secure-stream'}}).encode())
        result = self.registry.upgrade('test/profile', core='gleam', profile='gleam-secure-stream',
            config={'config_path':str(path)}, context=minimal_context('gleam'))
        self.assertEqual(result['state'], 'applied')
        self.assertEqual(result['profileBinding']['profile'], 'gleam-secure-stream')
        self.assertIsNone(result.get('runtime'))
        self.assertTrue(self.registry.doctor('test/profile')['lockValid'])

    def test_upgrade_failure_restores_previous_lock_atomically(self):
        old = profiles('go')[0]
        self.create(old); self.registry.lock('test/profile')
        # A valid, privately owned registry need not already use the manager's
        # compact serialization. Rollback must preserve its exact bytes.
        value = json.loads(self.registry.path.read_text())
        before = (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode()
        atomic_write(self.registry.path, before)
        path = self.directory / 'bad-upgrade.json'
        atomic_write(path, json.dumps({'role':'client','client':{'transport':'micro-mux'}}).encode())
        with self.assertRaisesRegex(ValueError, 'ProfileConfigMismatch'):
            self.registry.upgrade('test/profile', core='gleam', profile='gleam-secure-stream',
                config={'config_path':str(path)}, context=minimal_context('gleam'))
        self.assertEqual(self.registry.path.read_bytes(), before)
        self.assertEqual(self.registry.apply('test/profile')['state'], 'applied')

    def test_upgrade_apply_failure_restores_raw_registry_after_lock_writes(self):
        from unittest.mock import patch
        old = profiles('go')[0]
        self.create(old); self.registry.lock('test/profile')
        value = json.loads(self.registry.path.read_text())
        before = (json.dumps(value, sort_keys=False, indent=2) + '\n').encode()
        atomic_write(self.registry.path, before)
        path = self.directory / 'upgrade-apply-failure.json'
        atomic_write(path, json.dumps({'role':'client',
            'client':{'transport':'secure-stream'}}).encode())
        with patch.object(self.registry, 'apply', side_effect=RuntimeError('injected apply failure')):
            with self.assertRaisesRegex(RuntimeError, 'injected apply failure'):
                self.registry.upgrade('test/profile', core='gleam',
                    profile='gleam-secure-stream', config={'config_path':str(path)},
                    context=minimal_context('gleam'))
        self.assertEqual(self.registry.path.read_bytes(), before)
        self.assertEqual(self.registry.inspect('test/profile')['profileBinding']['core'], 'go')
        self.assertEqual(self.registry.inspect('test/profile')['state'], 'locked')

    def test_guard_tls_external_material_is_locked_and_rechecked(self):
        profile = profiles('go')[0]
        self.create(profile)
        cert, key = self.directory / 'guard-cert.pem', self.directory / 'guard-key.pem'
        atomic_write(cert, b'guard-certificate'); atomic_write(key, b'guard-private-key')
        config = self.directory / 'guard.json'
        atomic_write(config, json.dumps({'role': 'broker_guard', 'broker_shield': {
            'enabled': True, 'tls_cert_file': str(cert), 'tls_key_file': str(key)}}).encode())
        self.catalog.component_binary = lambda component: Path(self.catalog.inspect('go')['executable'])
        self.registry.configure('test/profile', core='go', profile=profile['id'],
            config=self.registry.require_binding('test/profile')['config'], spec={
                'guard_config': str(config),
                'limits': {'mode':'custom','operator_overrides':{'process_fds':768}}})
        self.registry.lock('test/profile')
        _, plan = self.registry.launch_plan('test/profile')
        material_key = 'guard.broker_shield.tls_key_file'
        self.assertEqual(plan['componentMaterials'][material_key], str(key))
        service_runtime.verify_launch_material(plan)
        omitted = copy.deepcopy(plan); omitted['componentMaterials'] = {}
        with self.assertRaisesRegex(ValueError, 'component launch material differs'):
            service_runtime.verify_launch_material(omitted)
        atomic_write(key, b'replaced-guard-key')
        with self.assertRaisesRegex(ValueError, 'drift before launch: componentMaterial'):
            service_runtime.verify_launch_material(plan)
        with self.assertRaisesRegex(ValueError, 'deployment drift'):
            self.registry.apply('test/profile')

    def test_credited_attachment_config_key_and_limits_are_locked(self):
        profile = profiles('go')[0]
        item = self.create(profile)
        key = self.directory / 's6na.key'
        atomic_write(key, b'k' * 32)
        attachment = self.directory / 's6na.json'
        atomic_write(attachment, json.dumps({
            'schema':'shadow6.s6na-attachment.v1','core':'go',
            'key_file':str(key),'bind':['127.0.0.1',41000],
            'peer':['127.0.0.1',41001],'side':0,'stream':0,
            'limits':{'max_message':4096,'max_inflight':4096,
                      'payload_bytes':128,'window_frames':32}}).encode())
        self.registry.configure('test/profile', core='go', profile=profile['id'],
            config=item['coreBinding']['config'],
            spec={'credited_config':str(attachment)})
        lock = self.registry.lock('test/profile')
        self.assertEqual(lock['componentLimits']['components']['credited']['max_message'],4096)
        _, plan = self.registry.launch_plan('test/profile')
        self.assertEqual(plan['creditedAttachment']['keyPath'],str(key))
        service_runtime.verify_launch_material(plan)
        atomic_write(key, b'x' * 32)
        with self.assertRaisesRegex(ValueError,'deployment drift'):
            self.registry.apply('test/profile')

    def test_doctor_uses_locked_profile_and_reports_missing_feature_contract(self):
        profile = profiles('go')[0]
        self.create(profile); self.registry.lock('test/profile')
        result = self.registry.doctor('test/profile')
        self.assertTrue(result['lockValid'])
        self.assertTrue(result['materialValid'])
        self.assertFalse(result['healthy'])
        self.assertFalse(result['featureReportValid'])
        self.assertIn('InstalledProfileFeatureReportUnavailableOrMismatch', result['findings'])
        self.assertEqual(result['profileBinding'], bind_profile('go'))
        self.assertIsNone(result['runtime'])

    def test_native_tls_reference_drift_permissions_and_plan_omission(self):
        profile = profiles('nim')[0]
        cert, key = self.directory / 'cert.pem', self.directory / 'key.pem'
        atomic_write(cert, b'fixture-certificate'); atomic_write(key, b'fixture-private-key')
        item = self.create(profile, native={'role': 'broker', 'broker':
            {'tls_cert': str(cert), 'tls_key': str(key)}})
        self.registry.lock('test/profile')
        _, plan = self.registry.launch_plan('test/profile')
        self.assertEqual(plan['nativeMaterials']['broker.tls_key'], str(key))
        self.assertIn('nativeMaterial:broker.tls_key', plan['launchDigests'])
        service_runtime.verify_launch_material(plan)
        omitted = copy.deepcopy(plan); omitted['nativeMaterials'].pop('broker.tls_key')
        with self.assertRaisesRegex(ValueError, 'native launch material differs'):
            service_runtime.verify_launch_material(omitted)
        atomic_write(key, b'replaced-key')
        with self.assertRaisesRegex(ValueError, 'drift before launch'):
            service_runtime.verify_launch_material(plan)
        with self.assertRaisesRegex(ValueError, 'deployment drift'):
            self.registry.apply('test/profile')
        key.chmod(0o644)
        with self.assertRaises(ValueError): self.registry.lock('test/profile')




class ProfileRuntimeIdentityTests(unittest.TestCase):
    from Deployment.test_service_lifecycle import ServiceLifecycleTests as _Fixtures
    setUp = _Fixtures.setUp
    cleanup_process = _Fixtures.cleanup_process

    def test_process_alive_never_receives_startup_acknowledgement(self):
        self.binary.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(1)\n')
        self.registry.configure('home/nas', core='go', config={'config_path':str(self.config)})
        self.registry.apply('home/nas')
        with self.assertRaisesRegex(ValueError, 'failed to start'):
            self.registry.run('home/nas')
        self.assertNotEqual(self.registry.status('home/nas')['state'], 'running')

    def test_runtime_profile_identity_drift_is_stale_and_stoppable(self):
        self.registry.run('home/nas')
        value = strict_json(self.registry.path.read_bytes())
        value['services']['home/nas']['runtime']['profileBinding']['contractDigest'] = 'sha256:' + '0' * 64
        atomic_write(self.registry.path, json.dumps(value).encode())
        actual = self.registry.status('home/nas')
        self.assertEqual(actual['state'], 'stale')
        self.assertEqual(actual['runtime']['readiness'], 'unavailable')
        self.assertIsNone(actual['runtime']['endpoint'])
        stopped = self.registry.stop('home/nas')
        self.assertFalse(service_runtime.alive(stopped['runtime']))

    def test_owned_component_crash_is_failed(self):
        import hashlib, os, signal, time
        actual = self.registry.run('home/nas')
        path = self.registry.path.parent / (hashlib.sha256(b'home/nas').hexdigest() + '.runtime.json.observed')
        observation = strict_json(path.read_bytes())
        child = observation['processes'][0]
        self.assertTrue(service_runtime.alive(child))
        os.kill(child['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 3
        while service_runtime.alive(actual['runtime']) and time.monotonic() < deadline:
            time.sleep(.05)
        actual = self.registry.status('home/nas')
        self.assertEqual(actual['state'], 'failed')
        self.assertEqual(actual['runtime']['readiness'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
