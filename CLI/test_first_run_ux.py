"""First-run regressions use existing adapters; no builds or external network."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import shadow6

ROOT = Path(shadow6.__file__).resolve().parents[1]


class FirstRunUXTests(unittest.TestCase):
    def invoke(self, *args, cwd=None, clean=False, root=ROOT, env=None):
        environment = {key: value for key, value in os.environ.items()
                       if key not in {'PYTHONPATH', 'SHADOW6_ROOT', 'SHADOW6_PYTHON',
                                      'SHADOW6_RUNTIME_SELECTED', 'SHADOW6_CORE_DESCRIPTORS'}}
        if env: environment.update(env)
        return subprocess.run([sys.executable, *(['-S'] if clean else []),
                               str(root / 'CLI/shadow6.py'), *args], cwd=cwd,
                              env=environment, capture_output=True, text=True, timeout=20)

    def test_help_without_dependencies_from_unrelated_cwd(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-help-') as directory:
            for action in ('install', 'setup', 'run', 'status', 'connect', 'stop',
                           'restart', 'relock', 'remove', 'doctor'):
                result = self.invoke(action, '--help', cwd=directory, clean=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('usage:', result.stdout)
            result = self.invoke('setup', '--help', cwd=directory, clean=True)
            self.assertIn('binding.json', result.stdout)
            self.assertIn('--core go --profile go-kcp', result.stdout)
            self.assertIn('--run', result.stdout)

    def test_install_json_uses_existing_prebuilt_installer_and_stderr_logs(self):
        output=io.StringIO()
        with mock.patch.object(sys,'argv',['shadow6','install','--prefix','/tmp/shadow6-test-prefix','--json']), \
             mock.patch('subprocess.run',return_value=mock.Mock(returncode=0)) as installer, \
             contextlib.redirect_stdout(output):
            self.assertEqual(shadow6.main(),0)
        self.assertEqual(installer.call_args.args[0][:2],['make','install-prebuilt'])
        self.assertIs(installer.call_args.kwargs['stdout'],sys.stderr)
        self.assertEqual(json.loads(output.getvalue())['operation'],'install-prebuilt')

    def test_no_arguments_show_first_run_discovery(self):
        result=self.invoke(clean=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('shadow6 doctor --human',result.stdout)
        self.assertIn('shadow6 setup --help',result.stdout)

    def test_human_connect_reports_bound_profile_and_waits_for_readiness(self):
        import shadow6_connect as connect
        plan={'core':'go','profileBinding':{'profile':'go-kcp'},'state':'observed',
              'readiness':'listener-ready','applicationBoundary':None,'endpoint':None}
        output=io.StringIO()
        with mock.patch.object(sys,'argv',['shadow6-connect','home/nas','--human']), \
             mock.patch.object(connect,'resolve_connection',return_value=plan), \
             mock.patch.object(connect,'CoreCatalog'),mock.patch.object(connect,'ServiceRegistry'), \
             contextlib.redirect_stdout(output):
            connect.main()
        self.assertIn('Profile: go-kcp',output.getvalue())
        self.assertIn('Readiness: listener-ready',output.getvalue())
        self.assertIn('shadow6 doctor home/nas',output.getvalue())
        self.assertNotIn('--records',output.getvalue())

    def test_core_required_error_has_recovery_without_registry(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-explicit-') as directory:
            registry = Path(directory) / 'services.json'
            result = self.invoke('setup', 'home/nas', cwd=directory,
                                 env={'SHADOW6_SERVICE_REGISTRY': str(registry)})
            self.assertEqual(result.returncode, 2, result.stderr)
            error = json.loads(result.stderr)
            self.assertEqual(error['error'], 'CoreSelectionRequired')
            self.assertIn('core profiles --installed', error['hint'])
            self.assertFalse(registry.exists())

    def test_binding_relative_path_is_anchored_to_binding_file(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-binding-') as directory:
            binding = Path(directory) / 'binding.json'
            binding.write_text('{"config_path":"native.json"}'); binding.chmod(0o600)
            self.assertEqual(shadow6.load_service_config(binding)['config_path'],
                             str(Path(directory) / 'native.json'))
            binding.chmod(0o644)
            if os.name != 'nt':
                with self.assertRaises(ValueError): shadow6.load_service_config(binding)

    def test_relock_only_locks_and_does_not_start_or_apply(self):
        registry = mock.Mock()
        registry.lock.return_value = {'schema': 'shadow6.deployment-lock.v2'}
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['shadow6', 'relock', 'home/nas', '--human']), \
             mock.patch.object(shadow6, 'ServiceRegistry', return_value=registry), \
             mock.patch.object(shadow6, 'CoreCatalog'), contextlib.redirect_stdout(output):
            self.assertEqual(shadow6.main(), 0)
        registry.lock.assert_called_once_with('home/nas')
        registry.apply.assert_not_called(); registry.run.assert_not_called()
        self.assertIn('shadow6 apply home/nas', output.getvalue())

    def test_lifecycle_options_work_before_or_after_service_name(self):
        for action in shadow6.LIFECYCLE_ACTIONS:
            for tail in (['home/nas','--json'],['--json','home/nas']):
                with mock.patch.object(sys,'argv',['shadow6',action,*tail]), \
                     mock.patch.object(shadow6,'lifecycle_action',return_value=0) as lifecycle:
                    self.assertEqual(shadow6.main(),0)
                lifecycle.assert_called_once_with(action,'home/nas',human=False)
        result=self.invoke('status','home/nas','--help',clean=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('--human',result.stdout)

    def test_human_failure_shows_missing_prerequisite_and_repair(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            shadow6.lifecycle_output({'error': 'ProfileUnavailable', 'diagnostics': [
                {'code': 'KernelSCTPUnavailable', 'message': 'Kernel SCTP unavailable',
                 'action': 'Ask the operator to enable kernel SCTP.'}]}, human=True, error=True)
        self.assertIn('KernelSCTPUnavailable', output.getvalue())
        self.assertIn('enable kernel SCTP', output.getvalue())

    def test_portable_clean_doctor_reports_artifacts_dependencies_and_no_state(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-portable-') as directory:
            tree = Path(directory) / 'portable'
            # Reproduce an extracted tree with standard-library-only Python and
            # no Core products; keep module copies outside the original checkout.
            for component in ('CLI', 'Crosed', 'Deployment', 'Public6', 'Tools', 'Control-Center'):
                target = tree / component; target.mkdir(parents=True)
                for source in (ROOT / component).glob('*.py'):
                    shutil.copy2(source, target / source.name)
            (tree / 'Makefile').write_text('# portable tree marker\n')
            registry = Path(directory) / 'services.json'
            descriptor = Path(directory) / 'cores.json'
            environment = {'SHADOW6_SERVICE_REGISTRY': str(registry),
                           'SHADOW6_CORE_DESCRIPTORS': str(descriptor)}
            result = self.invoke('doctor', '--json', root=tree, cwd=directory,
                                 clean=True, env=environment)
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['root'], str(tree))
            self.assertEqual(len(report['profiles']), 13)
            self.assertEqual(report['availableProfiles'], [])
            self.assertEqual(report['runtimeMaterialsMissing'], [])
            self.assertFalse(report['python']['dependencies_ok'])
            self.assertTrue(all(any(d['code'] == 'NativeArtifactMissing' for d in p['diagnostics'])
                                for p in report['profiles']))
            self.assertFalse(registry.exists()); self.assertFalse(descriptor.exists())
            self.assertIn('SCTP', report['privacyEnvelope']['hint'])
            self.assertIn('WebRTC', report['privacyEnvelope']['hint'])
            for action in ('setup', 'connect'):
                result = self.invoke(action, '--help', root=tree, cwd=directory, clean=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_environment_doctor_detects_unsafe_runtime_material_before_setup(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-material-') as directory:
            material=Path(directory)/'service_runtime.py'
            material.write_text('# fixture'); material.chmod(0o666)
            runtime=mock.Mock()
            runtime.runtime_report.return_value={'usable':True}
            with mock.patch.dict(sys.modules, {'python_runtime':runtime}), \
                 mock.patch('profile_availability.installed_profiles', return_value={'profiles':[], 'availableProfiles':['go-kcp']}), \
                 mock.patch('service_runtime.runtime_material_paths',return_value={'service_runtime':str(material)}):
                report=shadow6.environment_doctor()
            self.assertFalse(report['healthy'])
            self.assertEqual(report['runtimeMaterialsMissing'],['service_runtime'])
            self.assertIn('without group/world write',report['diagnostics'][0]['action'])

    def test_connect_json_error_keeps_explicit_selection_and_recovery(self):
        from protocol_context import minimal_context
        from join_code import pack_protocol
        result=self.invoke('connect','--protocol-envelope',pack_protocol(minimal_context()),'--json')
        self.assertEqual(result.returncode,2,result.stderr)
        error=json.loads(result.stderr)
        self.assertEqual(error['stage'],'connect')
        self.assertIn('CoreSelectionRequired',error['error'])
        self.assertIn('Choose --core explicitly',error['hint'])

    def test_direct_native_config_reuses_binding_and_private_file_check(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-native-setup-') as directory:
            native=Path(directory)/'core.json'; native.write_text('{}'); native.chmod(0o600)
            catalog=mock.Mock()
            def check_config(core, config):
                self.assertEqual(core,'go')
                self.assertEqual(config,{'config_path':str(native)})
            catalog.binding.side_effect=check_config
            for mode,expected in ((0o600,0),(0o644,2)):
                if mode==0o644 and os.name=='nt': continue
                native.chmod(mode)
                with mock.patch.object(sys,'argv',['shadow6','setup','home/nas','--core','go',
                        '--native-config',str(native),'--check']), \
                     mock.patch.object(shadow6,'CoreCatalog',return_value=catalog), \
                     mock.patch.object(shadow6,'ServiceRegistry',side_effect=AssertionError('registry opened')), \
                     mock.patch('profile_availability.inspect_profile',return_value={'available':True,'profile':'go-kcp'}), \
                     mock.patch.object(shadow6,'service_spec',return_value={}), \
                     mock.patch.object(shadow6,'service_context',return_value={}), \
                     contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(shadow6.main(),expected)
            catalog.binding.assert_called_once()

    def test_missing_config_and_failed_setup_check_do_not_create_state(self):
        with tempfile.TemporaryDirectory(prefix='shadow6-preflight-') as directory:
            registry = Path(directory) / 'services.json'
            with mock.patch.object(sys, 'argv', ['shadow6', 'setup', 'home/nas', '--core', 'go',
                                               '--check', '--config', str(Path(directory)/'absent.json')]), \
                 mock.patch.object(shadow6, 'ServiceRegistry', side_effect=AssertionError('opened registry')), \
                 mock.patch('profile_availability.inspect_profile', return_value={'available': True, 'profile': 'go-kcp'}), \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(shadow6.main(), 2)
            report = json.loads(errors.getvalue())
            self.assertIn('binding.json', report['hint'])
            self.assertFalse(registry.exists())


if __name__ == '__main__': unittest.main()
