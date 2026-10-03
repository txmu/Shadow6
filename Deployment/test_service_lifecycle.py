import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from Deployment.core_catalog import CoreCatalog
from Deployment.service_registry import ServiceRegistry
from Deployment.service_storage import atomic_write, strict_json
from Deployment import service_runtime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'Control-Center'))


class ServiceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='shadow6-service-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root/'core.json'
        atomic_write(self.config, b'{}')
        self.binary = self.root/'test-core'
        self.binary.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(120)\n')
        self.binary.chmod(0o700)
        self.catalog = CoreCatalog(ROOT)
        self.catalog._items['go']['executable'] = str(self.binary)
        self.registry = ServiceRegistry(self.root/'services.json', self.catalog)
        self.registry.create('home/nas', core='go', config={'config_path':str(self.config)})
        self.addCleanup(self.cleanup_process)

    def cleanup_process(self):
        try:
            self.registry.stop('home/nas')
        except ValueError:
            pass

    def test_real_supervisor_idempotent_run_restart_stop_remove(self):
        first = self.registry.run('home/nas')
        self.assertTrue(service_runtime.alive(first['runtime']))
        self.assertEqual(first['privacyTelemetry']['observation'], 'not-configured')
        self.assertNotIn('authenticated_sessions', first['privacyTelemetry'])
        self.assertEqual(self.registry.run('home/nas')['runtime']['pid'], first['runtime']['pid'])
        with self.assertRaises(ValueError):
            self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)})
        second = self.registry.restart('home/nas')
        self.assertNotEqual(second['runtime']['pid'], first['runtime']['pid'])
        self.assertEqual(self.registry.connect('home/nas')['core'], 'go')
        self.registry.stop('home/nas')
        self.assertFalse(service_runtime.alive(second['runtime']))
        with self.assertRaises(ValueError): self.registry.connect('home/nas')
        self.registry.remove('home/nas')
        self.assertEqual(self.registry.list(), [])

    def test_actual_native_config_drift_is_rejected(self):
        self.registry.apply('home/nas')
        atomic_write(self.config, b'{"changed":true}')
        with self.assertRaisesRegex(ValueError, 'drift'):
            self.registry.run('home/nas')
        self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)})
        self.assertEqual(self.registry.apply('home/nas')['state'], 'applied')

    def test_startup_failure_never_claims_running(self):
        self.binary.write_text('#!/usr/bin/env python3\nraise SystemExit(2)\n')
        self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)})
        with self.assertRaisesRegex(ValueError, 'failed to start'):
            self.registry.run('home/nas')
        self.assertNotEqual(self.registry.status('home/nas')['state'], 'running')

    def test_stale_instances_reload_in_transaction(self):
        other = ServiceRegistry(self.registry.path, self.catalog)
        other.create('home/other',core=None,config=None)
        self.registry.init()
        self.assertEqual(len(other.list()), 2)

    def test_registry_symlink_permissions_and_unknown_fields_fail_closed(self):
        link = self.root/'link'; link.symlink_to(self.registry.path)
        with self.assertRaises((ValueError, OSError)): ServiceRegistry(link, self.catalog)
        self.registry.path.chmod(0o644)
        with self.assertRaises(ValueError): ServiceRegistry(self.registry.path, self.catalog)
        self.registry.path.chmod(0o600)
        value = json.loads(self.registry.path.read_text()); value['unknown'] = True
        atomic_write(self.registry.path, json.dumps(value).encode())
        with self.assertRaises(ValueError): ServiceRegistry(self.registry.path, self.catalog)
        del value['unknown']; atomic_write(self.registry.path, json.dumps(value).encode())

    def test_strict_json_and_private_config(self):
        for value in (b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}'):
            with self.assertRaises(ValueError): strict_json(value)
        self.config.chmod(0o644)
        with self.assertRaises(ValueError): self.registry.apply('home/nas')

    def test_cli_identical_setup_reuses_existing_real_go_process(self):
        # An actual built Go broker on loopback; no Core compilation.
        if not (ROOT/'Core-Go/shadow6-go').is_file():
            self.skipTest('existing Go binary unavailable')
        import socket
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()) + key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
        config = self.root/'go.json'
        atomic_write(config,json.dumps({'role':'broker','broker':{'listen_addr':f'127.0.0.1:{port}','private_key':private.hex(),'agents':[],'clients':[],'webhook_url':'','stealth_mode':False}}).encode())
        binding = self.root/'binding.json'; atomic_write(binding,json.dumps({'config_path':str(config)}).encode())
        env = {**os.environ,'SHADOW6_SERVICE_REGISTRY':str(self.root/'native-registry.json')}
        def cli(*args):
            result = subprocess.run([sys.executable,str(ROOT/'CLI/shadow6.py'),*args],env=env,capture_output=True,text=True,timeout=12)
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout)
        try:
            first = cli('setup','test/go','--core','go','--config',str(binding),'--ttl','30')
            second = cli('setup','test/go','--core','go','--config',str(binding),'--ttl','30')
            self.assertEqual(first['runtime']['pid'],second['runtime']['pid'])
            with socket.create_connection(('127.0.0.1',port),timeout=2): pass
            self.assertEqual(cli('connect','test/go')['core'],'go')
        finally:
            cli('stop','test/go')

    def test_pid_identity_mismatch_never_signals(self):
        with patch('Deployment.service_runtime.signal.pidfd_send_signal') as signal:
            service_runtime.stop({'pid':os.getpid(),'processIdentity':'wrong'})
            signal.assert_not_called()

    def test_named_envelope_starts_real_runtime_and_reads_observed_metrics(self):
        binary = os.environ.get('S6EPE_BINARY')
        if not binary:
            self.skipTest('S6EPE_BINARY unavailable; no envelope runtime verification')
        import socket, secrets, hmac
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
        # The fixture Core remains alive; authentication must be measured by OCaml,
        # never by the registry even if the fixture has no native listener.
        with socket.socket() as native_sock:
            native_sock.bind(('127.0.0.1',0));native_port=native_sock.getsockname()[1]
        self.binary.write_text(f'#!/usr/bin/env python3\nimport socket,time\ns=socket.socket();s.bind(("127.0.0.1",{native_port}));s.listen();time.sleep(120)\n')
        atomic_write(self.config,json.dumps({'listen_addr':f'127.0.0.1:{native_port}'}).encode())
        metrics = self.root/'metrics.json'; config = self.root/'envelope.conf'
        key = 'test-only-shared-key-0123456789'
        atomic_write(config,f'listen=127.0.0.1:{port}\nupstream=127.0.0.1:{native_port}\nauth_key={key}\nmetrics_path={metrics}\n'.encode())
        self.catalog.envelope_binary = lambda: Path(binary)
        self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)},privacy='envelope',
                                spec={'envelope_config':str(config),'metrics_path':str(metrics)})
        item = self.registry.run('home/nas')
        self.assertEqual(item['privacyTelemetry']['authenticated_sessions'],0)
        with socket.create_connection(('127.0.0.1',port),timeout=2) as sock:
            nonce = b''
            while len(nonce)<32: nonce += sock.recv(32-len(nonce))
            client = secrets.token_bytes(32)
            sock.sendall(client+hmac.digest(key.encode(),b'S6EPE/2 client'+nonce+client,'sha256'))
            reply = b''
            while len(reply)<32:
                part=sock.recv(32-len(reply))
                if not part: break
                reply += part
            self.assertEqual(reply,hmac.digest(key.encode(),b'S6EPE/2 server'+nonce+client,'sha256'))
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            value=self.registry.status('home/nas')['privacyTelemetry']
            if value.get('authenticated_sessions')==1 and value['observation']=='current': break
            time.sleep(.1)
        self.assertEqual(value['authenticated_sessions'],1)
        self.assertEqual(value['observation'],'current')

    def test_cli_public6_help_not_intercepted(self):
        result = subprocess.run([sys.executable,str(ROOT/'CLI/shadow6.py'),'connect','--help'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('--invitation', result.stdout)


class LaunchLockTests(unittest.TestCase):
    setUp = ServiceLifecycleTests.setUp
    cleanup_process = ServiceLifecycleTests.cleanup_process
    def plan(self):
        import hashlib
        return {'root':str(ROOT),'core':'go','binary':str(self.binary),'config':str(self.config),'ttl':30,
                'launchDigests':{'binary':service_runtime.executable_digest(self.binary),
                                'config':'sha256:'+hashlib.sha256(self.config.read_bytes()).hexdigest()}}

    def test_locked_launch_rejects_config_change_after_registry_apply(self):
        marker=self.root/'started'
        self.binary.write_text(f'#!/usr/bin/env python3\nfrom pathlib import Path\nimport time\nPath({str(marker)!r}).write_text("started")\ntime.sleep(120)\n')
        self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)})
        original=service_runtime.start
        def changed_start(plan):
            atomic_write(self.config,b'{"changed_after_apply":true}')
            return original(plan)
        with patch('Deployment.service_runtime.start',side_effect=changed_start):
            with self.assertRaisesRegex(ValueError,'failed to start'):self.registry.run('home/nas')
        self.assertFalse(marker.exists())
        self.assertNotEqual(self.registry.status('home/nas')['state'],'running')

    def test_config_mutation_during_startup_never_receives_success_ack(self):
        marker=self.root/'child-pid'
        self.binary.write_text(f'#!/usr/bin/env python3\nfrom pathlib import Path\nimport os,time\nPath({str(marker)!r}).write_text(str(os.getpid()))\nPath({str(self.config)!r}).write_text("{{}}\\n")\ntime.sleep(120)\n')
        self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)})
        with self.assertRaisesRegex(ValueError,'failed to start'):self.registry.run('home/nas')
        self.assertTrue(marker.exists())
        self.assertIsNone(service_runtime.identity(int(marker.read_text())))
        self.assertNotEqual(self.registry.status('home/nas')['state'],'running')

    def test_launch_digest_contract_rejects_drift_and_unknown_fields(self):
        plan=self.plan();service_runtime.verify_launch_material(plan)
        with self.assertRaisesRegex(ValueError,'fields'):
            service_runtime.verify_launch_material({**plan,'arbitraryCommand':['false']})
        with self.assertRaisesRegex(ValueError,'exact locked'):
            service_runtime.verify_launch_material({**plan,'launchDigests':{}})
        with self.assertRaisesRegex(ValueError,'incomplete'):
            service_runtime.verify_launch_material({**plan,'gateBinary':str(self.binary)})
        with self.assertRaisesRegex(ValueError,'lifetime'):
            service_runtime.verify_launch_material({**plan,'ttl':True})
        self.binary.write_text('#!/bin/false\n')
        with self.assertRaisesRegex(ValueError,'drift before launch: binary'):
            service_runtime.verify_launch_material(plan)

    def test_all_critical_peripheral_digests_are_checked(self):
        import hashlib
        for component in ('envelope','gate','guard'):
            plan=self.plan();config=self.root/(component+'.json');atomic_write(config,b'{}')
            binary=self.root/(component+'-binary');binary.write_bytes(self.binary.read_bytes());binary.chmod(0o700)
            plan[component+'Config']=str(config);plan[component+'Binary']=str(binary)
            plan['launchDigests'][component+'Config']='sha256:'+hashlib.sha256(config.read_bytes()).hexdigest()
            plan['launchDigests'][component+'Binary']=service_runtime.executable_digest(binary)
            service_runtime.verify_launch_material(plan)
            atomic_write(config,b'{"drift":true}')
            with self.assertRaisesRegex(ValueError,'drift before launch: '+component+'Config'):
                service_runtime.verify_launch_material(plan)
            atomic_write(config,b'{}');binary.write_text('#!/bin/false\n')
            with self.assertRaisesRegex(ValueError,'drift before launch: '+component+'Binary'):
                service_runtime.verify_launch_material(plan)


if __name__ == '__main__': unittest.main()
