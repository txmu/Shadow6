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
        self.assertEqual(first['runtime']['readiness'], 'process-alive')
        self.assertEqual(first['privacyTelemetry']['observation'], 'not-configured')
        self.assertNotIn('authenticated_sessions', first['privacyTelemetry'])
        self.assertEqual(self.registry.run('home/nas')['runtime']['pid'], first['runtime']['pid'])
        with self.assertRaises(ValueError):
            self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)})
        second = self.registry.restart('home/nas')
        self.assertNotEqual(second['runtime']['pid'], first['runtime']['pid'])
        with self.assertRaisesRegex(ValueError, 'readiness is unavailable'):
            self.registry.connect('home/nas')
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
            sys.path.insert(0, str(ROOT/'OCaml/privacy_envelope/test'))
            from wire_v3 import Peer
            Peer(sock, key)
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            value=self.registry.status('home/nas')['privacyTelemetry']
            if value.get('authenticated_sessions')==1 and value['observation']=='current': break
            time.sleep(.1)
        self.assertEqual(value['authenticated_sessions'],1)
        self.assertEqual(value['observation'],'current')

    def test_tls_registry_lock_and_plan_keep_material_out_of_s6p1(self):
        config=self.root/'tls-envelope.conf'
        atomic_write(self.config,b'{"listen_addr":"127.0.0.1:14433"}')
        fields={'listen':'127.0.0.1:14444','upstream':'127.0.0.1:14433',
                'auth_key':'test-only-key-0123456789abcdef','carrier':'tls','tls_peer_name':'epe-client'}
        for key in ('tls_cert','tls_key','tls_ca'):
            path=self.root/(key+'.pem');atomic_write(path,('test-only-'+key).encode());fields[key]=str(path)
        atomic_write(config,''.join(f'{k}={v}\n' for k,v in fields.items()).encode())
        self.catalog.envelope_binary=lambda:self.binary
        self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)},privacy='envelope',
                                spec={'envelope_config':str(config)})
        lock=self.registry.lock('home/nas');_,plan=self.registry.launch_plan('home/nas')
        self.assertEqual(plan['envelopeTlsKey'],fields['tls_key'])
        self.assertIn('envelopeTlsKey',plan['launchDigests'])
        self.assertNotIn(str(self.root),json.dumps(plan['protocolContext']))
        service_runtime.verify_launch_material(plan)
        atomic_write(fields['tls_key'],b'replaced-key')
        with self.assertRaisesRegex(ValueError,'drift'):self.registry.apply('home/nas')
        with self.assertRaisesRegex(ValueError,'drift before launch'):service_runtime.verify_launch_material(plan)
        self.assertNotEqual(self.registry.lock('home/nas')['digest'],lock['digest'])

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

    def test_running_material_drift_stops_the_actual_component_group(self):
        first = self.registry.run('home/nas')
        observed = self.root / ( __import__('hashlib').sha256(b'home/nas').hexdigest() + '.runtime.json.observed')
        child = strict_json(observed.read_bytes())['processes'][0]
        atomic_write(self.config,b'{"changed_during_runtime":true}')
        deadline = time.monotonic() + 8
        while service_runtime.alive(first['runtime']) and time.monotonic() < deadline:
            time.sleep(.05)
        self.assertFalse(service_runtime.alive(first['runtime']))
        self.assertFalse(service_runtime.alive(child))
        self.assertEqual(self.registry.status('home/nas')['runtime']['readiness'],'unavailable')

    def test_restart_drift_rejection_preserves_existing_process(self):
        first = self.registry.run('home/nas')
        atomic_write(self.config,b'{"replacement_not_approved":true}')
        with self.assertRaisesRegex(ValueError,'drift'):
            self.registry.restart('home/nas')
        self.assertTrue(service_runtime.alive(first['runtime']))

    def test_launch_preserves_s6p1_and_rechecks_expiration(self):
        from Deployment.protocol_context import minimal_context, context_digest
        from join_code import issue_passport
        from unittest.mock import patch
        now = int(time.time())
        context = minimal_context('go')
        context['role'] = 'client'
        context['credentials']['passport'] = issue_passport('operator', roles=['client'], ttl=2, issuer_key=os.urandom(32))
        plan = {**self.plan(), 'protocolContext':context, 'contextDigest':context_digest(context), 'lockDigest':'sha256:' + 'a'*64}
        service_runtime.verify_launch_admission(plan)
        with patch('join_code.time.time', return_value=now + 10):
            with self.assertRaises(ValueError): service_runtime.verify_launch_admission(plan)
        plan['contextDigest'] = 'sha256:' + '0'*64
        with self.assertRaisesRegex(ValueError,'intent digest'): service_runtime.verify_launch_admission(plan)

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
            plan=self.plan();config=self.root/(component+'.json')
            original=b'listen=127.0.0.1:14444\nupstream=127.0.0.1:14433\nauth_key=test-only-key-0123456789abcdef\n' if component == 'envelope' else b'{}'
            atomic_write(config,original)
            binary=self.root/(component+'-binary');binary.write_bytes(self.binary.read_bytes());binary.chmod(0o700)
            plan[component+'Config']=str(config);plan[component+'Binary']=str(binary)
            plan['launchDigests'][component+'Config']='sha256:'+hashlib.sha256(config.read_bytes()).hexdigest()
            plan['launchDigests'][component+'Binary']=service_runtime.executable_digest(binary)
            service_runtime.verify_launch_material(plan)
            atomic_write(config,b'{"drift":true}')
            with self.assertRaisesRegex(ValueError,'drift before launch: '+component+'Config'):
                service_runtime.verify_launch_material(plan)
            atomic_write(config,original);binary.write_text('#!/bin/false\n')
            with self.assertRaisesRegex(ValueError,'drift before launch: '+component+'Binary'):
                service_runtime.verify_launch_material(plan)

    def test_tls_material_is_exact_private_and_locked(self):
        import hashlib
        plan=self.plan(); config=self.root/'tls-envelope.conf'
        fields={'mode':'stream','carrier':'tls','listen':'127.0.0.1:14444',
                'upstream':'127.0.0.1:14433','auth_key':'test-only-key-0123456789abcdef',
                'tls_peer_name':'epe-client'}
        for name,key in (('Cert','tls_cert'),('Key','tls_key'),('Ca','tls_ca')):
            path=self.root/(name+'.pem');atomic_write(path,('test-'+name).encode())
            fields[key]=str(path);plan['envelopeTls'+name]=str(path)
            plan['launchDigests']['envelopeTls'+name]='sha256:'+hashlib.sha256(path.read_bytes()).hexdigest()
        atomic_write(config,''.join(f'{key}={value}\n' for key,value in fields.items()).encode())
        plan.update(envelopeConfig=str(config),envelopeBinary=str(self.binary))
        plan['launchDigests']['envelopeConfig']='sha256:'+hashlib.sha256(config.read_bytes()).hexdigest()
        plan['launchDigests']['envelopeBinary']=service_runtime.executable_digest(self.binary)
        service_runtime.validate_envelope(fields);service_runtime.verify_launch_material(plan)
        for name in ('Cert','Key','Ca'):
            path=Path(plan['envelopeTls'+name]);original=path.read_bytes()
            atomic_write(path,b'replaced')
            with self.assertRaisesRegex(ValueError,'drift before launch: envelopeTls'+name):
                service_runtime.verify_launch_material(plan)
            atomic_write(path,original)
        without_tls={k:v for k,v in plan.items() if not k.startswith('envelopeTls')}
        without_tls['launchDigests']={k:v for k,v in plan['launchDigests'].items() if not k.startswith('envelopeTls')}
        with self.assertRaisesRegex(ValueError,'differs from envelope configuration'):
            service_runtime.verify_launch_material(without_tls)
        path=Path(fields['tls_key']);path.chmod(0o644)
        with self.assertRaises(ValueError): service_runtime.verify_launch_material(plan)
        path.chmod(0o600)
        for overrides in ({'carrier':'raw'},{'mode':'datagram'},{'tls_peer_name':'*'},
                          {'tls_cert':fields['tls_key']}):
            with self.subTest(overrides=overrides),self.assertRaises(ValueError):
                service_runtime.validate_envelope({**fields,**overrides})
        with self.assertRaises(ValueError):service_runtime.parse_envelope(b'carrier=tls\ncarrier=raw\n')


class ObservationTruthTests(unittest.TestCase):
    setUp = ServiceLifecycleTests.setUp
    cleanup_process = ServiceLifecycleTests.cleanup_process

    def test_proc_observation_budget_does_not_silently_truncate(self):
        import io, socket
        from Deployment import runtime_observation as observation
        with patch.object(observation,'MAX_ROWS',1):
            self.assertEqual(list(observation.proc_rows(io.StringIO('header\nrow\n'))),['row\n'])
            with self.assertRaisesRegex(ValueError,'table limit'):
                list(observation.proc_rows(io.StringIO('header\nrow\nsecond\n')))
        with self.assertRaisesRegex(ValueError,'row limit'):
            list(observation.proc_rows(io.StringIO('header\n'+'x'*5000)))
        with patch.object(observation,'MAX_FDS',0):
            with self.assertRaisesRegex(ValueError,'FD observation limit'):
                observation.sockets(os.getpid())
        with socket.socket() as listener, patch.object(observation,'MAX_SOCKETS',0):
            listener.bind(('127.0.0.1',0));listener.listen()
            with self.assertRaisesRegex(ValueError,'listener observation limit'):
                observation.sockets(os.getpid())

    def test_observation_schema_rejects_empty_foreign_and_unknown_claims(self):
        import copy
        from Deployment.runtime_observation import validate_observation
        item=self.registry.run('home/nas');value=item['runtimeObservation']
        validate_observation(value)
        for changed in ({**value,'extra':True},{**value,'processes':[]},
                        {**value,'processes':value['processes']*2},
                        {**value,'readiness':'connected'},
                        {**value,'transportReadiness':'ready'}):
            with self.assertRaises(ValueError):validate_observation(changed)
        changed=copy.deepcopy(value)
        changed.update(readiness='application-ready',applicationReadiness='ready',endpoint={
            'host':'127.0.0.1','port':14433,'boundary':'stream','mode':'localhost-tcp-proxy',
            'observation':'structured-ready-event','owner':{'pid':os.getpid(),'processIdentity':service_runtime.identity(os.getpid())}})
        with self.assertRaisesRegex(ValueError,'native process'):validate_observation(changed)

    def test_missing_sidecar_and_stopped_process_do_not_reuse_readiness(self):
        import hashlib
        item=self.registry.run('home/nas')
        path=self.registry.path.parent/(hashlib.sha256(b'home/nas').hexdigest()+'.runtime.json')
        item['runtime'].update(readiness='application-ready',endpoint={'host':'127.0.0.1','port':14433})
        with patch('Deployment.service_runtime.private_read',side_effect=FileNotFoundError):
            service_runtime.observe(item,path)
        self.assertIsNone(item['runtime']['endpoint'])
        self.assertEqual(item['runtime']['readiness'],'unavailable')
        stopped=self.registry.stop('home/nas')
        self.assertEqual(stopped['runtime']['readiness'],'unavailable')
        self.assertIsNone(stopped['runtime']['endpoint'])

    def test_fresh_sidecar_cannot_turn_nonexistent_socket_into_ready_endpoint(self):
        import copy,hashlib
        item=self.registry.run('home/nas');value=copy.deepcopy(item['runtimeObservation'])
        socket_claim={'host':'127.0.0.1','port':14433,'transport':'tcp','observation':'process-owned-socket'}
        value.update(readiness='listener-ready',endpoints=[socket_claim],nativeEndpoints=[socket_claim],endpoint=socket_claim)
        path=self.registry.path.parent/(hashlib.sha256(b'home/nas').hexdigest()+'.runtime.json')
        original=service_runtime.private_read
        def read(target,*args):
            if str(target).endswith('.observed'):return json.dumps(value).encode()
            return original(target,*args)
        with patch('Deployment.service_runtime.private_read',side_effect=read):service_runtime.observe(item,path)
        self.assertEqual(item['runtime']['readiness'],'unavailable')
        self.assertIsNone(item['runtime']['endpoint'])

    def test_critical_component_cannot_be_omitted_from_fresh_observation(self):
        import hashlib
        item=self.registry.run('home/nas');value=item['runtimeObservation']
        path=self.registry.path.parent/(hashlib.sha256(b'home/nas').hexdigest()+'.runtime.json')
        original=service_runtime.private_read
        def read(target,*args):
            if str(target).endswith('.observed'):return json.dumps(value).encode()
            plan=json.loads(original(target,*args));plan['gateConfig']='/unused/gate.json'
            return json.dumps(plan).encode()
        with patch('Deployment.service_runtime.private_read',side_effect=read):
            with self.assertRaisesRegex(ValueError,'critical processes differ'):
                service_runtime.observe(item,path)

    def test_other_live_process_is_not_a_supervised_core(self):
        import copy,hashlib
        item=self.registry.run('home/nas');value=copy.deepcopy(item['runtimeObservation'])
        value['processes']=[{'pid':os.getpid(),'processIdentity':service_runtime.identity(os.getpid())}]
        path=self.registry.path.parent/(hashlib.sha256(b'home/nas').hexdigest()+'.runtime.json')
        original=service_runtime.private_read
        def read(target,*args):
            if str(target).endswith('.observed'):return json.dumps(value).encode()
            return original(target,*args)
        with patch('Deployment.service_runtime.private_read',side_effect=read):service_runtime.observe(item,path)
        self.assertEqual(item['runtime']['readiness'],'unavailable')


class ConnectionSnapshotTests(unittest.TestCase):
    setUp = ServiceLifecycleTests.setUp
    cleanup_process = ServiceLifecycleTests.cleanup_process

    def test_connection_inputs_recheck_lock_inside_one_transaction(self):
        self.registry.run('home/nas')
        original=self.registry._material;calls=[]
        def material(name):
            self.assertEqual(self.registry._depth,1)
            calls.append(name)
            if len(calls)==2:atomic_write(self.config,b'{"changed_during_resolution":true}')
            return original(name)
        with patch.object(self.registry,'_material',side_effect=material):
            with self.assertRaisesRegex(ValueError,'deployment drift'):
                self.registry.connect('home/nas')
        self.assertGreaterEqual(len(calls),2)

    def test_same_registry_threads_cannot_bypass_nested_transaction_lock(self):
        import threading
        self.registry.run('home/nas')
        entered=threading.Event();release=threading.Event();attempted=threading.Event();finished=threading.Event()
        errors=[];original=self.registry._material
        def material(name):
            entered.set()
            if not release.wait(3):raise ValueError('test transaction timed out')
            return original(name)
        def first():
            try:self.registry.connection_inputs('home/nas')
            except Exception as error:errors.append(error)
        def second():
            attempted.set()
            try:self.registry.list()
            except Exception as error:errors.append(error)
            finally:finished.set()
        with patch.object(self.registry,'_material',side_effect=material):
            worker=threading.Thread(target=first);other=threading.Thread(target=second)
            worker.start()
            try:
                self.assertTrue(entered.wait(2));other.start()
                self.assertTrue(attempted.wait(2))
                self.assertFalse(finished.wait(.2))
            finally:
                release.set();worker.join(4)
                if other.ident is not None:other.join(4)
        self.assertFalse(worker.is_alive());self.assertFalse(other.is_alive());self.assertEqual(errors,[])

    def test_failed_connect_does_not_apply_a_stopped_service(self):
        self.registry.run('home/nas');self.registry.stop('home/nas')
        with self.assertRaisesRegex(ValueError,'not running'):self.registry.connect('home/nas')
        self.assertEqual(self.registry.inspect('home/nas')['state'],'stopped')


if __name__ == '__main__': unittest.main()
