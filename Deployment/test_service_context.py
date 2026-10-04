"""Focused S6P1 lifecycle/topology/import regressions, no native build."""
import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from Deployment.core_catalog import CoreCatalog
from Deployment.service_registry import ServiceRegistry
from Deployment.service_storage import atomic_write
from Deployment.protocol_context import minimal_context, validate_context, context_digest
from Deployment.connection_plan import resolve_connection
from Deployment.broker_set import realize, gate_patch
from Deployment.runtime_observation import ready

ROOT = Path(__file__).resolve().parents[1]


def pool(count=1):
    return {'kind':'broker_set','id':'home','policy':'round_robin',
            'members':[{'identity':f'broker-{i}', 'endpoint':f'tcp://127.0.0.{i+1}:14433',
                        'public_key':'a'*64} for i in range(count)]}


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='shadow6-context-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = self.directory/'native.json'; atomic_write(self.config,b'{}')
        self.catalog = CoreCatalog(ROOT)
        # Source-only acceptance runs have no compiled Go Core. Tests that
        # exercise locking still need a real, owner-controlled executable to
        # validate the binary digest without depending on checkout artifacts.
        for core in ('go', 'rust'):
            binary = self.directory/('fixture-' + core)
            binary.write_text('#!/bin/false\n')
            binary.chmod(0o700)
            self.catalog._items[core]['executable'] = str(binary)
        self.registry = ServiceRegistry(self.directory/'registry.json', self.catalog)

    def create(self, context=None, **kwargs):
        return self.registry.create('home/nas',core='go',config={'config_path':str(self.config)},context=context,**kwargs)

    def test_context_is_unique_semantic_source(self):
        context = minimal_context('go'); context.update(role='client',identity={'ref':'nas'})
        context['routes']=[pool()]
        item = self.create(context)
        self.assertEqual(item['protocolContext'],context)
        self.assertFalse({'role','brokers','routes','identity','credentials'} & set(item['spec']))
        loaded = ServiceRegistry(self.registry.path,self.catalog).inspect('home/nas')
        self.assertEqual(loaded['protocolContext'],context)
        for field in ('role','routes','brokers','credentials','identity','endpoint'):
            with self.assertRaises(ValueError): self.registry._spec({field:{}})

    def test_core_scope_rejects_binding_conflict(self):
        with self.assertRaisesRegex(ValueError,'scope'): self.create(minimal_context('rust'))
        self.create(minimal_context('all'))
        self.registry.configure('home/nas',core='rust',config={'config_path':str(self.config)})
        self.assertEqual(self.registry.require_binding('home/nas')['core'],'rust')

    def test_ambiguous_core_never_auto_selected(self):
        with self.assertRaisesRegex(ValueError,'AmbiguousCore'):
            resolve_connection(context=minimal_context(),catalog=self.catalog)
        self.assertEqual(resolve_connection(context=minimal_context('go'),catalog=self.catalog)['core'],'go')

    def test_third_party_descriptor_participates(self):
        descriptor = copy.deepcopy(self.catalog.inspect('go'))
        descriptor.update(id='vendor-x', source='imported')
        descriptor['configurationSchema']['core']='vendor-x'
        self.catalog.register(descriptor)
        item = self.registry.create('home/vendor',core='vendor-x',config={'config_path':str(self.config)},context=minimal_context('vendor-x'))
        plan = resolve_connection(context=item['protocolContext'],catalog=self.catalog,binding=item['coreBinding'])
        self.assertEqual(plan['core'],'vendor-x')

    def test_unknown_runtime_material_rejected_from_context(self):
        for key in ('pid','binaryDigest','config_path','telemetry','runtime'):
            context=minimal_context(); context['identity'][key]=1
            with self.assertRaises(ValueError): validate_context(context)
        context=minimal_context();context['routes']=[{ 'kind':'broker_set',**pool(), 'health':'ready'}]
        with self.assertRaises(ValueError): validate_context(context)

    def test_lock_detects_route_identity_privacy_core_drift(self):
        item=self.create(); first=self.registry.lock('home/nas')
        self.assertEqual(first['contextDigest'],context_digest(item['protocolContext']))
        context=minimal_context('go');context['routes']=[pool()]
        atomic_write(self.config,json.dumps({'broker_addr':pool()['members'][0]['endpoint']}).encode())
        self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)},context=context)
        second=self.registry.lock('home/nas')
        self.assertNotEqual(first['digest'],second['digest'])
        value=json.loads(self.registry.path.read_text());value['services']['home/nas']['protocolContext']['identity']={'ref':'changed'}
        atomic_write(self.registry.path,json.dumps(value).encode())
        with self.assertRaisesRegex(ValueError,'drift'): self.registry.apply('home/nas')

    def test_safe_legacy_migration_and_ambiguous_fail_closed(self):
        self.create()
        value=json.loads(self.registry.path.read_text());value['schema']='shadow6.service-registry.v1'
        del value['services']['home/nas']['protocolContext']
        value['services']['home/nas']['spec']['endpoint']={'mode':'private'}
        atomic_write(self.registry.path,json.dumps(value).encode())
        migrated=ServiceRegistry(self.registry.path,self.catalog)
        migrated.init()
        self.assertEqual(json.loads(self.registry.path.read_text())['schema'],'shadow6.service-registry.v2')
        value['services']['home/nas']['spec']['endpoint']['address']='127.0.0.1:1234'
        atomic_write(self.registry.path,json.dumps(value).encode())
        with self.assertRaisesRegex(ValueError,'ambiguous legacy'): ServiceRegistry(self.registry.path,self.catalog)

    def test_legacy_simulated_pid_never_runtime_proof(self):
        self.create();value=json.loads(self.registry.path.read_text())
        value['schema']='shadow6.service-registry.v1'
        del value['services']['home/nas']['protocolContext']
        value['services']['home/nas']['runtime']={'pid':os.getpid()}
        atomic_write(self.registry.path,json.dumps(value).encode())
        with self.assertRaisesRegex(ValueError,'runtime identity'): ServiceRegistry(self.registry.path,self.catalog)

    def test_named_and_s6p1_use_one_pipeline_and_real_observation(self):
        self.catalog._items['go']['executable']=str(self.directory/'fixture-core')
        binary=Path(self.catalog.inspect('go')['executable'])
        binary.write_text('#!/usr/bin/env python3\nimport socket,time\ns=socket.socket();s.bind(("127.0.0.1",0));s.listen();time.sleep(60)\n');binary.chmod(0o700)
        self.create()
        try:
            self.registry.apply('home/nas')
            running=self.registry.run('home/nas')
            named=self.registry.connect('home/nas')
            direct=resolve_connection(context=running['protocolContext'],catalog=self.catalog,binding=running['coreBinding'],runtime=running['runtime'])
            self.assertEqual(direct['endpoint'],named['endpoint']);self.assertEqual(direct['readiness'],'listener-ready')
            self.assertEqual(direct['capability']['sessionLaunch'],'unavailable')
            self.assertFalse(direct['connected'])
        finally: self.registry.stop('home/nas')

    def test_ready_event_runtime_endpoint_not_desired_route(self):
        binary=self.directory/'fixture-core'
        binary.write_text('''#!/usr/bin/env python3
import socket,json,time
s=socket.socket();s.bind(('127.0.0.1',0));s.listen()
print(json.dumps({'event':'shadow6.ready','schema':1,'core':'shadow6-go','role':'client',
'application_boundary':{'kind':'stream','mode':'localhost-tcp-proxy','endpoint':{'host':'127.0.0.1','port':s.getsockname()[1]}}}),flush=True)
time.sleep(60)
''');binary.chmod(0o700);self.catalog._items['go']['executable']=str(binary)
        context=minimal_context('go');context['role']='client';context['routes']=[{'boundary':'stream','endpoint':'tcp://127.0.0.1:1'}]
        self.create(context)
        try:
            self.registry.apply('home/nas')
            result=self.registry.run('home/nas')
            self.assertEqual(result['runtime']['readiness'],'application-ready')
            self.assertNotEqual(result['runtime']['endpoint']['port'],1)
            self.assertEqual(self.registry.connect('home/nas')['applicationBoundary'],'stream')
        finally:self.registry.stop('home/nas')

    def test_envelope_rejects_public_upstream_and_native_exposure(self):
        from Deployment.service_runtime import validate_envelope,validate_native_private
        with self.assertRaisesRegex(ValueError,'loopback'):
            validate_envelope({'listen':'0.0.0.0:14444','upstream':'0.0.0.0:14433','auth_key':'x'*32})
        atomic_write(self.config,b'{"role":"broker","broker":{"listen_addr":"0.0.0.0:14433"}}')
        with self.assertRaisesRegex(ValueError,'public native'):
            validate_native_private(self.config)
        atomic_write(self.config,b'{"role":"broker","broker":{"listen_addr":"127.0.0.1:14433"}}')
        validate_native_private(self.config)

    def test_broker_set_single_multi_capability_health_and_gate(self):
        self.assertEqual(realize(pool())['selected']['identity'],'broker-0')
        with self.assertRaisesRegex(ValueError,'capability unavailable'): realize(pool(2))
        self.assertEqual(realize(pool(2),adapter='broker-set-selector',cursor=1)['selected']['identity'],'broker-1')
        self.assertEqual(realize(pool(2),adapter='broker-set-selector',observations={pool(2)['members'][0]['endpoint']:'unavailable'})['selected']['identity'],'broker-1')
        patch=gate_patch(pool(2));self.assertEqual(len(patch['remote_hosts']),2)
        self.assertEqual(patch['peer_public_keys'],['a'*64]);self.assertFalse(patch['mtd']['enabled'])
        self.assertFalse(realize(pool(2),adapter='gate')['sessionMigration'])



class CompositionTests(unittest.TestCase):
    def test_four_explicit_stacks_and_no_gate_requirement(self):
        from Deployment.service_composition import validate_composition
        envelope={'listen':'127.0.0.1:14444','upstream':'127.0.0.1:14433'}
        gate={'enabled':True,'role':'server','listen_host':'127.0.0.1','listen_port':14433,'protocol':['tcp'],'upstream':'127.0.0.1:14432'}
        guard={'spa_config':{'enabled':True,'agent_tcp_port':14444}}
        for g in (None,gate):
            for perimeter in (None,guard):
                result=validate_composition(privacy='envelope',envelope=envelope,gate=g,guard=perimeter)
                self.assertEqual(result['layers'],(['Guard'] if perimeter else [])+['S6EPE']+(['Gate'] if g else [])+['Core'])
                self.assertFalse(result['outerEncryptedCamouflage'])
        guard['spa_config']['agent_tcp_port']=14432
        with self.assertRaisesRegex(ValueError,'EPE admission'):
            validate_composition(privacy='envelope',envelope=envelope,gate=gate,guard=guard)
        gate['enabled']=False
        with self.assertRaisesRegex(ValueError,'explicit enabled'):
            validate_composition(privacy='envelope',envelope=envelope,gate=gate)

    def test_ready_unknown_schema_identity_and_public_endpoint_rejected(self):
        event={'event':'shadow6.ready','schema':1,'core':'shadow6-go','role':'client',
               'application_boundary':{'kind':'stream','mode':'localhost-tcp-proxy','endpoint':{'host':'127.0.0.1','port':14433}}}
        self.assertEqual(ready(json.dumps(event).encode(),'go')['readiness'],'application-ready')
        for field,value in (('core','shadow6-rust'),('schema',2),('role','broker'),('unknown',True)):
            altered={**event,field:value}
            with self.assertRaises(ValueError):ready(json.dumps(altered).encode(),'go')
        event['application_boundary']['endpoint']['host']='0.0.0.0'
        with self.assertRaises(ValueError):ready(json.dumps(event).encode(),'go')

class LocalSessionTests(unittest.TestCase):
    def test_actual_application_stream_attach_and_byte_budget(self):
        import threading
        from Deployment.connection_plan import open_local_session
        from Deployment.service_runtime import identity
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen();port=listener.getsockname()[1]
            def echo():
                with listener.accept()[0] as client:
                    client.sendall(client.recv(1024))
            worker=threading.Thread(target=echo);worker.start()
            token={'pid':os.getpid(),'processIdentity':identity(os.getpid())}
            plan={'readiness':'application-ready','runtimeIdentity':token,
                  'endpoint':{'host':'127.0.0.1','port':port,'boundary':'stream', 'mode':'localhost-tcp-proxy','observation':'structured-ready-event','owner':token}}
            with open_local_session(plan) as session:
                session.send(b'actual-session');self.assertEqual(session.receive(),b'actual-session')
                session.remaining=0
                with self.assertRaisesRegex(ValueError,'budget'):session.send(b'x')
            worker.join(3);self.assertFalse(worker.is_alive())
        plan['readiness']='process-alive'
        with self.assertRaisesRegex(ValueError,'capability unavailable'):open_local_session(plan)

class ContextDriftAndScope(unittest.TestCase):
    setUp = ContextTests.setUp
    create = ContextTests.create
    def test_candidate_scope_and_explicit_binding_are_consistent(self):
        context=minimal_context();context['core']=['go','rust']
        with self.assertRaisesRegex(ValueError,'AmbiguousCore'):resolve_connection(context=context,catalog=self.catalog)
        self.assertEqual(resolve_connection(context=context,catalog=self.catalog,core='rust')['core'],'rust')
        with self.assertRaisesRegex(ValueError,'scope'):self.create({**context,'core':['rust','gleam']})
        item=self.create(context)
        with self.assertRaisesRegex(ValueError,'locked CoreBinding'):
            resolve_connection(context=context,catalog=self.catalog,binding=item['coreBinding'],core='rust')

    def test_invalid_admission_material_is_rejected_on_create(self):
        context=minimal_context('go');context['credentials']={'passport':'S6PASS1.invalid'}
        with self.assertRaises(ValueError):self.create(context)

    def test_native_role_drift_from_context_is_rejected(self):
        atomic_write(self.config,b'{"role":"broker"}')
        self.create({**minimal_context('go'),'role':'client'})
        with self.assertRaisesRegex(ValueError,'role realization'):self.registry.lock('home/nas')

    def test_envelope_config_binary_privacy_and_core_drift_lock(self):
        atomic_write(self.config,b'{"listen_addr":"127.0.0.1:14433"}')
        binary=self.directory/'epe';binary.write_text('#!/bin/false\n');binary.chmod(0o700)
        self.catalog.envelope_binary=lambda:binary
        config=self.directory/'epe.conf'
        atomic_write(config,b'listen=127.0.0.1:14434\nupstream=127.0.0.1:14433\nauth_key=abcdefghijklmnop\n')
        self.create(privacy='envelope',spec={'envelope_config':str(config)})
        first=self.registry.lock('home/nas')['digest']
        atomic_write(config,config.read_bytes()+b'max_sessions=4\n')
        with self.assertRaisesRegex(ValueError,'drift'):self.registry.apply('home/nas')
        self.registry.lock('home/nas');binary.write_text('#!/bin/false\n# changed\n')
        with self.assertRaisesRegex(ValueError,'drift'):self.registry.apply('home/nas')
        self.registry.configure('home/nas',core='go',config={'config_path':str(self.config)},privacy='native')
        self.assertNotEqual(self.registry.lock('home/nas')['digest'],first)
        self.registry.configure('home/nas',core='rust',config={'config_path':str(self.config)},context=minimal_context('rust'))
        self.assertNotEqual(self.registry.lock('home/nas')['digest'],first)

    def test_imported_descriptor_persists_for_next_catalog(self):
        from unittest.mock import patch
        path=self.directory/'descriptors.json';source=self.directory/'descriptor.json'
        descriptor=copy.deepcopy(self.catalog.inspect('go'));descriptor.update(id='vendor-x',source='imported')
        descriptor['configurationSchema']['core']='vendor-x'
        source.write_text(json.dumps(descriptor))
        with patch.dict(os.environ,{'SHADOW6_CORE_DESCRIPTORS':str(path)}):
            CoreCatalog(ROOT).import_file(source)
            self.assertEqual(CoreCatalog(ROOT).inspect('vendor-x')['id'],'vendor-x')


class BrokerRuntimeRealizationTests(unittest.TestCase):
    setUp = ContextTests.setUp
    create = ContextTests.create

    def test_registry_locks_realization_and_rejects_native_and_gate_drift(self):
        context=minimal_context('go');context['role']='client';context['routes']=[pool(2)]
        gate={'enabled':True,'role':'client','listen_host':'127.0.0.1','listen_port':14434,**gate_patch(context['routes'][0])}
        path=self.directory/'gate.json';atomic_write(path,json.dumps(gate).encode())
        binary=self.directory/'fixture-gate';binary.write_text('#!/bin/false\n');binary.chmod(0o700)
        self.catalog.component_binary=lambda component:binary
        atomic_write(self.config,b'{"role":"client","broker_addr":"127.0.0.1:14434"}')
        self.create(context,spec={'gate_config':str(path)})
        first=self.registry.lock('home/nas')
        self.registry.apply('home/nas')
        self.assertEqual(self.registry._material('home/nas')['brokerRealization']['adapter'],'gate')
        atomic_write(path,json.dumps({**gate,'remote_hosts':['127.0.0.99']}).encode())
        with self.assertRaisesRegex(ValueError,'S6P1 BrokerSet'):self.registry.apply('home/nas')
        atomic_write(path,json.dumps(gate).encode())
        atomic_write(self.config,b'{"role":"client","broker_addr":"127.0.0.1:14435"}')
        with self.assertRaisesRegex(ValueError,'native broker endpoint'):self.registry.lock('home/nas')
        self.assertEqual(self.registry.inspect('home/nas')['deploymentLock'],first)

    def test_gate_route_matches_native_endpoint_and_lock_is_deterministic(self):
        from Deployment.service_composition import broker_realization
        context=minimal_context('go');context['role']='client';context['routes']=[pool(2)]
        context['routes'][0]['policy']='random'
        gate={'enabled':True,'role':'client','listen_host':'127.0.0.1','listen_port':14434,**gate_patch(context['routes'][0])}
        native={'role':'client','client':{'broker_addrs':['wss://127.0.0.1:14434/ws']}}
        first=broker_realization(context,native=native,gate=gate)
        for _ in range(5):self.assertEqual(broker_realization(context,native=native,gate=gate),first)
        self.assertNotIn('selected',first);self.assertNotIn('health',first)
        with self.assertRaisesRegex(ValueError,'S6P1 BrokerSet'):
            broker_realization(context,native=native,gate={**gate,'remote_hosts':['127.0.0.99']})
        with self.assertRaisesRegex(ValueError,'native broker endpoint'):
            broker_realization(context,native={'broker_addr':'127.0.0.1:1'},gate=gate)
        with self.assertRaisesRegex(ValueError,'native-single'):
            broker_realization(context,native=native)

    def test_named_multi_broker_connection_uses_explicit_deployed_gate(self):
        from unittest.mock import patch
        from Deployment.connection_plan import resolve_connection
        context=minimal_context('go');context['role']='client';context['routes']=[pool(2)]
        item={'state':'running','protocolContext':context,'profileBinding':__import__('Deployment.profile_registry',fromlist=['bind_profile']).bind_profile('go'),'coreBinding':{'core':'go'},'runtime':{'readiness':'process-alive','endpoint':None}}
        with patch('Deployment.connection_plan.connection_plan',wraps=__import__('Deployment.connection_plan',fromlist=['connection_plan']).connection_plan) as planner:
            from unittest.mock import Mock
            registry=Mock();registry.connection_inputs.return_value=(item,{'brokerRealization':{'adapter':'gate'}})
            result=resolve_connection(service='home/nas',registry=registry,catalog=CoreCatalog(ROOT))
            self.assertEqual(result['brokerSets'][0]['adapter'],'gate')
            planner.assert_called_once()
            with self.assertRaisesRegex(ValueError,'locked service realization'):
                resolve_connection(service='home/nas',registry=registry,catalog=CoreCatalog(ROOT),adapter='native-single')

class RealizationAdmissionTests(unittest.TestCase):
    setUp = ContextTests.setUp
    create = ContextTests.create

    def gate_service(self, context):
        path=self.directory/'gate.json'
        atomic_write(path,b'{"enabled":true,"role":"client"}')
        binary=self.directory/'fixture-gate';binary.write_text('#!/bin/false\n');binary.chmod(0o700)
        self.catalog.component_binary=lambda component:binary
        atomic_write(self.config,b'{"role":"client"}')
        return self.create(context,spec={'gate_config':str(path)})

    def test_explicit_component_disable_cannot_be_overridden_by_config(self):
        context=minimal_context('go');context['role']='client';context['components']={'gate':False}
        self.gate_service(context)
        with self.assertRaisesRegex(ValueError,'does not advertise'):self.registry.lock('home/nas')
        from unittest.mock import patch
        with patch('Deployment.service_registry.runtime.start') as start:
            with self.assertRaisesRegex(ValueError,'DeploymentLock required'):self.registry.run('home/nas')
            start.assert_not_called()

    def test_required_component_needs_local_realization(self):
        for component in ('gate','guard','s6epe'):
            context=minimal_context('go');context['components']={component:True}
            from Deployment.protocol_context import admit_realization
            with self.assertRaisesRegex(ValueError,'explicit local realization'):
                admit_realization(context)
        context['components']={}
        self.assertEqual(admit_realization(context),context)

    def test_passport_role_scope_is_enforced_before_registry_creation(self):
        from join_code import issue_passport
        context=minimal_context('go');context['role']='client'
        context['credentials']={'passport':issue_passport('nas',components=('all',),roles=('agent',),issuer_key=b'r'*32)}
        with self.assertRaisesRegex(ValueError,'role'):self.create(context)
        self.assertEqual(self.registry.services,{})

    def test_passport_component_scope_is_enforced_before_lock(self):
        from join_code import issue_passport
        context=minimal_context('go');context['role']='client';context['components']={'gate':True}
        context['credentials']={'passport':issue_passport('nas',components=('guard',),roles=('client',),issuer_key=b'r'*32)}
        self.gate_service(context)
        with self.assertRaisesRegex(ValueError,'component'):self.registry.lock('home/nas')
        self.assertNotIn('deploymentLock',self.registry.inspect('home/nas'))

    def test_unspecified_context_role_cannot_bypass_actual_native_role_scope(self):
        from join_code import issue_passport
        from Deployment.protocol_context import admit_realization
        context=minimal_context('go')
        context['credentials']={'passport':issue_passport('nas',components=('gate',),roles=('agent',),issuer_key=b'r'*32)}
        with self.assertRaisesRegex(ValueError,'role'):
            admit_realization(context,native_role='client',components=('gate',))
        with self.assertRaisesRegex(ValueError,'explicit logical or native role'):
            admit_realization(context,components=('gate',))


class ObservedBoundaryContractTests(unittest.TestCase):
    def test_owned_socket_address_decoding_respects_host_byte_order(self):
        from Deployment.runtime_observation import proc_address
        self.assertEqual(proc_address('0100007F',byteorder='little'),'127.0.0.1')
        self.assertEqual(proc_address('7F000001',byteorder='big'),'127.0.0.1')
        self.assertEqual(proc_address('00000000000000000000000001000000',ipv6=True,byteorder='little'),'::1')
        self.assertEqual(proc_address('00000000000000000000000000000001',ipv6=True,byteorder='big'),'::1')
        with self.assertRaisesRegex(ValueError,'invalid proc socket address'):proc_address('00')

    def test_observed_application_boundary_must_match_descriptor_and_intent(self):
        from Deployment.connection_plan import connection_plan
        catalog=CoreCatalog(ROOT)
        catalog._items['go']['applicationBoundaries']=['stream','message']
        context=minimal_context('go');context['role']='client'
        runtime={'readiness':'application-ready','endpoint':{'host':'127.0.0.1','port':14433,'boundary':'stream','mode':'localhost-tcp-proxy','observation':'structured-ready-event'}}
        plan=connection_plan(context,catalog=catalog,runtime=runtime)
        self.assertEqual(plan['capability']['sessionLaunch'],'local-application-stream')
        context['routes']=[{'boundary':'message'}]
        with self.assertRaisesRegex(ValueError,'S6P1 routes'):
            connection_plan(context,catalog=catalog,runtime=runtime)
        context['routes']=[];context['role']='broker'
        with self.assertRaisesRegex(ValueError,'S6P1 role'):
            connection_plan(context,catalog=catalog,runtime=runtime)
        context['role']='client';catalog._items['go']['applicationBoundaries']=['message']
        with self.assertRaisesRegex(ValueError,'not declared by Core'):
            connection_plan(context,catalog=catalog,runtime=runtime)
        context['role']='all';catalog._items['go']['applicationBoundaries']=['stream'];catalog._items['go']['roles']=['broker']
        with self.assertRaisesRegex(ValueError,'client role is not declared'):
            connection_plan(context,catalog=catalog,runtime=runtime)

    def test_udp_listener_cannot_prove_stream_application_readiness(self):
        temp=tempfile.TemporaryDirectory(prefix='shadow6-ready-udp-');self.addCleanup(temp.cleanup)
        directory=Path(temp.name)
        binary=directory/'fixture';binary.write_text("""#!/usr/bin/env python3
import socket,json,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0))
print(json.dumps({'event':'ready','schema':1,'core':'go','role':'client','application_boundary':{'kind':'stream','mode':'localhost-tcp-proxy','endpoint':{'host':'127.0.0.1','port':s.getsockname()[1]}}}),flush=True)
time.sleep(1)
""");binary.chmod(0o700)
        config=directory/'native.json';atomic_write(config,b'{"role":"client"}')
        catalog=CoreCatalog(ROOT);catalog._items['go']['executable']=str(binary)
        registry=ServiceRegistry(directory/'registry.json',catalog)
        registry.create('home/udp',core='go',config={'config_path':str(config)},context={**minimal_context('go'),'role':'client'})
        try:
            registry.apply('home/udp')
            with self.assertRaisesRegex(ValueError, 'failed to start'):
                registry.run('home/udp')
            self.assertNotEqual(registry.status('home/udp')['state'], 'running')
        finally:registry.stop('home/udp')


class ConnectionRoleTests(unittest.TestCase):
    setUp = ContextTests.setUp
    create = ContextTests.create

    def test_requested_role_filters_capability_and_preserves_context_digest(self):
        context=minimal_context('go');original=context_digest(context)
        plan=resolve_connection(context=context,catalog=self.catalog,role='client')
        self.assertEqual(plan['role'],'client');self.assertEqual(plan['contextDigest'],original)
        self.assertEqual(context['role'],'all')
        self.catalog._items['go']['roles']=['broker']
        with self.assertRaises(ValueError):resolve_connection(context=context,catalog=self.catalog,role='client')
        with self.assertRaisesRegex(ValueError,'invalid requested role'):
            resolve_connection(context=context,catalog=self.catalog,role=['client'])

    def test_requested_role_must_match_context_and_passport_scope(self):
        from join_code import issue_passport
        context=minimal_context('go');context['role']='agent'
        with self.assertRaisesRegex(ValueError,'role mismatch'):
            resolve_connection(context=context,catalog=self.catalog,role='client')
        context['role']='all';context['credentials']={'passport':issue_passport('nas',components=('all',),roles=('agent',),issuer_key=b'r'*32)}
        with self.assertRaisesRegex(ValueError,'role'):
            resolve_connection(context=context,catalog=self.catalog,role='client')

    def test_named_role_request_matches_locked_native_realization(self):
        binary=self.directory/'fixture-core';binary.write_text('#!/usr/bin/env python3\nimport json,socket,time\ns=socket.socket();s.bind(("127.0.0.1",0));s.listen()\nprint(json.dumps({"event":"shadow6.ready","schema":1,"core":"shadow6-go","role":"client","application_boundary":{"kind":"stream","mode":"localhost-tcp-proxy","endpoint":{"host":"127.0.0.1","port":s.getsockname()[1]}}}),flush=True)\ntime.sleep(60)\n');binary.chmod(0o700)
        self.catalog._items['go']['executable']=str(binary)
        atomic_write(self.config,b'{"role":"client"}')
        self.create(minimal_context('go'))
        try:
            self.registry.apply('home/nas')
            self.registry.run('home/nas')
            self.assertEqual(self.registry.connect('home/nas',role='client')['applicationBoundary'], 'stream')
            with self.assertRaisesRegex(ValueError,'locked native realization'):
                resolve_connection(service='home/nas',registry=self.registry,catalog=self.catalog,role='agent')
        finally:self.registry.stop('home/nas')


if __name__ == '__main__':unittest.main()
