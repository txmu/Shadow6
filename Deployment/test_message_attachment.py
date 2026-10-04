"""Real local supervisor/record attachment contract, using bounded fixture engines.

These tests validate application FD ownership, observation, and lifecycle; they
never claim native wire/trio verification for the fixture artifacts.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from Deployment.connection_plan import open_local_session
from Deployment.core_catalog import CoreCatalog
from Deployment.profile_registry import profiles
from Deployment.protocol_context import minimal_context
from Deployment.service_registry import ServiceRegistry
from Deployment.service_storage import atomic_write
from Deployment.shadow6_abi import encode_record, decode_record
from Deployment.application_attachment import NativeRecordAttachment, HANDSHAKE_SCHEMA
from Deployment.profile_registry import bind_profile

ROOT = Path(__file__).resolve().parents[1]


def native_config(core):
    if core == 'pony':
        return dict(core=core, role='client', listen_port=18010, peer_port=18011,
                    application_port=18012, private_key='a'*64, peer_public_key='b'*64)
    if core == 'hare':
        return dict(core=core, role='client', listen_port=18010, target_port=18012,
                    private_key='a'*64, peer_public_key='b'*64)
    value = dict(core=core, role='client', listen_port=18010, peer_port=18011,
                 application_port=18012, key_material='a'*192)
    if core == 'idris': value.update(listen_host='127.0.0.1', peer_host='127.0.0.1', application_host='127.0.0.1', iterations=100000)
    return value


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'pidfd_open'),
                    'record lifecycle requires the Linux owned-FD/pidfd observation backend')
class MessageAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='shadow6-msg-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.catalog = CoreCatalog(ROOT)
        self.registry = ServiceRegistry(self.directory/'services.json', self.catalog)
        self.names = []
        self.addCleanup(self.stop_all)

    def stop_all(self):
        for name in self.names:
            try: self.registry.stop(name)
            except ValueError: pass

    def service(self, profile, *, ready=True):
        core = profile['core']
        script = self.directory/(core + '-fixture')
        script.write_text('''#!/usr/bin/env python3
import json,os,socket,time
fd=int(os.environ['SHADOW6_APP_FLOW_FD'])
s=socket.socket(fileno=fd);s.setblocking(True);s.settimeout(10)
''' + (f'''print(json.dumps({{'event':'shadow6.ready','schema':1,'core':'shadow6-{core}','role':'client','application_boundary':{{'kind':'message','mode':'seqpacket-fd','endpoint':{{'fd':fd}}}}}}),flush=True)
''' if ready else '') + '''while True:
    data=s.recv(65536)
    if not data:break
    s.send(data)
s.close()
''')
        script.chmod(0o700)
        self.catalog._items[core]['executable'] = str(script)
        path = self.directory/(core+'.json'); atomic_write(path,json.dumps(native_config(core)).encode())
        context=minimal_context(core);context['role']='client'
        name='message/'+core; self.names.append(name)
        self.registry.create(name,core=core,profile=profile['id'],config={'config_path':str(path)},context=context)
        self.registry.apply(name)
        return name

    def test_four_seqpacket_profiles_share_owned_attachment_and_lifecycle(self):
        for profile in profiles():
            if profile['attachment']['mode'] != 'seqpacket-fd':continue
            with self.subTest(profile=profile['id']):
                name=self.service(profile)
                item=self.registry.run(name)
                self.assertEqual(item['state'],'running')
                self.assertEqual(item['runtime']['readiness'],'application-ready')
                target=item['runtime']['endpoint']
                self.assertEqual(target['nativeOwner'],item['runtimeObservation']['processes'][0])
                plan=self.registry.connect(name)
                self.assertEqual(plan['capability']['sessionLaunch'],'local-application-message')
                self.assertEqual(plan['endpointFraming'],'native-application-records')
                with open_local_session(plan) as session:
                    for data in (b'one',b'two\x00bytes',b'x'*profile['limits']['max_record']):
                        session.send_record(data); self.assertEqual(session.receive_record(),data)
                    with self.assertRaisesRegex(ValueError,'OversizedApplicationRecord'):
                        session.send_record(b'x'*(session.max_record+1))
                    with self.assertRaisesRegex(ValueError,'UnsupportedPartialRecordReceive'):
                        session.receive(1)
                    with self.assertRaisesRegex(ValueError,'UnsupportedApplicationHalfClose'):
                        session.half_close()
                    with self.assertRaisesRegex(ValueError,'AttachmentConsumed'):
                        open_local_session(self.registry.connect(name))
                    session.finish(); self.assertEqual(session.receive_record(),b'');self.assertTrue(session.eof)
                self.registry.stop(name)
                second=self.registry.run(name)
                self.assertNotEqual(second['runtime']['pid'],item['runtime']['pid'])
                self.registry.stop(name); self.registry.remove(name)

    def test_micro_mux_owned_datagrams_remain_message_preserving_best_effort(self):
        profile = next(p for p in profiles('gleam') if p['id'] == 'gleam-micro-mux')
        binary = self.directory / 'gleam-fixture'
        binary.write_text("#!/usr/bin/env python3\nimport json,socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.settimeout(10)\nprint(json.dumps({'event':'shadow6.ready','schema':1,'core':'shadow6-gleam','role':'client','application_boundary':{'kind':'message','mode':'localhost-udp-datagram-proxy','endpoint':{'host':'127.0.0.1','port':s.getsockname()[1]}}}),flush=True)\nwhile True:\n    data,peer=s.recvfrom(65536);s.sendto(data,peer)\n")
        binary.chmod(0o700);self.catalog._items['gleam']['executable']=str(binary)
        path=self.directory/'gleam.json';atomic_write(path,b'{"role":"client","client":{"transport":"micro-mux"}}')
        name='message/gleam';self.names.append(name)
        self.registry.create(name,core='gleam',profile=profile['id'],config={'config_path':str(path)},context={**minimal_context('gleam'),'role':'client'})
        self.registry.apply(name);item=self.registry.run(name)
        self.assertEqual(item['runtime']['readiness'],'application-ready')
        with open_local_session(self.registry.connect(name)) as session:
            for record in (b'a',b'\0b',b'',b'x'*65465):
                session.send_record(record);self.assertEqual(session.receive_record(),record)
                self.assertFalse(session.eof)
            with self.assertRaisesRegex(ValueError,'UnsupportedApplicationEOF'):session.finish()
            with self.assertRaisesRegex(ValueError,'UnsupportedApplicationHalfClose'):session.half_close()
        self.registry.stop(name);self.registry.remove(name)

    def test_libshadow6_uses_the_same_message_session_contract(self):
        from unittest.mock import patch
        import libshadow6
        profile=next(p for p in profiles() if p['core']=='pony')
        name=self.service(profile);self.registry.run(name)
        with patch.object(libshadow6.Shadow6, 'connection_plan', return_value=self.registry.connect(name)):
            client=libshadow6.Shadow6(cli=sys.executable)
            with client.connect(name) as session:
                session.send_record(b'library-record');self.assertEqual(session.receive_record(),b'library-record')

    def test_missing_native_fd_ack_never_claims_application_ready(self):
        profile=next(p for p in profiles() if p['core']=='pony')
        name=self.service(profile,ready=False)
        with self.assertRaisesRegex(ValueError,'failed to start'):
            self.registry.run(name)
        self.assertNotEqual(self.registry.status(name)['state'],'running')

    def test_record_stdio_preserves_multiple_record_boundaries_and_eof(self):
        profile=next(p for p in profiles() if p['core']=='pony')
        name=self.service(profile);self.registry.run(name)
        env={**os.environ,'SHADOW6_SERVICE_REGISTRY':str(self.registry.path)}
        # The subprocess needs the same fixture descriptor; use the real registry
        # plan directly with the public record-stdio function, not a new Core map.
        plan=self.registry.connect(name)
        path=self.directory/'plan.json';atomic_write(path,json.dumps(plan).encode())
        code="import sys,json;from shadow6_connect import record_session;record_session(json.load(open(sys.argv[1])))"
        payload=b''.join(encode_record(data,max_record=1172) for data in (b'a',b'b\x00c',b'd'*1172))
        result=subprocess.run([sys.executable,'-c',code,str(path)],input=payload,capture_output=True,
            env={**env,'PYTHONPATH':str(ROOT/'CLI')},timeout=12)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        actual=[];data=result.stdout
        while data:
            size=int.from_bytes(data[:4],'big');actual.append(decode_record(data[:size+4],max_record=1172));data=data[size+4:]
        self.assertEqual(actual,[b'a',b'b\x00c',b'd'*1172])

    def test_record_codec_rejects_truncation_oversize_and_type_coercion(self):
        for frame in (b'',b'\0\0\0\2a',b'\0\0\0\1ab'):
            with self.assertRaises(ValueError):decode_record(frame,max_record=1172)
        with self.assertRaises(ValueError):encode_record(b'x'*1173,max_record=1172)
        with self.assertRaises(ValueError):encode_record(b'x',max_record=True)

    def test_record_adapter_backpressure_is_bounded_and_recovers_without_splitting(self):
        binding = bind_profile('pony')
        with NativeRecordAttachmentFixture(self.directory, binding) as attachment:
            peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self.addCleanup(peer.close); peer.connect(str(attachment.path)); peer.setblocking(False)
            peer.send(json.dumps(dict(schema=HANDSHAKE_SCHEMA, profileBinding=binding,
                lockDigest='sha256:'+'a'*64, nonce='b'*64)).encode())
            attachment.pump()
            self.assertEqual(json.loads(peer.recv(4096))['state'], 'accepted')
            record = b'x' * attachment.max_record
            accepted = 0
            for _ in range(1024):
                try: peer.send(record)
                except BlockingIOError: break
                accepted += 1; attachment.pump()
            else: self.fail('record adapter did not propagate bounded backpressure')
            self.assertEqual(attachment.pending_native, record)
            observed = []
            for _ in range(2048):
                attachment.pump()
                try: observed.append(attachment.child.recv(2048))
                except BlockingIOError: pass
                if len(observed) == accepted: break
            self.assertEqual(observed, [record] * accepted)
            self.assertIsNone(attachment.pending_native)

    def test_wrong_handshake_lock_binding_cannot_consume_native_attachment(self):
        binding = bind_profile('pony')
        with NativeRecordAttachmentFixture(self.directory, binding) as attachment:
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
                peer.connect(str(attachment.path)); peer.settimeout(1)
                peer.send(json.dumps(dict(schema=HANDSHAKE_SCHEMA, profileBinding=binding,
                    lockDigest='sha256:'+'0'*64, nonce='b'*64)).encode())
                attachment.pump()
                self.assertEqual(json.loads(peer.recv(4096))['error'], 'AttachmentBindingMismatch')
                self.assertFalse(attachment.accepted)
                with self.assertRaises(BlockingIOError): attachment.child.recv(2048)


class NativeRecordAttachmentFixture:
    def __init__(self, directory, binding):
        self.adapter = NativeRecordAttachment(directory/'adapter.sock', binding, 1172, 'sha256:'+'a'*64)
        self.adapter.acknowledge({'readiness':'application-ready', 'endpoint':{
            'boundary':'message','mode':'seqpacket-fd','fd':self.adapter.child_fd}}, {'pid':os.getpid()})
    def __enter__(self): return self.adapter
    def __exit__(self, *_): self.adapter.close()


if __name__=='__main__':unittest.main()
