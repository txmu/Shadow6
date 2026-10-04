"""Full source-built encrypted SCTP path through real local associations."""
import ctypes as c
import hmac
import secrets
import socket
import threading
import time
import unittest
import test_e2e as e2e
import test_sctp_native as native_fixture
KEY=e2e.KEY
from wire_v3 import lib as sodium

CHANNELS='0:ordered:reliable,1:unordered:retransmits:0,2:unordered:reliable'

class SCTPEnvelopeE2E(unittest.TestCase):
    setUp=e2e.EnvelopeE2E.setUp
    stop=e2e.EnvelopeE2E.stop
    launch=e2e.EnvelopeE2E.launch
    metrics=e2e.EnvelopeE2E.metrics
    send=native_fixture.SCTPNativeTests.send
    receive=native_fixture.SCTPNativeTests.receive
    next_event=native_fixture.SCTPNativeTests.next_event

    @classmethod
    def setUpClass(cls):
        native_fixture.SCTPNativeTests.setUpClass.__func__(cls)

    def native_socket(self):
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM,132)
        self.assertEqual(self.lib.s6_sctp_prepare(sock.fileno(),4),0)
        return sock

    def handle(self,sock,maximum=73728):
        sock.setblocking(False)
        handle=self.lib.s6_sctp_attach(sock.fileno(),maximum)
        self.assertTrue(handle)
        return handle

    def echo_sctp(self,expect_abort=False,resets=None):
        listener=self.native_socket();listener.bind(('127.0.0.1',0));listener.listen(8);listener.settimeout(.1)
        self.addCleanup(listener.close)
        failures=[]
        def echo():
            while not self.done.is_set():
                try:sock,_=listener.accept()
                except TimeoutError:continue
                except OSError:return
                handle=None
                try:
                    handle=self.handle(sock,4096)
                    while not self.done.is_set():
                        result,event,data=self.receive(handle)
                        if result<0:
                            if expect_abort:break
                            raise RuntimeError('native echo SCTP failed')
                        if not result:time.sleep(.001);continue
                        if event.kind in (3,4):break
                        if event.kind==2 and resets is not None:
                            resets.append((event.reset_flags,list(event.reset_streams[:event.reset_count])))
                            continue
                        if event.kind!=1:raise RuntimeError('unexpected native echo lifecycle')
                        policy=1 if event.stream==1 else 0
                        until=time.monotonic()+3
                        while self.send(handle,data,event.stream,bool(event.ordered),event.ppid,policy,0)==0:
                            if time.monotonic()>until:raise RuntimeError('native echo backpressure deadline')
                            time.sleep(.001)
                except Exception as error:failures.append(error)
                finally:
                    if handle:self.lib.s6_sctp_free(handle)
                    sock.close()
        worker=threading.Thread(target=echo,daemon=True);worker.start()
        self.addCleanup(lambda:(self.done.set(),worker.join(3)))
        return listener.getsockname()[1],failures

    def launch_sctp(self,name,role,upstream,**options):
        return self.launch(name,'message',role,upstream,carrier='sctp',message_channels=CHANNELS,sctp_streams=4,**options)

    def connect(self,port):
        sock=self.native_socket();sock.settimeout(3);sock.connect(('127.0.0.1',port))
        self.addCleanup(sock.close);handle=self.handle(sock)
        self.addCleanup(self.lib.s6_sctp_free,handle)
        return sock,handle

    def wire_relay(self,upstream,attack=None):
        listener=self.native_socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(.1)
        self.addCleanup(listener.close)
        captured=[];failures=[]
        def relay():
            sockets=[];handles=[]
            try:
                deadline=time.monotonic()+4
                while not self.done.is_set():
                    try:peer,_=listener.accept();break
                    except TimeoutError:
                        if time.monotonic()>deadline:raise RuntimeError('SCTP relay accept deadline')
                else:return
                sockets.append(peer)
                target=self.native_socket();sockets.append(target)
                target.settimeout(3);target.connect(('127.0.0.1',upstream))
                handles.extend((self.handle(peer),self.handle(target)))
                changed=False
                while not self.done.is_set() and time.monotonic()<deadline:
                    activity=False
                    for direction,source in enumerate(handles):
                        result,event,data=self.receive(source)
                        if result<0:raise RuntimeError('SCTP relay receive failed')
                        if not result:continue
                        activity=True
                        if event.kind in (3,4):return
                        if event.kind!=1:raise RuntimeError('unexpected relay lifecycle')
                        captured.append((direction,event.stream,data))
                        packets=[data]
                        if direction==0 and data.startswith(b'S6EP3M00') and not changed:
                            changed=True
                            if attack=='replay':packets=[data,data]
                            if attack=='tamper':packets=[data[:-1]+bytes([data[-1]^1])]
                        for packet in packets:
                            policy=1 if event.stream==1 else 0
                            until=time.monotonic()+1
                            while self.send(handles[1-direction],packet,event.stream,bool(event.ordered),event.ppid,policy,0)==0:
                                if time.monotonic()>until:raise RuntimeError('SCTP relay send deadline')
                                time.sleep(.001)
                    if not activity:time.sleep(.001)
            except Exception as error:failures.append(error)
            finally:
                for handle in handles:self.lib.s6_sctp_free(handle)
                for sock in sockets:sock.close()
        worker=threading.Thread(target=relay,daemon=True);worker.start()
        self.addCleanup(lambda:(self.done.set(),worker.join(3)))
        return listener.getsockname()[1],captured,failures

    def test_actual_sctp_wire_encrypts_payload_but_identifies_hello(self):
        native,failures=self.echo_sctp()
        server,_=self.launch_sctp('wire-server','server',native)
        relay,captured,relay_failures=self.wire_relay(server)
        client,_=self.launch_sctp('wire-client','client',relay)
        _,handle=self.connect(client)
        payload=b'opaque-native-payload-'+secrets.token_bytes(512)
        self.assertEqual(self.send(handle,payload,2,False,1234),1)
        result,event,data=self.next_event(handle)
        self.assertEqual((result,event.kind,data,event.stream),(1,1,payload,2))
        wire=b''.join(data for _,_,data in captured)
        self.assertIn(b'S6EP3S00',wire)
        self.assertIn(b'S6EP3C00',wire)
        self.assertNotIn(payload,wire)
        self.assertTrue(any(stream==2 and data.startswith(b'S6EP3M00') for _,stream,data in captured))
        self.assertFalse(failures);self.assertFalse(relay_failures)

    def test_authenticated_reset_reaches_native_peer_and_stream_reuses(self):
        resets=[]
        native,failures=self.echo_sctp(resets=resets)
        server,server_metrics=self.launch_sctp('reset-server','server',native)
        client,client_metrics=self.launch_sctp('reset-client','client',server)
        sock,handle=self.connect(client)
        def roundtrip(payload):
            self.assertEqual(self.send(handle,payload,2,False,77),1)
            result,event,data=self.next_event(handle)
            self.assertEqual((result,event.kind,data,event.stream),(1,1,payload,2))
        roundtrip(b'before-authenticated-reset')
        self.assertEqual(self.lib.s6_sctp_reset(handle,2,0,1),1)
        result,event,_=self.next_event(handle)
        self.assertEqual((result,event.kind),(1,2))
        self.assertTrue(event.reset_flags&2)
        until=time.monotonic()+2
        while not resets and time.monotonic()<until:time.sleep(.01)
        self.assertTrue(any(flags&1 and ids==[2] for flags,ids in resets),resets)
        roundtrip(b'after-authenticated-reset')
        sock.shutdown(socket.SHUT_WR)
        for path in (server_metrics,client_metrics):
            self.assertEqual(self.metrics(path,'authenticated_sessions',1)['session_rejection_count'],0)
        self.assertFalse(failures)

    def test_wire_replay_and_tamper_fail_closed(self):
        for attack in ('replay','tamper'):
            with self.subTest(attack=attack):
                native,failures=self.echo_sctp(expect_abort=True)
                server,metrics=self.launch_sctp(attack+'-server','server',native)
                relay,_,relay_failures=self.wire_relay(server,attack)
                client,_=self.launch_sctp(attack+'-client','client',relay)
                _,handle=self.connect(client)
                payload=b'one-authenticated-native-message'
                self.assertEqual(self.send(handle,payload,2,False,1234),1)
                key='replay_rejection_count' if attack=='replay' else 'session_rejection_count'
                value=self.metrics(metrics,key,1)
                self.assertEqual(value['authenticated_sessions'],1)
                self.assertEqual(value['bytes_in'],len(payload) if attack=='replay' else 0)
                self.assertFalse(failures);self.assertFalse(relay_failures)

    def test_real_envelope_preserves_messages_ppid_stream_order_and_shutdown(self):
        native,failures=self.echo_sctp()
        server,server_metrics=self.launch_sctp('sctp-server','server',native)
        client,client_metrics=self.launch_sctp('sctp-client','client',server)
        sock,handle=self.connect(client)
        total=0
        for stream,ordered,policy in ((0,True,0),(2,False,0),(1,False,1)):
            for number in range(8):
                payload=b'native-sctp-payload-marker-'+secrets.token_bytes(3000+number)
                ppid=0xffffffff-number
                self.assertEqual(self.send(handle,payload,stream,ordered,ppid,policy,0),1)
                result,event,data=self.next_event(handle)
                self.assertEqual((result,event.kind,data,event.stream,bool(event.ordered),event.ppid),
                                 (1,1,payload,stream,ordered,ppid));total+=len(payload)
        sock.shutdown(socket.SHUT_WR)
        # A process staying alive or byte counters advancing does not prove
        # the authenticated FINAL exchange and association close completed.
        closing=[]
        until=time.monotonic()+3
        while time.monotonic()<until:
            result,event,data=self.receive(handle)
            self.assertGreaterEqual(result,0)
            if not result:time.sleep(.001);continue
            self.assertIn(event.kind,(3,4));self.assertEqual(data,b'')
            closing.append(event.kind)
            if event.kind==4:break
        self.assertIn(4,closing,'authenticated association close did not complete')
        # Public admission metrics are actual crypto sessions, not inferred from
        # the native listener or TLS/SCTP association being alive.
        for path in (server_metrics,client_metrics):
            value=self.metrics(path,'bytes_out',total)
            self.assertEqual(value['authenticated_sessions'],1)
            self.assertEqual(value['carrier'],'sctp')
            self.assertEqual(value['wire_appearance'],'standard-sctp')
            self.assertEqual(value['session_rejection_count'],0)
        self.assertFalse(failures)

    def test_wrong_message_proof_never_opens_native_upstream(self):
        native=self.native_socket();native.bind(('127.0.0.1',0));native.listen(1);native.settimeout(.2)
        self.addCleanup(native.close)
        server,metrics=self.launch_sctp('sctp-proof','server',native.getsockname()[1])
        _,handle=self.connect(server)
        result,event,hello=self.next_event(handle)
        self.assertEqual((result,event.kind,len(hello)),(1,1,88))
        public,secret=c.create_string_buffer(32),c.create_string_buffer(32)
        self.assertEqual(sodium.crypto_kx_keypair(public,secret),0)
        client=b'S6EP3C00'+secrets.token_bytes(32)+public.raw+b'0000000000000001'
        self.assertEqual(self.send(handle,client),1)
        proof=hmac.digest(b'wrong-message-secret',b'S6EPE/3 message client'+hello+client,'sha256')
        self.assertEqual(self.send(handle,proof),1)
        value=self.metrics(metrics,'preauth_rejection_count',1)
        self.assertEqual(value['authenticated_sessions'],0)
        with self.assertRaises(TimeoutError):native.accept()

    def test_sctp_runtime_configuration_rejects_wrong_mode_channels_and_fields(self):
        base=dict(mode='message',carrier='sctp',listen='127.0.0.1:19343',upstream='127.0.0.1:19344',auth_key=KEY)
        for index,override in enumerate(({'mode':'stream'},{'carrier':'raw'},
          {'message_channels':'1:ordered:reliable'},{'message_channels':'0:ordered:reliable,0:unordered:reliable'},
          {'message_channels':'0:ordered:reliable,4:ordered:reliable'},
          {'message_channels':'0:ordered:reliable,1:unordered:lifetime:60001'},
          {'tls_peer_name':'unexpected'},{'listen':'unix:'+str(self.root/'socket')})):
            import subprocess
            with self.subTest(index=index):
                path=self.root/f'invalid-sctp-{index}.conf'
                path.write_text(''.join(f'{key}={value}\n' for key,value in {**base,**override}.items()));path.chmod(0o600)
                result=subprocess.run([self.binary,'--config',str(path)],capture_output=True,timeout=3)
                self.assertNotEqual(result.returncode,0)

    def test_feature_report_describes_actual_message_security(self):
        import json, subprocess
        report=json.loads(subprocess.check_output([self.binary,'--feature-report'],timeout=3))
        self.assertIn('message',report['transports'])
        self.assertEqual(report['carriers']['message_adapters'],['sctp'])
        self.assertEqual(report['message_security'],{
            'key_exchange':'PSK-authenticated-X25519','rekey_records':4096,
            'replay_window':4096,'records_per_channel':1000000,'channels':64,
            'authenticated_close':True,'fresh_session_keys':True})


if __name__=='__main__':unittest.main()
