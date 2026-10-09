"""Native bounded loopback SCTP records and lifecycle; no Core build or wire parsing."""
import ctypes as c
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]

def peer_address_count(sock):
    # Linux SCTP_GET_PEER_ADDRS on a one-to-one, established association.
    buffer=c.create_string_buffer(4096);size=c.c_uint(len(buffer))
    query=c.CDLL(None,use_errno=True).getsockopt
    query.argtypes=[c.c_int,c.c_int,c.c_int,c.c_void_p,c.POINTER(c.c_uint)]
    query.restype=c.c_int
    if query(sock.fileno(),132,108,buffer,c.byref(size)):
        raise OSError(c.get_errno(),'SCTP peer address observation failed')
    if not 8<=size.value<=len(buffer):raise ValueError('SCTP peer address result bound')
    count=c.c_uint.from_buffer(buffer,4).value
    if not 1<=count<=64:raise ValueError('SCTP peer address count bound')
    return count

class Event(c.Structure):
    _fields_=[('kind',c.c_uint),('stream',c.c_uint),('ordered',c.c_uint),
              ('ppid',c.c_uint32),('context',c.c_uint32),('size',c.c_size_t),
              ('reset_flags',c.c_uint),('reset_count',c.c_uint),('reset_streams',c.c_uint16*64)]

class SCTPNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='s6epe-native-sctp-')
        cls.addClassCleanup(cls.temp.cleanup)
        library=Path(cls.temp.name)/'sctp.so'
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared',
                        str(ROOT/'src/carrier_sctp_native.c'),'-o',str(library)],
                       check=True,capture_output=True,timeout=30)
        cls.lib=c.CDLL(str(library),use_errno=True)
        declarations={
            's6_sctp_available':([],c.c_int),
            's6_sctp_prepare':([c.c_int,c.c_uint],c.c_int),
            's6_sctp_attach':([c.c_int,c.c_size_t],c.c_void_p),
            's6_sctp_free':([c.c_void_p],None),
            's6_sctp_send':([c.c_void_p,c.c_void_p,c.c_size_t,c.c_uint,c.c_int,c.c_uint32,c.c_uint32,c.c_int,c.c_uint],c.c_int),
            's6_sctp_receive':([c.c_void_p,c.c_void_p,c.c_size_t,c.POINTER(Event)],c.c_int),
            's6_sctp_reset':([c.c_void_p,c.c_uint,c.c_int,c.c_int],c.c_int),
            's6_sctp_watch_sender':([c.c_void_p],c.c_int),
        }
        for name,(args,result) in declarations.items():
            function=getattr(cls.lib,name);function.argtypes=args;function.restype=result

    def pair(self,maximum=131072,source_bound=False):
        listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM,132)
        self.addCleanup(listener.close)
        self.assertEqual(self.lib.s6_sctp_prepare(listener.fileno(),8),0)
        listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(3)
        client=socket.socket(socket.AF_INET,socket.SOCK_STREAM,132);self.addCleanup(client.close)
        self.assertEqual(self.lib.s6_sctp_prepare(client.fileno(),8),0)
        if source_bound:
            with socket.socket(type=socket.SOCK_DGRAM) as route:
                route.connect(listener.getsockname())
                client.bind((route.getsockname()[0],0))
        client.settimeout(3);client.connect(listener.getsockname())
        server,_=listener.accept();self.addCleanup(server.close)
        handles=[]
        for sock in (client,server):
            sock.setblocking(False)
            handle=self.lib.s6_sctp_attach(sock.fileno(),maximum)
            self.assertTrue(handle);self.addCleanup(self.lib.s6_sctp_free,handle);handles.append(handle)
        return *handles,client,server

    def test_route_selected_source_advertises_one_peer_address(self):
        _,_,_,server=self.pair(source_bound=True)
        self.assertEqual(peer_address_count(server),1)

    def send(self,handle,payload,stream=0,ordered=True,ppid=0,policy=0,budget=0):
        return self.lib.s6_sctp_send(handle,payload,len(payload),stream,ordered,ppid,0,policy,budget)

    def receive(self,handle,maximum=131072):
        buffer=c.create_string_buffer(maximum);event=Event()
        result=self.lib.s6_sctp_receive(handle,buffer,maximum,c.byref(event))
        return result,event,buffer.raw[:event.size]

    def next_event(self,handle,maximum=131072):
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            result,event,data=self.receive(handle,maximum)
            if result:return result,event,data
            time.sleep(.001)
        self.fail('bounded SCTP event deadline')

    def test_native_messages_streams_ordering_and_ppid(self):
        client,server,_,_=self.pair()
        messages=[(b'first',2,True,0x12345678),(b'second',2,True,0xffffffff),
                  (b'unordered',3,False,7),(bytes(range(256))*256,4,True,42)]
        for payload,stream,ordered,ppid in messages:
            self.assertEqual(self.send(client,payload,stream,ordered,ppid),1)
            result,event,data=self.next_event(server)
            self.assertEqual(result,1);self.assertEqual(event.kind,1)
            self.assertEqual((data,event.stream,bool(event.ordered),event.ppid),(payload,stream,ordered,ppid))
        self.assertEqual(self.receive(server)[0],0)

    def test_sender_dry_rechecks_current_send_queue(self):
        client,server,sock,peer=self.pair()
        self.assertEqual(self.lib.s6_sctp_watch_sender(client),0)
        # Leave the immediately generated empty-queue notification unread,
        # then queue enough data to keep sends pending behind receive credit.
        peer.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,8192)
        payload=b'drain-evidence'+bytes(3000)
        sent=0
        for _ in range(128):
            result=self.send(client,payload)
            self.assertIn(result,(0,1))
            if not result:break
            sent+=1
        self.assertGreater(sent,0)
        result,event,_=self.receive(client)
        self.assertEqual(result,0,'stale empty notification accepted after new sends')
        for _ in range(sent):
            result,event,data=self.next_event(server)
            self.assertEqual((result,event.kind,data),(1,1,payload))
        result,event,_=self.next_event(client)
        self.assertEqual((result,event.kind),(1,7))

    def test_fragmented_large_native_record_emits_only_at_eor(self):
        client,server,_,_=self.pair()
        payload=bytes(range(256))*512
        self.assertEqual(self.send(client,payload,5,False,0xabcdef),1)
        incomplete=0;deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            result,event,data=self.receive(server)
            if not result:
                incomplete+=1;self.assertEqual(data,b'');continue
            self.assertEqual((result,event.kind,data,event.stream,event.ordered,event.ppid),
                             (1,1,payload,5,0,0xabcdef));break
        else:self.fail('fragmented record deadline')
        self.assertGreaterEqual(incomplete,7)

    def test_backpressure_refuses_whole_message_then_retry_preserves_count(self):
        client,server,sock,peer=self.pair()
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
        peer.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
        payload=b'whole-message-backpressure'+bytes(2000)
        accepted=0
        for _ in range(128):
            result=self.send(client,payload,2)
            if result==0:break
            self.assertEqual(result,1);accepted+=1
        else:self.fail('bounded small buffers did not exercise backpressure')
        received=0;retried=False;deadline=time.monotonic()+3
        while time.monotonic()<deadline and (received<accepted or not retried):
            result,event,data=self.receive(server)
            if result:
                self.assertEqual((result,event.kind,data),(1,1,payload));received+=1
            if not retried:
                result=self.send(client,payload,2)
                self.assertIn(result,(0,1))
                if result==1:retried=True;accepted+=1
            time.sleep(.001)
        self.assertTrue(retried);self.assertEqual(received,accepted)
        self.assertEqual(self.receive(server)[0],0)

    def test_partial_reliability_policies_are_native_send_options(self):
        client,server,_,_=self.pair()
        for policy,budget in ((1,0),(1,3),(2,60000)):
            payload=f'PR policy {policy} budget {budget}'.encode()
            self.assertEqual(self.send(client,payload,1,False,policy,policy,budget),1)
            result,event,data=self.next_event(server)
            self.assertEqual((result,event.kind,data,event.stream,event.ordered),(1,1,payload,1,0))

    def test_invalid_send_cannot_emit_partial_or_empty_native_message(self):
        client,server,_,_=self.pair(4096)
        for options in ({'payload':b''},{'payload':b'x'*4097},{'payload':b'x','stream':8},
                        {'payload':b'x','policy':2,'budget':0},
                        {'payload':b'x','policy':1,'budget':65536}):
            self.assertEqual(self.send(client,**options),-1)
        self.assertEqual(self.receive(server,4096)[0],0)
        self.assertEqual(self.send(client,b'valid'),1)
        self.assertEqual(self.next_event(server,4096)[2],b'valid')

    def test_oversize_receive_fails_closed_without_native_prefix(self):
        client,server,sock,_=self.pair(4096)
        self.assertEqual(sock.send(b'x'*5000),5000)
        result,event,data=self.next_event(server,4096)
        self.assertEqual(result,-1);self.assertEqual(data,b'')
        self.assertEqual(self.receive(server,4096)[0],-1)

    def test_reset_is_a_native_reset_and_stream_remains_reusable(self):
        client,server,_,_=self.pair()
        self.assertEqual(self.send(client,b'before',2),1)
        self.assertEqual(self.next_event(server)[2],b'before')
        self.assertEqual(self.lib.s6_sctp_reset(client,2,1,1),1,('reset errno',c.get_errno()))
        deadline=time.monotonic()+3;resets={client:0,server:0}
        while time.monotonic()<deadline and any(flags!=3 for flags in resets.values()):
            for handle in (client,server):
                result,event,_=self.receive(handle)
                if result:
                    self.assertEqual(result,1);self.assertEqual(event.kind,2)
                    self.assertFalse(event.reset_flags & 12)
                    self.assertIn(2,list(event.reset_streams)[:event.reset_count])
                    resets[handle] |= event.reset_flags
            time.sleep(.001)
        self.assertEqual(resets,{client:3,server:3})
        self.assertEqual(self.send(client,b'after',2),1)
        result,event,data=self.next_event(server)
        self.assertEqual((result,event.kind,data,event.stream),(1,1,b'after',2))

    def test_association_shutdown_is_not_an_empty_message(self):
        client,server,sock,_=self.pair()
        sock.shutdown(socket.SHUT_WR)
        deadline=time.monotonic()+3;kinds=[]
        while time.monotonic()<deadline and 4 not in kinds:
            result,event,data=self.receive(server)
            if result:
                self.assertEqual(result,1);self.assertIn(event.kind,(3,4));self.assertEqual(data,b'')
                kinds.append(event.kind)
            time.sleep(.001)
        self.assertIn(4,kinds)
        self.assertEqual(self.receive(server)[0],0)

    def test_build_without_linux_backend_reports_capability_unavailable(self):
        library=Path(self.temp.name)/'unsupported-sctp.so'
        subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-U__linux__','-fPIC','-shared',
                        str(ROOT/'src/carrier_sctp_native.c'),'-o',str(library)],
                       check=True,capture_output=True,timeout=30)
        unavailable=c.CDLL(str(library))
        self.assertEqual(unavailable.s6_sctp_available(),0)
        self.assertEqual(unavailable.s6_sctp_prepare(-1,8),-1)

    def test_tcp_and_unestablished_sctp_are_rejected(self):
        for protocol in (0,132):
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM,protocol) as sock:
                sock.setblocking(False)
                self.assertFalse(self.lib.s6_sctp_attach(sock.fileno(),4096))
                if not protocol:self.assertEqual(self.lib.s6_sctp_prepare(sock.fileno(),8),-1)


if __name__=='__main__':unittest.main()
