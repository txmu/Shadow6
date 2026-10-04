"""Compile only the small TLS binding; real local TLS, no Native Core build."""
import ctypes as c
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from tls_fixtures import identities

ROOT = Path(__file__).resolve().parents[1]


class TLSNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='s6epe-tls-native-')
        cls.addClassCleanup(cls.temp.cleanup)
        library = Path(cls.temp.name) / 'tls.so'
        subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
                        str(ROOT/'src/carrier_tls_native.c'), '-lssl', '-lcrypto', '-o', str(library)],
                       check=True, capture_output=True, timeout=30)
        cls.lib = c.CDLL(str(library))
        types = {
            's6_tls_context_create': ([c.c_void_p,c.c_size_t]*3,c.c_void_p),
            's6_tls_context_free': ([c.c_void_p],None),
            's6_tls_create': ([c.c_void_p,c.c_int,c.c_int,c.c_char_p],c.c_void_p),
            's6_tls_free': ([c.c_void_p],None),
            's6_tls_handshake': ([c.c_void_p],c.c_int),
            's6_tls_read': ([c.c_void_p,c.c_void_p,c.c_size_t],c.c_int),
            's6_tls_write': ([c.c_void_p,c.c_void_p,c.c_size_t],c.c_int),
            's6_tls_pending': ([c.c_void_p],c.c_int),
            's6_tls_shutdown_send': ([c.c_void_p],c.c_int),
        }
        for name,(args,result) in types.items():
            getattr(cls.lib,name).argtypes=args
            getattr(cls.lib,name).restype=result

    def setUp(self):
        self.material = identities()

    def context(self, role, material=None):
        material = material or self.material
        cert,key,ca = [material[k] for k in (role+'_cert',role+'_key','ca')]
        context = self.lib.s6_tls_context_create(cert,len(cert),key,len(key),ca,len(ca))
        self.assertTrue(context)
        self.addCleanup(self.lib.s6_tls_context_free,context)
        return context

    def session(self, role, fd, *, peer=None, material=None):
        handle = self.lib.s6_tls_create(self.context(role,material),fd.fileno(),role=='server',
                                       (peer or ('epe-client' if role=='server' else 'epe-server')).encode())
        self.assertTrue(handle)
        self.addCleanup(self.lib.s6_tls_free,handle)
        return handle

    def pair(self, **client_options):
        client,server = socket.socketpair()
        for sock in (client,server):
            self.addCleanup(sock.close)
            sock.setblocking(False)
        return self.session('client',client,**client_options),self.session('server',server),client,server

    def handshake(self, client, server):
        states = [0,0]
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            for i,session in enumerate((client,server)):
                if states[i] != 1: states[i]=self.lib.s6_tls_handshake(session)
            if -3 in states: return False
            if states==[1,1]: return True
            time.sleep(.001)
        self.fail('bounded TLS handshake timed out')

    def read(self, session, count=131072):
        data=c.create_string_buffer(count)
        n=self.lib.s6_tls_read(session,data,count)
        return n,data.raw[:max(n,0)]

    def eventually(self, operation):
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            result=operation()
            if result not in (-1,-2):return result
            time.sleep(.001)
        self.fail('bounded TLS operation timed out')

    def test_mutual_tls_preserves_send_half_close_and_peer_data(self):
        client,server,_,_=self.pair()
        self.assertTrue(self.handshake(client,server))
        self.assertEqual(self.lib.s6_tls_write(client,b'opaque',6),6)
        result=self.eventually(lambda:self.read(server)[0])
        self.assertEqual(result,6)
        self.assertEqual(self.eventually(lambda:self.lib.s6_tls_shutdown_send(client)),1)
        self.assertEqual(self.eventually(lambda:self.read(server)[0]),0)
        self.assertEqual(self.lib.s6_tls_write(server,b'reply',5),5)
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            n,data=self.read(client)
            if n not in (-1,-2):break
            time.sleep(.001)
        self.assertEqual((n,data),(5,b'reply'))
        self.assertEqual(self.eventually(lambda:self.lib.s6_tls_shutdown_send(server)),1)
        self.assertEqual(self.eventually(lambda:self.read(client)[0]),0)

    def test_backpressure_retry_preserves_exact_record_bytes(self):
        client,server,sock,_=self.pair()
        self.assertTrue(self.handshake(client,server))
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
        payload=b'bounded-record-'*2048
        pending=payload; sent=bytearray(); received=bytearray(); blocked=False
        deadline=time.monotonic()+3
        # Force a write retry before permitting the peer to drain.
        while time.monotonic()<deadline:
            n=self.lib.s6_tls_write(client,pending,len(pending))
            if n in (-1,-2): blocked=True;break
            self.assertGreater(n,0);sent.extend(pending[:n]);pending=pending[n:]
            if not pending: pending=payload
        self.assertTrue(blocked,'small socket buffer must exercise TLS backpressure')
        while time.monotonic()<deadline and pending:
            n,data=self.read(server)
            if n>0: received.extend(data)
            else:self.assertIn(n,(-1,-2))
            n=self.lib.s6_tls_write(client,pending,len(pending))
            if n>0: sent.extend(pending[:n]);pending=pending[n:]
            else:self.assertIn(n,(-1,-2))
        self.assertFalse(pending,'write retry must progress after peer drain')
        while len(received)<len(sent) and time.monotonic()<deadline:
            n,data=self.read(server)
            if n>0: received.extend(data)
            else:self.assertIn(n,(-1,-2))
        self.assertEqual(received,sent)

    def test_wrong_san_and_untrusted_ca_fail_before_application_bytes(self):
        for options in ({'peer':'wrong-name'}, {'material':identities()}):
            with self.subTest(options=tuple(options)):
                client,server,_,_=self.pair(**options)
                self.assertFalse(self.handshake(client,server))
                self.assertEqual(self.lib.s6_tls_write(client,b'forbidden',9),-3)

    def test_raw_tcp_eof_is_not_authenticated_tls_close(self):
        client,server,sock,_=self.pair()
        self.assertTrue(self.handshake(client,server))
        sock.shutdown(socket.SHUT_WR)
        self.assertEqual(self.eventually(lambda:self.read(server)[0]),-3)
        self.assertEqual(self.lib.s6_tls_shutdown_send(server),-3)

    def test_material_parser_rejects_junk_extra_cert_wrong_key_and_oversize(self):
        m=self.material
        for cert,key,ca in ((m['server_cert']+m['server_cert'],m['server_key'],m['ca']),
                            (b'junk'+m['server_cert'],m['server_key'],m['ca']),
                            (m['server_cert'],m['client_key'],m['ca']),
                            (m['server_cert'],m['server_key']+b'junk',m['ca']),
                            (m['server_cert'],m['server_key'],b'x'*16385)):
            self.assertFalse(self.lib.s6_tls_context_create(cert,len(cert),key,len(key),ca,len(ca)))

    def test_standard_tls_wire_conceals_inner_hello_and_payload(self):
        client,left=socket.socketpair();right,server=socket.socketpair()
        for sock in (client,left,right,server):self.addCleanup(sock.close)
        client.setblocking(False);server.setblocking(False)
        wire=[];stop=threading.Event()
        def relay():
            try:
                while not stop.is_set():
                    ready,_,_=select.select([left,right],[],[],.02)
                    for source in ready:
                        data=source.recv(65536)
                        if not data:return
                        wire.append((source is left,data))
                        (right if source is left else left).sendall(data)
            except OSError:pass
        worker=threading.Thread(target=relay,daemon=True);worker.start()
        self.addCleanup(lambda:(stop.set(),worker.join(1)))
        c_session=self.session('client',client);s_session=self.session('server',server)
        self.assertTrue(self.handshake(c_session,s_session))
        inner=b'S6EP3C00'+b'inner-envelope-hello-payload-marker'
        self.assertEqual(self.lib.s6_tls_write(c_session,inner,len(inner)),len(inner))
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            n,data=self.read(s_session)
            if n not in (-1,-2):break
            time.sleep(.001)
        self.assertEqual(data,inner)
        captured=b''.join(data for _,data in wire)
        client_wire=b''.join(data for direction,data in wire if direction)
        self.assertEqual(client_wire[0],22) # Standard TLS handshake record.
        self.assertNotIn(b'S6EP3',captured)
        self.assertNotIn(b'inner-envelope-hello-payload-marker',captured)


if __name__=='__main__':unittest.main()
