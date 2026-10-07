"""Real Unix SCM_RIGHTS/ownership tests; not Native artifact evidence."""
import array
import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import time
import struct
import unittest
from unittest.mock import patch
import shadow6_control as control
from fd_gateway import FDGateway, SCHEMA
from Deployment.profile_registry import bind_profile
from Deployment.service_runtime import identity
from Deployment.session_handles import sessions


class FDGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='shadow6-fd-gateway-')
        self.addCleanup(self.temp.cleanup)
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(4)
        self.addCleanup(self.listener.close)
        owner={'pid':os.getpid(),'processIdentity':identity(os.getpid())}
        self.plan={'core':'go','profileBinding':bind_profile('go','go-kcp'),
            'lockDigest':'sha256:'+'a'*64,'runtimeIdentity':owner,'readiness':'application-ready',
            'applicationBoundary':'stream','endpoint':{'host':'127.0.0.1','port':self.listener.getsockname()[1],
                'boundary':'stream','mode':'localhost-tcp-proxy','observation':'structured-ready-event','owner':owner},
            'applicationAdapter':{'provider':'native','boundary':'stream'}}
        self.gateway=await FDGateway(Path(self.temp.name)/'control.sock','t'*32,allow_mutations=True).start()
        self.addAsyncCleanup(self.gateway.close)

    def fake_response(self,request,*,allow_mutations):
        if request['method']=='service.connection_review':
            return {'ok':True,'result':{'plan':self.plan,
                'expected_plan_digest':'sha256:'+'b'*64,'expected_material_digest':'sha256:'+'a'*64,
                'expected_lock_digest':'sha256:'+'a'*64}}
        self.assertEqual(request['method'],'service.connect_execute')
        self.assertTrue(allow_mutations)
        return {'ok':True,'result':{'session':sessions.open('home/game',self.plan['lockDigest'],'review',self.plan)}}

    def request(self,token='t'*32,nonce=None,issued_at=None):
        connection=socket.socket(socket.AF_UNIX,self.gateway.kind)
        connection.settimeout(10)
        try:
            connection.connect(str(self.gateway.path))
            nonce=nonce or secrets.token_hex(32)
            request=json.dumps({'schema':SCHEMA,'nonce':nonce,'token':token,'name':'home/game','confirmed':True,'issuedAt':int(time.time()) if issued_at is None else issued_at}).encode()
            connection.sendall(struct.pack('!I',len(request))+request if self.gateway.kind==socket.SOCK_STREAM else request)
            body,ancillary,flags,_=connection.recvmsg(65536,socket.CMSG_SPACE(4),getattr(socket,'MSG_CMSG_CLOEXEC',0))
            fds=[]
            for level,kind,data in ancillary:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    items=array.array('i');items.frombytes(data);fds.extend(items)
            if self.gateway.kind==socket.SOCK_STREAM:
                while len(body)<4 or len(body)<4+struct.unpack('!I',body[:4])[0]:
                    part=connection.recv(65540-len(body))
                    if not part: raise ValueError('truncated response')
                    body+=part
                body=body[4:]
            for fd in fds:os.set_inheritable(fd,False)
            return json.loads(body),fds,flags
        finally:connection.close()

    async def test_handoff_is_direct_cloexec_and_closing_fd_does_not_stop_authority(self):
        with patch.object(control,'response',side_effect=self.fake_response):
            metadata,fds,flags=await asyncio.to_thread(self.request)
        self.assertEqual(flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC),0)
        self.assertEqual(len(fds),1)
        fd=fds[0]
        try:
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(metadata['connection']['boundary']['semantics'],'stream')
            peer,_=self.listener.accept()
            with peer:
                os.write(fd,b'raw-native-data');self.assertEqual(peer.recv(15),b'raw-native-data')
                peer.sendall(b'reply');self.assertEqual(os.read(fd,5),b'reply')
        finally:os.close(fd)
        self.assertIsNotNone(self.gateway.listener)

    async def test_authentication_and_mutation_gate_fail_before_dispatch(self):
        with patch.object(control,'response') as dispatch:
            value,fds,_=await asyncio.to_thread(self.request,'wrong')
            self.assertIn('error',value);self.assertEqual(fds,[]);dispatch.assert_not_called()
            self.gateway.allow_mutations=False
            value,fds,_=await asyncio.to_thread(self.request)
            self.assertIn('error',value);self.assertEqual(fds,[]);dispatch.assert_not_called()

    async def test_replay_and_expired_request_never_open_another_session(self):
        nonce=secrets.token_hex(32)
        with patch.object(control,'response',side_effect=self.fake_response) as dispatch:
            value,fds,_=await asyncio.to_thread(self.request,nonce=nonce)
            for fd in fds:os.close(fd)
            accepted=dispatch.call_count
            value,fds,_=await asyncio.to_thread(self.request,nonce=nonce)
            self.assertIn('error',value);self.assertEqual(fds,[])
            self.assertEqual(dispatch.call_count,accepted)
            value,fds,_=await asyncio.to_thread(self.request,issued_at=int(time.time())-60)
            self.assertIn('error',value);self.assertEqual(fds,[])
            self.assertEqual(dispatch.call_count,accepted)

    async def test_c_abi_early_cancel_and_invalid_options_never_dispatch(self):
        import ctypes
        library=Path(__file__).resolve().parents[1]/'libshadow6/native/libshadow6.so'
        if not library.is_file():self.skipTest('small native SDK must be built by the application-sdk CI job')
        token=Path(self.temp.name)/'token';token.write_bytes(b't'*32);token.chmod(0o600)
        class Options(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('timeout_ms',ctypes.c_uint32),('cancel_fd',ctypes.c_int)]
        class Error(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('code',ctypes.c_char*96)]
        lib=ctypes.CDLL(str(library))
        lib.s6_connection_open_with_options.argtypes=[ctypes.c_uint32,ctypes.c_char_p,ctypes.POINTER(Options),ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(Error)]
        read_fd,write_fd=os.pipe()
        try:
            os.write(write_fd,b'cancel')
            def invoke():
                handle=ctypes.c_void_p();error=Error()
                options=Options(1,1000,read_fd)
                self.assertEqual(lib.s6_connection_open_with_options(1,b'home/game',ctypes.byref(options),ctypes.byref(handle),ctypes.byref(error)),-1)
                self.assertEqual(error.code,b'ConnectionCancelled');self.assertFalse(handle)
                options.timeout_ms=0
                self.assertEqual(lib.s6_connection_open_with_options(1,b'home/game',ctypes.byref(options),ctypes.byref(handle),ctypes.byref(error)),-1)
                self.assertEqual(error.code,b'InvalidApplicationOptions')
            with patch.dict(os.environ,{'SHADOW6_CONTROL_SOCKET':str(self.gateway.path),'SHADOW6_CONTROL_TOKEN_FILE':str(token)}),patch.object(control,'response') as dispatch:
                await asyncio.to_thread(invoke)
                dispatch.assert_not_called()
            self.assertEqual(os.read(read_fd,6),b'cancel')
        finally:os.close(read_fd);os.close(write_fd)
