"""Real Unix SCM_RIGHTS/ownership tests; not Native artifact evidence."""
import array
import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import unittest
from unittest.mock import patch
import shadow6_control as control
from fd_gateway import FDGateway, SCHEMA
from profile_registry import bind_profile
from service_runtime import identity
from session_handles import sessions


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

    def request(self,token='t'*32):
        connection=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        connection.settimeout(10)
        try:
            connection.connect(str(self.gateway.path))
            nonce=secrets.token_hex(32)
            connection.send(json.dumps({'schema':SCHEMA,'nonce':nonce,'token':token,'name':'home/game','confirmed':True}).encode())
            body,ancillary,flags,_=connection.recvmsg(65536,socket.CMSG_SPACE(4),socket.MSG_CMSG_CLOEXEC)
            fds=[]
            for level,kind,data in ancillary:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    items=array.array('i');items.frombytes(data);fds.extend(items)
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
