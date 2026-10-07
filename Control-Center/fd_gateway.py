"""Fixed owner-only FD attachment adapter over the canonical dispatcher."""
import array
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading

SCHEMA = 'shadow6.fd-attachment.v1'


class FDGateway:
    def __init__(self,path,token,*,allow_mutations=False):
        self.path = Path(path).absolute()
        self.token = token
        self.allow_mutations = allow_mutations
        self.listener = None
        self.tasks = set()
        self.replay = set()
        self.replay_order = []
        self.closed = False

    async def start(self):
        from service_storage import private_directory
        private_directory(self.path.parent)
        if len(os.fsencode(self.path))>103 or self.path.exists() or self.path.is_symlink():
            raise ValueError('FD socket path must be new, private and bounded')
        self.listener = socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        self.listener.setblocking(False)
        try:
            self.listener.bind(str(self.path));os.chmod(self.path,0o600);self.listener.listen(16)
            self.identity = self.path.lstat().st_ino
        except BaseException:
            self.listener.close();self.listener=None;raise
        self.accept_task = asyncio.create_task(self.accept())
        return self

    async def accept(self):
        loop = asyncio.get_running_loop()
        while not self.closed:
            try: connection,_ = await loop.sock_accept(self.listener)
            except (OSError,asyncio.CancelledError): break
            if len(self.tasks)>=16:
                connection.close();continue
            task = asyncio.create_task(self.attach(connection))
            self.tasks.add(task);task.add_done_callback(self.tasks.discard)

    async def attach(self,connection):
        fd = None
        session_handle = None
        loop = asyncio.get_running_loop()
        nonce = None
        abandoned = threading.Event()
        try:
            from shadow6_control import response, MAX_REQUEST, strict_json_loads
            pid,uid,_ = struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if pid<=1 or uid!=os.geteuid(): raise PermissionError('FDPeerIdentityRejected')
            raw = await asyncio.wait_for(loop.sock_recv(connection,MAX_REQUEST+1),5)
            if len(raw)>MAX_REQUEST: raise ValueError('FDRequestTooLarge')
            request = strict_json_loads(raw,limit=MAX_REQUEST)
            fields = {'schema','nonce','token','name','confirmed'}
            if not isinstance(request,dict) or set(request)!=fields or request['schema']!=SCHEMA:
                raise ValueError('InvalidFDRequest')
            nonce = request['nonce']
            if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{64}',nonce): raise ValueError('InvalidFDNonce')
            if nonce in self.replay: raise ValueError('FDReplayRejected')
            if not isinstance(request['token'],str) or not hmac.compare_digest(request['token'].encode(),self.token.encode()):
                raise PermissionError('FDOperatorAuthenticationRequired')
            if request['confirmed'] is not True or not self.allow_mutations:
                raise PermissionError('FDMutationOptInRequired')
            self.replay.add(nonce);self.replay_order.append(nonce)
            if len(self.replay_order)>1024: self.replay.remove(self.replay_order.pop(0))
            def execute():
                review = response({'method':'service.connection_review','params':{'name':request['name']}},allow_mutations=False)
                if not review['ok']: return review,None
                value = review['result']
                executed = response({'method':'service.connect_execute','params':{
                    'name':request['name'],'confirmed':True,
                    **{key:value[key] for key in ('expected_plan_digest','expected_material_digest','expected_lock_digest')}}},
                    allow_mutations=True)
                if abandoned.is_set() and executed.get('ok'):
                    late = executed['result'].get('session')
                    if late:
                        from session_handles import sessions
                        sessions.close(late['handle'])
                return executed,value['plan']
            result,plan = await asyncio.wait_for(asyncio.to_thread(execute),30)
            if not result['ok']:
                await loop.sock_sendall(connection,json.dumps({'schema':SCHEMA,'nonce':nonce,'error':result['error']['code']}).encode())
                return
            session = result['result'].get('session')
            if not session: raise ValueError('DirectBoundaryUnavailable')
            session_handle = session['handle']
            from libshadow6.boundary import BoundaryDescriptor
            descriptor = BoundaryDescriptor.from_plan(plan).to_dict()
            metadata = {'schema':'shadow6.connection-handle.v1','name':request['name'],'state':'connected',
                'boundary':descriptor,'profileBinding':plan.get('profileBinding'),
                'lockDigest':plan.get('lockDigest'),'readiness':plan.get('readinessEvidence'),
                'transportReadiness':plan.get('transportReadiness'), 'identity':plan.get('runtimeIdentity'),
                'endpoint':plan.get('endpoint'),'fdOwnership':'caller-owned-until-close'}
            from session_handles import sessions
            fd = sessions.transfer_fd(session_handle);session_handle=None
            body = json.dumps({'schema':SCHEMA,'nonce':nonce,'connection':metadata},ensure_ascii=True,separators=(',',':')).encode()
            if len(body)>65536: raise ValueError('FDMetadataTooLarge')
            # One datagram, one CLOEXEC-receivable socket descriptor. Application
            # data never enters this adapter after handoff.
            connection.setblocking(False)
            count = connection.sendmsg([body],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
            if count!=len(body): raise OSError('FDMetadataPartialWrite')
        except (ValueError,OSError,PermissionError,TimeoutError):
            try:
                body = json.dumps({'schema':SCHEMA,'nonce':nonce,'error':'FDAttachmentRejected'}).encode()
                await loop.sock_sendall(connection,body)
            except (OSError,TimeoutError): pass
        finally:
            abandoned.set()
            if fd is not None: os.close(fd)
            if session_handle is not None:
                from session_handles import sessions
                sessions.close(session_handle)
            connection.close()

    async def close(self):
        self.closed = True
        if self.listener: self.listener.close()
        if hasattr(self,'accept_task'):
            self.accept_task.cancel();await asyncio.gather(self.accept_task,return_exceptions=True)
        for task in tuple(self.tasks): task.cancel()
        if self.tasks: await asyncio.gather(*tuple(self.tasks),return_exceptions=True)
        try:
            info=self.path.lstat()
            if stat.S_ISSOCK(info.st_mode) and info.st_uid==os.geteuid() and info.st_ino==self.identity:
                self.path.unlink()
        except FileNotFoundError: pass
