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
import time
import sys

SCHEMA = 'shadow6.fd-attachment.v1'


class FDGateway:
    def __init__(self,path,token,*,allow_mutations=False,registry=None):
        self.path = Path(path).absolute()
        self.token = token
        self.allow_mutations = allow_mutations
        self.registry = registry
        self.listener = None
        self.tasks = set()
        self.executions = set()
        self.replay = {}
        self.closed = False
        self.diagnostic_count = 0

    async def start(self):
        from Deployment.service_storage import private_directory
        private_directory(self.path.parent)
        if len(os.fsencode(self.path))>103 or self.path.exists() or self.path.is_symlink():
            raise ValueError('FD socket path must be new, private and bounded')
        self.kind=socket.SOCK_STREAM if sys.platform=='darwin' else socket.SOCK_SEQPACKET
        self.listener = socket.socket(socket.AF_UNIX,self.kind)
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
            if len(self.tasks)+len(self.executions)>=16:
                connection.close();continue
            task = asyncio.create_task(self.attach(connection))
            self.tasks.add(task);task.add_done_callback(self.tasks.discard)

    async def attach(self,connection):
        fd = None
        session_handle = None
        transfer_handle = None
        delivered = False
        loop = asyncio.get_running_loop()
        nonce = None
        abandoned = threading.Event()
        try:
            if self.registry is None:
                from shadow6_control import response, MAX_REQUEST
            else:
                MAX_REQUEST=65536
            from libshadow6.fd_client import peer_identity
            from Deployment.service_storage import strict_json as strict_json_loads
            peer_identity(connection)
            async def receive():
                if self.kind!=socket.SOCK_STREAM:
                    return await loop.sock_recv(connection,MAX_REQUEST+1)
                async def exact(size):
                    data=bytearray()
                    while len(data)<size:
                        part=await loop.sock_recv(connection,size-len(data))
                        if not part: raise ValueError('FDRequestTruncated')
                        data.extend(part)
                    return bytes(data)
                size=struct.unpack('!I',await exact(4))[0]
                if size>MAX_REQUEST: raise ValueError('FDRequestTooLarge')
                return await exact(size)
            raw = await asyncio.wait_for(receive(),5)
            if len(raw)>MAX_REQUEST: raise ValueError('FDRequestTooLarge')
            request = strict_json_loads(raw,limit=MAX_REQUEST)
            fields = {'schema','nonce','token','name','confirmed','issuedAt'}
            if not isinstance(request,dict) or set(request)!=fields or request['schema']!=SCHEMA:
                raise ValueError('InvalidFDRequest')
            nonce = request['nonce']
            if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{64}',nonce): raise ValueError('InvalidFDNonce')
            now=int(time.time())
            if type(request['issuedAt']) is not int or not now-30<=request['issuedAt']<=now+2:
                raise ValueError('FDRequestExpired')
            self.replay={key:stamp for key,stamp in self.replay.items() if now-stamp<=32}
            if nonce in self.replay: raise ValueError('FDReplayRejected')
            if len(self.replay)>=1024: raise ValueError('FDReplayCapacity')
            if not isinstance(request['token'],str) or not hmac.compare_digest(request['token'].encode(),self.token.encode()):
                raise PermissionError('FDOperatorAuthenticationRequired')
            if request['confirmed'] is not True or not self.allow_mutations:
                raise PermissionError('FDMutationOptInRequired')
            self.replay[nonce]=request['issuedAt']
            def execute():
                review = ({'ok':True,'result':self.registry.connection_review(request['name'])} if self.registry is not None else
                          response({'method':'service.connection_review','params':{'name':request['name']}},allow_mutations=False))
                if not review['ok']: return review,None
                value = review['result']
                arguments = {
                    'name':request['name'],'confirmed':True,
                    **{key:value[key] for key in ('expected_plan_digest','expected_material_digest','expected_lock_digest')}}
                executed = ({'ok':True,'result':self.registry.connect_execute(**arguments)} if self.registry is not None else
                            response({'method':'service.connect_execute','params':arguments},allow_mutations=True))
                if abandoned.is_set() and executed.get('ok'):
                    late = executed['result'].get('session')
                    if late:
                        from Deployment.session_handles import sessions
                        sessions.close(late['handle'])
                return executed,value['plan']
            task=asyncio.create_task(asyncio.to_thread(execute))
            self.executions.add(task)
            def dispose_late(done):
                self.executions.discard(done)
                if abandoned.is_set() and not done.cancelled():
                    try:
                        late_result,_=done.result()
                        late_session=late_result.get('result',{}).get('session')
                        if late_session:
                            from Deployment.session_handles import sessions
                            sessions.close(late_session['handle'])
                    except (ValueError,OSError,RuntimeError): pass
            task.add_done_callback(dispose_late)
            result,plan = await asyncio.wait_for(asyncio.shield(task),30)
            if not result['ok']:
                await self.send_error(connection,nonce,result['error']['code'])
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
                'endpoint':plan.get('endpoint'),'securityPolicyDigest':plan.get('securityPolicyDigest'),
                'contextDigest':plan.get('contextDigest'),'fdOwnership':'caller-owned-until-close'}
            from Deployment.session_handles import sessions
            transfer_handle=session_handle
            fd = sessions.transfer_fd(session_handle);session_handle=None
            body = json.dumps({'schema':SCHEMA,'nonce':nonce,'connection':metadata},ensure_ascii=True,separators=(',',':')).encode()
            if len(body)>65536: raise ValueError('FDMetadataTooLarge')
            # One datagram, one CLOEXEC-receivable socket descriptor. Application
            # data never enters this adapter after handoff.
            connection.setblocking(False)
            packet=struct.pack('!I',len(body))+body if self.kind==socket.SOCK_STREAM else body
            count = connection.sendmsg([packet],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
            if self.kind==socket.SOCK_STREAM and 0<count<len(packet):
                await asyncio.wait_for(loop.sock_sendall(connection,packet[count:]),5)
            elif count!=len(packet): raise OSError('FDMetadataPartialWrite')
            delivered=True
        except (ValueError,OSError,PermissionError,TimeoutError,RuntimeError) as error:
            # Keep credentials, paths, request bodies and exception messages
            # out of diagnostics. Fixed frame names/lines identify the failed
            # admission stage without weakening the public rejection contract.
            if self.diagnostic_count < 8:
                self.diagnostic_count += 1
                frames = []; trace = error.__traceback__
                while trace is not None and len(frames) < 8:
                    frames.append({'function': trace.tb_frame.f_code.co_name[:96], 'line': trace.tb_lineno})
                    trace = trace.tb_next
                print(json.dumps({'schema': 'shadow6.fd-admission-diagnostic.v1',
                    'exception': type(error).__name__, 'frames': frames}), file=sys.stderr, flush=True)
            try:
                await self.send_error(connection,nonce,'FDAttachmentRejected')
            except (OSError,TimeoutError): pass
        finally:
            abandoned.set()
            if fd is not None: os.close(fd)
            if session_handle is not None:
                from Deployment.session_handles import sessions
                sessions.close(session_handle)
            if transfer_handle is not None and not delivered:
                from Deployment.session_handles import sessions
                sessions.close(transfer_handle)
            connection.close()

    async def send_error(self,connection,nonce,code):
        body=json.dumps({'schema':SCHEMA,'nonce':nonce,'error':code}).encode()
        packet=struct.pack('!I',len(body))+body if self.kind==socket.SOCK_STREAM else body
        await asyncio.wait_for(asyncio.get_running_loop().sock_sendall(connection,packet),5)

    async def close(self):
        self.closed = True
        if self.listener: self.listener.close()
        if hasattr(self,'accept_task'):
            self.accept_task.cancel();await asyncio.gather(self.accept_task,return_exceptions=True)
        for task in tuple(self.tasks): task.cancel()
        if self.tasks: await asyncio.gather(*tuple(self.tasks),return_exceptions=True)
        if self.executions:
            # Shielded executions finish their canonical operation and dispose
            # abandoned capabilities; they never outlive gateway shutdown.
            await asyncio.gather(*tuple(self.executions),return_exceptions=True)
        try:
            info=self.path.lstat()
            if stat.S_ISSOCK(info.st_mode) and info.st_uid==os.geteuid() and info.st_ino==self.identity:
                self.path.unlink()
        except FileNotFoundError: pass
