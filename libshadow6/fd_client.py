"""Owner-checked local descriptor transfer client for the canonical FD gateway."""
import array
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import time
from .boundary import ConnectionError
from Deployment.service_storage import private_read, strict_json


def peer_identity(channel):
    if __import__('sys').platform.startswith('linux') and hasattr(socket,'SO_PEERCRED'):
        pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if pid<=1 or uid!=os.geteuid(): raise ConnectionError('FDControlPeerRejected')
        return uid
    if hasattr(channel,'getpeereid'):
        uid,_=channel.getpeereid()
        if uid!=os.geteuid(): raise ConnectionError('FDControlPeerRejected')
        return uid
    if os.name=='posix':
        import ctypes
        libc=ctypes.CDLL(None,use_errno=True)
        if hasattr(libc,'getpeereid'):
            uid,gid=ctypes.c_uint(),ctypes.c_uint()
            libc.getpeereid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)]
            if libc.getpeereid(channel.fileno(),ctypes.byref(uid),ctypes.byref(gid)) or uid.value!=os.geteuid():
                raise ConnectionError('FDControlPeerRejected')
            return uid.value
    raise ConnectionError('FDPeerIdentityUnavailable')


def open_fd(name, *, timeout, cancellation=None):
    path=Path(os.environ['SHADOW6_CONTROL_SOCKET'])
    parent,entry=path.parent.lstat(),path.lstat()
    if (not path.is_absolute() or len(os.fsencode(path))>103 or
            not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.geteuid() or parent.st_mode&0o077 or
            not stat.S_ISSOCK(entry.st_mode) or entry.st_uid!=os.geteuid() or entry.st_mode&0o077):
        raise ConnectionError('UnsafeFDControlSocket')
    token=private_read(Path(os.environ['SHADOW6_CONTROL_TOKEN_FILE']),limit=4096).decode('ascii').strip()
    if not 32<=len(token)<=4096 or any(not 33<=ord(c)<=126 for c in token):
        raise ConnectionError('UnsafeFDControlCredential')
    nonce=secrets.token_hex(32)
    body=json.dumps({'schema':'shadow6.fd-attachment.v1','nonce':nonce,'token':token,
                     'name':name,'confirmed':True,'issuedAt':int(time.time())},separators=(',',':')).encode()
    kind=socket.SOCK_STREAM if __import__('sys').platform=='darwin' else socket.SOCK_SEQPACKET
    channel=socket.socket(socket.AF_UNIX,kind);fds=[]
    deadline=time.monotonic()+timeout
    try:
        channel.settimeout(min(timeout,30));channel.connect(str(path));peer_identity(channel)
        current=path.lstat()
        if (entry.st_dev,entry.st_ino)!=(current.st_dev,current.st_ino):
            raise ConnectionError('FDControlSocketChanged')
        channel.sendall(struct.pack('!I',len(body))+body if kind==socket.SOCK_STREAM else body)
        while True:
            if cancellation is not None and cancellation.is_set():
                raise ConnectionError('ConnectionCancelled',state='cancelled')
            remaining=deadline-time.monotonic()
            if remaining<=0: raise ConnectionError('ConnectionTimedOut',retryable=True)
            channel.settimeout(min(.05,remaining))
            try:
                raw,ancillary,flags,_=channel.recvmsg(65541,socket.CMSG_SPACE(4*4),getattr(socket,'MSG_CMSG_CLOEXEC',0))
                break
            except socket.timeout: continue
        for level,type_,data in ancillary:
            if level==socket.SOL_SOCKET and type_==socket.SCM_RIGHTS:
                values=array.array('i');values.frombytes(data[:len(data)-len(data)%values.itemsize]);fds.extend(values)
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC): raise ConnectionError('InvalidFDControlResponse')
        if kind==socket.SOCK_STREAM:
            packet=bytearray(raw)
            while len(packet)<4 or len(packet)<4+struct.unpack('!I',packet[:4])[0]:
                if len(packet)>=4 and struct.unpack('!I',packet[:4])[0]>65536: raise ConnectionError('InvalidFDControlResponse')
                remaining=deadline-time.monotonic()
                if remaining<=0: raise ConnectionError('ConnectionTimedOut',retryable=True)
                channel.settimeout(min(.05,remaining))
                if cancellation is not None and cancellation.is_set(): raise ConnectionError('ConnectionCancelled',state='cancelled')
                try: chunk=channel.recv(65541-len(packet))
                except socket.timeout: continue
                if not chunk: raise ConnectionError('InvalidFDControlResponse')
                packet.extend(chunk)
            if len(packet)!=4+struct.unpack('!I',packet[:4])[0]: raise ConnectionError('InvalidFDControlResponse')
            raw=bytes(packet[4:])
        value=strict_json(raw,limit=65536)
        if not isinstance(value,dict) or value.get('schema')!='shadow6.fd-attachment.v1' or value.get('nonce')!=nonce:
            raise ConnectionError('InvalidFDControlResponse')
        if set(value)=={'schema','nonce','error'}:
            code=value['error']
            raise ConnectionError(code if isinstance(code,str) and code.isascii() and code.isalpha() and len(code)<96 else 'FDAttachmentRejected')
        if set(value)!={'schema','nonce','connection'} or len(fds)!=1:
            raise ConnectionError('InvalidFDControlResponse')
        metadata=value['connection']
        if not isinstance(metadata,dict) or metadata.get('schema')!='shadow6.connection-handle.v1' or metadata.get('name')!=name or metadata.get('state')!='connected':
            raise ConnectionError('InvalidFDControlResponse')
        if not stat.S_ISSOCK(os.fstat(fds[0]).st_mode): raise ConnectionError('InvalidFDControlResponse')
        connection=socket.socket(fileno=fds[0]);fds.clear();connection.set_inheritable(False)
        return connection,metadata
    except (OSError,ValueError,KeyError) as error:
        raise ConnectionError('FDControlUnavailable',retryable=isinstance(error,OSError)) from None
    finally:
        channel.close()
        for fd in fds: os.close(fd)


class CancellationFD:
    """Borrow a POSIX cancellation event fd; never consume it or close it."""
    def __init__(self,fd):
        import select
        if type(fd) is not int or fd<0: raise ValueError('InvalidCancellationFD')
        os.fstat(fd)
        self.fd=fd
    def is_set(self):
        import select
        return bool(select.select([self.fd],[],[],0)[0])
    def wait(self,timeout):
        import select
        return bool(select.select([self.fd],[],[],timeout)[0])


class SocketAttachment:
    def __init__(self,connection): self.socket=connection
    def close(self): self.socket.close()
