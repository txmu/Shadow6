"""Explicit Windows socket handle transfer over an authenticated control channel.

Uses WSADuplicateSocket via socket.share/fromshare, never an integer-fd cast.
The operator supplies a private session credential already shared with the
recipient. This backend does not start a listener or choose a target process.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import threading
import time
from Deployment.service_storage import strict_json
from .boundary import ConnectionError


def _same_windows_user(pid):
    if os.name!='nt': raise ConnectionError('WindowsHandleTransferUnavailable')
    if type(pid) is not int or not 1<pid<2**32: raise ConnectionError('InvalidHandleRecipient')
    import ctypes
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    advapi=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    advapi.EqualSid.argtypes=[ctypes.c_void_p,ctypes.c_void_p]
    def sid(process_id):
        process=kernel.OpenProcess(0x1000,False,process_id)
        if not process: raise ConnectionError('HandlePeerIdentityRejected')
        token=wintypes.HANDLE()
        try:
            if not advapi.OpenProcessToken(process,0x0008,ctypes.byref(token)):
                raise ConnectionError('HandlePeerIdentityRejected')
            size=wintypes.DWORD()
            advapi.GetTokenInformation(token,1,None,0,ctypes.byref(size))
            if not 1<=size.value<=4096: raise ConnectionError('HandlePeerIdentityRejected')
            buffer=ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token,1,buffer,size,ctypes.byref(size)):
                raise ConnectionError('HandlePeerIdentityRejected')
            pointer=ctypes.cast(buffer,ctypes.POINTER(ctypes.c_void_p))[0]
            return buffer,pointer
        finally:
            if token: kernel.CloseHandle(token)
            kernel.CloseHandle(process)
    ours,left=sid(os.getpid());theirs,right=sid(pid)
    if not advapi.EqualSid(left,right): raise ConnectionError('HandlePeerIdentityRejected')


def _credential(value):
    if not isinstance(value,bytes) or not 32<=len(value)<=4096:
        raise ConnectionError('InvalidHandleCredential')


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


class WindowsHandleTransfer:
    _lock=threading.Lock()
    _replay={}

    @staticmethod
    def export(connection,peer_pid,*,credential,nonce):
        _credential(credential);_same_windows_user(peer_pid)
        if not isinstance(nonce,str) or len(nonce)!=64 or any(c not in '0123456789abcdef' for c in nonce):
            raise ConnectionError('InvalidHandleNonce')
        blob=connection.share(peer_pid)
        if len(blob)>4096: raise ConnectionError('HandleTransferTooLarge')
        value={'schema':'shadow6.windows-socket-transfer.v1','sender':os.getpid(),
               'recipient':peer_pid,'nonce':nonce,'expires':int(time.time())+30,
               'socket':base64.b64encode(blob).decode()}
        value['mac']=hmac.new(credential,_canonical(value),hashlib.sha256).hexdigest()
        return _canonical(value)

    @classmethod
    def receive(cls,raw,*,credential,nonce):
        _credential(credential)
        if not isinstance(nonce,str) or len(nonce)!=64 or any(c not in '0123456789abcdef' for c in nonce):
            raise ConnectionError('InvalidHandleNonce')
        value=strict_json(raw,limit=16384)
        if not isinstance(value,dict) or set(value)!={'schema','sender','recipient','nonce','expires','socket','mac'}:
            raise ConnectionError('InvalidHandleTransfer')
        if value['schema']!='shadow6.windows-socket-transfer.v1' or value['recipient']!=os.getpid() or value['nonce']!=nonce:
            raise ConnectionError('HandleRecipientMismatch')
        if not isinstance(value['socket'],str) or len(value['socket'])>8192:
            raise ConnectionError('InvalidHandleTransfer')
        now=int(time.time())
        if type(value['expires']) is not int or not now<=value['expires']<=now+30:
            raise ConnectionError('HandleTransferExpired')
        mac=value.pop('mac')
        if not isinstance(mac,str) or not hmac.compare_digest(mac,hmac.new(credential,_canonical(value),hashlib.sha256).hexdigest()):
            raise ConnectionError('HandleCredentialRejected')
        _same_windows_user(value['sender'])
        with cls._lock:
            cls._replay={key:expiry for key,expiry in cls._replay.items() if expiry>=now}
            key=(value['sender'],nonce)
            if key in cls._replay: raise ConnectionError('HandleReplayRejected')
            if len(cls._replay)>=1024: raise ConnectionError('HandleTransferCapacity')
            cls._replay[key]=value['expires']
        connection=None
        try:
            blob=base64.b64decode(value['socket'],validate=True)
            if len(blob)>4096: raise ConnectionError('HandleTransferTooLarge')
            connection=socket.fromshare(blob);connection.set_inheritable(False)
            return connection
        except BaseException:
            if connection is not None: connection.close()
            raise

    @staticmethod
    def nonce(): return secrets.token_hex(32)
