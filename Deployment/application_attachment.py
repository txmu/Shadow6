"""Bounded local record adapter for a declared inherited Native Core ingress.

Opaque application records only: no native transport/wire parsing. One peer,
one whole pending record per direction, no reconnect after the single flow
receives EOF. Producer success is local kernel queue acceptance, not delivery.
"""
import json
import os
import socket
import stat
import struct
import time
from pathlib import Path
try:
    from .service_storage import strict_json
except ImportError:
    from service_storage import strict_json

HANDSHAKE_SCHEMA = 'shadow6.local-record-attachment.v1'
MAX_HANDSHAKE = 4096


def socket_inode(pid, fd):
    if type(pid) is not int or pid <= 1 or type(fd) is not int or not 0 <= fd <= 1048576:
        return None
    try:
        value = os.readlink(f'/proc/{pid}/fd/{fd}')
    except OSError:
        return None
    if value.startswith('socket:[') and value.endswith(']'):
        return value[8:-1]
    return None


def owned_seqpacket(pid, fd, inode):
    if not isinstance(inode, str) or not inode.isdecimal() or socket_inode(pid, fd) != inode:
        return False
    try:
        with Path(f'/proc/{pid}/net/unix').open() as stream:
            next(stream)
            for index, line in enumerate(stream):
                if index >= 65536: raise ValueError('Unix socket observation table limit')
                if len(line) > 4096: raise ValueError('Unix socket observation row limit')
                values = line.split()
                if len(values) >= 7 and values[6] == inode:
                    return values[4] == '0005'
    except OSError:
        pass
    return False


class NativeRecordAttachment:
    def __init__(self, path, profile_binding, max_record, lock_digest):
        if type(max_record) is not int or not 1 <= max_record <= 65536:
            raise ValueError('InvalidApplicationRecordLimit')
        path = Path(path)
        parent = path.parent.lstat()
        if (not path.is_absolute() or len(str(path).encode()) > 103 or
                not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077):
            raise ValueError('private bounded attachment directory required')
        self.path = path
        self.binding, self.max_record, self.lock_digest = profile_binding, max_record, lock_digest
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.native = self.child = self.peer = self.rejected = None
        self.path_identity = None
        try:
            self.listener.bind(str(path)); path.chmod(0o600)
            entry = path.lstat(); self.path_identity = (entry.st_dev, entry.st_ino)
            self.listener.listen(1); self.listener.setblocking(False)
            self.native, self.child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            for sock in (self.native, self.child):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
                sock.setblocking(False)
            self.child_fd = self.child.fileno()
            self.child_inode = socket_inode(os.getpid(), self.child_fd)
            self.ready = self.accepted = self.input_eof = self.output_eof = False
            self.pending_native = self.pending_peer = None
            self.handshake_deadline = self.drain_deadline = None
        except BaseException:
            self.close(); raise

    def release_child(self):
        self.child.close(); self.child = None

    def acknowledge(self, event, owner):
        target = event.get('endpoint', {})
        if (event.get('readiness') != 'application-ready' or target.get('boundary') != 'message' or
                target.get('mode') != 'seqpacket-fd' or target.get('fd') != self.child_fd or
                not owned_seqpacket(owner['pid'], self.child_fd, self.child_inode)):
            raise ValueError('NativeApplicationFDReadyMismatch')
        self.ready = True

    def endpoint(self, supervisor, native_owner):
        return dict(path=str(self.path), boundary='message', mode='seqpacket-fd',
            observation='supervisor-owned-record-adapter', owner=supervisor,
            nativeOwner=native_owner, nativeFd=self.child_fd, nativeInode=self.child_inode,
            maxRecord=self.max_record, attachmentState='draining' if self.input_eof else
                'attached' if self.accepted else 'available')

    def _reply(self, peer, value):
        data = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        try: peer.send(data)
        except (BlockingIOError, BrokenPipeError, ConnectionResetError): pass

    def pump(self):
        # Never accept more than one pending handshake or connection per tick.
        try: peer, _ = self.listener.accept()
        except BlockingIOError: peer = None
        if peer is not None:
            peer.setblocking(False)
            _, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.geteuid() or not self.ready or self.peer is not None or self.accepted:
                if self.rejected is not None: peer.close()
                else:
                    self.rejected = peer; self.rejection_deadline = time.monotonic() + 2
            else:
                self.peer = peer; self.handshake_deadline = time.monotonic() + 2
        if self.rejected is not None:
            try: packet = self.rejected.recv(MAX_HANDSHAKE)
            except BlockingIOError: packet = None
            except ConnectionResetError: packet = b''
            if packet is not None or time.monotonic() >= self.rejection_deadline:
                self._reply(self.rejected, {'schema':HANDSHAKE_SCHEMA, 'error':'AttachmentConsumed' if self.accepted else 'AttachmentBusy'})
                self.rejected.close(); self.rejected = None
        if self.peer is not None and not self.accepted:
            try: data, _, flags, _ = self.peer.recvmsg(MAX_HANDSHAKE)
            except BlockingIOError: data = None; flags = 0
            if data is None:
                if time.monotonic() >= self.handshake_deadline: self.peer.close(); self.peer = None
                return
            try:
                request = strict_json(data)
                if flags & socket.MSG_TRUNC or not isinstance(request, dict) or set(request) != {'schema','profileBinding','lockDigest','nonce'}:
                    raise ValueError('InvalidAttachmentHandshake')
                if (request['schema'] != HANDSHAKE_SCHEMA or request['profileBinding'] != self.binding or
                        request['lockDigest'] != self.lock_digest or not isinstance(request['nonce'], str) or
                        len(request['nonce']) != 64 or any(c not in '0123456789abcdef' for c in request['nonce'])):
                    raise ValueError('AttachmentBindingMismatch')
            except ValueError:
                self._reply(self.peer, {'schema':HANDSHAKE_SCHEMA, 'error':'AttachmentBindingMismatch'})
                self.peer.close(); self.peer = None; return
            self._reply(self.peer, {'schema':HANDSHAKE_SCHEMA, 'state':'accepted',
                'nonce':request['nonce'], 'maxRecord':self.max_record})
            self.accepted = True
        if not self.accepted: return
        for _ in range(32):
            progressed = False
            for attribute, target in (('pending_native', self.native), ('pending_peer', self.peer)):
                value = getattr(self, attribute)
                if value is None or target is None: continue
                try: count = target.send(value)
                except (BlockingIOError, InterruptedError): continue
                except (BrokenPipeError, ConnectionResetError):
                    if target is self.native: raise ValueError('NativeApplicationFDClosed')
                    self.peer.close(); self.peer = None; self.pending_peer = None
                    continue
                if count != len(value): raise ValueError('ApplicationRecordPartialSend')
                setattr(self, attribute, None); progressed = True
            if self.peer is not None and not self.input_eof and self.pending_native is None:
                try: data, _, flags, _ = self.peer.recvmsg(self.max_record + 1)
                except (BlockingIOError, InterruptedError): data = None; flags = 0
                except ConnectionResetError: data = b''; flags = 0
                if data is not None:
                    progressed = True
                    if flags & socket.MSG_TRUNC or len(data) > self.max_record:
                        continue  # Native contract: discard oversize record, continue.
                    self.pending_native = data
                    if not data:
                        self.input_eof = True; self.drain_deadline = time.monotonic() + 8
            if self.pending_peer is None and not self.output_eof:
                try: data, _, flags, _ = self.native.recvmsg(self.max_record + 1)
                except (BlockingIOError, InterruptedError): data = None; flags = 0
                if data is not None:
                    progressed = True
                    if flags & socket.MSG_TRUNC or len(data) > self.max_record:
                        raise ValueError('NativeApplicationRecordOversize')
                    if self.peer is not None: self.pending_peer = data
                    if not data: self.output_eof = True
            if not progressed: break
        if self.output_eof and self.pending_peer is None and self.peer is not None:
            self.peer.close(); self.peer = None
        if self.drain_deadline is not None and time.monotonic() >= self.drain_deadline and not self.output_eof:
            raise ValueError('ApplicationDrainTimeout')

    def close(self):
        for name in ('peer', 'rejected', 'native', 'child', 'listener'):
            sock = getattr(self, name, None)
            if sock is not None: sock.close(); setattr(self, name, None)
        if self.path_identity is not None:
            try:
                entry = self.path.lstat()
                if (entry.st_dev, entry.st_ino) == self.path_identity and stat.S_ISSOCK(entry.st_mode):
                    self.path.unlink()
            except FileNotFoundError: pass
