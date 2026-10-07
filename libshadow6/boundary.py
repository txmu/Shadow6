"""Versioned application handles; native sockets remain the data path."""
from __future__ import annotations
from dataclasses import dataclass, asdict, replace
from threading import RLock
import copy
import os
import time


class ConnectionError(RuntimeError):
    def __init__(self, code, *, state='failed', retryable=False):
        self.code, self.state, self.retryable = code, state, retryable
        super().__init__(code)

    def to_dict(self):
        return dict(schema='shadow6.connection-error.v1', code=self.code,
                    state=self.state, retryable=self.retryable)


@dataclass(frozen=True)
class BoundaryDescriptor:
    schema: str
    kind: str
    realization: str
    semantics: str
    max_record: int | None
    reliable: bool | None
    ordered: bool | None
    freshness_preferred: bool | None
    fd_ownership: str = 'borrowed-until-close'
    data_path: str = 'native-socket'

    @classmethod
    def from_plan(cls, plan):
        from Deployment.profile_registry import validate_profile_binding
        profile = validate_profile_binding(plan.get('profileBinding'), core=plan.get('core'))
        boundary = profile['applicationBoundary']
        mode = boundary['mode']
        semantics = {'localhost-tcp-proxy':'stream',
                     'localhost-udp-datagram-proxy':'datagram',
                     'seqpacket-fd':'record'}.get(mode)
        if semantics is None:
            raise ConnectionError('UnsupportedApplicationBoundary')
        # Unknown capability is distinct from false. Never manufacture reliable
        # or ordered delivery from a local record socket.
        maximum = boundary.get('max_record')
        if maximum is not None:
            effective = plan.get('effectiveLimits', {}).get('max_record', maximum)
            if type(effective) is not int or not 1 <= effective <= maximum:
                raise ConnectionError('InvalidApplicationRecordLimit')
            maximum = effective
        result = cls('shadow6.boundary-descriptor.v1', boundary['kind'], mode,
                   semantics, maximum, boundary.get('reliable'),
                   boundary.get('ordered'), boundary.get('freshness_preferred'))
        if (plan.get('applicationAdapter') or {}).get('provider')=='s6na':
            credited_maximum=plan.get('creditedBoundaryMaximum')
            if type(credited_maximum) is not int or not 1<=credited_maximum<=65536:
                raise ConnectionError('InvalidCreditedBoundaryLimit')
            result=replace(result,realization='credited-socket',
                semantics='stream' if boundary['kind']=='stream' else 'record',
                max_record=min(maximum,credited_maximum) if maximum is not None else None,
                data_path='s6na-credited-socket')
        return result

    def to_dict(self):
        return asdict(self)


class ConnectionHandle:
    """Own an attachment, never the independently managed Named Service.

    fileno is borrowed. dup_fd transfers an independent CLOEXEC reference to
    the caller. Duplicates share queues and socket flags, and must be closed by
    the caller. Concurrent I/O/close requires application synchronization;
    control operations are serialized here. No finalizer kills a runtime.
    """
    def __init__(self, owner, name, plan, attachment, descriptor):
        self._owner, self.name = owner, name
        self._plan = copy.deepcopy(plan)
        self._attachment, self.boundary = attachment, descriptor
        self._lock = RLock()
        self.state = 'connected'
        self.created_at = time.monotonic()

    def fileno(self):
        with self._lock:
            if self.state == 'closed': raise ConnectionError('ConnectionClosed', state='closed')
            return self._attachment.socket.fileno()

    def export_handle(self, peer_pid, *, credential, nonce):
        """Transfer to an explicit authenticated same-user Windows process."""
        from .handle_transfer import WindowsHandleTransfer
        with self._lock:
            self.fileno()
            return WindowsHandleTransfer.export(self.socket,peer_pid,credential=credential,nonce=nonce)

    def dup_fd(self):
        with self._lock:
            self.fileno()
            if os.name=='nt':
                raise ConnectionError('UseWindowsHandleTransfer')
            fd = os.dup(self.fileno())
            try: os.set_inheritable(fd, False)
            except BaseException: os.close(fd);raise
            return fd

    @property
    def socket(self):
        self.fileno()
        return self._attachment.socket

    def describe(self):
        with self._lock:
            return dict(schema='shadow6.connection-handle.v1', name=self.name,
                state=self.state, boundary=self.boundary.to_dict(),
                profileBinding=copy.deepcopy(self._plan.get('profileBinding')),
                lockDigest=self._plan.get('lockDigest'),
                readiness=copy.deepcopy(self._plan.get('readinessEvidence', {})),
                transportReadiness=self._plan.get('transportReadiness', 'unavailable'),
                peerIdentity=copy.deepcopy(self._plan.get('peerIdentity')),
                sessionIdentity=copy.deepcopy(self._plan.get('sessionIdentity')),
                identity=copy.deepcopy(self._plan.get('runtimeIdentity', {})),
                endpoint=copy.deepcopy(self._plan.get('endpoint')))

    def status(self):
        with self._lock:
            self.fileno()
            import socket, select
            connection=self._attachment.socket
            if connection.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR):
                self.state='degraded'
                raise ConnectionError('PeerUnavailable',retryable=True)
            if self.boundary.semantics=='stream' and select.select([connection],[],[],0)[0]:
                try:
                    if not connection.recv(1,socket.MSG_PEEK|getattr(socket,'MSG_DONTWAIT',0)):
                        self.state='degraded'
                        raise ConnectionError('PeerUnavailable',retryable=True)
                except BlockingIOError: pass
            value = self._owner._control('service.status', {'name':self.name})
            if getattr(self._attachment,'error',None):
                self.state='degraded'
                raise ConnectionError('PeerUnavailable',retryable=True)
            lock = (value.get('deploymentLock') or {}).get('digest')
            if lock != self._plan.get('lockDigest'):
                self.state = 'drifted'
                raise ConnectionError('ReviewedLockChanged')
            return value

    def close(self):
        with self._lock:
            if self.state == 'closed': return
            try: self._attachment.close()
            finally:
                self.state = 'closed'
                with self._owner._attachment_lock:
                    self._owner._connections.discard(self)

    disconnect = close
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
