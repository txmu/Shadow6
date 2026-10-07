"""Versioned application handles; native sockets remain the data path."""
from __future__ import annotations
from dataclasses import dataclass, asdict
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
        return cls('shadow6.boundary-descriptor.v1', boundary['kind'], mode,
                   semantics, maximum, boundary.get('reliable'),
                   boundary.get('ordered'), boundary.get('freshness_preferred'))

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

    def dup_fd(self):
        with self._lock:
            fd = os.dup(self.fileno())
            os.set_inheritable(fd, False)
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
            value = self._owner._control('service.status', {'name':self.name})
            lock = (value.get('deploymentLock') or {}).get('digest')
            if lock != self._plan.get('lockDigest'):
                self.state = 'drifted'
                raise ConnectionError('ReviewedLockChanged')
            return value

    def close(self):
        with self._lock:
            if self.state == 'closed': return
            self._attachment.close()
            self.state = 'closed'
            with self._owner._attachment_lock:
                self._owner._connections.discard(self)

    disconnect = close
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
