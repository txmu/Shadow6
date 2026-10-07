"""Deterministic application-owned connections to explicit Named Service paths."""
import copy
import math
from threading import Event, RLock
import time
from .boundary import ConnectionError

RETRYABLE_PATH_ERRORS = frozenset({'ConnectionRefused','ConnectionTimedOut',
    'TransportReadinessTimeout','ApplicationReadinessTimeout','PeerUnavailable',
    'ControlCenterUnavailable','ApplicationEndpointOwnerUnavailable'})
_BINDING = ('core','profileBinding','securityPolicyDigest','contextDigest')


class _Cancellation:
    def __init__(self, internal, external): self.internal,self.external=internal,external
    def is_set(self): return self.internal.is_set() or bool(self.external and self.external.is_set())
    def wait(self, seconds):
        deadline=time.monotonic()+seconds
        while not self.is_set() and time.monotonic()<deadline:
            self.internal.wait(min(.02,max(0,deadline-time.monotonic())))
        return self.is_set()


class PeerConnection:
    """Fallback is explicit reconnect with identical policy; migration is unsupported."""
    def __init__(self,facade,name,*,fallback_services=(),require=None,protocol_envelope=None):
        from Deployment.service_registry import NAME
        if not isinstance(name,str) or not NAME.fullmatch(name):
            raise ValueError('bounded Named Service required')
        if (not isinstance(fallback_services,(tuple,list)) or len(fallback_services)>4 or
                any(not isinstance(value,str) or not NAME.fullmatch(value) for value in fallback_services) or
                len(set((name,*fallback_services)))!=1+len(fallback_services)):
            raise ValueError('at most four distinct explicit Named Service fallbacks')
        self.facade,self.name=facade,name
        self.fallback_services=tuple(fallback_services)
        self.require=copy.deepcopy(require)
        self.protocol_envelope=protocol_envelope
        self.state='idle';self.handle=None;self.selected_path=None
        self._lock=RLock();self._generation=0;self._events=[]
        self._cancel=Event();self._binding=None;self._connecting=False

    def _transition(self,state,code=None):
        self.state=state
        self._events.append({'state':state,'code':code,'atMonotonicMs':int(time.monotonic()*1000)})
        self._events=self._events[-32:]

    def connect(self,*,timeout=15,cancellation=None):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=300:
            raise ValueError('timeout must be in (0,300]')
        with self._lock:
            if self._connecting or self.state not in {'idle','closed','failed','cancelled'}:
                raise ConnectionError('PeerConnectionBusy')
            self._connecting=True
            self._generation+=1;generation=self._generation
            self._cancel=Event();cancel=_Cancellation(self._cancel,cancellation)
            self._transition('planning')
        deadline=time.monotonic()+timeout
        def current():
            if cancel.is_set(): raise ConnectionError('ConnectionCancelled',state='cancelled')
            if time.monotonic()>=deadline: raise ConnectionError('PeerConnectionTimeout',retryable=True)
        try:
            current()
            primary=self.facade._connection_plan_before(self.name,deadline,cancel) if hasattr(self.facade,'_connection_plan_before') else self.facade.connection_plan(self.name)
            current()
            binding={key:copy.deepcopy(primary.get(key)) for key in _BINDING}
            if self._binding is not None and binding!=self._binding:
                raise ConnectionError('PeerBindingChanged')
            if self.protocol_envelope is not None:
                if not isinstance(self.protocol_envelope,str) or len(self.protocol_envelope)>65536:
                    raise ValueError('bounded existing protocol envelope required')
                verified=self.facade._control('protocol.envelope.validate',{'envelope':self.protocol_envelope,'role':'client'})
                from Deployment.protocol_context import context_digest
                if context_digest(verified['envelope'])!=primary.get('contextDigest'):
                    raise ConnectionError('MatchmakingMaterialBindingMismatch')
            for index,path in enumerate((self.name,)+self.fallback_services):
                current()
                candidate=primary if not index else self.facade._connection_plan_before(path,deadline,cancel) if hasattr(self.facade,'_connection_plan_before') else self.facade.connection_plan(path)
                if index and (not primary.get('securityPolicyDigest') or
                              any(candidate.get(key)!=primary.get(key) for key in _BINDING)):
                    raise ConnectionError('FallbackPolicyMismatch')
                current()
                with self._lock:
                    if generation!=self._generation: current();raise ConnectionError('ConnectionCancelled',state='cancelled')
                    self._transition('connecting')
                try:
                    handle=self.facade.connect_handle(path,timeout=(deadline-time.monotonic())/(1+len(self.fallback_services)-index),cancellation=cancel,require=self.require)
                except ConnectionError as error:
                    if error.code not in RETRYABLE_PATH_ERRORS or index==len(self.fallback_services): raise
                    with self._lock:
                        if generation==self._generation: self._transition('path-failed',error.code)
                    continue
                try:
                    current()
                    # Bind the handle actually opened, rather than a stale pre-connect plan.
                    actual=getattr(handle,'_plan',None)
                    if actual is not None and (any(actual.get(key)!=candidate.get(key) for key in _BINDING) or
                            actual.get('lockDigest')!=candidate.get('lockDigest')):
                        raise ConnectionError('PeerBindingChanged')
                    with self._lock:
                        if generation!=self._generation:
                            raise ConnectionError('ConnectionCancelled',state='cancelled')
                        self.handle,self.selected_path=handle,path
                        self._binding=binding
                        self._transition('connected')
                    return handle
                except BaseException:
                    handle.close();raise
            raise ConnectionError('PeerUnavailable')
        except BaseException as error:
            with self._lock:
                if generation==self._generation:
                    code=error.code if isinstance(error,ConnectionError) else 'PeerConnectionRejected'
                    self._transition('cancelled' if code=='ConnectionCancelled' else 'failed',code)
            raise
        finally:
            with self._lock: self._connecting=False

    def cancel(self):
        with self._lock: self._cancel.set()

    def status(self):
        with self._lock:
            handle=self.handle;generation=self._generation
            snapshot={'schema':'shadow6.peer-connection.v1','state':self.state,
                      'primaryPath':self.name,'selectedPath':self.selected_path,
                      'events':copy.deepcopy(self._events),'migrationSupported':False,
                      'iceSupported':False}
        if handle is not None:
            try:
                runtime=handle.status();snapshot['runtime']=runtime
                if runtime.get('state') not in {'running','degraded'}:
                    raise ConnectionError('PeerUnavailable',retryable=True)
            except ConnectionError as error:
                with self._lock:
                    if generation==self._generation and handle is self.handle:
                        self._transition('degraded',error.code);snapshot['state']='degraded'
                snapshot['error']=error.to_dict()
        return snapshot

    def disconnect(self):
        with self._lock:
            self._cancel.set();self._generation+=1
            handle=self.handle;self.handle=None;self.selected_path=None
            self._transition('disconnecting')
        try:
            if handle is not None: handle.close()
        finally:
            with self._lock: self._transition('closed')

    def reconnect(self,**options):
        self.disconnect()
        return self.connect(**options)

    close=disconnect
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
