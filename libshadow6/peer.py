"""Application-owned peer connection state, without matchmaking or Core choice."""
import copy
from threading import RLock
import time
from .boundary import ConnectionError

RETRYABLE_PATH_ERRORS = frozenset({'ConnectionRefused','ConnectionTimedOut',
    'TransportReadinessTimeout','ApplicationReadinessTimeout','PeerUnavailable'})


class PeerConnection:
    """One explicit Named Service path, optionally explicit same-policy fallback.

    Matchmaking supplies existing S6P1/session material; this object validates
    it through the canonical dispatcher and never allocates peers or identities.
    A disconnect closes its application attachment, never a Named Service.
    """
    def __init__(self,facade,name,*,fallback_services=(),require=None,protocol_envelope=None):
        if not isinstance(name,str) or not name or len(name)>129:
            raise ValueError('bounded Named Service required')
        if not isinstance(fallback_services,(tuple,list)) or len(fallback_services)>4 or any(
                not isinstance(value,str) or not value or len(value)>129 for value in fallback_services):
            raise ValueError('at most four explicit bounded fallback services')
        self.facade,self.name=facade,name
        self.fallback_services=tuple(fallback_services)
        self.require=copy.deepcopy(require)
        self.protocol_envelope=protocol_envelope
        self.state='idle';self.handle=None;self.selected_path=None
        self._lock=RLock();self._generation=0;self._events=[]

    def transition(self,state,code=None):
        with self._lock:
            self.state=state
            self._events.append({'state':state,'code':code,'atMonotonicMs':int(time.monotonic()*1000)})
            self._events=self._events[-32:]

    def connect(self,*,timeout=15,cancellation=None):
        if type(timeout) not in (int,float) or not 0<timeout<=300:
            raise ValueError('timeout must be in (0,300]')
        with self._lock:
            if self.state not in {'idle','closed','failed','cancelled'}:
                raise ConnectionError('PeerConnectionBusy')
            self._generation+=1;generation=self._generation
            self.transition('planning')
        deadline=time.monotonic()+timeout
        try:
            primary=self.facade.connection_plan(self.name)
            if self.protocol_envelope is not None:
                if not isinstance(self.protocol_envelope,str) or len(self.protocol_envelope)>65536:
                    raise ValueError('bounded existing protocol envelope required')
                verified=self.facade._control('protocol.envelope.validate',{'envelope':self.protocol_envelope,'role':'client'})
                from Deployment.protocol_context import context_digest
                if context_digest(verified['envelope'])!=primary.get('contextDigest'):
                    raise ConnectionError('MatchmakingMaterialBindingMismatch')
            last=None
            for index,path in enumerate((self.name,)+self.fallback_services):
                if cancellation is not None and cancellation.is_set():
                    raise ConnectionError('ConnectionCancelled',state='cancelled')
                remaining=deadline-time.monotonic()
                if remaining<=0: raise ConnectionError('PeerConnectionTimeout',retryable=True)
                if index:
                    candidate=self.facade.connection_plan(path)
                    if (candidate.get('core')!=primary.get('core') or candidate.get('profileBinding')!=primary.get('profileBinding') or
                        not primary.get('securityPolicyDigest') or candidate.get('securityPolicyDigest')!=primary['securityPolicyDigest']):
                        raise ConnectionError('FallbackPolicyMismatch')
                self.transition('connecting')
                try:
                    handle=self.facade.connect_handle(path,timeout=remaining,cancellation=cancellation,require=self.require)
                except ConnectionError as error:
                    last=error
                    if error.code not in RETRYABLE_PATH_ERRORS or index==len(self.fallback_services): raise
                    self.transition('path-failed',error.code)
                    continue
                with self._lock:
                    if generation!=self._generation:
                        handle.close();raise ConnectionError('ConnectionCancelled',state='cancelled')
                    self.handle,self.selected_path=handle,path
                    self.transition('connected')
                return handle
            raise last or ConnectionError('PeerUnavailable')
        except ConnectionError as error:
            self.transition('cancelled' if error.code=='ConnectionCancelled' else 'failed',error.code)
            raise
        except BaseException:
            self.transition('failed','PeerConnectionRejected')
            raise

    def status(self):
        with self._lock:
            handle=self.handle
            snapshot={'schema':'shadow6.peer-connection.v1','state':self.state,
                      'primaryPath':self.name,'selectedPath':self.selected_path,
                      'events':copy.deepcopy(self._events),'migrationSupported':False}
        if handle is not None:
            try: snapshot['runtime']=handle.status()
            except ConnectionError as error:
                self.transition('degraded',error.code);snapshot['state']='degraded';snapshot['error']=error.to_dict()
        return snapshot

    def disconnect(self):
        with self._lock:
            self._generation+=1
            handle=self.handle;self.handle=None
            self.transition('disconnecting')
        if handle is not None:handle.close()
        self.transition('closed')

    close=disconnect
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
