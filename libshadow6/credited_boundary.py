"""Bounded local socket boundary over the existing credited S6NA session.

The worker never opens a native Core socket. Credits and the pinned transport
remain owned by CreditedPool. Socket buffering adds at most one pending record
in each direction; it never grants native delivery/reliability capabilities.
"""
import select
import socket
from threading import BoundedSemaphore, Event, Thread
import time

_WORKERS = BoundedSemaphore(64)


def record_pair():
    if hasattr(socket,'SOCK_SEQPACKET'):
        try: return (*socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET),'seqpacket')
        except OSError: pass
    # Windows/macOS: connected loopback UDP preserves records without a new
    # wire codec. Socket.share/fromshare provides Windows handle transfer.
    left,right=socket.socket(socket.AF_INET,socket.SOCK_DGRAM),socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        left.bind(('127.0.0.1',0));right.bind(('127.0.0.1',0))
        left.connect(right.getsockname());right.connect(left.getsockname())
        return left,right,'datagram'
    except BaseException:
        left.close();right.close();raise


class CreditedBoundary:
    def __init__(self, session, *, kind, max_record, lifetime=300, owner=None,
                 authority=None,name=None,lock_digest=None):
        if kind not in {'stream','message'} or type(max_record) is not int or not 1<=max_record<=65536:
            raise ValueError('InvalidCreditedBoundary')
        if type(lifetime) not in (int,float) or not 0<lifetime<=300:
            raise ValueError('InvalidCreditedLifetime')
        if not _WORKERS.acquire(blocking=False):
            session.close();raise ValueError('ApplicationSessionCapacityReached')
        self.session,self.owner=session,owner
        self.authority,self.name,self.lock_digest=authority,name,lock_digest
        adapter=session.endpoint.adapter
        window=min(adapter.limits.window_frames or adapter.policy.window,adapter.limits.max_window)
        self.kind=kind
        self.max_record=min(max_record,adapter.limits.max_message,adapter.codec.payload*window)
        self._read_bound=adapter.codec.payload if kind=='stream' else self.max_record
        self.stop=Event();self.error=None;self.transferred=False
        self.deadline=time.monotonic()+lifetime;self.remaining=16*1024*1024
        self.eof=self.write_closed=False
        try:
            if kind=='stream':
                self.socket,self._worker=socket.socketpair();self.local_mode='stream'
            else:
                self.socket,self._worker,self.local_mode=record_pair()
            self.socket.set_inheritable(False);self._worker.set_inheritable(False)
            for endpoint in (self.socket,self._worker):
                endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,65536)
                endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,65536)
            self._worker.setblocking(False)
            self.thread=Thread(target=self._run,name='shadow6-credited-boundary',daemon=True)
            self.thread.start()
        except BaseException:
            for endpoint in (getattr(self,'socket',None),getattr(self,'_worker',None)):
                if endpoint: endpoint.close()
            session.close();_WORKERS.release();raise

    def _run(self):
        outgoing=incoming=None
        observed_at=0
        try:
            while not self.stop.is_set() and time.monotonic()<self.deadline and self.remaining>0:
                if self.authority is not None and time.monotonic()-observed_at>=1:
                    current=self.authority._control('service.status',{'name':self.name})
                    if (current.get('state') not in {'running','degraded'} or
                            (current.get('deploymentLock') or {}).get('digest')!=self.lock_digest):
                        raise ValueError('CreditedServiceBindingChanged')
                    observed_at=time.monotonic()
                # Receive one bounded record only after the previous is accepted
                # by S6NA. The local socket's own bounded queue supplies pressure.
                if outgoing is None:
                    readable,_,_=select.select([self._worker],[],[],.01)
                    if readable:
                        if self.kind=='message' and hasattr(self._worker,'recvmsg'):
                            outgoing,_,flags,_=self._worker.recvmsg(self.max_record+1)
                            if flags & socket.MSG_TRUNC: raise ValueError('OversizedApplicationRecord')
                        else: outgoing=self._worker.recv(self.max_record+1 if self.kind=='message' else self._read_bound)
                        if not outgoing and self.local_mode!='datagram': break
                        if len(outgoing)>self.max_record: raise ValueError('OversizedApplicationRecord')
                if outgoing is not None:
                    try:
                        self.session.send_record(outgoing)
                        self.remaining-=len(outgoing);outgoing=None
                    except Exception as error:
                        if str(error)!='S6NA_BACKPRESSURE': raise
                if incoming is None:
                    incoming=self.session.receive_record(timeout=0)
                    if incoming is not None and len(incoming)>self.max_record:
                        raise ValueError('OversizedApplicationRecord')
                if incoming is not None:
                    try:
                        count=self._worker.send(incoming)
                        self.remaining-=count
                        if self.kind=='message' and count!=len(incoming): raise ValueError('ApplicationRecordPartialSend')
                        incoming=incoming[count:] if count<len(incoming) else None
                    except BlockingIOError: pass
                if outgoing is not None or incoming is not None: self.stop.wait(.005)
        except (OSError,ValueError,RuntimeError) as error:
            self.error=type(error).__name__
        finally:
            self.stop.set()
            try:
                self._worker.close();self.session.close()
                if self.owner is not None: self.owner.close()
            finally:_WORKERS.release()

    def close(self):
        self.stop.set()
        self.socket.close()
        if self.thread is not __import__('threading').current_thread(): self.thread.join(1)

    def detach(self):
        self.transferred=True
        return self.socket.detach()

    def send(self,data): self.socket.sendall(data)
    def receive(self,size): return self.socket.recv(size)
    def send_record(self,data):
        if len(data)>self.max_record: raise ValueError('OversizedApplicationRecord')
        return self.socket.send(data)
    def receive_record(self):
        data=self.socket.recv(self.max_record+1)
        if len(data)>self.max_record: raise ValueError('OversizedApplicationRecord')
        return data
