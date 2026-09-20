#!/usr/bin/env python3
"""Authenticated, bounded chunking/reassembly shared by all Shadow6 cores."""
from __future__ import annotations
import argparse, collections, hashlib, hmac, ipaddress, json, os, socket, stat, struct, subprocess, time
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC=b"S6NA"; VERSION=1; DATA=1; ACK=2; EXTENSION=3
HEADER=struct.Struct("!4sBBHQQHHI")
TAG_BYTES=16; MAX_MESSAGE=16*1024*1024; MAX_STREAMS=64; MAX_INFLIGHT=16*1024*1024

@dataclass(frozen=True)
class Policy:
    mode: str
    payload: int
    window: int
    reason: str

POLICIES={
 "go":Policy("native",65536,64,"KCP stack already presents a stream"),
 "rust":Policy("native",65536,64,"QUIC stack already presents a stream"),
 "zig":Policy("native",32768,64,"ENet provides reliable fragmentation"),
 "ada":Policy("native",448,32,"native authenticated cell relay is independently deployable"),
 "d":Policy("native",1200,32,"native authenticated broker/agent/client secure stream"),
 "nim":Policy("native",16384,64,"WebRTC data channel provides message transport"),
 "cpp":Policy("native",32768,64,"SCTP provides ordered reliable delivery"),
 "pony":Policy("native",960,32,"native bounded authenticated datagrams are independently deployable"),
 "hare":Policy("native",896,16,"native bounded authenticated proxy is independently deployable"),
 "carp":Policy("native",960,16,"native bounded authenticated UDP path is independently deployable"),
 "gleam":Policy("native",4096,32,"native authenticated broker/agent/client secure stream"),
 "idris":Policy("native",1024,32,"native authenticated UDP agent/client relay"),
}

def load_key(path:Path):
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size!=32:
        raise PermissionError("adapter key must be an owned 32-byte mode-0600 regular file")
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(descriptor); data=os.read(descriptor,33); final=os.fstat(descriptor)
        # Reads may update atime; compare identity, authority and content-change
        # metadata instead of the entire stat result.
        fingerprint=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mode,st.st_uid,st.st_nlink,st.st_mtime_ns,st.st_ctime_ns)
        if fingerprint(opened)!=fingerprint(before) or fingerprint(final)!=fingerprint(opened) or len(data)!=32:
            raise PermissionError("adapter key changed while reading")
        return data
    finally: os.close(descriptor)

def _portable(value):
    def validate(item,depth=0):
        if depth>8: raise ValueError("extension nesting exceeds 8")
        if item is None or type(item) in (bool,str):
            if isinstance(item,str) and len(item.encode())>1024: raise ValueError("extension string is oversized")
            return
        if type(item) is int:
            if not -(2**53-1)<=item<=2**53-1: raise ValueError("extension integer is not portable")
            return
        if isinstance(item,list):
            if len(item)>64: raise ValueError("extension array is oversized")
            for child in item: validate(child,depth+1)
            return
        if isinstance(item,dict):
            if len(item)>64 or any(not isinstance(key,str) for key in item): raise ValueError("extension object is invalid")
            for key,child in item.items(): validate(key,depth+1); validate(child,depth+1)
            return
        raise ValueError("extension contains a nonportable value")
    validate(value)
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
    if len(raw)>4096: raise ValueError("extension payload exceeds 4 KiB")
    return raw

class Codec:
    def __init__(self,key:bytes,payload:int,side:int):
        if not isinstance(key,bytes) or len(key)!=32: raise ValueError("adapter key must be 32 bytes")
        if type(payload) is not int or not 64<=payload<=65536: raise ValueError("invalid adapter payload")
        if side not in (0,1): raise ValueError("adapter side must be 0 or 1")
        derive=lambda direction:hmac.digest(key,b"shadow6-network-v1:"+bytes([direction]),"sha256")
        self.tx=ChaCha20Poly1305(derive(side)); self.rx=ChaCha20Poly1305(derive(1-side)); self.payload=payload
    @staticmethod
    def nonce(header): return hashlib.sha256(b"shadow6-network-nonce-v1"+header).digest()[:12]
    def encode(self,kind,stream,message,index,count,payload=b""):
        if kind not in (DATA,ACK,EXTENSION) or not 0<=stream<MAX_STREAMS or not 0<=message<2**64:
            raise ValueError("invalid frame identity")
        if not isinstance(payload,bytes) or len(payload)>self.payload or not 1<=count<=65535 or not 0<=index<count:
            raise ValueError("invalid frame bounds")
        header=HEADER.pack(MAGIC,VERSION,kind,0,stream,message,index,count,len(payload))
        return header+self.tx.encrypt(self.nonce(header),payload,header)
    def decode(self,wire):
        if not isinstance(wire,bytes) or not HEADER.size+TAG_BYTES<=len(wire)<=HEADER.size+self.payload+TAG_BYTES:
            raise ValueError("invalid frame size")
        header,ciphertext=wire[:HEADER.size],wire[HEADER.size:]
        magic,version,kind,reserved,stream,message,index,count,length=HEADER.unpack(header)
        if magic!=MAGIC or version!=VERSION or reserved or kind not in (DATA,ACK,EXTENSION) or length!=len(ciphertext)-TAG_BYTES:
            raise ValueError("invalid frame header")
        if stream>=MAX_STREAMS or count<1 or index>=count: raise ValueError("invalid frame fields")
        try: payload=self.rx.decrypt(self.nonce(header),ciphertext,header)
        except Exception as exc: raise ValueError("frame authentication failed") from exc
        if kind==ACK and payload: raise ValueError("invalid acknowledgment")
        return kind,stream,message,index,count,payload

class ReliableAdapter:
    """Transport-neutral reliable messages; callers never split their data."""
    def __init__(self,core,key,side=0,extensions=(),clock=time.monotonic):
        if core not in POLICIES:
            raise ValueError("core has no safely established adapter profile")
        policy=POLICIES[core]; self.codec=Codec(key,policy.payload,side); self.policy=policy; self.clock=clock
        self.extensions=frozenset(extensions)
        if len(self.extensions)>16 or any(not isinstance(x,str) or not x or len(x)>64 for x in self.extensions): raise ValueError("invalid extension allowlist")
        self.next_message=[0]*MAX_STREAMS; self.pending={}; self.queues=[collections.deque() for _ in range(MAX_STREAMS)]; self.cursor=0; self.incoming={}; self.buffered=0
        self.completed=set(); self.completed_order=collections.deque()
        self.srtt=None; self.rttvar=None; self.rto=.2
    def _remember(self,key):
        self.completed.add(key); self.completed_order.append(key)
        if len(self.completed_order)>4096: self.completed.discard(self.completed_order.popleft())
    def send(self,stream,data):
        if type(stream) is not int or not 0<=stream<MAX_STREAMS: raise ValueError("invalid stream")
        if not isinstance(data,bytes) or not data or len(data)>MAX_MESSAGE: raise ValueError("message must be 1 byte..16 MiB")
        chunks=[data[i:i+self.codec.payload] for i in range(0,len(data),self.codec.payload)]
        if len(chunks)>65535 or self.buffered+len(data)>MAX_INFLIGHT:
            raise BufferError("adapter backpressure limit reached")
        message=self.next_message[stream]
        if message>=2**64-1: raise OverflowError("message sequence exhausted; rekey")
        self.next_message[stream]=message+1
        now=self.clock()
        for index,chunk in enumerate(chunks):
            wire=self.codec.encode(DATA,stream,message,index,len(chunks),chunk)
            self.queues[stream].append(((stream,message,index),wire,len(chunk)))
        self.buffered+=len(data); return self.outbound(now)
    def outbound(self,now=None):
        now=self.clock() if now is None else now; frames=[]
        empty=0
        while len(self.pending)<self.policy.window and empty<MAX_STREAMS:
            queue=self.queues[self.cursor]
            if queue:
                key,wire,size=queue.popleft(); self.pending[key]=[wire,now+self.rto,0,size,now,False]; frames.append(wire); empty=0
            else: empty+=1
            self.cursor=(self.cursor+1)%MAX_STREAMS
        return frames
    def _sample(self,rtt):
        if self.srtt is None: self.srtt,self.rttvar=rtt,rtt/2
        else: self.rttvar=.75*self.rttvar+.25*abs(self.srtt-rtt); self.srtt=.875*self.srtt+.125*rtt
        self.rto=max(.05,min(5.0,self.srtt+4*self.rttvar))
    def extension(self,stream,name,value):
        if type(stream) is not int or not 0<=stream<MAX_STREAMS: raise ValueError("invalid stream")
        if name not in self.extensions: raise PermissionError("extension is not enabled")
        payload=_portable({"name":name,"value":value}); message=self.next_message[stream]
        if message>=2**64-1: raise OverflowError("message sequence exhausted; rekey")
        self.next_message[stream]=message+1
        return self.codec.encode(EXTENSION,stream,message,0,1,payload)
    def receive(self,wire):
        kind,stream,message,index,count,payload=self.codec.decode(wire)
        if kind==ACK:
            item=self.pending.pop((stream,message,index),None)
            if item:
                self.buffered-=item[3]
                if not item[5]: self._sample(max(0,self.clock()-item[4]))
            return [],[],[]
        ack=self.codec.encode(ACK,stream,message,index,count)
        if kind==EXTENSION:
            key=(stream,message)
            if key in self.completed: return [ack],[],[]
            def pairs(items):
                result={}
                for name,item in items:
                    if name in result: raise ValueError("duplicate extension field")
                    result[name]=item
                return result
            value=json.loads(payload,object_pairs_hook=pairs,parse_float=lambda _:(_ for _ in ()).throw(ValueError("floats forbidden")),parse_constant=lambda _:(_ for _ in ()).throw(ValueError("constant forbidden")))
            if _portable(value)!=payload or not isinstance(value,dict) or set(value)!={"name","value"} or value["name"] not in self.extensions:
                raise PermissionError("received extension is not enabled")
            self._remember(key)
            return [ack],[],[(stream,value["name"],value["value"])]
        key=(stream,message); state=self.incoming.setdefault(key,{"count":count,"parts":{},"bytes":0,"deadline":self.clock()+30})
        if key in self.completed: return [ack],[],[]
        if state["count"]!=count: raise ValueError("contradictory chunk count")
        if index not in state["parts"]:
            if sum(item["bytes"] for item in self.incoming.values())+len(payload)>MAX_INFLIGHT: raise BufferError("reassembly limit reached")
            state["parts"][index]=payload; state["bytes"]+=len(payload)
        completed=[]
        if len(state["parts"])==count:
            data=b"".join(state["parts"][i] for i in range(count))
            if len(data)>MAX_MESSAGE: raise ValueError("reassembled message is oversized")
            del self.incoming[key]; completed.append((stream,data)); self._remember(key)
        return [ack],completed,[]
    def retransmit(self):
        now=self.clock(); frames=[]
        for key,state in list(self.incoming.items()):
            if now>=state["deadline"]: del self.incoming[key]
        for key,item in list(self.pending.items()):
            wire,deadline,attempts,size,sent,retried=item
            if now<deadline: continue
            if attempts>=8:
                raise TimeoutError(f"retransmission limit reached for stream {key[0]} message {key[1]}")
            item[2]+=1; item[5]=True; item[1]=now+min(5.0,self.rto*(2**item[2])); frames.append(wire)
        return frames+self.outbound(now)

class DatagramEndpoint:
    """Pinned-peer UDP carrier for companion profiles and datagram cores."""
    def __init__(self,core,key,bind,peer,side=0,extensions=()):
        def endpoint(value):
            if not isinstance(value,tuple) or len(value)!=2 or type(value[1]) is not int or not 0<=value[1]<=65535:
                raise ValueError("invalid endpoint")
            address=ipaddress.ip_address(value[0])
            return address,value[1]
        local,lport=endpoint(bind); remote,rport=endpoint(peer)
        if local.version!=remote.version or remote.is_unspecified or remote.is_multicast:
            raise ValueError("invalid pinned peer")
        family=socket.AF_INET6 if local.version==6 else socket.AF_INET
        self.socket=socket.socket(family,socket.SOCK_DGRAM)
        self.socket.bind((str(local),lport)); self.peer=(str(remote),rport)
        self.adapter=ReliableAdapter(core,key,side,extensions)
    @property
    def address(self): return self.socket.getsockname()[:2]
    def close(self): self.socket.close()
    def send(self,stream,data):
        for frame in self.adapter.send(stream,data): self.socket.sendto(frame,self.peer)
    def send_extension(self,stream,name,value):
        self.socket.sendto(self.adapter.extension(stream,name,value),self.peer)
    def poll(self,timeout=.2):
        if not 0<=timeout<=5: raise ValueError("invalid poll timeout")
        self.socket.settimeout(timeout)
        completed=[]; events=[]
        for packet in range(64):
            if packet: self.socket.setblocking(False)
            try: wire,address=self.socket.recvfrom(HEADER.size+65536+TAG_BYTES+1)
            except (socket.timeout,BlockingIOError): break
            if address[:2]!=self.peer: raise PermissionError("datagram from unpinned peer")
            acks,done,received_events=self.adapter.receive(wire); completed+=done; events+=received_events
            for ack in acks:self.socket.sendto(ack,self.peer)
            for frame in self.adapter.outbound(): self.socket.sendto(frame,self.peer)
        self.socket.setblocking(True)
        for frame in self.adapter.retransmit(): self.socket.sendto(frame,self.peer)
        return completed,events

def audit(bin_dir:Path):
    rows=[]
    for core,policy in POLICIES.items():
        path=bin_dir/("shadow6-"+core)
        row={"core":core,"policy":policy.mode,"payload":policy.payload,"reason":policy.reason,"installed":path.is_file()}
        if path.is_file() and not path.is_symlink():
            result=subprocess.run([str(path),"--feature-report"],capture_output=True,text=True,timeout=5,check=False)
            row["feature_report"]="ok" if result.returncode==0 else "failed"
        rows.append(row)
    return {"schema":"shadow6.network-adapter-audit.v1","cores":rows}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("action",choices=("catalog","audit"),default="catalog",nargs="?")
    parser.add_argument("--bin-dir",type=Path,default=Path.home()/".local/bin"); args=parser.parse_args()
    result=audit(args.bin_dir) if args.action=="audit" else {"schema":"shadow6.network-adapter-catalog.v1","cores":{k:v.__dict__ for k,v in POLICIES.items()}}
    print(json.dumps(result,sort_keys=True,indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
