#!/usr/bin/env python3
"""Public6 virtual Broker: authenticated admission plus opaque bounded relay."""
from __future__ import annotations
import argparse, asyncio, base64, hashlib, heapq, hmac, ipaddress, json, os, stat, struct, sys, time
from threading import RLock
from dataclasses import dataclass, field
from pathlib import Path
# Select only for executable entry points; library imports keep the caller's runtime.
if __name__ == "__main__":
    import sys
    _root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(_root / "Tools"))
    sys.path.insert(0, str(_root / "share/shadow6/modules"))
    from python_runtime import bootstrap
    bootstrap(_root, Path(__file__).absolute())
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA="shadow6.virtual-broker.v1"; CORES={"go","rust","gleam","ada","nim","pony","zig","d","cpp","idris","hare","carp"}

def reject_float(_): raise ValueError("floats are forbidden")
def pairs(items):
    out={}
    for key,value in items:
        if key in out: raise ValueError("duplicate JSON field")
        out[key]=value
    return out
def canonical(value)->bytes: return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
def bounded_file(path:Path,maximum:int,secret=False)->bytes:
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_uid!=os.geteuid() or before.st_size>maximum or (secret and stat.S_IMODE(before.st_mode)!=0o600): raise ValueError("unsafe configuration or secret file")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(fd); data=os.read(fd,maximum+1); after=os.fstat(fd)
        fp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_uid,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
        if fp(before)!=fp(opened) or fp(opened)!=fp(after) or len(data)>maximum: raise ValueError("file changed while reading")
        return data
    finally: os.close(fd)

@dataclass(frozen=True)
class Tenant:
    tenant_id:str; public_keys:tuple[bytes,...]; approval:str
    max_connections:int; bytes_per_second:int; burst_bytes:int

@dataclass(frozen=True)
class Config:
    listen_host:str; listen_port:int; identity_key:bytes
    cores:dict[str,tuple[str,int]]; tenants:dict[str,Tenant]; routes:dict[tuple[str,str],tuple[str,int]]
    guard_required:bool; gate_required:bool; relay_socket:str|None
    approvals:frozenset[tuple[str,str]]; max_frame:int; handshake_seconds:int; idle_seconds:int

def load_config(path:Path)->Config:
    value=json.loads(bounded_file(path,262144).decode(),object_pairs_hook=pairs,parse_float=reject_float,parse_constant=reject_float)
    allowed={"schema","listen","identity_key_file","cores","tenants","routes","approvals","guard","gate","c11relay","limits"}
    if type(value) is not dict or set(value)!=allowed or value["schema"]!=SCHEMA: raise ValueError("unknown virtual Broker schema or field")
    listen=value["listen"]
    if type(listen) is not dict or set(listen)!={"host","port"} or not ipaddress.ip_address(listen["host"]).is_loopback or type(listen["port"]) is not int or not 1<=listen["port"]<=65535: raise ValueError("virtual Broker must listen behind Guard/Gate on loopback")
    if value["guard"]!={"required":True} or value["gate"]!={"required":True}: raise ValueError("Guard and Gate are mandatory")
    cores={}
    if type(value["cores"]) is not dict or not value["cores"]: raise ValueError("at least one real Broker is required")
    for core,target in value["cores"].items():
        if core not in CORES or type(target) is not dict or set(target)!={"host","port"} or not ipaddress.ip_address(target["host"]).is_loopback or type(target["port"]) is not int or not 1<=target["port"]<=65535: raise ValueError("invalid real Broker target")
        cores[core]=(target["host"],target["port"])
    tenants={}
    if type(value["tenants"]) is not list or not 1<=len(value["tenants"])<=1024: raise ValueError("invalid tenant catalog")
    for item in value["tenants"]:
        if type(item) is not dict or set(item)!={"id","public_keys","approval","max_connections","bytes_per_second","burst_bytes"}: raise ValueError("unknown tenant field")
        tid=item["id"]
        if type(tid) is not str or not 1<=len(tid)<=64 or not all(c.isalnum() or c in "._-" for c in tid) or tid in tenants: raise ValueError("invalid tenant id")
        if item["approval"] not in ("default-approved","approval-required"): raise ValueError("invalid approval mode")
        if type(item["public_keys"]) is not list or not 1<=len(item["public_keys"])<=32 or any(type(x) is not str or len(x)!=44 for x in item["public_keys"]): raise ValueError("invalid tenant public key")
        keys=tuple(base64.b64decode(x,validate=True) for x in item["public_keys"])
        if not 1<=len(keys)<=32 or any(len(x)!=32 for x in keys): raise ValueError("invalid tenant public key")
        for name,low,high in (("max_connections",1,1024),("bytes_per_second",1024,1<<30),("burst_bytes",1024,1<<30)):
            if type(item[name]) is not int or not low<=item[name]<=high: raise ValueError(f"invalid {name}")
        tenants[tid]=Tenant(tid,keys,item["approval"],item["max_connections"],item["bytes_per_second"],item["burst_bytes"])
    routes={}; endpoints=set()
    if type(value["routes"]) is not list or not 1<=len(value["routes"])<=len(tenants)*len(CORES): raise ValueError("invalid tenant route catalog")
    for route in value["routes"]:
        if type(route) is not dict or set(route)!={"tenant","core","host","port"} or route["tenant"] not in tenants or route["core"] not in cores or not ipaddress.ip_address(route["host"]).is_loopback or type(route["port"]) is not int or not 1<=route["port"]<=65535: raise ValueError("invalid tenant Core route")
        key=(route["tenant"],route["core"]); endpoint=(route["host"],route["port"])
        if key in routes or endpoint in endpoints: raise ValueError("tenant Core routes must use dedicated real Broker endpoints")
        routes[key]=endpoint; endpoints.add(endpoint)
    limits=value["limits"]
    if type(limits) is not dict or set(limits)!={"max_frame","handshake_seconds","idle_seconds"}: raise ValueError("invalid limits")
    if any(type(x) is not int for x in limits.values()) or not 1024<=limits["max_frame"]<=16*1024*1024 or not 1<=limits["handshake_seconds"]<=30 or not 5<=limits["idle_seconds"]<=3600: raise ValueError("limit outside safe bounds")
    key=bounded_file(Path(value["identity_key_file"]),32,True)
    if len(key)!=32: raise ValueError("identity key must contain exactly 32 bytes")
    relay=value["c11relay"]
    if type(relay) is not dict or set(relay)!={"control_socket"} or type(relay["control_socket"]) is not str or not relay["control_socket"].startswith("/") or len(relay["control_socket"])>4096: raise ValueError("invalid C11Relay integration")
    approvals=set()
    if type(value["approvals"]) is not list or len(value["approvals"])>4096: raise ValueError("invalid approval catalog")
    for approval in value["approvals"]:
        if type(approval) is not dict or set(approval)!={"tenant","client"} or approval["tenant"] not in tenants or type(approval["client"]) is not str or not 1<=len(approval["client"])<=128: raise ValueError("invalid approval")
        approvals.add((approval["tenant"],approval["client"]))
    return Config(listen["host"],listen["port"],key,cores,tenants,routes,True,True,relay["control_socket"],frozenset(approvals),**limits)

@dataclass
class RuntimeTenant:
    active:int=0; tokens:float=0; updated:float=field(default_factory=time.monotonic)

class Broker:
    def __init__(self,config:Config):
        self.config=config; self.approved=config.approvals; self.runtime={x:RuntimeTenant(tokens=t.burst_bytes) for x,t in config.tenants.items()}; self.nonces={}; self.nonce_expiry=[]
        self.verifiers={name:{key:Ed25519PublicKey.from_public_bytes(key) for key in tenant.public_keys} for name,tenant in config.tenants.items()}
        self.connections=0
        self._nonce_lock=RLock()
    def expire_nonces(self,now:int)->None:
        with self._nonce_lock:
            while self.nonce_expiry and self.nonce_expiry[0][0]<now:
                expires,key=heapq.heappop(self.nonce_expiry)
                if self.nonces.get(key)==expires: del self.nonces[key]
    def admit(self,raw:bytes)->tuple[Tenant,str,tuple[str,int]]:
        if len(raw)>16384: raise ValueError("admission request oversized")
        request=json.loads(raw,object_pairs_hook=pairs,parse_float=reject_float,parse_constant=reject_float)
        expected={"schema","tenant","client","core","issued","expires","nonce","public_key","signature"}
        if type(request) is not dict or set(request)!=expected or request["schema"]!="shadow6.virtual-broker-admission.v1": raise ValueError("invalid admission schema")
        if any(type(request[name]) is not str for name in ("tenant","client","core","nonce","public_key","signature")): raise ValueError("invalid admission field type")
        tenant=self.config.tenants.get(request["tenant"]); core=request["core"]
        if tenant is None or (tenant.tenant_id,core) not in self.config.routes or type(request["client"]) is not str or not 1<=len(request["client"])<=128: raise PermissionError("unknown tenant, client, or Core")
        now=int(time.time())
        if type(request["issued"]) is not int or type(request["expires"]) is not int or request["issued"]>now+30 or request["expires"]<now or not 0<=request["expires"]-request["issued"]<=120: raise PermissionError("expired admission")
        nonce=base64.b64decode(request["nonce"],validate=True); pub=base64.b64decode(request["public_key"],validate=True); sig=base64.b64decode(request["signature"],validate=True)
        if len(nonce)!=32 or len(pub)!=32 or len(sig)!=64 or pub not in tenant.public_keys: raise PermissionError("invalid admission credential")
        nonce_key=(tenant.tenant_id,nonce)

        unsigned={k:v for k,v in request.items() if k!="signature"}
        try: self.verifiers[tenant.tenant_id][pub].verify(sig,canonical(unsigned))
        except InvalidSignature as exc: raise PermissionError("invalid admission signature") from exc
        if tenant.approval=="approval-required" and (tenant.tenant_id,request["client"]) not in self.approved: raise PermissionError("connection requires operator approval")
        with self._nonce_lock:
            self.expire_nonces(now)
            if nonce_key in self.nonces: raise PermissionError("replayed admission")
            if len(self.nonces)>=65536: raise PermissionError("admission replay capacity reached")
            self.nonces[nonce_key]=request["expires"]
            heapq.heappush(self.nonce_expiry,(request["expires"],nonce_key))
        virtual_id=hmac.new(self.config.identity_key,canonical([tenant.tenant_id,request["client"],core]),hashlib.sha256).hexdigest()
        return tenant,virtual_id,self.config.routes[(tenant.tenant_id,core)]
    async def copy(self,reader,writer,tenant:Tenant):
        runtime=self.runtime[tenant.tenant_id]
        while True:
            async with asyncio.timeout(self.config.idle_seconds):
                data=await reader.read(min(65536,self.config.max_frame))
            if not data:
                if writer.can_write_eof(): writer.write_eof()
                async with asyncio.timeout(self.config.idle_seconds): await writer.drain()
                return
            now=time.monotonic(); runtime.tokens=min(tenant.burst_bytes,runtime.tokens+(now-runtime.updated)*tenant.bytes_per_second); runtime.updated=now
            runtime.tokens-=len(data)
            if runtime.tokens<0:
                delay=-runtime.tokens/tenant.bytes_per_second
                if delay>self.config.idle_seconds:
                    runtime.tokens+=len(data)
                    raise TimeoutError("tenant rate limit exceeds idle deadline")
                try: await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    runtime.tokens+=len(data)
                    raise
            writer.write(data)
            if writer.transport.get_write_buffer_size()>=65536:
                async with asyncio.timeout(self.config.idle_seconds): await writer.drain()
    async def handle(self,reader,writer):
        if self.connections>=4096:
            writer.close(); return
        self.connections+=1
        tenant=None; admitted=False; upstream_writer=None; copies=[]
        try:
            async with asyncio.timeout(self.config.handshake_seconds):
                size=struct.unpack("!I",await reader.readexactly(4))[0]
                if not 1<=size<=16384: raise ValueError("invalid admission length")
                tenant,_virtual,target=self.admit(await reader.readexactly(size))
            runtime=self.runtime[tenant.tenant_id]
            if runtime.active>=tenant.max_connections: raise PermissionError("tenant connection quota reached")
            runtime.active+=1; admitted=True
            async with asyncio.timeout(self.config.handshake_seconds):
                upstream_reader,upstream_writer=await asyncio.open_connection(*target,limit=65536)
            copies=[asyncio.create_task(self.copy(reader,upstream_writer,tenant)),asyncio.create_task(self.copy(upstream_reader,writer,tenant))]
            await asyncio.gather(*copies)
        except (asyncio.IncompleteReadError,asyncio.TimeoutError,OSError,ValueError,TypeError,RecursionError): pass
        finally:
            for task in copies: task.cancel()
            if copies: await asyncio.gather(*copies,return_exceptions=True)
            if admitted: self.runtime[tenant.tenant_id].active-=1
            self.connections-=1
            for item in (upstream_writer,writer):
                if item: item.close()
    async def serve(self):
        server=await asyncio.start_server(self.handle,self.config.listen_host,self.config.listen_port,limit=65536)
        async with server: await server.serve_forever()

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--config",type=Path,required=True); parser.add_argument("--check",action="store_true"); args=parser.parse_args()
    try:
        config=load_config(args.config)
        if args.check: print(json.dumps({"schema":SCHEMA,"cores":sorted(config.cores),"tenants":len(config.tenants),"guard":True,"gate":True})); return 0
        asyncio.run(Broker(config).serve()); return 0
    except (OSError,ValueError,PermissionError) as exc: print(f"virtual Broker: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
