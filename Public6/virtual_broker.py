#!/usr/bin/env python3
"""Public6 virtual Broker: authenticated admission plus opaque bounded relay."""
from __future__ import annotations
import argparse, asyncio, base64, hashlib, heapq, hmac, ipaddress, json, os, socket, stat, struct, sys, time
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
DATAGRAM_CORES={"hare","carp","pony","idris"}

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
    anonymous_listeners:tuple[tuple[int,str,str],...]=()
    datagram_listeners:tuple[tuple[int,str,str,str,bool],...]=()

def load_config(path:Path)->Config:
    value=json.loads(bounded_file(path,262144).decode(),object_pairs_hook=pairs,parse_float=reject_float,parse_constant=reject_float)
    allowed={"schema","listen","identity_key_file","cores","tenants","routes","approvals","guard","gate","c11relay","limits","anonymous_listeners","datagram_listeners"}
    if type(value) is not dict or set(value)-allowed or allowed-{"anonymous_listeners","datagram_listeners"}-set(value) or value["schema"]!=SCHEMA: raise ValueError("unknown virtual Broker schema or field")
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
        if type(item["public_keys"]) is not list or len(item["public_keys"])>32 or any(type(x) is not str or len(x)!=44 for x in item["public_keys"]): raise ValueError("invalid tenant public key")
        keys=tuple(base64.b64decode(x,validate=True) for x in item["public_keys"])
        if any(len(x)!=32 for x in keys): raise ValueError("invalid tenant public key")
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
    anonymous=value.get("anonymous_listeners",[])
    if type(anonymous) is not list or len(anonymous)>32: raise ValueError("invalid anonymous listeners")
    anonymous_ports={listen["port"]}; anonymous_listeners=[]
    for entry in anonymous:
        if type(entry) is not dict or set(entry)!={"port","tenant","core"} or type(entry["port"]) is not int or not 1<=entry["port"]<=65535 or entry["port"] in anonymous_ports or type(entry["tenant"]) is not str or type(entry["core"]) is not str or (entry["tenant"],entry["core"]) not in routes:
            raise ValueError("invalid anonymous listener")
        anonymous_ports.add(entry["port"])
        anonymous_listeners.append((entry["port"],entry["tenant"],entry["core"]))
    datagrams=value.get("datagram_listeners",[])
    if type(datagrams) is not list or len(datagrams)>32: raise ValueError("invalid datagram listeners")
    datagram_ports=set(); datagram_listeners=[]
    for entry in datagrams:
        if type(entry) is not dict or set(entry)!={"port","tenant","core","carrier","anonymous"} or type(entry["port"]) is not int or not 1<=entry["port"]<=65535 or entry["port"] in datagram_ports or type(entry["tenant"]) is not str or type(entry["core"]) is not str or (entry["tenant"],entry["core"]) not in routes or entry["core"] not in DATAGRAM_CORES or entry["carrier"] not in ("gate","s6na") or type(entry["anonymous"]) is not bool:
            raise ValueError("invalid datagram listener")
        datagram_ports.add(entry["port"])
        datagram_listeners.append((entry["port"],entry["tenant"],entry["core"],entry["carrier"],entry["anonymous"]))
    anonymous_tenants={tenant for _,tenant,_ in anonymous_listeners} | {tenant for _,tenant,_,_,enabled in datagram_listeners if enabled}
    if any(not tenant.public_keys and tenant.tenant_id not in anonymous_tenants for tenant in tenants.values()):
        raise ValueError("tenant without keys needs an anonymous listener")
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
    return Config(listen["host"],listen["port"],key,cores,tenants,routes,True,True,relay["control_socket"],frozenset(approvals),**limits,anonymous_listeners=tuple(anonymous_listeners),datagram_listeners=tuple(datagram_listeners))

@dataclass
class RuntimeTenant:
    active:int=0; tokens:float=0; updated:float=field(default_factory=time.monotonic)

class Broker:
    def __init__(self,config:Config):
        self.config=config; self.approved=config.approvals; self.runtime={x:RuntimeTenant(tokens=t.burst_bytes) for x,t in config.tenants.items()}; self.nonces={}; self.nonce_expiry=[]
        self.verifiers={name:{key:Ed25519PublicKey.from_public_bytes(key) for key in tenant.public_keys} for name,tenant in config.tenants.items()}
        self.connections=0
        self._nonce_lock=RLock()
    async def charge(self,tenant:Tenant,size:int):
        runtime=self.runtime[tenant.tenant_id]
        now=time.monotonic()
        runtime.tokens=min(tenant.burst_bytes,runtime.tokens+(now-runtime.updated)*tenant.bytes_per_second)
        runtime.updated=now
        runtime.tokens-=size
        if runtime.tokens<0:
            delay=-runtime.tokens/tenant.bytes_per_second
            if delay>self.config.idle_seconds:
                runtime.tokens+=size
                raise TimeoutError("tenant rate limit exceeds idle deadline")
            try: await asyncio.sleep(delay)
            except asyncio.CancelledError:
                runtime.tokens+=size
                raise
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
            await self.charge(tenant,len(data))
            writer.write(data)
            if writer.transport.get_write_buffer_size()>=65536:
                async with asyncio.timeout(self.config.idle_seconds): await writer.drain()
    async def handle(self,reader,writer,anonymous:tuple[str,str]|None=None):
        if self.connections>=4096:
            writer.close(); return
        self.connections+=1
        tenant=None; admitted=False; upstream_writer=None; copies=[]
        try:
            if anonymous is None:
                async with asyncio.timeout(self.config.handshake_seconds):
                    size=struct.unpack("!I",await reader.readexactly(4))[0]
                    if not 1<=size<=16384: raise ValueError("invalid admission length")
                    tenant,_virtual,target=self.admit(await reader.readexactly(size))
            else:
                tenant=self.config.tenants[anonymous[0]]
                target=self.config.routes[anonymous]
            runtime=self.runtime[tenant.tenant_id]
            if runtime.active>=tenant.max_connections: raise PermissionError("tenant connection quota reached")
            runtime.active+=1; admitted=True
            async with asyncio.timeout(self.config.handshake_seconds):
                upstream_reader,upstream_writer=await asyncio.open_connection(*target,limit=65536)
            copies=[asyncio.create_task(self.copy(reader,upstream_writer,tenant)),asyncio.create_task(self.copy(upstream_reader,writer,tenant))]
            await asyncio.gather(*copies)
        except (asyncio.IncompleteReadError,asyncio.TimeoutError,OSError,ValueError,TypeError,RecursionError,PermissionError): pass
        finally:
            for task in copies: task.cancel()
            if copies: await asyncio.gather(*copies,return_exceptions=True)
            if admitted: self.runtime[tenant.tenant_id].active-=1
            self.connections-=1
            for item in (upstream_writer,writer):
                if item: item.close()
    def datagram_payload(self,raw,route,anonymous):
        tenant_id,core=route
        if not 1<=len(raw)<=min(self.config.max_frame,65507): raise ValueError("invalid datagram size")
        if anonymous: return raw
        if len(raw)<3: raise ValueError("missing datagram admission")
        size=struct.unpack_from("!H",raw)[0]
        if not 1<=size<=16384 or len(raw)<=size+2: raise ValueError("invalid datagram admission")
        admitted,_,target=self.admit(raw[2:2+size])
        if admitted.tenant_id!=tenant_id or target!=self.config.routes[route]: raise PermissionError("wrong datagram route")
        return raw[2+size:]
    async def datagram(self,listener,source,raw,route,anonymous):
        tenant=self.config.tenants[route[0]]
        runtime=self.runtime[route[0]]
        upstream=None
        try:
            payload=self.datagram_payload(raw,route,anonymous)
            if runtime.active>=tenant.max_connections: return
            runtime.active+=1
            try:
                await self.charge(tenant,len(payload))
                target=self.config.routes[route]
                family=socket.AF_INET6 if ":" in target[0] else socket.AF_INET
                upstream=socket.socket(family,socket.SOCK_DGRAM)
                upstream.setblocking(False)
                loop=asyncio.get_running_loop()
                async with asyncio.timeout(self.config.idle_seconds):
                    await loop.sock_connect(upstream,target)
                    await loop.sock_sendall(upstream,payload)
                    reply=await loop.sock_recv(upstream,min(self.config.max_frame,65507)+1)
                    if not 1<=len(reply)<=min(self.config.max_frame,65507): return
                    await self.charge(tenant,len(reply))
                    await loop.sock_sendto(listener,reply,source)
            finally:
                runtime.active-=1
        except (OSError,ValueError,PermissionError,asyncio.TimeoutError,struct.error): pass
        finally:
            if upstream is not None: upstream.close()
            self.connections-=1
    async def serve_datagrams(self,port,tenant,core,carrier,anonymous,ready=None):
        family=socket.AF_INET6 if ":" in self.config.listen_host else socket.AF_INET
        listener=socket.socket(family,socket.SOCK_DGRAM)
        listener.setblocking(False)
        listener.bind((self.config.listen_host,port))
        if ready is not None: ready.set_result(listener.getsockname()[1])
        tasks=set(); sessions={}
        route=(tenant,core); runtime=self.runtime[tenant]; quota=self.config.tenants[tenant]
        loop=asyncio.get_running_loop()
        async def receive_session(source,upstream):
            try:
                while True:
                    try:
                        async with asyncio.timeout(self.config.idle_seconds):
                            reply=await loop.sock_recv(upstream,min(self.config.max_frame,65507)+1)
                    except asyncio.TimeoutError:
                        if time.monotonic()-sessions[source][2]<self.config.idle_seconds: continue
                        break
                    if not 1<=len(reply)<=min(self.config.max_frame,65507): break
                    await self.charge(quota,len(reply))
                    await loop.sock_sendto(listener,reply,source)
                    sessions[source][2]=time.monotonic()
            except (OSError,asyncio.TimeoutError): pass
            finally:
                upstream.close()
                sessions.pop(source,None)
                runtime.active-=1; self.connections-=1
        try:
            while True:
                raw,source=await loop.sock_recvfrom(listener,min(self.config.max_frame,65507)+1)
                if carrier=="gate":
                    if self.connections>=4096: continue
                    self.connections+=1
                    task=asyncio.create_task(self.datagram(listener,source,raw,route,anonymous))
                    tasks.add(task); task.add_done_callback(tasks.discard)
                    continue
                try:
                    payload=self.datagram_payload(raw,route,anonymous)
                    session=sessions.get(source)
                    if session is None:
                        if self.connections>=4096 or runtime.active>=quota.max_connections: continue
                        target=self.config.routes[route]
                        upstream=socket.socket(socket.AF_INET6 if ":" in target[0] else socket.AF_INET,socket.SOCK_DGRAM)
                        upstream.setblocking(False)
                        try: await loop.sock_connect(upstream,target)
                        except BaseException: upstream.close(); raise
                        task=asyncio.create_task(receive_session(source,upstream))
                        sessions[source]=[upstream,task,time.monotonic()]
                        runtime.active+=1; self.connections+=1
                    else: upstream=session[0]
                    sessions[source][2]=time.monotonic()
                    await self.charge(quota,len(payload))
                    await loop.sock_sendall(upstream,payload)
                except (OSError,ValueError,PermissionError,asyncio.TimeoutError,struct.error): pass
        finally:
            listener.close()
            for task in tasks: task.cancel()
            session_tasks=[session[1] for session in sessions.values()]
            for task in session_tasks: task.cancel()
            if tasks or session_tasks: await asyncio.gather(*tasks,*session_tasks,return_exceptions=True)
    async def serve(self):
        servers=[]
        try:
            servers.append(await asyncio.start_server(self.handle,self.config.listen_host,self.config.listen_port,limit=65536))
            for port,tenant,core in self.config.anonymous_listeners:
                async def entry(reader,writer,route=(tenant,core)):
                    await self.handle(reader,writer,route)
                servers.append(await asyncio.start_server(entry,self.config.listen_host,port,limit=65536))
            await asyncio.gather(*(server.serve_forever() for server in servers),
                *(self.serve_datagrams(port,tenant,core,carrier,anonymous) for port,tenant,core,carrier,anonymous in self.config.datagram_listeners))
        finally:
            for server in servers: server.close()
            await asyncio.gather(*(server.wait_closed() for server in servers))

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("--config",type=Path,required=True); parser.add_argument("--check",action="store_true"); args=parser.parse_args()
    try:
        config=load_config(args.config)
        if args.check: print(json.dumps({"schema":SCHEMA,"cores":sorted(config.cores),"tenants":len(config.tenants),"anonymous_ports":[x[0] for x in config.anonymous_listeners],"datagram_ports":[x[0] for x in config.datagram_listeners],"guard":True,"gate":True})); return 0
        asyncio.run(Broker(config).serve()); return 0
    except (OSError,ValueError,PermissionError) as exc: print(f"virtual Broker: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
