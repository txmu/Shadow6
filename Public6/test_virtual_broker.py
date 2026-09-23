import asyncio, base64, json, os, socket, struct, subprocess, sys, tempfile, time, unittest
from dataclasses import replace
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from virtual_broker import Broker, canonical, load_config

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"Network-Adapter"))
from shadow6_network import ReliableAdapter  # noqa: E402

class VirtualBrokerTests(unittest.TestCase):
    def fixture(self,approval="default-approved",approvals=()):
        directory=tempfile.TemporaryDirectory(); root=Path(directory.name)
        secret=root/"identity"; secret.write_bytes(os.urandom(32)); secret.chmod(0o600)
        key=Ed25519PrivateKey.generate(); public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        document={"schema":"shadow6.virtual-broker.v1","listen":{"host":"127.0.0.1","port":7443},"identity_key_file":str(secret),
          "cores":{"go":{"host":"127.0.0.1","port":7444}},"tenants":[{"id":"tenant","public_keys":[base64.b64encode(public).decode()],
          "approval":approval,"max_connections":2,"bytes_per_second":4096,"burst_bytes":8192}],
          "routes":[{"tenant":"tenant","core":"go","host":"127.0.0.1","port":7444}],
          "approvals":[{"tenant":"tenant","client":x} for x in approvals],"guard":{"required":True},"gate":{"required":True},
          "c11relay":{"control_socket":"/run/shadow6/c11relay.sock"},"limits":{"max_frame":4096,"handshake_seconds":5,"idle_seconds":30}}
        config=root/"config.json"; config.write_text(json.dumps(document)); config.chmod(0o600)
        return directory,load_config(config),key
    def request(self,key,client="device",core="go"):
        now=int(time.time()); value={"schema":"shadow6.virtual-broker-admission.v1","tenant":"tenant","client":client,"core":core,"issued":now,"expires":now+60,"nonce":base64.b64encode(os.urandom(32)).decode(),"public_key":base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()}
        value["signature"]=base64.b64encode(key.sign(canonical(value))).decode(); return canonical(value)
    def test_concurrent_replay_is_atomic(self):
        from concurrent.futures import ThreadPoolExecutor
        directory,config,key=self.fixture(); self.addCleanup(directory.cleanup)
        broker=Broker(config); raw=self.request(key)
        def attempt(_):
            try: broker.admit(raw); return True
            except PermissionError: return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            accepted=list(pool.map(attempt,range(64)))
        self.assertEqual(sum(accepted),1)
        self.assertEqual(len(broker.nonces),1)

    def test_signed_admission_replay_and_identity(self):
        directory,config,key=self.fixture(); self.addCleanup(directory.cleanup); broker=Broker(config); request=self.request(key)
        tenant,identity,target=broker.admit(request); self.assertEqual((tenant.tenant_id,len(identity),target),("tenant",64,("127.0.0.1",7444)))
        with self.assertRaises(PermissionError): broker.admit(request)
    def test_required_approval_is_startup_catalog(self):
        directory,config,key=self.fixture("approval-required",("approved",)); self.addCleanup(directory.cleanup); broker=Broker(config)
        broker.admit(self.request(key,"approved"))
        with self.assertRaises(PermissionError): broker.admit(self.request(key,"other"))
    def test_nonce_expiration_and_bounded_replay_state(self):
        directory,config,key=self.fixture(); self.addCleanup(directory.cleanup); broker=Broker(config)
        broker.admit(self.request(key)); self.assertEqual(len(broker.nonces),1)
        broker.expire_nonces(int(time.time())+61)
        self.assertEqual((len(broker.nonces),len(broker.nonce_expiry)),(0,0))
    def test_bad_signature_does_not_crash_admission(self):
        directory,config,key=self.fixture(); self.addCleanup(directory.cleanup); broker=Broker(config)
        value=json.loads(self.request(key)); value["client"]="tampered"
        with self.assertRaises(PermissionError): broker.admit(canonical(value))
    def test_bidirectional_copy_and_shared_rate_budget(self):
        directory,config,key=self.fixture(); self.addCleanup(directory.cleanup); broker=Broker(config)
        async def exercise():
            async def echo(reader,writer):
                data=await reader.readexactly(4096)
                writer.write(data); await writer.drain(); writer.close()
            upstream=await asyncio.start_server(echo,"127.0.0.1",0)
            destination=upstream.sockets[0].getsockname()[1]
            config.routes[("tenant","go")]=("127.0.0.1",destination)
            server=await asyncio.start_server(broker.handle,"127.0.0.1",0)
            try:
                reader,writer=await asyncio.open_connection("127.0.0.1",server.sockets[0].getsockname()[1])
                request=self.request(key); writer.write(len(request).to_bytes(4,"big")+request+b"x"*4096)
                self.assertEqual(await asyncio.wait_for(reader.readexactly(4096),5),b"x"*4096)
                writer.close(); await writer.wait_closed()
            finally:
                server.close(); upstream.close(); await server.wait_closed(); await upstream.wait_closed()
        asyncio.run(exercise())
    def test_anonymous_tcp_route_uses_fixed_tenant(self):
        directory,config,_=self.fixture(); self.addCleanup(directory.cleanup)
        async def exercise():
            async def echo(reader,writer):
                writer.write(await reader.readexactly(4)); await writer.drain(); writer.close()
            upstream=await asyncio.start_server(echo,"127.0.0.1",0)
            config.routes[("tenant","go")]=("127.0.0.1",upstream.sockets[0].getsockname()[1])
            broker=Broker(config)
            listener=await asyncio.start_server(lambda r,w:broker.handle(r,w,("tenant","go")),"127.0.0.1",0)
            try:
                reader,writer=await asyncio.open_connection("127.0.0.1",listener.sockets[0].getsockname()[1])
                writer.write(b"ping")
                self.assertEqual(await asyncio.wait_for(reader.readexactly(4),2),b"ping")
                writer.close(); await writer.wait_closed()
            finally:
                listener.close(); upstream.close()
                await listener.wait_closed(); await upstream.wait_closed()
        asyncio.run(exercise())
    def test_optional_ports_are_strict_and_bound_to_routes(self):
        directory,_,_=self.fixture(); self.addCleanup(directory.cleanup)
        path=Path(directory.name)/"config.json"
        document=json.loads(path.read_text())
        document["anonymous_listeners"]=[{"port":7446,"tenant":"tenant","core":"go"}]
        document["datagram_listeners"]=[{"port":7447,"tenant":"tenant","core":"hare","carrier":"gate","anonymous":False}]
        document["cores"]["hare"]={"host":"127.0.0.1","port":7448}
        document["routes"].append({"tenant":"tenant","core":"hare","host":"127.0.0.1","port":7448})
        path.write_text(json.dumps(document))
        config=load_config(path)
        self.assertEqual(config.anonymous_listeners,((7446,"tenant","go"),))
        self.assertEqual(config.datagram_listeners,((7447,"tenant","hare","gate",False),))
        document["tenants"][0]["public_keys"]=[]
        path.write_text(json.dumps(document))
        self.assertEqual(load_config(path).tenants["tenant"].public_keys,())
        document["anonymous_listeners"]=[]
        path.write_text(json.dumps(document))
        with self.assertRaises(ValueError): load_config(path)
        document["anonymous_listeners"]=[{"port":7446,"tenant":"tenant","core":"go"}]
        for bad in ({"port":7443,"tenant":"tenant","core":"go"},
                    {"port":7449,"tenant":"other","core":"go"}):
            document["anonymous_listeners"]=[bad]; path.write_text(json.dumps(document))
            with self.assertRaises(ValueError): load_config(path)
        document["anonymous_listeners"]=[]
        document["datagram_listeners"][0]["extra"]=True
        path.write_text(json.dumps(document))
        with self.assertRaises(ValueError): load_config(path)
    def test_unified_cli_and_ai_validation_are_read_only(self):
        directory,_,_=self.fixture(); self.addCleanup(directory.cleanup)
        path=Path(directory.name)/"config.json"
        cli=subprocess.run([sys.executable,str(ROOT/"CLI/shadow6.py"),"virtual-broker","--config",str(path),"--check"],capture_output=True,text=True,timeout=10)
        self.assertEqual(cli.returncode,0,cli.stderr)
        self.assertEqual(json.loads(cli.stdout)["tenants"],1)
        method=subprocess.run([sys.executable,str(ROOT/"Control-Center/shadow6_control.py"),"call","virtual_broker.validate","--params",json.dumps({"config":str(path)})],capture_output=True,text=True,timeout=10)
        self.assertEqual(method.returncode,0,method.stderr)
        self.assertEqual(json.loads(method.stdout)["datagram_ports"],[])
    def test_four_core_datagram_gate_and_s6na_paths(self):
        directory,base,key=self.fixture(); self.addCleanup(directory.cleanup)
        async def exercise(core,carrier,anonymous):
            loop=asyncio.get_running_loop()
            class Echo(asyncio.DatagramProtocol):
                def connection_made(self,transport): self.transport=transport
                def datagram_received(self,data,addr): self.transport.sendto(data,addr)
            upstream,_=await loop.create_datagram_endpoint(Echo,local_addr=("127.0.0.1",0))
            target=("127.0.0.1",upstream.get_extra_info("sockname")[1])
            config=replace(base,cores={core:target},routes={("tenant",core):target},max_frame=4096)
            broker=Broker(config)
            listener=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); listener.bind(("127.0.0.1",0)); listener.setblocking(False)
            client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); client.bind(("127.0.0.1",0)); client.setblocking(False)
            try:
                payload=(b"S6NA" if carrier=="s6na" else b"gate")+b"-core-"+core.encode()
                raw=payload if anonymous else struct.pack("!H",len(request:=self.request(key,core=core)))+request+payload
                loopback=listener.getsockname()
                broker.connections=1
                task=asyncio.create_task(broker.datagram(listener,client.getsockname(),raw,("tenant",core),anonymous))
                self.assertEqual(await asyncio.wait_for(loop.sock_recvfrom(client,4096),2),(payload,loopback))
                await task
                self.assertEqual(broker.connections,0)
                self.assertEqual(broker.runtime["tenant"].active,0)
                if not anonymous:
                    broker.connections=1
                    replay=asyncio.create_task(broker.datagram(listener,client.getsockname(),raw,("tenant",core),False))
                    await replay
                    with self.assertRaises(asyncio.TimeoutError):
                        await asyncio.wait_for(loop.sock_recv(client,4096),.03)
            finally:
                client.close(); listener.close(); upstream.close()
        for core in ("hare","carp","pony","idris"):
            for carrier in ("gate","s6na"):
                for anonymous in (False,True):
                    with self.subTest(core=core,carrier=carrier,anonymous=anonymous):
                        asyncio.run(exercise(core,carrier,anonymous))
    def test_s6na_session_keeps_source_and_multiple_replies(self):
        directory,base,key=self.fixture(); self.addCleanup(directory.cleanup)
        async def exercise():
            loop=asyncio.get_running_loop()
            class DoubleEcho(asyncio.DatagramProtocol):
                def connection_made(self,transport): self.transport=transport
                def datagram_received(self,data,addr):
                    self.transport.sendto(b"ack:"+data,addr)
                    self.transport.sendto(b"data:"+data,addr)
            upstream,_=await loop.create_datagram_endpoint(DoubleEcho,local_addr=("127.0.0.1",0))
            target=("127.0.0.1",upstream.get_extra_info("sockname")[1])
            config=replace(base,cores={"hare":target},routes={("tenant","hare"):target})
            broker=Broker(config)
            ready=loop.create_future()
            listener=asyncio.create_task(broker.serve_datagrams(0,"tenant","hare","s6na",False,ready))
            client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); client.setblocking(False)
            try:
                port=await asyncio.wait_for(ready,2)
                for payload in (b"first",b"second"):
                    request=self.request(key,core="hare")
                    await loop.sock_sendto(client,struct.pack("!H",len(request))+request+payload,("127.0.0.1",port))
                    replies={await asyncio.wait_for(loop.sock_recv(client,4096),2) for _ in range(2)}
                    self.assertEqual(replies,{b"ack:"+payload,b"data:"+payload})
                self.assertEqual((broker.connections,broker.runtime["tenant"].active),(1,1))
            finally:
                listener.cancel(); await asyncio.gather(listener,return_exceptions=True)
                client.close(); upstream.close()
            self.assertEqual((broker.connections,broker.runtime["tenant"].active),(0,0))
        asyncio.run(exercise())
    def test_gate_datagram_listener_requires_signed_admission(self):
        directory,base,key=self.fixture(); self.addCleanup(directory.cleanup)
        async def exercise():
            loop=asyncio.get_running_loop()
            class Echo(asyncio.DatagramProtocol):
                def connection_made(self,transport): self.transport=transport
                def datagram_received(self,data,source): self.transport.sendto(data,source)
            upstream,_=await loop.create_datagram_endpoint(Echo,local_addr=("127.0.0.1",0))
            target=("127.0.0.1",upstream.get_extra_info("sockname")[1])
            broker=Broker(replace(base,cores={"pony":target},routes={("tenant","pony"):target}))
            ready=loop.create_future()
            listener=asyncio.create_task(broker.serve_datagrams(0,"tenant","pony","gate",False,ready))
            client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); client.setblocking(False)
            try:
                port=await asyncio.wait_for(ready,2)
                await loop.sock_sendto(client,b"unauthorized",("127.0.0.1",port))
                with self.assertRaises(asyncio.TimeoutError): await asyncio.wait_for(loop.sock_recv(client,4096),.03)
                request=self.request(key,core="pony")
                packet=struct.pack("!H",len(request))+request+b"authorized"
                await loop.sock_sendto(client,packet,("127.0.0.1",port))
                self.assertEqual(await asyncio.wait_for(loop.sock_recv(client,4096),2),b"authorized")
                await loop.sock_sendto(client,packet,("127.0.0.1",port))
                with self.assertRaises(asyncio.TimeoutError): await asyncio.wait_for(loop.sock_recv(client,4096),.03)
            finally:
                listener.cancel(); await asyncio.gather(listener,return_exceptions=True)
                client.close(); upstream.close()
        asyncio.run(exercise())
    def test_four_core_s6na_frames_round_trip_through_broker(self):
        directory,base,_=self.fixture(); self.addCleanup(directory.cleanup)
        async def exercise(core):
            loop=asyncio.get_running_loop(); key=os.urandom(32)
            sender=ReliableAdapter(core,key,0)
            receiver=ReliableAdapter(core,key,1)
            class CoreEcho(asyncio.DatagramProtocol):
                def connection_made(self,transport): self.transport=transport
                def datagram_received(self,wire,source):
                    acks,messages,_=receiver.receive(wire)
                    for ack in acks:self.transport.sendto(ack,source)
                    for _,payload in messages:
                        for frame in receiver.send(0,b"reply:"+payload):self.transport.sendto(frame,source)
            upstream,_=await loop.create_datagram_endpoint(CoreEcho,local_addr=("127.0.0.1",0))
            target=("127.0.0.1",upstream.get_extra_info("sockname")[1])
            config=replace(base,cores={core:target},routes={("tenant",core):target})
            broker=Broker(config); ready=loop.create_future()
            listener=asyncio.create_task(broker.serve_datagrams(0,"tenant",core,"s6na",True,ready))
            client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); client.setblocking(False)
            try:
                port=await asyncio.wait_for(ready,2)
                for message in (b"one",b"two"):
                    for frame in sender.send(0,message): await loop.sock_sendto(client,frame,("127.0.0.1",port))
                    completed=[]
                    while not completed:
                        wire=await asyncio.wait_for(loop.sock_recv(client,4096),2)
                        acks,messages,_=sender.receive(wire)
                        completed.extend(messages)
                        for ack in acks:await loop.sock_sendto(client,ack,("127.0.0.1",port))
                    self.assertEqual(completed,[(0,b"reply:"+message)])
                self.assertEqual(broker.runtime["tenant"].active,1)
            finally:
                listener.cancel(); await asyncio.gather(listener,return_exceptions=True)
                client.close(); upstream.close()
        for core in ("hare","carp","pony","idris"):
            with self.subTest(core=core): asyncio.run(exercise(core))

if __name__=="__main__": unittest.main()
