import asyncio, base64, json, os, tempfile, time, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from virtual_broker import Broker, canonical, load_config

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
    def request(self,key,client="device"):
        now=int(time.time()); value={"schema":"shadow6.virtual-broker-admission.v1","tenant":"tenant","client":client,"core":"go","issued":now,"expires":now+60,"nonce":base64.b64encode(os.urandom(32)).decode(),"public_key":base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()}
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

if __name__=="__main__": unittest.main()
