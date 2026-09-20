#!/usr/bin/env python3
"""Real Core-Gleam broker/agent/client encrypted forwarding test."""
import json, os, pathlib, re, socket, subprocess, sys, tempfile, threading, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

binary=pathlib.Path(sys.argv[1]).resolve()
def keypair():
    key=Ed25519PrivateKey.generate()
    return key.private_bytes_raw().hex(),key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

class Echo:
    def __init__(self):
        self.s=socket.socket();self.s.bind(('127.0.0.1',0));self.s.listen(1);self.port=self.s.getsockname()[1];self.error=None
        self.t=threading.Thread(target=self.run,daemon=True);self.t.start()
    def run(self):
        try:
            c,_=self.s.accept()
            with c:
                while data:=c.recv(65536):c.sendall(data)
        except Exception as exc:self.error=exc
    def close(self):
        self.s.close();self.t.join(2)
        if self.error:raise self.error

bpv,bpu=keypair();apv,apu=keypair();cpv,cpu=keypair();port=free_port();echo=Echo();processes=[]
with tempfile.TemporaryDirectory(prefix='shadow6-gleam-e2e.') as td:
    root=pathlib.Path(td)
    def cfg(name,value):
        p=root/name;p.write_text(json.dumps(value,separators=(',',':')));p.chmod(0o600);return p
    broker=cfg('broker.json',{'role':'broker','broker':{'listen_addr':f'127.0.0.1:{port}','private_key':bpv,
      'agents':[{'id':'agent','pubkey':apu}],'clients':[{'id':'client','pubkey':cpu,'allowed_agents':['agent']}],
      'webhook_url':'','stealth_mode':False},'agent':None,'client':None})
    agent=cfg('agent.json',{'role':'agent','broker':None,'agent':{'id':'agent','broker_addrs':[f'ws://127.0.0.1:{port}/ws'],
      'broker_pubkey':bpu,'private_key':apv,'target_port':echo.port,'auto_close_after':30,'allow_local_discovery':False,
      'client_pubkeys':{'client':cpu},'transport':'secure-stream'},'client':None})
    client=cfg('client.json',{'role':'client','broker':None,'agent':None,'client':{'id':'client','broker_addrs':[f'ws://127.0.0.1:{port}/ws'],
      'broker_pubkey':bpu,'private_key':cpv,'target_agent':'agent','agent_pubkey':apu,'on_success':'',
      'allow_local_discovery':False,'transport':'secure-stream'}})
    try:
        for path in (broker,agent,client):
            checked=subprocess.run([binary,'--config',path,'--check-config'],capture_output=True,text=True,timeout=10)
            assert checked.returncode==0,checked.stderr
        for path in (broker,agent,client):
            p=subprocess.Popen([binary,'--config',path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(p);time.sleep(.2)
        cp=processes[-1];deadline=time.time()+10;match=None
        while time.time()<deadline:
            line=cp.stdout.readline();match=re.search(r'proxy listening on 127\.0\.0\.1:(\d+)',line,re.I)
            if match:break
            if cp.poll() is not None:
                for process in processes:
                    if process.poll() is None:process.terminate()
                diagnostics=[process.communicate(timeout=2)[1] for process in processes]
                raise AssertionError(f'client exited before publishing its proxy: {diagnostics}')
        assert match,'client proxy was not published'
        payload=os.urandom(256*1024+91)
        with socket.create_connection(('127.0.0.1',int(match.group(1))),timeout=5) as app:
            app.settimeout(10);app.sendall(payload);app.shutdown(socket.SHUT_WR);received=bytearray()
            while chunk:=app.recv(65536):received.extend(chunk)
        if bytes(received)!=payload:
            for process in processes:
                if process.poll() is None:process.terminate()
            diagnostics=[process.communicate(timeout=2)[1] for process in processes]
            raise AssertionError(f'forwarded {len(received)} of {len(payload)} bytes: {diagnostics}')
        assert cp.wait(timeout=5)==0,cp.stderr.read();assert processes[1].wait(timeout=5)==0,processes[1].stderr.read()
        print('Core-Gleam real broker/agent/client forwarding passed')
    finally:
        for p in reversed(processes):
            if p.poll() is None:p.terminate()
            try:p.communicate(timeout=2)
            except subprocess.TimeoutExpired:p.kill();p.communicate(timeout=2)
        echo.close()
