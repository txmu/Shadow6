#!/usr/bin/env python3
"""Loopback mutual-authentication test for the embedded WebSocket control plane."""
import base64, json, os, pathlib, socket, struct, subprocess, sys, tempfile, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

binary=pathlib.Path(sys.argv[1]).resolve(); client=Ed25519PrivateKey.generate()
public=client.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)

def signed(domain,*fields):
    return domain+b''.join(struct.pack('>I',len(f))+f for f in fields)
def send_frame(s,opcode,data):
    mask=os.urandom(4); n=len(data); head=bytes([0x80|opcode])+(bytes([0x80|n]) if n<126 else bytes([0xfe])+struct.pack('>H',n))
    s.sendall(head+mask+bytes(v^mask[i&3] for i,v in enumerate(data)))
def exact(s,n,buffer=b''):
    while len(buffer)<n: buffer+=s.recv(n-len(buffer))
    return buffer[:n],buffer[n:]
def recv_frame(s,buffer=b''):
    h,buffer=exact(s,2,buffer); n=h[1]&127
    if n==126: x,buffer=exact(s,2,buffer);n=struct.unpack('>H',x)[0]
    data,buffer=exact(s,n,buffer);return h[0]&15,data,buffer

with tempfile.TemporaryDirectory(prefix='shadow6-gleam-control.') as d:
    reserve=socket.socket();reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1];reserve.close()
    cfg=pathlib.Path(d)/'config.json'
    cfg.write_text(json.dumps({'role':'broker','broker':{'listen_addr':f'127.0.0.1:{port}',
      'private_key':'00'*32,'agents':[],'clients':[{'id':'client-1','pubkey':public.hex(),
      'allowed_agents':[]}],'webhook_url':'','stealth_mode':False},'agent':None,'client':None}))
    cfg.chmod(0o600); process=subprocess.Popen([binary,'--config',cfg],stderr=subprocess.PIPE)
    try:
        deadline=time.time()+5
        while True:
            try:s=socket.create_connection(('127.0.0.1',port),.2);break
            except OSError:
                if time.time()>deadline:raise
                time.sleep(.05)
        key=base64.b64encode(os.urandom(16)).decode()
        s.sendall((f'GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n').encode())
        buf=b''
        while b'\r\n\r\n' not in buf:buf+=s.recv(4096)
        headers,buf=buf.split(b'\r\n\r\n',1);assert headers.startswith(b'HTTP/1.1 101 ')
        op,nonce,buf=recv_frame(s,buf);assert op==2 and len(nonce)==32
        identity=b'client-1'; signature=client.sign(signed(b'shadow6-rust-control-auth-v1',identity,nonce))
        send_frame(s,1,json.dumps({'id':'client-1','signature':base64.b64encode(signature).decode()}).encode())
        peer_nonce=os.urandom(32);send_frame(s,2,peer_nonce)
        op,response,buf=recv_frame(s,buf);auth=json.loads(response);assert op==1 and auth['id']=='broker'
        broker=Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key()
        broker.verify(base64.b64decode(auth['signature']),signed(b'shadow6-rust-control-auth-v1',b'broker',peer_nonce))
        send_frame(s,1,json.dumps({'jsonrpc':'2.0','id':7,'method':'Broker.UpdateIP','params':{'agent_id':'x','ipv6':'::1'}}).encode())
        _,response,_=recv_frame(s,buf);reply=json.loads(response);assert reply['id']==7 and reply['error']['code']==-32601
        print('Core-Gleam WebSocket mutual-auth test passed')
    finally:
        process.terminate();process.wait(timeout=5)
