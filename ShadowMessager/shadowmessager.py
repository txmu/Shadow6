#!/usr/bin/env python3
"""Small standalone ShadowChat client over the installed Shadow6 SDK."""
import argparse
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import stat
import struct
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'Application-Layer'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shadow_protocols import ShadowChat,ShadowIdentity,encode_frame,decode_frame
from libshadow6._verified_guards import chat_peer_bound

MAX_MESSAGE=4096
MAX_WIRE=32768
PART=struct.Struct('!3s16sHHI')


def private(path,maximum):
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077
                or info.st_nlink!=1 or info.st_size>maximum):raise ValueError('owner-only bounded regular file required')
        data=os.read(fd,maximum+1)
        if len(data)>maximum:raise ValueError('file byte budget exceeded')
        return data
    finally:os.close(fd)


def write_new(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())


def initialize(directory,name,service,session_file=None):
    if not re.fullmatch('[A-Za-z0-9_.@-]{1,64}',name):raise ValueError('portable chat identity required')
    if not isinstance(service,str) or not 1<=len(service)<=160 or '\0' in service:raise ValueError('explicit Named Service required')
    root=Path(directory).absolute()
    if root.resolve()!=root:raise ValueError('regular configuration directory required')
    root.mkdir(mode=0o700,parents=True,exist_ok=True);root.chmod(0o700)
    if any((root/name).exists() for name in ('config.json','identity.key','session.key')):raise ValueError('fresh chat directory required')
    identity=ShadowIdentity.generate(name);key=private(session_file,32) if session_file else secrets.token_bytes(32)
    if len(key)!=32:raise ValueError('32-byte shared session key required')
    write_new(root/'identity.key',identity.private_key.private_bytes_raw());write_new(root/'session.key',key)
    config={'schema':'shadowmessager.v1','name':name,'service':service,'identity_file':str(root/'identity.key'),
            'session_file':str(root/'session.key'),'peer':None,'peer_public_key':None}
    write_new(root/'config.json',json.dumps(config,indent=2).encode())
    return {'config':str(root/'config.json'),'name':name,'public_key':identity.public_hex(),'session_key_file':str(root/'session.key')}


def load(path):
    from Deployment.service_storage import strict_json
    config=strict_json(private(path,16384),limit=16384)
    if not isinstance(config,dict) or set(config)!={'schema','name','service','identity_file','session_file','peer','peer_public_key'} or config['schema']!='shadowmessager.v1':raise ValueError('exact ShadowMessager configuration required')
    for field in ('name','peer'):
        if not isinstance(config[field],str) or not re.fullmatch('[A-Za-z0-9_.@-]{1,64}',config[field]):raise ValueError('configured local and pinned peer names required')
    if not isinstance(config['peer_public_key'],str) or not re.fullmatch('[a-f0-9]{64}',config['peer_public_key']):raise ValueError('pinned peer Ed25519 key required')
    if not isinstance(config['service'],str) or not 1<=len(config['service'])<=160 or '\0' in config['service']:raise ValueError('explicit Named Service required')
    return config


class Framing:
    def __init__(self,sock,semantics='stream',max_record=16384):
        if semantics not in {'stream','message','credited'}:raise ValueError('supported Shadow6 application boundary required')
        if semantics!='stream' and (type(max_record) is not int or max_record<64):raise ValueError('application record boundary must hold at least 64 bytes')
        self.socket=sock;self.stream=semantics=='stream';self.maximum=min(max_record or 16384,16384);self.pending={};self.lock=threading.Lock()

    def send(self,wire):
        if not isinstance(wire,bytes) or not 4<len(wire)<=MAX_WIRE:raise ValueError('bounded ShadowChat frame required')
        with self.lock:
            if self.stream:self.socket.sendall(wire);return
            capacity=self.maximum-PART.size;count=math.ceil(len(wire)/capacity)
            if count>128:raise ValueError('chat message exceeds this Profile record budget')
            identity=secrets.token_bytes(16)
            for index in range(count):
                frame=PART.pack(b'SM1',identity,count,index,len(wire))+wire[index*capacity:(index+1)*capacity]
                if self.socket.send(frame)!=len(frame):raise OSError('partial application record')

    def exact(self,length):
        parts=[]
        while length:
            part=self.socket.recv(length)
            if not part:raise EOFError('Shadow6 application connection closed')
            parts.append(part);length-=len(part)
        return b''.join(parts)

    def receive(self):
        if self.stream:
            prefix=self.exact(4);length=struct.unpack('!I',prefix)[0]
            if not 0<length<=MAX_WIRE-4:raise ValueError('incoming chat frame exceeds its byte budget')
            return prefix+self.exact(length)
        while True:
            raw=self.socket.recv(self.maximum+1)
            if not raw:raise EOFError('Shadow6 application connection closed')
            if not PART.size<len(raw)<=self.maximum:raise ValueError('bounded chat application record required')
            magic,ident,count,index,total=PART.unpack(raw[:PART.size])
            capacity=self.maximum-PART.size
            if magic!=b'SM1' or not 1<=count<=128 or index>=count or not 4<total<=MAX_WIRE or count!=math.ceil(total/capacity):raise ValueError('invalid chat fragment header')
            now=time.monotonic();self.pending={k:v for k,v in self.pending.items() if now-v[0]<15}
            if ident not in self.pending:
                if len(self.pending)>=8:raise ValueError('fragment assembly budget exceeded')
                self.pending[ident]=(now,count,total,{})
            _,known_count,known_total,parts=self.pending[ident]
            if (known_count,known_total)!=(count,total):raise ValueError('conflicting chat fragment metadata')
            payload=raw[PART.size:];expected=capacity if index<count-1 else total-capacity*(count-1)
            if len(payload)!=expected or index in parts and parts[index]!=payload:raise ValueError('conflicting chat fragment bytes')
            parts[index]=payload
            if len(parts)==count:
                self.pending.pop(ident);return b''.join(parts[i] for i in range(count))


class Messenger:
    def __init__(self,config,connection):
        self.config=config;self.connection=connection
        secret=private(config['identity_file'],32);session=private(config['session_file'],32)
        if len(secret)!=32 or len(session)!=32:raise ValueError('32-byte private identity and session keys required')
        self.identity=ShadowIdentity(config['name'],Ed25519PrivateKey.from_private_bytes(secret))
        self.chat=ShadowChat(session,self.identity);boundary=connection.boundary
        self.wire=Framing(connection.socket,boundary.semantics,getattr(boundary,'max_record',16384))

    def send(self,text,attachments=None):
        if not isinstance(text,str):raise ValueError('chat text must be a string')
        valid_attachments=[]
        if attachments:
            if not isinstance(attachments,(list,tuple)) or len(attachments)>4:raise ValueError('at most 4 attachments allowed')
            for item in attachments:
                fid=item if isinstance(item,str) else item.get('file_id') if isinstance(item,dict) else None
                if not fid or not re.fullmatch(r'cf1-[a-f0-9]{64}',fid):raise ValueError('invalid Content Fabric attachment reference')
                valid_attachments.append(fid)
        payload=json.dumps({'text':text,'attachments':valid_attachments}) if valid_attachments else text
        if not 1<=len(payload.encode())<=MAX_MESSAGE:raise ValueError('chat text must contain 1..4096 UTF-8 bytes')
        self.wire.send(encode_frame(self.chat.encrypt(self.config['peer'],payload)))

    def receive(self):
        document=decode_frame(self.wire.receive())
        if (not isinstance(document.get('recipient'),str) or not isinstance(document.get('sender'),str)
                or not chat_peer_bound(self.config['name'],document['recipient'],self.config['peer'],document['sender'])):
            raise ValueError('message does not match the pinned conversation')
        raw=self.chat.decrypt(document,self.config['peer_public_key'])
        if len(raw.encode())>MAX_MESSAGE:raise ValueError('incoming chat text exceeds this application budget')
        try:
            parsed=json.loads(raw)
            if isinstance(parsed,dict) and 'text' in parsed and 'attachments' in parsed:
                return parsed
        except (json.JSONDecodeError,ValueError,TypeError):
            pass
        return raw


def run(config,terminal=False):
    from libshadow6 import Shadow6
    with Shadow6() as sdk,sdk.connect_handle(config['service']) as connection:
        messenger=Messenger(config,connection);events=queue.Queue(maxsize=128);stopped=threading.Event()
        def receiver():
            try:
                while not stopped.is_set():events.put(('message',messenger.receive()),timeout=5)
            except (OSError,EOFError,ValueError,queue.Full):
                try:events.put_nowait(('status','Connection closed'))
                except queue.Full:pass
        threading.Thread(target=receiver,daemon=True).start()
        try:
            if terminal:
                def display():
                    while not stopped.is_set():
                        try:kind,value=events.get(timeout=.5)
                        except queue.Empty:continue
                        line=value['text']+(' [cf1: '+', '.join(value['attachments'])+']' if value.get('attachments') else '') if isinstance(value,dict) else value
                        print(config['peer']+': '+line if kind=='message' else line,flush=True)
                threading.Thread(target=display,daemon=True).start()
                print('ShadowMessager · '+config['service']+' · peer '+config['peer'])
                for line in sys.stdin:
                    if line.strip()=='/quit':break
                    if line.rstrip('\n'):messenger.send(line.rstrip('\n'))
            else:gui(messenger,events)
        finally:
            stopped.set()
            try:connection.socket.shutdown(socket.SHUT_RDWR)
            except OSError:pass


def gui(messenger,events):
    import tkinter as tk
    from tkinter import ttk
    root=tk.Tk();root.title('ShadowMessager');root.geometry('680x520')
    root.columnconfigure(0,weight=1);root.rowconfigure(1,weight=1)
    title=ttk.Label(root,text=messenger.config['name']+' ↔ '+messenger.config['peer']+' · '+messenger.config['service'],padding=12);title.grid(row=0,column=0,sticky='ew')
    transcript=tk.Text(root,wrap='word',state='disabled',padx=12,pady=12);transcript.grid(row=1,column=0,sticky='nsew')
    frame=ttk.Frame(root,padding=12);frame.grid(row=2,column=0,sticky='ew');frame.columnconfigure(0,weight=1)
    entry=ttk.Entry(frame);entry.grid(row=0,column=0,sticky='ew',padx=(0,8));status=ttk.Label(root,padding=8,text='ShadowChat · pinned peer');status.grid(row=3,column=0,sticky='ew')
    def append(name,text):
        transcript.configure(state='normal');transcript.insert('end',name+': '+text+'\n')
        if int(transcript.index('end-1c').split('.')[0])>400:transcript.delete('1.0','100.0')
        transcript.configure(state='disabled');transcript.see('end')
    sending=False
    def send(_=None):
        nonlocal sending
        if sending:return
        text=entry.get()
        if not text:return
        if len(text.encode())>MAX_MESSAGE:status.configure(text='Maximum 4096 UTF-8 bytes');return
        entry.delete(0,'end');button.configure(state='disabled');sending=True
        def work():
            try:messenger.send(text);events.put(('sent',text),timeout=5)
            except (OSError,ValueError,queue.Full):
                try:events.put_nowait(('error','Message could not be sent'))
                except queue.Full:pass
        threading.Thread(target=work,daemon=True).start()
    button=ttk.Button(frame,text='发送 / Send',command=send);button.grid(row=0,column=1);entry.bind('<Return>',send);entry.focus_set()
    def poll():
        nonlocal sending
        for _ in range(16):
            try:kind,value=events.get_nowait()
            except queue.Empty:break
            if kind in {'message','sent'}:
                line=value['text']+(' [cf1: '+', '.join(value['attachments'])+']' if value.get('attachments') else '') if isinstance(value,dict) else value
                append(messenger.config['peer'] if kind=='message' else messenger.config['name'],line)
            else:status.configure(text=value)
            if kind in {'sent','error'}:button.configure(state='normal');sending=False
        root.after(75,poll)
    root.after(75,poll);root.mainloop()


def main(argv=None):
    parser=argparse.ArgumentParser(prog='ShadowMessager');sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('init');p.add_argument('--directory',type=Path,required=True);p.add_argument('--name',required=True);p.add_argument('--service',required=True);p.add_argument('--session-key-file',type=Path)
    p=sub.add_parser('peer');p.add_argument('--config',type=Path,required=True);p.add_argument('--name',required=True);p.add_argument('--public-key',required=True)
    p=sub.add_parser('run');p.add_argument('--config',type=Path,required=True);p.add_argument('--terminal',action='store_true')
    args=parser.parse_args(argv)
    if args.action=='init':print(json.dumps(initialize(args.directory,args.name,args.service,args.session_key_file)))
    elif args.action=='peer':
        if not re.fullmatch('[A-Za-z0-9_.@-]{1,64}',args.name) or not re.fullmatch('[a-f0-9]{64}',args.public_key):raise ValueError('pinned peer name and public key required')
        from Deployment.service_storage import strict_json
        config=strict_json(private(args.config,16384),limit=16384);config.update(peer=args.name,peer_public_key=args.public_key)
        temporary=args.config.with_name(args.config.name+'.'+secrets.token_hex(8));write_new(temporary,json.dumps(config,indent=2).encode());os.replace(temporary,args.config)
        print(json.dumps({'peer':args.name,'public_key':args.public_key}))
    else:run(load(args.config),args.terminal)
    return 0


if __name__=='__main__':raise SystemExit(main())
