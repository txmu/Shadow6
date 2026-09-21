import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import {Codec,DatagramEndpoint,ReliableAdapter,loadKey} from './shadow6_network.mjs';

test('startup limits expand payload, streams and window without mutation',()=>{
  const limits={max_message:32*1024*1024,max_streams:128,max_inflight:64*1024*1024,max_window:128,
    reassembly_seconds:60,max_extensions:32,payload_bytes:4096,window_frames:96};
  const adapter=new ReliableAdapter('idris',Buffer.alloc(32),0,[],limits);
  assert.equal(adapter.queues.length,128); assert.equal(adapter.codec.payload,4096);
  assert.throws(()=>{adapter.limits.max_streams=2},TypeError);
});

test('permission changes between lstat and open fail closed',{skip:process.platform==='win32'},()=>{
 const original={lstatSync:fs.lstatSync,openSync:fs.openSync,fstatSync:fs.fstatSync,closeSync:fs.closeSync};
 const stat={isFile:()=>true,isSymbolicLink:()=>false,uid:BigInt(process.geteuid()),mode:0o100600n,
  size:32n,dev:1n,ino:2n,nlink:1n,mtimeNs:1n,ctimeNs:1n};
 try{
  fs.lstatSync=()=>stat;fs.openSync=()=>3;fs.closeSync=()=>{};
  fs.fstatSync=()=>({...stat,mode:0o100644n});
  assert.throws(()=>loadKey('mock-only'),/changed while opening/);
  fs.fstatSync=()=>({...stat,uid:stat.uid+1n});
  assert.throws(()=>loadKey('mock-only'),/changed while opening/);
 }finally{Object.assign(fs,original)}
});
test('large inode identities remain exact',{skip:process.platform==='win32'},()=>{
 const original={lstatSync:fs.lstatSync,openSync:fs.openSync,fstatSync:fs.fstatSync,readSync:fs.readSync,closeSync:fs.closeSync};
 const value={isFile:()=>true,isSymbolicLink:()=>false,uid:BigInt(process.geteuid()),mode:0o100600n,
  size:32n,dev:1n,ino:9007199254740993n,nlink:1n,mtimeNs:1n,ctimeNs:1n};
 try{
  fs.lstatSync=(_path,options)=>{assert.equal(options.bigint,true);return value};
  fs.openSync=()=>3;fs.closeSync=()=>{};fs.fstatSync=()=>value;
  fs.readSync=(_fd,data)=>{data.fill(65);return 32};
  assert.equal(loadKey('mock-only').length,32);
 }finally{Object.assign(fs,original)}
});

test('fixed vector and tamper rejection',()=>{let key=Buffer.from([...Array(32).keys()]),codec=new Codec(key,1200,0),peer=new Codec(key,1200,1),wire=codec.encode(1,7,42n,0,1,Buffer.from('cross-backend'));assert.equal(wire.toString('hex'),'53364e41010100000000000000000007000000000000002a000000010000000d42e3db28ec08001b41581ea8010d468a5f828ae126237ba96b6b3f53f6');assert.equal(peer.decode(wire).payload.toString(),'cross-backend');wire[wire.length-1]^=1;assert.throws(()=>peer.decode(wire),/authentication/)});
test('large messages and concurrent streams',()=>{let key=crypto.randomBytes(32),left=new ReliableAdapter('pony',key,0),right=new ReliableAdapter('pony',key,1);for(let stream=0;stream<8;stream++){let data=Buffer.alloc(32000,stream),queue=left.send(stream,data),messages=[];while(queue.length){let result=right.receive(queue.pop());messages.push(...result.messages);for(let ack of result.acks)left.receive(ack);queue.push(...left.outbound())}assert.equal(messages.length,1);assert.ok(messages[0][1].equals(data))}});
test('node companion carrier transfers an Idris message',async()=>{let key=crypto.randomBytes(32),reserve=dgram.createSocket('udp4');await new Promise(r=>reserve.bind(0,'127.0.0.1',r));let firstPort=reserve.address().port;reserve.close();let reserve2=dgram.createSocket('udp4');await new Promise(r=>reserve2.bind(0,'127.0.0.1',r));let secondPort=reserve2.address().port;reserve2.close();let first=new DatagramEndpoint('idris',key,{host:'127.0.0.1',port:firstPort},{host:'127.0.0.1',port:secondPort},0),second=new DatagramEndpoint('idris',key,{host:'127.0.0.1',port:secondPort},{host:'127.0.0.1',port:firstPort},1);await Promise.all([first.ready,second.ready]);let data=crypto.randomBytes(5000),received=new Promise((resolve,reject)=>{second.once('data',(stream,value)=>resolve([stream,value]));second.once('adapterError',reject)});first.send(4,data);let [stream,value]=await received;assert.equal(stream,4);assert.ok(value.equals(data));first.close();second.close()});
