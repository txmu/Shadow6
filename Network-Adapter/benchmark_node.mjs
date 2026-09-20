import crypto from 'node:crypto';
import {ReliableAdapter} from './shadow6_network.mjs';
let rows=[];
for(let payload of [4096,65536,1048576])for(let requested of [1,16,64]){let streams=Math.min(requested,Math.floor(16*1024*1024/payload)),key=crypto.randomBytes(32),left=new ReliableAdapter('idris',key,0),right=new ReliableAdapter('idris',key,1),queues=[],received=0,start=performance.now();for(let s=0;s<streams;s++)queues.push(...left.send(s,crypto.randomBytes(payload)));while(queues.length){let r=right.receive(queues.pop());received+=r.messages.reduce((n,x)=>n+x[1].length,0);for(let ack of r.acks)left.receive(ack);queues.push(...left.outbound())}let seconds=(performance.now()-start)/1000;rows.push({backend:'node',payload_bytes:payload,requested_streams:requested,active_streams:streams,bytes:received,seconds,throughput_bps:received*8/seconds})}
console.log(JSON.stringify({schema:'shadow6.network-adapter-benchmark.v1',rows}));
