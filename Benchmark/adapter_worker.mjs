// Direct-library component measurement. No native Core or network is implied.
import {performance} from 'node:perf_hooks';
import {ReliableAdapter} from '../Network-Adapter/shadow6_network.mjs';

const spec=JSON.parse(process.argv[2]);
const {core,payload_bytes:size,concurrency:workers,requests,loss_percent:loss,reorder}=spec;
if(!Number.isInteger(size)||size<1||size>1048576||!Number.isInteger(workers)||workers<1||workers>8||
   !Number.isInteger(requests)||requests<1||requests>4096||![0,1,3].includes(loss)||typeof reorder!=='boolean')throw Error('invalid benchmark bounds');
let now=0,transmissions=0,retransmissions=0,dropped=0,delivered=0;
const left=new ReliableAdapter(core,Buffer.alloc(32),0,[],{},()=>now);
const right=new ReliableAdapter(core,Buffer.alloc(32),1,[],{},()=>now);
const payload=Buffer.alloc(size,97),started=performance.now();
for(let round=0;round<requests;round++){
 let queue=[],seen=new Set(),ordinal=0,received=new Set();
 for(let stream=0;stream<workers;stream++)queue.push(...left.send(stream,payload));
 for(let turns=0;received.size<workers||left.buffered;turns++){
  if(turns>1000000)throw Error('bounded transfer did not finish');
  if(reorder)queue.reverse();
  for(const wire of queue){
   transmissions++;
   const id=wire.subarray(8,28).toString('hex');
   if(!seen.has(id)){
    seen.add(id);ordinal++;
    if(loss&&ordinal%Math.ceil(100/loss)===1){dropped++;continue}
   }else retransmissions++;
   const result=right.receive(wire);
   for(const ack of result.acks)left.receive(ack);
   for(const [stream,value] of result.messages){
    if(received.has(stream)||!value.equals(payload))throw Error('duplicate or corrupt application message');
    received.add(stream);delivered+=value.length;
   }
  }
  queue=left.outbound();
  if(!queue.length&&left.buffered){now+=1;queue=left.retransmit()}
 }
}
const duration=(performance.now()-started)/1000;
console.log(JSON.stringify({duration_seconds:duration,throughput_bps:delivered*8/duration,
 bytes_received:delivered,transmissions,retransmissions,dropped,success_rate:1}));
