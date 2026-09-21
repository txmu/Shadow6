// Same bounded local library-driver contract as companion_worker.py.
// Only the existing S6NA/1 records are sent through native Core transports.
import fs from 'node:fs';
import {ReliableAdapter, loadKey} from '../Network-Adapter/shadow6_network.mjs';
const [core, keyPath, side] = process.argv.slice(2);
const adapter = new ReliableAdapter(core, loadKey(keyPath), Number(side));
let pending = Buffer.alloc(0), count = 0;
for await (const chunk of process.stdin) {
  pending = Buffer.concat([pending, chunk]);
  if (pending.length > 16384) throw Error('oversized library request');
  let end;
  while ((end = pending.indexOf(10)) >= 0) {
    if (++count > 1000000) throw Error('library operation limit');
    const request = JSON.parse(pending.subarray(0, end).toString('utf8'));
    pending = pending.subarray(end + 1);
    if (Object.keys(request).sort().join(',') !== 'data,op' ||
        typeof request.data !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(request.data)) throw Error('invalid request');
    const raw = Buffer.from(request.data, 'hex');
    if (raw.length > 4096) throw Error('oversized library input');
    let frames, messages = [];
    if (request.op === 'send') frames = adapter.send(0, raw);
    else if (request.op === 'receive') {
      const result = adapter.receive(raw);
      if (result.events.length) throw Error('unexpected extension');
      frames = result.acks.concat(adapter.outbound()); messages = result.messages;
    } else if (request.op === 'tick' && !raw.length) frames = adapter.retransmit();
    else throw Error('unknown library operation');
    fs.writeSync(1, JSON.stringify({frames: frames.map(f => f.toString('hex')),
      messages: messages.map(([stream, data]) => data.toString('hex'))}) + '\n');
  }
}
if (pending.length) throw Error('truncated request');
