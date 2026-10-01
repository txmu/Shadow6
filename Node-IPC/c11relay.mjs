/** Fixed-target companion for the existing C11Relay UDP wire path. */
import dgram from 'node:dgram';
import net from 'node:net';
import {FastRPCServer, RawIPCServer, canonical} from './shadow6_ipc.mjs';

export const RELAY_IPC_TYPES = Object.freeze({datagram: 17, metrics: 19, batch: 20});
const MAGIC = Buffer.from('S6CR');
export function encodeRelayDatagram(peer, payload) {
  if (!Number.isSafeInteger(peer) || peer < 0 || peer > 0xffffffff || !Buffer.isBuffer(payload) || payload.length > 65507) throw Error('invalid relay datagram');
  const out = Buffer.alloc(12 + payload.length); MAGIC.copy(out); out[4] = 1; out[5] = 17;
  out.writeUInt16BE(payload.length, 6); out.writeUInt32BE(peer, 8); payload.copy(out, 12); return out;
}
export function decodeRelayDatagram(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 12 || !bytes.subarray(0, 4).equals(MAGIC) || bytes[4] !== 1 || bytes[5] !== 17 || bytes.readUInt16BE(6) !== bytes.length - 12 || bytes.length > 65519) throw Error('invalid relay datagram');
  return {peer: bytes.readUInt32BE(8), payload: bytes.subarray(12)};
}
export function encodeRelayBatch(datagrams) {
  if (!Array.isArray(datagrams) || datagrams.length < 1 || datagrams.length > 256) throw Error('invalid relay batch count');
  const pieces = []; const header = Buffer.alloc(2); header.writeUInt16BE(datagrams.length); pieces.push(header);
  for (const item of datagrams) { const data = encodeRelayDatagram(item.peer, item.payload), prefix = Buffer.alloc(4); prefix.writeUInt32BE(data.length); pieces.push(prefix, data); }
  const bytes = Buffer.concat(pieces); if (bytes.length > 900000) throw Error('relay batch exceeds IPC budget'); return bytes;
}
export function decodeRelayBatch(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > 900000) throw Error('invalid relay batch');
  const count = bytes.readUInt16BE(), items = []; if (count < 1 || count > 256) throw Error('invalid relay batch count');
  let offset = 2;
  for (let i = 0; i < count; i++) {
    if (offset + 4 > bytes.length) throw Error('truncated relay batch');
    const size = bytes.readUInt32BE(offset); offset += 4;
    if (size < 12 || offset + size > bytes.length) throw Error('truncated relay batch');
    items.push(decodeRelayDatagram(bytes.subarray(offset, offset + size))); offset += size;
  }
  if (offset !== bytes.length) throw Error('trailing relay batch data'); return items;
}
const int = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
function base64(value) {
  if (typeof value !== 'string' || value.length > 87344 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw Error('invalid relay base64');
  const bytes = Buffer.from(value, 'base64'); if (bytes.toString('base64') !== value || bytes.length > 65507) throw Error('invalid relay payload'); return bytes;
}

export class C11RelayAdapter {
  constructor({host = '127.0.0.1', port, maxPeers = 64, maxQueue = 128, timeoutMs = 2000,
    idleMs = 30000, rate = 1000, burst = 256} = {}) {
    if (!['127.0.0.1','::1'].includes(host) || !int(port, 1, 65535) || !int(maxPeers, 1, 4096) || !int(maxQueue, 1, 4096) ||
        !int(timeoutMs, 10, 300000) || !int(idleMs, 10, 3600000) || !int(rate, 1, 1000000) || !int(burst, 1, 65536)) throw Error('invalid fixed relay target or limits');
    Object.assign(this, {host, port, maxPeers, maxQueue, timeoutMs, idleMs, rate, burst});
    this.peers = new Map(); this.inflight = 0; this.closed = false;
    this.metrics = {requests: 0, replies: 0, bytes_in: 0, bytes_out: 0, rejected: 0, timeouts: 0};
    this.sweep = setInterval(() => { const now = performance.now(); for (const [peer, state] of this.peers) if (!state.pending && now - state.last > idleMs) this.remove(peer, state); }, Math.max(10, Math.min(idleMs, 1000)));
    this.sweep.unref();
  }
  remove(peer, state) { if (this.peers.get(peer) === state) this.peers.delete(peer); if (state.socket) { state.socket.close(); state.socket = null; } }
  status() { return {schema: 'shadow6.c11relay-ipc-status.v1', peers: this.peers.size, inflight: this.inflight, ...this.metrics,
    limits: {max_peers: this.maxPeers, max_queue: this.maxQueue, max_datagram: 65507, max_batch: 256, rate: this.rate, burst: this.burst}}; }
  async exchange(peer, payload, {signal} = {}) {
    if (this.closed || !int(peer, 0, this.maxPeers - 1) || !Buffer.isBuffer(payload) || payload.length > 65507 || this.inflight >= this.maxQueue || signal?.aborted) { this.metrics.rejected++; throw Error('relay request rejected'); }
    let state = this.peers.get(peer);
    if (!state) {
      const socket = dgram.createSocket(net.isIP(this.host) === 6 ? 'udp6' : 'udp4');
      state = {socket, pending: null, tokens: this.burst, last: performance.now(), ready: null}; this.peers.set(peer, state);
      socket.on('error', error => { if (state.pending) state.pending.finish(error); this.remove(peer, state); });
      socket.on('message', bytes => { if (state.pending) state.pending.finish(null, bytes); });
      state.ready = new Promise((resolve, reject) => { socket.once('error', reject); socket.connect(this.port, this.host, () => { socket.off('error', reject); resolve(); }); });
    }
    const now = performance.now(); state.tokens = Math.min(this.burst, state.tokens + (now - state.last) * this.rate / 1000); state.last = now;
    if (state.pending || state.tokens < 1) { this.metrics.rejected++; throw Error('relay peer busy or rate limited'); }
    state.tokens--; this.inflight++; this.metrics.requests++; this.metrics.bytes_in += payload.length;
    return new Promise((resolve, reject) => {
      const abort = () => finish(new Error('relay operation cancelled'));
      const timer = setTimeout(() => { this.metrics.timeouts++; finish(new Error('relay operation timed out')); }, this.timeoutMs);
      let completed = false;
      const finish = (error, bytes) => {
        if (completed) return; completed = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); state.pending = null; this.inflight--; state.last = performance.now();
        if (error) { this.remove(peer, state); reject(error); }
        else { this.metrics.replies++; this.metrics.bytes_out += bytes.length; resolve(bytes); }
      };
      state.pending = {finish}; signal?.addEventListener('abort', abort, {once: true});
      state.ready.then(() => { if (!completed && state.socket) state.socket.send(payload, error => { if (error) finish(error); }); }, finish);
    });
  }
  async batch(items, context = {}) {
    if (!Array.isArray(items) || items.length < 1 || items.length > 256) throw Error('invalid relay batch');
    encodeRelayBatch(items);
    if (items.some(item => !int(item.peer, 0, this.maxPeers - 1))) throw Error('invalid batch peer');
    // FIFO for repeated peers, concurrency across different peers.
    const groups = new Map(), results = new Array(items.length);
    items.forEach((item, i) => { if (!groups.has(item.peer)) groups.set(item.peer, []); groups.get(item.peer).push([i, item]); });
    await Promise.all([...groups.values()].map(async group => { for (const [i, item] of group) results[i] = {peer: item.peer, payload: await this.exchange(item.peer, item.payload, context)}; }));
    return results;
  }
  async rpc(method, params, context = {}) {
    if (!params || Array.isArray(params) || typeof params !== 'object') throw Error('invalid relay params');
    if (method === 'c11relay.status' || method === 'c11relay.capabilities') {
      if (Object.keys(params).length) throw Error('unexpected relay parameters');
      return method.endsWith('status') ? this.status() : {schema: 'shadow6.c11relay-ipc.v1', types: RELAY_IPC_TYPES, methods: ['c11relay.status','c11relay.capabilities','c11relay.exchange','c11relay.batch'], ...this.status().limits};
    }
    if (method === 'c11relay.exchange') {
      if (Object.keys(params).sort().join(',') !== 'payload_base64,peer') throw Error('invalid exchange params');
      return {peer: params.peer, payload_base64: (await this.exchange(params.peer, base64(params.payload_base64), context)).toString('base64')};
    }
    if (method === 'c11relay.batch') {
      if (Object.keys(params).join(',') !== 'datagrams' || !Array.isArray(params.datagrams)) throw Error('invalid batch params');
      const items = params.datagrams.map(v => { if (!v || Object.keys(v).sort().join(',') !== 'payload_base64,peer') throw Error('invalid batch item'); return {peer: v.peer, payload: base64(v.payload_base64)}; });
      // Validate the entire batch budget before sending any packet.
      encodeRelayBatch(items);
      return {datagrams: (await this.batch(items, context)).map(v => ({peer: v.peer, payload_base64: v.payload.toString('base64')}))};
    }
    throw Error('unknown relay method');
  }
  async raw(type, payload, context = {}) {
    if (type === RELAY_IPC_TYPES.metrics) { if (payload.length) throw Error('unexpected metrics payload'); return canonical(this.status()); }
    if (type === RELAY_IPC_TYPES.datagram) { const v = decodeRelayDatagram(payload); return encodeRelayDatagram(v.peer, await this.exchange(v.peer, v.payload, context)); }
    if (type === RELAY_IPC_TYPES.batch) return encodeRelayBatch(await this.batch(decodeRelayBatch(payload), context));
    throw Error('unknown relay type');
  }
  close() { this.closed = true; clearInterval(this.sweep); for (const [peer, state] of this.peers) { state.pending?.finish(new Error('relay adapter closed')); this.remove(peer, state); } }
}

export class C11RelayRawIPCBridge {
  constructor(options) {
    this.adapter = options.adapter ?? new C11RelayAdapter(options);
    this.server = new RawIPCServer({...options, handler: (type, payload, context) => this.adapter.raw(type, payload, context)});
  }
  listen() { return this.server.listen(); }
  async close() { await this.server.close(); this.adapter.close(); }
}
export function relayFastRPC(options, adapter) { return new FastRPCServer({...options, handler: (method, params, context) => adapter.rpc(method, params, context)}); }
