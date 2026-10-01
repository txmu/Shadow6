/** Dependency-free, bounded local component transports. */
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

export const LIMITS = Object.freeze({frame: 1048576, rpcFrame: 1048576,
  clockSkewSeconds: 60, replayEntries: 4096, connections: 64, timeoutMs: 10000});
const MAGIC = Buffer.from('S6RI'), HEADER = 24, TAG = 16;
const fail = message => { throw new TypeError(message); };
const integer = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const id = v => typeof v === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(v);
const exact = (v, keys) => object(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const nowSeconds = () => Math.floor(Date.now() / 1000);
const same = (a, b) => ['dev','ino','size','mode','uid','nlink','mtimeNs','ctimeNs'].every(k => a[k] === b[k]);

export function readPrivate(file, max = LIMITS.frame) {
  if (typeof process.geteuid !== 'function') fail('private file checks require POSIX; use in-memory keys on this platform');
  const before = fs.lstatSync(file, {bigint: true});
  if (!before.isFile() || before.uid !== BigInt(process.geteuid()) || before.nlink !== 1n ||
      (before.mode & 0o777n) !== 0o600n || before.size > BigInt(max)) fail('expected owned mode-0600 regular file');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd, {bigint: true});
    if (!same(before, opened)) fail('private file changed while opening');
    const data = Buffer.alloc(Number(opened.size)); let count = 0;
    while (count < data.length) { const n = fs.readSync(fd, data, count, data.length - count, null); if (!n) break; count += n; }
    if (count !== data.length || !same(opened, fs.fstatSync(fd, {bigint: true}))) fail('private file changed while reading');
    return data;
  } finally { fs.closeSync(fd); }
}
export function loadKey(file) { return key32(readPrivate(file, 32)); }
function key32(key) { if (!Buffer.isBuffer(key) || key.length !== 32) fail('IPC key must be 32 bytes'); return Buffer.from(key); }

export function canonical(value) {
  let nodes = 0;
  function walk(v, depth = 0) {
    if (depth > 16 || ++nodes > 32768) fail('IPC JSON complexity limit exceeded');
    if (v === null || typeof v === 'boolean') return v;
    if (typeof v === 'number') { if (!Number.isSafeInteger(v) || Object.is(v, -0)) fail('IPC JSON requires safe integers'); return v; }
    if (typeof v === 'string') {
      if (v.length > 262144 || !v.isWellFormed() || v.normalize('NFC') !== v || v.includes('\0')) fail('invalid IPC string');
      return v;
    }
    if (Array.isArray(v)) { if (v.length > 4096) fail('IPC array limit exceeded'); return v.map(x => walk(x, depth + 1)); }
    if (object(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v))) {
      const keys = Object.keys(v).sort(); if (keys.length > 1024) fail('IPC object limit exceeded');
      return Object.fromEntries(keys.map(k => [walk(k, depth + 1), walk(v[k], depth + 1)]));
    }
    fail('nonportable IPC JSON value');
  }
  return Buffer.from(JSON.stringify(walk(value)).replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')));
}
export function parseCanonical(bytes, max = LIMITS.rpcFrame) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > max) fail('invalid IPC JSON size');
  const value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
  if (!bytes.equals(canonical(value))) fail('noncanonical IPC JSON (duplicates or ambiguous values)');
  return value;
}

export class ReplayCache {
  constructor({capacity = LIMITS.replayEntries, clock = nowSeconds} = {}) {
    if (!integer(capacity, 1, 65536)) fail('invalid replay capacity');
    this.capacity = capacity; this.clock = clock; this.entries = new Map();
  }
  reserve(nonce, expires) {
    const now = this.clock();
    for (const [key, expiry] of this.entries) if (expiry < now) this.entries.delete(key);
    if (this.entries.has(nonce)) fail('IPC replay detected');
    // Never evict a still-valid nonce to make room for a new one.
    if (this.entries.size >= this.capacity) fail('IPC replay capacity reached');
    this.entries.set(nonce, expires);
  }
}
function derived(key, name) { return crypto.createHmac('sha256', key32(key)).update('shadow6-ipc-v1:' + name).digest(); }
export function signRpc(message, key, direction = 'request') {
  const unsigned = {...message}; delete unsigned.mac;
  return crypto.createHmac('sha256', derived(key, 'fastrpc:' + direction)).update(canonical(unsigned)).digest('hex');
}
export function makeRpc(method, params, key, requestId = crypto.randomUUID()) {
  if (!id(method) || !id(requestId) || !object(params)) fail('invalid FastRPC call');
  const request = {jsonrpc: '2.0', id: requestId, method, params, issued_at: nowSeconds(), nonce: crypto.randomBytes(16).toString('hex')};
  request.mac = signRpc(request, key); return request;
}
function authenticate(message, key, direction) {
  if (message.jsonrpc !== '2.0' || !id(message.id) || !integer(message.issued_at, nowSeconds() - 60, nowSeconds() + 60) ||
      !/^[0-9a-f]{32}$/.test(message.nonce ?? '') || !/^[0-9a-f]{64}$/.test(message.mac ?? '')) fail('invalid IPC authentication');
  if (!crypto.timingSafeEqual(Buffer.from(signRpc(message, key, direction)), Buffer.from(message.mac))) fail('IPC authentication failed');
}
export function verifyRpc(message, key, replay) {
  if (!exact(message, ['jsonrpc','id','method','params','issued_at','nonce','mac']) || !id(message.method) || !object(message.params)) fail('invalid FastRPC request');
  authenticate(message, key, 'request'); replay.reserve(message.nonce, message.issued_at + 60);
}
function rpcReply(request, key, result, error) {
  const reply = {jsonrpc: '2.0', id: request.id, request_nonce: request.nonce, issued_at: nowSeconds(), nonce: crypto.randomBytes(16).toString('hex')};
  if (error) reply.error = {code: 'request-rejected', message: 'Request rejected'}; else reply.result = result;
  reply.mac = signRpc(reply, key, 'response'); return reply;
}

export function encodeRaw(payload, key, type = 1, issuedAt = nowSeconds(), direction = 'request') {
  if (!Buffer.isBuffer(payload) || payload.length > LIMITS.frame - HEADER - TAG - 8 || !integer(type, 1, 255) || !integer(issuedAt, 0, Number.MAX_SAFE_INTEGER)) fail('invalid RawIPC payload');
  const nonce = crypto.randomBytes(12), header = Buffer.alloc(HEADER), plain = Buffer.alloc(8 + payload.length);
  MAGIC.copy(header); header[4] = 1; header[5] = type; header.writeUInt32BE(plain.length + TAG, 8); nonce.copy(header, 12);
  plain.writeBigUInt64BE(BigInt(issuedAt)); payload.copy(plain, 8);
  const cipher = crypto.createCipheriv('aes-256-gcm', derived(key, 'rawipc:' + direction), nonce); cipher.setAAD(header);
  return Buffer.concat([header, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}
export function decodeRaw(bytes, key, now = nowSeconds(), direction = 'request') {
  if (!Buffer.isBuffer(bytes) || bytes.length < HEADER + TAG + 8 || bytes.length > LIMITS.frame) fail('invalid RawIPC frame');
  const header = bytes.subarray(0, HEADER);
  if (!header.subarray(0, 4).equals(MAGIC) || header[4] !== 1 || header[5] === 0 || header.readUInt16BE(6) !== 0 || header.readUInt32BE(8) !== bytes.length - HEADER) fail('invalid RawIPC header');
  const decipher = crypto.createDecipheriv('aes-256-gcm', derived(key, 'rawipc:' + direction), header.subarray(12));
  decipher.setAAD(header); decipher.setAuthTag(bytes.subarray(-TAG));
  let plain; try { plain = Buffer.concat([decipher.update(bytes.subarray(HEADER, -TAG)), decipher.final()]); } catch { fail('RawIPC authentication failed'); }
  const issued = Number(plain.readBigUInt64BE());
  if (!integer(issued, now - 60, now + 60)) fail('RawIPC timestamp outside clock window');
  return {type: header[5], payload: plain.subarray(8), nonce: header.subarray(12).toString('hex'), issued_at: issued};
}

export function frame(bytes, max = LIMITS.frame) {
  if (!Buffer.isBuffer(bytes) || !integer(bytes.length, 1, max)) fail('invalid IPC frame length');
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length); return Buffer.concat([prefix, bytes]);
}
// One bounded request per connection: no ambiguous pipelining or unbounded async queues.
function readFrame(socket, max) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0), size;
    const finish = (error, bytes) => { socket.off('data', data); socket.off('error', errorEvent); socket.off('end', end); socket.off('close', end); error ? reject(error) : resolve(bytes); };
    const errorEvent = error => finish(error), end = () => finish(new Error('truncated IPC frame'));
    const data = chunk => {
      if (buffer.length + chunk.length > max + 4) { finish(new Error('IPC frame exceeds limit')); return; }
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= 4) size = buffer.readUInt32BE();
      if (size !== undefined && (!integer(size, 1, max) || buffer.length > size + 4)) { finish(new Error('invalid IPC frame size')); return; }
      if (size !== undefined && buffer.length === size + 4) { socket.pause(); finish(null, buffer.subarray(4)); }
    };
    socket.on('data', data); socket.once('error', errorEvent); socket.once('end', end); socket.once('close', end);
  });
}
function endpoint(options, server = false) {
  if (options.socketPath) {
    const name = options.socketPath;
    if (process.platform === 'win32' || !path.isAbsolute(name) || name.length > 103) fail('use a bounded absolute POSIX socket path');
    const parent = path.dirname(name), info = fs.lstatSync(parent);
    if (!info.isDirectory() || info.uid !== process.geteuid() || (info.mode & 0o077) !== 0 || fs.realpathSync(parent) !== parent) fail('IPC socket needs an owned private directory without symlinks');
    if (server && fs.existsSync(name)) fail('socket path already exists; refusing to unlink');
    if (!server) { const st = fs.lstatSync(name); if (!st.isSocket() || st.uid !== process.geteuid() || (st.mode & 0o077) !== 0) fail('unsafe IPC socket'); }
    return {path: name};
  }
  if (!['127.0.0.1','::1'].includes(options.host ?? '127.0.0.1') || !integer(options.port, server ? 0 : 1, 65535)) fail('IPC TCP requires a numeric loopback endpoint');
  return {host: options.host ?? '127.0.0.1', port: options.port};
}
function timeout(options) { const value = options.timeoutMs ?? LIMITS.timeoutMs; if (!integer(value, 10, 300000)) fail('invalid IPC timeout'); return value; }
class Server {
  constructor(options, max, exchange) {
    key32(options.key); if (typeof options.handler !== 'function') fail('IPC handler required');
    this.options = options; this.max = max; this.exchange = exchange; this.sockets = new Set(); this.inflight = 0;
    this.capacity = options.maxConnections ?? LIMITS.connections;
    if (!integer(this.capacity, 1, 4096)) fail('invalid connection limit');
    this.timeoutMs = timeout(options); this.address = endpoint(options, true);
    this.server = net.createServer(socket => this.accept(socket));
    this.server.on('error', () => {});
  }
  async accept(socket) {
    socket.on('error', () => {});
    if (this.inflight >= this.capacity || this.sockets.size >= this.capacity) { socket.destroy(); return; }
    this.inflight++; this.sockets.add(socket);
    const abort = new AbortController(); const timer = setTimeout(() => { abort.abort(); socket.destroy(new Error('IPC deadline exceeded')); }, this.timeoutMs);
    socket.once('close', () => { this.sockets.delete(socket); abort.abort(); });
    try { const body = await readFrame(socket, this.max); const reply = await this.exchange(body, {signal: abort.signal}); if (!socket.destroyed) socket.end(frame(reply, this.max)); }
    catch { socket.destroy(); }
    finally { clearTimeout(timer); this.inflight--; }
  }
  async listen() {
    await new Promise((resolve, reject) => { const onError = error => reject(error); this.server.once('error', onError); this.server.listen(this.address, () => { this.server.off('error', onError); resolve(); }); });
    if (this.address.path) { fs.chmodSync(this.address.path, 0o600); this.socketIdentity = fs.lstatSync(this.address.path); }
    return this.server.address();
  }
  async close() {
    for (const socket of this.sockets) socket.destroy();
    if (this.server.listening) await new Promise(resolve => this.server.close(resolve));
    // net.Server removes its own Unix socket. Never delete a replacement file.
  }
}
async function call(options, bytes, max) {
  const address = endpoint(options), socket = net.createConnection(address);
  socket.on('error', () => {});
  const timer = setTimeout(() => socket.destroy(new Error('IPC deadline exceeded')), timeout(options));
  try {
    const reply = readFrame(socket, max);
    socket.once('connect', () => socket.write(frame(bytes, max)));
    return await reply;
  } finally { clearTimeout(timer); socket.destroy(); }
}

export class FastRPCServer extends Server {
  constructor(options) {
    const key = key32(options.key), replay = new ReplayCache(options.replay);
    super(options, LIMITS.rpcFrame, async (body, context) => {
      const request = parseCanonical(body); verifyRpc(request, key, replay);
      let reply;
      try { reply = rpcReply(request, key, await options.handler(request.method, request.params, {...request, ...context})); }
      catch { reply = rpcReply(request, key, null, true); }
      return canonical(reply);
    });
    this.replay = replay;
  }
}
export class FastRPCClient {
  constructor(options) { this.options = {...options, key: key32(options.key)}; timeout(options); }
  async call(method, params = {}, requestId = crypto.randomUUID()) {
    const request = makeRpc(method, params, this.options.key, requestId);
    const reply = parseCanonical(await call(this.options, canonical(request), LIMITS.rpcFrame));
    if (!exact(reply, ['jsonrpc','id','request_nonce','issued_at','nonce','mac', Object.hasOwn(reply, 'result') ? 'result' : 'error'])) fail('invalid FastRPC response');
    authenticate(reply, this.options.key, 'response');
    if (reply.id !== request.id || reply.request_nonce !== request.nonce) fail('RPC response binding mismatch');
    return reply;
  }
}
export class RawIPCServer extends Server {
  constructor(options) {
    const key = key32(options.key), replay = new ReplayCache(options.replay);
    super(options, LIMITS.frame, async (body, context) => {
      const message = decodeRaw(body, key); replay.reserve(message.nonce, message.issued_at + 60);
      const result = await options.handler(message.type, message.payload, context);
      if (!Buffer.isBuffer(result)) fail('RawIPC handler must return a Buffer');
      const binding = crypto.createHash('sha256').update(body).digest();
      return encodeRaw(Buffer.concat([binding, result]), key, message.type, nowSeconds(), 'response');
    });
    this.replay = replay;
  }
}
export class RawIPCClient {
  constructor(options) { this.options = {...options, key: key32(options.key)}; timeout(options); }
  async call(payload, type = 1) {
    const request = encodeRaw(payload, this.options.key, type);
    const response = decodeRaw(await call(this.options, request, LIMITS.frame), this.options.key, nowSeconds(), 'response');
    const binding = crypto.createHash('sha256').update(request).digest();
    if (response.type !== type || response.payload.length < 32 || !crypto.timingSafeEqual(response.payload.subarray(0, 32), binding)) fail('RawIPC response binding mismatch');
    return response.payload.subarray(32);
  }
}
