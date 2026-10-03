import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import dgram from 'node:dgram';
import {spawn, execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {FastRPCClient, FastRPCServer, RawIPCClient, RawIPCServer, ReplayCache,
  makeRpc, verifyRpc, signRpc, encodeRaw, decodeRaw, canonical, parseCanonical, frame, loadKey, LIMITS} from './shadow6_ipc.mjs';
import {C11RelayAdapter, C11RelayRawIPCBridge, relayFastRPC, RELAY_IPC_TYPES,
  encodeRelayDatagram, decodeRelayDatagram, encodeRelayBatch, decodeRelayBatch} from './c11relay.mjs';
import {controlHandler, catalog, serve} from './cli.mjs';

const run = promisify(execFile), posix = process.platform !== 'win32';
function fixture(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'shadow6-ipc-')));
  if (posix) fs.chmodSync(dir, 0o700);
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  return {dir, key: crypto.randomBytes(32), socketPath: path.join(dir, 'ipc.sock')};
}
async function server(t, Type, handler, options = {}) {
  const key = crypto.randomBytes(32), s = new Type({key, host: '127.0.0.1', port: 0, handler, ...options});
  t.after(() => s.close()); const address = await s.listen();
  return {s, key, host: '127.0.0.1', port: address.port};
}
async function wire(options, bytes, fragmented = false) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({host: options.host, port: options.port}), chunks = [];
    const timer = setTimeout(() => socket.destroy(new Error('test timeout')), 1000);
    socket.once('error', reject);
    socket.on('data', bytes => chunks.push(bytes));
    socket.on('close', () => { clearTimeout(timer); resolve(Buffer.concat(chunks)); });
    socket.once('connect', () => {
      if (fragmented) { socket.write(bytes.subarray(0, 2)); setTimeout(() => socket.write(bytes.subarray(2)), 5); }
      else socket.write(bytes);
    });
  });
}
async function echo(t, silent = false) {
  const udp = dgram.createSocket('udp4'); await new Promise(resolve => udp.bind(0, '127.0.0.1', resolve));
  t.after(() => udp.close());
  if (!silent) udp.on('message', (bytes, info) => udp.send(bytes, info.port, info.address));
  return udp.address().port;
}

test('portable canonical JSON matches Python ASCII encoding and rejects ambiguous inputs', () => {
  assert.equal(canonical({z: '中', a: 1}).toString(), '{"a":1,"z":"\\u4e2d"}');
  for (const value of [1.5, NaN, Infinity, -0, 9007199254740992, {bad: undefined}, '\ud800']) assert.throws(() => canonical(value));
  for (const raw of ['{"a":1,"a":2}', '{"b":1,"a":2}', '{"a":1.0}', '{"a":NaN}', '{"a":-0}', '{"a":1} ']) assert.throws(() => parseCanonical(Buffer.from(raw)));
  assert.throws(() => canonical(new Array(4097).fill(1)));
  let deep = {}; for (let n = 0; n < 18; n++) deep = {deep}; assert.throws(() => canonical(deep));
});
test('private keys reject symlinks, writable modes and hard links', {skip: !posix}, t => {
  const f = fixture(t), keyFile = path.join(f.dir, 'key'); fs.writeFileSync(keyFile, f.key, {mode: 0o600});
  assert.deepEqual(loadKey(keyFile), f.key);
  fs.chmodSync(keyFile, 0o644); assert.throws(() => loadKey(keyFile)); fs.chmodSync(keyFile, 0o600);
  const link = path.join(f.dir, 'link'); fs.symlinkSync(keyFile, link); assert.throws(() => loadKey(link));
  fs.linkSync(keyFile, path.join(f.dir, 'hardlink')); assert.throws(() => loadKey(keyFile));
});
test('replay cache fails closed at capacity and expires only after validity window', () => {
  let now = 100; const cache = new ReplayCache({capacity: 1, clock: () => now});
  cache.reserve('a', 101); assert.throws(() => cache.reserve('a', 101), /replay/);
  assert.throws(() => cache.reserve('b', 102), /capacity/); now = 101; assert.throws(() => cache.reserve('b', 102));
  now = 102; cache.reserve('b', 103); assert.equal(cache.entries.size, 1);
});
test('FastRPC has direction separation, MAC tamper rejection and strict schemas', () => {
  const key = crypto.randomBytes(32), request = makeRpc('demo.add', {}, key, 'r1');
  assert.notEqual(signRpc(request, key), signRpc(request, key, 'response'));
  const cache = new ReplayCache(); verifyRpc(request, key, cache); assert.throws(() => verifyRpc(request, key, cache));
  assert.throws(() => verifyRpc({...request, id: 'tamper'}, key, new ReplayCache()));
  assert.throws(() => verifyRpc({...request, extra: true}, key, new ReplayCache()));
});
test('FastRPC real sockets support concurrent calls and generic authenticated errors', async t => {
  const o = await server(t, FastRPCServer, async (method, params) => { if (method === 'fail') throw Error('secret'); return params; });
  const client = new FastRPCClient(o);
  const responses = await Promise.all(Array.from({length: 20}, (_, i) => client.call('echo', {i})));
  assert.deepEqual(responses.map(r => r.result.i), Array.from({length: 20}, (_, i) => i));
  const rejected = await client.call('fail'); assert.equal(rejected.error.message, 'Request rejected'); assert.ok(!JSON.stringify(rejected).includes('secret'));
});
test('FastRPC accepts fragmented frames, rejects replay, wrong keys and duplicate JSON', async t => {
  let calls = 0; const o = await server(t, FastRPCServer, () => { calls++; return true; });
  const request = makeRpc('test', {}, o.key), bytes = frame(canonical(request));
  assert.ok((await wire(o, bytes, true)).length > 0); assert.equal(calls, 1);
  assert.equal((await wire(o, bytes)).length, 0); assert.equal(calls, 1);
  await assert.rejects(new FastRPCClient({...o, key: crypto.randomBytes(32)}).call('test'));
  assert.equal((await wire(o, frame(Buffer.from('{"a":1,"a":2}')))).length, 0);
  const size = Buffer.alloc(4); size.writeUInt32BE(LIMITS.frame + 1); assert.equal((await wire(o, size)).length, 0);
});
test('IPC socket creation refuses pre-existing files and public directories', {skip: !posix}, async t => {
  const f = fixture(t); fs.writeFileSync(f.socketPath, 'keep');
  assert.throws(() => new FastRPCServer({...f, handler: () => true})); assert.equal(fs.readFileSync(f.socketPath, 'utf8'), 'keep');
  fs.chmodSync(f.dir, 0o755); assert.throws(() => new RawIPCServer({...f, handler: () => Buffer.alloc(0)})); fs.chmodSync(f.dir, 0o700);
});
test('private Unix sockets have owner-only permissions and both protocols work', {skip: !posix}, async t => {
  const f = fixture(t), s = new FastRPCServer({...f, handler: () => true}); t.after(() => s.close()); await s.listen();
  assert.equal(fs.statSync(f.socketPath).mode & 0o777, 0o600);
  assert.equal((await new FastRPCClient(f).call('ping')).result, true);
});
test('non-loopback endpoints are rejected', () => {
  assert.throws(() => new FastRPCServer({key: crypto.randomBytes(32), host: '0.0.0.0', port: 1, handler: () => true}));
  assert.throws(() => new RawIPCServer({key: crypto.randomBytes(32), host: '192.0.2.1', port: 1, handler: () => Buffer.alloc(0)}));
});
test('server/client deadlines and truncated frames settle without leaking connections', async t => {
  const o = await server(t, FastRPCServer, async () => { await new Promise(r => setTimeout(r, 100)); return true; }, {timeoutMs: 30});
  await assert.rejects(new FastRPCClient({...o, timeoutMs: 80}).call('slow'));
  const s = net.createServer(() => {}); t.after(() => { s.closeAllConnections?.(); s.close(); });
  const sockets = new Set(); s.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  t.after(() => { for (const socket of sockets) socket.destroy(); });
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  await assert.rejects(new FastRPCClient({key: o.key, host: '127.0.0.1', port: s.address().port, timeoutMs: 30}).call('deadline'), /deadline/);
});
test('RawIPC AES-GCM tampering, reflection, timestamp and size checks', () => {
  const key = crypto.randomBytes(32), bytes = encodeRaw(Buffer.from('payload'), key);
  assert.equal(decodeRaw(bytes, key).payload.toString(), 'payload');
  assert.throws(() => decodeRaw(bytes, key, Math.floor(Date.now() / 1000), 'response'));
  const corrupt = Buffer.from(bytes); corrupt[corrupt.length - 1] ^= 1; assert.throws(() => decodeRaw(corrupt, key));
  assert.throws(() => decodeRaw(encodeRaw(Buffer.alloc(0), key, 1, 1), key));
  assert.throws(() => encodeRaw(Buffer.alloc(LIMITS.frame), key));
  assert.throws(() => encodeRaw(Buffer.alloc(0), key, 256));
});
test('RawIPC sockets transfer binary/empty data and reject wire replay', async t => {
  let calls = 0; const o = await server(t, RawIPCServer, (type, payload) => { calls++; return payload; });
  const client = new RawIPCClient(o), data = crypto.randomBytes(100000);
  assert.deepEqual(await client.call(data, 17), data); assert.equal((await client.call(Buffer.alloc(0))).length, 0);
  const bytes = frame(encodeRaw(Buffer.from('once'), o.key)); assert.ok((await wire(o, bytes)).length);
  const prior = calls; assert.equal((await wire(o, bytes)).length, 0); assert.equal(calls, prior);
});
test('relay datagram and batch framing reject truncation and oversized counts', () => {
  const items = [{peer: 0, payload: Buffer.alloc(0)}, {peer: 7, payload: Buffer.from('bin\0')}];
  assert.deepEqual(decodeRelayBatch(encodeRelayBatch(items)), items);
  assert.throws(() => decodeRelayDatagram(Buffer.alloc(11)));
  assert.throws(() => encodeRelayDatagram(1, Buffer.alloc(65508)));
  assert.throws(() => encodeRelayBatch(new Array(257).fill(items[0])));
  assert.throws(() => decodeRelayBatch(encodeRelayBatch(items).subarray(0, -1)));
});
test('C11Relay FastRPC/RawIPC share peer-isolated UDP channels, batches and metrics', async t => {
  const port = await echo(t), adapter = new C11RelayAdapter({port, maxPeers: 8, maxQueue: 8}); t.after(() => adapter.close());
  const fast = await server(t, FastRPCServer, (m, p, c) => adapter.rpc(m, p, c));
  const raw = await server(t, RawIPCServer, (type, payload, context) => adapter.raw(type, payload, context));
  const rpc = new FastRPCClient(fast), binary = new RawIPCClient(raw);
  const values = Array.from({length: 8}, (_, peer) => ({peer, payload: crypto.randomBytes(100)}));
  const result = await binary.call(encodeRelayBatch(values), RELAY_IPC_TYPES.batch); assert.deepEqual(decodeRelayBatch(result), values);
  const repeated = [...values.slice(0, 2), ...values.slice(0, 2)];
  const response = await rpc.call('c11relay.batch', {datagrams: repeated.map(v => ({peer: v.peer, payload_base64: v.payload.toString('base64')}))});
  assert.equal(response.result.datagrams.length, 4);
  const status = (await rpc.call('c11relay.status')).result; assert.equal(status.replies, 12); assert.equal(status.inflight, 0);
  const rawStatus = parseCanonical(await binary.call(Buffer.alloc(0), RELAY_IPC_TYPES.metrics)); assert.equal(rawStatus.replies, 12);
  await assert.rejects(binary.call(encodeRelayDatagram(9, Buffer.from('bad')), RELAY_IPC_TYPES.datagram));
  assert.ok((await rpc.call('c11relay.shell', {})).error);
});

test('component adapters expose read-only bounded contracts and live capsule observations', {skip: !posix}, async t => {
  const names = ['virtual-broker', 'detector', 's6na', 'app-flow', 'capsule-observer', 'plugins', 'slots', 'gate', 'abi'];
  assert.deepEqual((await import('./component_adapters.mjs')).IPC_COMPONENTS, names);
  for (const component of names) {
    const o = fixture(t), key = o.key;
    const server = new FastRPCServer({key, socketPath: o.socketPath, handler: async (method, params) => {
      const adapters = await import('./component_adapters.mjs');
      if (component === 'capsule-observer') {
        const handler = adapters.capsuleObserverHandler(async name => {
          assert.equal(name, 'capsule.list');
          return {schema: 'shadow6.capability-capsule-catalog.v1', capsules: [{core: 'hare', mode: 'seqpacket-fd', state: 'paused', pids: [123], expires_in: 30}]};
        });
        return handler(method, params);
      }
      return adapters.componentHandler(component)(method, params);
    }});
    t.after(() => server.close()); await server.listen();
    const client = new FastRPCClient({key, socketPath: o.socketPath});
    const capabilities = (await client.call(`${component}.capabilities`)).result;
    assert.equal(capabilities.read_only, true);
    assert.ok((await client.call(`${component}.status`)).result.state === 'available');
    for (const method of capabilities.methods.filter(name => !name.endsWith('.capabilities') && !name.endsWith('.status') && !name.endsWith('.pause') && !name.endsWith('.resume'))) {
      const result = (await client.call(method)).result;
      assert.equal(result.read_only, true);
      assert.ok(result.schema.startsWith('shadow6.'));
    }
    assert.ok((await client.call(`${component}.reload`, {})).error);
    if (component === 'app-flow' || component === 'capsule-observer') {
      assert.ok((await client.call(`${component}.pause`, {})).error);
    }
    if (component === 'capsule-observer') {
      const summary = (await client.call('capsule-observer.sessions.summary')).result;
      assert.equal(summary.items[0].state, 'paused');
      assert.equal((await client.call('capsule-observer.metrics')).result.counters.paused, 1);
    }
    await server.close();
  }
});
test('relay limits reject busy peers, invalid batch before send and clean expired mappings', async t => {
  const port = await echo(t, true), adapter = new C11RelayAdapter({port, maxPeers: 2, maxQueue: 1, timeoutMs: 30, idleMs: 20}); t.after(() => adapter.close());
  const pending = adapter.exchange(0, Buffer.from('slow'));
  await assert.rejects(adapter.exchange(0, Buffer.from('busy')));
  await assert.rejects(adapter.exchange(1, Buffer.from('full')));
  await assert.rejects(pending); assert.equal(adapter.status().inflight, 0); assert.equal(adapter.peers.size, 0);
  const before = adapter.metrics.requests;
  await assert.rejects(adapter.batch([{peer: 0, payload: Buffer.from('x')}, {peer: 3, payload: Buffer.from('bad')}]));
  assert.equal(adapter.metrics.requests, before);
});
test('relay per-peer rate and burst enforcement', async t => {
  const port = await echo(t), adapter = new C11RelayAdapter({port, burst: 1, rate: 1}); t.after(() => adapter.close());
  await adapter.exchange(0, Buffer.from('a')); await assert.rejects(adapter.exchange(0, Buffer.from('b')));
  assert.equal(adapter.metrics.rejected, 1);
});
test('CLI catalog, keygen, actual server/client subprocesses and unified route', {skip: !posix}, async t => {
  const f = fixture(t), keyFile = path.join(f.dir, 'key');
  const cli = path.resolve('Node-IPC/cli.mjs');
  await run(process.execPath, [cli, 'keygen', '--output', keyFile]); assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
  await assert.rejects(run(process.execPath, [cli, 'keygen', '--output', keyFile]));
  const port = await echo(t), configFile = path.join(f.dir, 'config.json');
  fs.writeFileSync(configFile, JSON.stringify({schema: 'shadow6.node-ipc-config.v1', component: 'c11relay', key_file: keyFile,
    fastrpc: {socketPath: f.socketPath}, rawipc: {socketPath: path.join(f.dir, 'raw.sock')}, relay: {port}}), {mode: 0o600});
  const running = await serve(JSON.parse(fs.readFileSync(configFile))); t.after(() => running.close());
  const reply = await run(process.execPath, [cli, 'call', '--config', configFile, '--method', 'c11relay.status']); assert.equal(JSON.parse(reply.stdout).result.replies, 0);
  const raw = await run(process.execPath, [cli, 'raw-send', '--config', configFile, '--type', '19', '--hex', '']); assert.ok(JSON.parse(raw.stdout).payload_base64);
  assert.equal(catalog().npm, false);
});
test('Control Center via FastRPC and RawIPC uses existing dispatcher and mutation boundary', {skip: process.env.SHADOW6_IPC_CONTROL_TEST !== '1' || process.platform === 'win32'}, async t => {
  const handler = controlHandler({python: process.env.SHADOW6_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3')});
  const fast = await server(t, FastRPCServer, handler), raw = await server(t, RawIPCServer, async (type, bytes, context) => {
    const req = parseCanonical(bytes); return canonical(await handler(req.method, req.params, context));
  });
  const result = (await new FastRPCClient(fast).call('system.schema')).result; assert.ok(result.methods['ipc.raw']);
  assert.ok((await new FastRPCClient(fast).call('config.render', {})).error);
  const capsuleCatalog = (await new FastRPCClient(fast).call('capsule.list')).result;
  assert.equal(capsuleCatalog.schema, 'shadow6.capability-capsule-catalog.v1');
  assert.ok(Array.isArray(capsuleCatalog.capsules));
  assert.ok((await new FastRPCClient(fast).call('capsule.pause', {token: 'not-a-token'})).error);
  const bytes = await new RawIPCClient(raw).call(canonical({method: 'system.guide', params: {lang: 'en'}})); assert.equal(parseCanonical(bytes).lang, 'en');
});
test('real prebuilt C11Relay normal/high-speed through both IPC paths', {skip: !process.env.SHADOW6_RELAY_BINARY, timeout: 15000}, async t => {
  const port = await echo(t);
  for (const mode of ['normal','high-speed']) {
    const reserve = dgram.createSocket('udp4'); await new Promise(r => reserve.bind(0, '127.0.0.1', r)); const relayPort = reserve.address().port; await new Promise(r => reserve.close(r));
    const child = spawn(process.env.SHADOW6_RELAY_BINARY, ['--bind','127.0.0.1','--port',String(relayPort),'--dest',`127.0.0.1:${port}`,'--mode',mode,'--max-peers','32'], {stdio: 'ignore'});
    // Failed startup UDP probes retain native mappings until idle expiry.
    // Bound startup headroom separately from the 16 application peers.
    const adapter = new C11RelayAdapter({port: relayPort, maxPeers: 16, timeoutMs: 2000});
    try {
      for (let tries = 0; ; tries++) { try { await adapter.exchange(0, Buffer.from('ready')); break; } catch (error) { if (tries > 8) throw error; } }
      const fast = await server(t, FastRPCServer, (m, p, c) => adapter.rpc(m, p, c)), raw = await server(t, RawIPCServer, (type, bytes, c) => adapter.raw(type, bytes, c));
      const datagrams = Array.from({length: 16}, (_, peer) => ({peer, payload: crypto.randomBytes(1024)}));
      assert.deepEqual(decodeRelayBatch(await new RawIPCClient(raw).call(encodeRelayBatch(datagrams), 20)), datagrams);
      for (const item of datagrams) {
        const reply = await new FastRPCClient(fast).call('c11relay.exchange', {peer: item.peer, payload_base64: item.payload.toString('base64')});
        assert.equal(reply.error, undefined, JSON.stringify(reply));
        assert.equal(reply.result.payload_base64, item.payload.toString('base64'));
      }
    } finally {
      adapter.close(); await new Promise(resolve => { child.once('close', resolve); child.kill('SIGTERM'); });
    }
  }
});
