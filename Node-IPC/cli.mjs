#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import {parseArgs} from 'node:util';
import {FastRPCClient, FastRPCServer, RawIPCClient, RawIPCServer, loadKey, readPrivate, canonical, parseCanonical, LIMITS} from './shadow6_ipc.mjs';
import {C11RelayAdapter, RELAY_IPC_TYPES} from './c11relay.mjs';

export function catalog() {
  return {schema: 'shadow6.node-ipc.v1', backend: 'node-builtin', node: '>=22', npm: false,
    transports: ['unix','loopback-tcp'], protocols: ['fastrpc','rawipc'], limits: LIMITS,
    components: ['control-center','c11relay'], relay_types: RELAY_IPC_TYPES,
    actions: ['catalog','keygen','call','raw-send','serve']};
}
function assertOnly(v, keys) {
  if (!v || Array.isArray(v) || typeof v !== 'object' || Object.keys(v).some(k => !keys.includes(k))) throw Error('unknown configuration field');
}
export function loadConfig(filename) {
  const value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(readPrivate(filename, 65536)));
  assertOnly(value, ['schema','key_file','fastrpc','rawipc','component','relay','timeout_ms','max_connections']);
  if (value.schema !== 'shadow6.node-ipc-config.v1' || !path.isAbsolute(value.key_file ?? '') || !['control-center','c11relay'].includes(value.component)) throw Error('invalid IPC configuration');
  for (const kind of ['fastrpc','rawipc']) if (value[kind]) {
    assertOnly(value[kind], ['socketPath','host','port']);
    if (value[kind].socketPath && (value[kind].host !== undefined || value[kind].port !== undefined)) throw Error('ambiguous IPC endpoint');
  }
  if (!value.fastrpc && !value.rawipc) throw Error('no configured IPC endpoint');
  if (value.relay) assertOnly(value.relay, ['host','port','maxPeers','maxQueue','timeoutMs','idleMs','rate','burst']);
  return value;
}
function controlPath() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [path.join(here, '..', 'Control-Center', 'shadow6_control.py'), path.join(here, 'shadow6-control')];
  const script = candidates.find(name => fs.existsSync(name));
  if (!script) throw Error('Control Center unavailable'); return script;
}
export function controlHandler({python = process.env.SHADOW6_PYTHON ?? 'python3', allowMutations = false} = {}) {
  const script = controlPath();
  return (method, params, {signal} = {}) => new Promise((resolve, reject) => {
    if (method.startsWith('ipc.') || method === 'c11relay.ipc.status') { reject(new Error('recursive transport call disabled')); return; }
    const request = method === 's6ar.dispatch' ? {s6ar1: params.token} : {id: 'ipc', method, params};
    const input = canonical(request);
    if (input.length > 65536) { reject(new Error('Control request exceeds current transport budget')); return; }
    const child = spawn(python, [script, 'rpc', ...(allowMutations ? ['--allow-mutations'] : [])], {stdio: ['pipe','pipe','pipe'], signal});
    const chunks = []; let total = 0;
    const timer = setTimeout(() => child.kill('SIGKILL'), LIMITS.timeoutMs);
    child.on('error', reject); child.stdin.on('error', () => {}); child.stderr.resume();
    child.stdout.on('data', bytes => { total += bytes.length; if (total > 1048576) child.kill('SIGKILL'); else chunks.push(bytes); });
    child.once('close', code => {
      clearTimeout(timer);
      try {
        if (code !== 0 || total > 1048576) throw Error('Control request failed');
        const reply = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (method === 's6ar.dispatch') { resolve(reply); return; }
        if (reply.ok !== true) throw Error('Control request rejected');
        resolve(reply.result);
      } catch (error) { reject(error); }
    });
    child.stdin.end(Buffer.concat([input, Buffer.from('\n')]));
  });
}
export async function serve(config, options = {}) {
  const key = loadKey(config.key_file), adapter = config.component === 'c11relay' ? new C11RelayAdapter(config.relay) : null;
  const control = adapter ? null : controlHandler(options), servers = [];
  const common = {key, timeoutMs: config.timeout_ms, maxConnections: config.max_connections ?? 8};
  try {
    if (config.fastrpc) {
      const handler = adapter ? (m, p, c) => adapter.rpc(m, p, c) : control;
      servers.push(new FastRPCServer({...common, ...config.fastrpc, handler}));
    }
    if (config.rawipc) {
      const handler = adapter ? (t, p, c) => adapter.raw(t, p, c) : async (t, p, c) => {
        if (t !== 1) throw Error('unknown Control RawIPC type');
        const request = parseCanonical(p); assertOnly(request, ['method','params']);
        if (typeof request.method !== 'string') throw Error('missing RawIPC method');
        return canonical(await control(request.method, request.params ?? {}, c));
      };
      servers.push(new RawIPCServer({...common, ...config.rawipc, handler}));
    }
    const addresses = [];
    for (const server of servers) addresses.push(await server.listen());
    return {addresses, async close() { await Promise.all(servers.map(server => server.close())); adapter?.close(); }};
  } catch (error) { await Promise.all(servers.map(server => server.close())); adapter?.close(); throw error; }
}
async function stdin() {
  const pieces = []; let size = 0;
  for await (const bytes of process.stdin) { size += bytes.length; if (size > 1048576) throw Error('input exceeds budget'); pieces.push(bytes); }
  return JSON.parse(Buffer.concat(pieces).toString('utf8'));
}
export async function main(argv = process.argv.slice(2)) {
  const {values, positionals} = parseArgs({args: argv, allowPositionals: true, options: {
    config: {type: 'string'}, endpoint: {type: 'string'}, socket: {type: 'string'}, key: {type: 'string'}, method: {type: 'string'}, params: {type: 'string'},
    type: {type: 'string'}, hex: {type: 'string'}, output: {type: 'string'}, 'json-stdin': {type: 'boolean'}, 'allow-mutations': {type: 'boolean'}, python: {type: 'string'}}});
  const action = positionals[0] ?? 'catalog';
  if (positionals.length > 1) throw Error('unexpected positional arguments');
  if (action === 'catalog') return catalog();
  if (action === 'keygen') {
    if (!values.output || !path.isAbsolute(values.output)) throw Error('absolute key output required');
    const fd = fs.openSync(values.output, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, crypto.randomBytes(32)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    return {created: true};
  }
  if (action === 'serve') {
    const running = await serve(loadConfig(values.config), {python: values.python, allowMutations: values['allow-mutations']});
    console.log(JSON.stringify({ready: true, addresses: running.addresses}));
    await new Promise(resolve => { process.once('SIGINT', resolve); process.once('SIGTERM', resolve); });
    await running.close(); return {stopped: true};
  }
  const request = values['json-stdin'] ? await stdin() : {};
  assertOnly(request, ['endpoint','method','params','type','payload_base64']);
  let options;
  if (values.config) {
    const config = loadConfig(values.config); const name = values.endpoint ?? request.endpoint ?? (action === 'raw-send' ? 'rawipc' : 'fastrpc');
    if (!['fastrpc','rawipc'].includes(name) || !config[name]) throw Error('unknown configured endpoint');
    options = {...config[name], key: loadKey(config.key_file), timeoutMs: config.timeout_ms};
  } else options = {socketPath: values.socket, key: loadKey(values.key)};
  if (action === 'call' || action === 'fastrpc-call') {
    return await new FastRPCClient(options).call(values.method ?? request.method, values.params ? JSON.parse(values.params) : request.params ?? {});
  }
  if (action === 'raw-send') {
    let bytes;
    if (values.hex !== undefined) { if (!/^(?:[0-9a-fA-F]{2})*$/.test(values.hex)) throw Error('invalid hex'); bytes = Buffer.from(values.hex, 'hex'); }
    else { bytes = Buffer.from(request.payload_base64 ?? '', 'base64'); if (bytes.toString('base64') !== (request.payload_base64 ?? '')) throw Error('invalid base64'); }
    return {payload_base64: (await new RawIPCClient(options).call(bytes, Number(values.type ?? request.type ?? 1))).toString('base64')};
  }
  throw Error('usage: shadow6 ipc [catalog|keygen|serve|call|raw-send]');
}
if (process.argv[1] && pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url) {
  main().then(result => console.log(JSON.stringify(result))).catch(() => { console.error('IPC operation rejected; check local configuration, key permissions and endpoint'); process.exitCode = 2; });
}
