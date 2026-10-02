# Shadow6 FastRPC and RawIPC

`shadow6_ipc.mjs` is a dependency-free Node.js component transport. It uses
only built-in `node:crypto`, `node:net`, and filesystem APIs; npm is not needed.

FastRPC is a bounded JSON request/response service over a Unix socket (or an
explicit loopback TCP endpoint). Requests use canonical safe-integer JSON,
strict method and id bounds, a timestamp window, a random nonce, and HMAC-SHA256
authentication. The server keeps a bounded replay set and returns a generic
authenticated error without exposing implementation details. Unix sockets are
created mode `0600`.

RawIPC is for binary component data. Each length-delimited frame uses AES-256-GCM
with a random nonce, authenticated header, timestamp window, and a 1 MiB frame
limit. Keys are owner-only mode `0600` files when loaded from disk.

`C11RelayRawIPCBridge` provides a relay-specific RawIPC contract. It uses the
`S6CR` datagram header, a bounded peer id, a bounded in-flight queue, and the
existing C11Relay UDP limits remain authoritative. It does not expose arbitrary
control operations or bypass C11Relay admission.

Run `node --test Node-IPC/test_ipc.mjs` for the loopback authentication,
tamper, replay-boundary, encryption, and C11Relay bridge tests.

## Quick Start

Node.js 22 or 24 is required. The source CLI is `node Node-IPC/cli.mjs`;
the unified route is `python3 CLI/shadow6.py ipc` (installed: `shadow6 ipc`).
The library exports clients/servers and the C11Relay adapter for direct imports.

Create a private runtime directory and key:

```sh
mkdir -m 700 /tmp/shadow6-ipc-local
shadow6 ipc keygen --output /tmp/shadow6-ipc-local/key
```

Save this configuration as `/tmp/shadow6-ipc-local/config.json`, mode `0600`.
The relay port must name a running local C11Relay listener. Both IPC services
share peer mappings and limits:

```json
{
  "schema": "shadow6.node-ipc-config.v1",
  "component": "c11relay",
  "key_file": "/tmp/shadow6-ipc-local/key",
  "fastrpc": {"socketPath": "/tmp/shadow6-ipc-local/fast.sock"},
  "rawipc": {"socketPath": "/tmp/shadow6-ipc-local/raw.sock"},
  "relay": {"host": "127.0.0.1", "port": 7000, "maxPeers": 64, "maxQueue": 128,
            "rate": 1000, "burst": 256, "timeoutMs": 2000, "idleMs": 30000}
}
```

```sh
shadow6 ipc serve --config /tmp/shadow6-ipc-local/config.json
# From another terminal:
shadow6 ipc call --config /tmp/shadow6-ipc-local/config.json --method c11relay.status
shadow6 ipc call --config /tmp/shadow6-ipc-local/config.json --method c11relay.exchange \
  --params '{"peer":0,"payload_base64":"aGVsbG8="}'
shadow6 ipc raw-send --config /tmp/shadow6-ipc-local/config.json --type 19 --hex ''
```

FastRPC returns a signed JSON-RPC result/error envelope; callers must inspect
`error` before using `result`. RawIPC returns `payload_base64`. SIGINT/SIGTERM
closes listeners and peer sockets; an existing socket path is never unlinked
on startup. A restart requires removal of any stale socket by its owner.

## Control Center and AI

Use `"component":"control-center"` and omit `relay` to expose the fixed
Control Center dispatcher through these transports. The server is read-only
unless started with `--allow-mutations`. RawIPC type 1 contains canonical
`{"method":"system.guide","params":{"lang":"en"}}` bytes.
FastRPC method `s6ar.dispatch` accepts `{"token":"S6AR1...."}` and uses the
existing S6AR1/S6P1 validation and response path; legacy methods remain usable.
Current Control Center requests remain bounded to 64 KiB, even though IPC
framing permits 1 MiB. JSON replies must use safe integers; binary data uses
RawIPC. Unix sockets and disk key/config loading require POSIX ownership checks;
Windows supports the library's loopback TCP with in-memory keys.

Configure `SHADOW6_IPC_CONFIG` in the operator's Control Center environment.
`ipc.catalog`, `ipc.call`, `ipc.raw`, `c11relay.ipc.status`, and
`c11relay.ipc.schema` appear in JSONL, HTTP, MCP, LSP, and OpenAI tools through
the shared schema. AI callers cannot supply key/config paths or destinations.
`ipc.call`/`ipc.raw` need explicit mutation permission, and nested bridge
invocation is rejected. Read-only discovery works without a running service.

## C11Relay Contract

FastRPC exposes `c11relay.capabilities`, `c11relay.status`, `c11relay.exchange`,
and `c11relay.batch`. RawIPC types are 17 (datagram), 19 (metrics), and 20
(batch). An S6CR datagram is a 12-byte header: magic `S6CR`, version 1, type 17,
16-bit big-endian payload length, and 32-bit big-endian peer id, followed by
up to 65,507 bytes. Peer ids are `0..maxPeers-1`; each peer owns a connected
UDP socket. A batch has a 16-bit count followed by 32-bit length-prefixed S6CR
datagrams, at most 256 items and 900,000 encoded bytes. Repeated peers execute
in order; different peers run concurrently under `maxQueue`. Failure may occur
after earlier packets have been sent, so batches are not transactions.

Use fresh, dedicated keys per service; replay state is process-local and
restart clears it. FastRPC authenticates but does not encrypt JSON. RawIPC
encrypts binary data. Neither transport is a WAN service, a replacement for
Core credentials, nor a secure boundary against another process running as
the same OS user with access to the key.

## Verification

`make node-ipc-test` runs socket, cryptographic rejection, CLI, and actual
Control Center bridge tests without compiling anything. Set
`SHADOW6_RELAY_BINARY` to an existing relay executable to exercise normal and
high-speed native relay chains. CI tests Node 22/24 on Linux, macOS, and Windows;
the Linux runner additionally builds and tests the native C11Relay companion.
Optional
tests report explicit skips when their prerequisites are absent.

## Candidate component contracts

The dependency-free service also supports `virtual-broker`, `detector`, `s6na`,
and `app-flow` as read-only component identities. Each exposes capabilities, status,
bounded metrics, and component-specific summary/snapshot observations. Mutation, packet
injection, configuration reload, and credential bypass are unavailable; each
component keeps its own authentication and lifecycle rules. Configure one of
these identities in `node-ipc-config.v1` with a dedicated owner-only key.
These are contract-level observations; they do not impersonate a running
component or replace its admission, policy, or transport authentication.
For `app-flow`, the contract reports the bounded loopback shim and its
intentional client-only scope; IPC does not start or mutate the shim.

```sh
shadow6 ipc call --config /tmp/shadow6-ipc-local/config.json \
  --method virtual-broker.capabilities
shadow6 ipc call --config /tmp/shadow6-ipc-local/config.json \
  --method detector.status
shadow6 ipc call --config /tmp/shadow6-ipc-local/config.json \
  --method s6na.status
```

The CLI catalog lists all five supported component identities. Unsupported
identities fail closed during configuration loading. RawIPC type 1 for these
components is limited to the same canonical status calls; other types are
rejected.
