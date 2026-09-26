# Core-Pony

Pony reference-capability UDP stack for Shadow6. `Main` splits `Env` into
opaque `NetAuth` and `FileAuth` authorities; actors cannot obtain ambient OS
authority through these interfaces. Example payloads cross actor boundaries as
consumed `iso` values and OCapToken stores immutable bytes. `crypto/session.c`
now contains a bounded Ed25519/X25519/ChaCha20-Poly1305 handshake/data-frame
boundary with replay and lifetime checks, covered by native negative tests. It
is wired into real UDP actors and a strict configuration loader. A two-process
loopback integration test verifies encrypted binary payload round trips.

The default build reports L0 and supports a pinned-peer UDP tunnel. Legacy
configuration stays loopback-only. An extended configuration adds
`bind_host`, `peer_host`, `application_host`, and `allow_external`; all hosts
must be IP literals, and any non-loopback address is rejected unless the
operator explicitly sets `allow_external` to true.

The agent accepts up to 256 concurrent sessions from explicitly pinned client
identities. Add an agent-only `peer_public_keys` array of up to 255 additional
Ed25519 public keys alongside `peer_public_key`; duplicates and unknown config
fields are rejected. Each authenticated session owns its token, independent
64-bit sequence spaces, send/receive windows, and ephemeral application socket.
The application socket is essential: responses from a shared UDP application
are routed back to the correct session, without a global last-client slot.

The broker supports 256 bounded A -> B -> C routes using a separate ephemeral
upstream UDP socket for each client address. B forwards ciphertext and never
receives a session key. An unconfirmed broker route expires after five seconds;
an inactive confirmed route expires after 60 seconds. Agent sessions are
allocated only after signature verification. Admission uses a 256-token burst,
64 tokens/second refill, a 256-session cap, and a 1024-entry replay table whose
60-second entries cannot be evicted by capacity pressure. Per-socket ingress
credits cap outstanding cross-actor datagrams at 32.

Transport v2 uses `S6Q1/S6Q2` handshakes and `S6E` DATA/ACK frames. Both ends
must be upgraded together; old frames fail closed. The authenticated hello
contains a public 128-bit identity selector plus a fresh random 128-bit nonce.
Selectors route verification to a pinned key and never substitute for verifying
the signature. AEAD nonces include frame kind and a 64-bit sequence, so
full-duplex DATA and ACK packets cannot reuse a nonce under the same key.

Each session has a bounded 4096-packet send and receive window (1200-byte wire MTU,
1172-byte payload). Receive buffers deliver in order, duplicate packets receive
ACKs without redelivery, and retransmissions reuse immutable ciphertext.
RTT estimation follows the RFC 6298 SRTT/RTTVAR equations and Karn's rule, with
a 100ms minimum and 5s maximum RTO and eight bounded retries. The 10ms shared
timer dispatches session timeout events independently of packet reception.
There is no former 1,000,000-packet or five-minute process lifetime cutoff.
Idle sessions expire after 60 seconds; clients reconnect with bounded backoff.

`make pony-crosed-variant` also produces an explicit L5 binary and restores the
default binary. Its immutable `CrosedGrant` is an OCAP attenuation boundary:
build level, signed request, requested level, per-Mod level, named capability,
and source/target domain policy must all agree. Plugin RPC, full A/B/C,
and external-address deployment are implemented as explicitly bounded runtime
paths. `--plugin-rpc ID CAPABILITY JSON` exists only in the L5 binary and starts
the fixed Shadow6 plugin manager. That manager rechecks the signed manifest,
attenuates the requested capability, and alone starts the plugin in its
resource-bounded network/user/IPC/UTS namespace over stdin/stdout JSON.

This is UDP-only: initial peers require configured reachable IPs, and
there is no WSS multi-tenant control plane, automatic NAT rendezvous, QUIC/KCP
congestion controller, or measured high-throughput claim. The bounded sliding
window is not a congestion controller or a claim of Go/Rust protocol parity.
OCap does not prohibit arbitrary native FFI syscalls; that needs a compiler FFI
allowlist and OS isolation. Immutable tokens are shared immutable memory.
No end-to-end zero-copy or throughput advantage over Go has been measured.

Extended endpoint example (the secret file must be owner-controlled mode 0600):

```json
{"role":"client","allow_external":true,"bind_host":"192.0.2.10","peer_host":"198.51.100.20","application_host":"127.0.0.1","listen_port":41001,"peer_port":41002,"application_port":41003,"private_key":"<64 lowercase hex>","peer_public_key":"<64 lowercase hex>"}
```

Build with `make core-pony` (requires `ponyc`, or the pinned tool under
`.tools/ponyc-0.72.0`). Windows IOCP and Termux portability depend on Pony's
platform runtime and are deployment properties, not claims made by this
source-only prototype.

CI runs the compiled `--transport-self-test` state-machine checks plus
`tests/test_network.py` and `tests/test_tenants.py`. The latter establishes 256
distinct signed identities against the real Pony listener, checks capacity
without eviction, per-tenant application return paths, broker key isolation,
out-of-order delivery, duplicates, and byte-identical lost-ACK retransmission.
Source/native crypto checks alone do not establish that the actor tests passed;
use the results of the focused Pony Actions job for the current commit.
