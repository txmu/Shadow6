# Core-Pony (exploratory prototype)

Pony reference-capability prototype for Shadow6. `Main` splits `Env` into
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

The broker role now provides an A -> B -> C single-tunnel relay. Its network
socket accepts one client address and its application-side socket talks to the
configured agent. B forwards opaque authenticated frames: the client and agent
remain pinned to each other's Ed25519 identities and derive their session keys
without exposing plaintext or session keys to B. Data uses a bounded 1200-byte
MTU, authenticated sequence numbers, ACKs, one in-flight frame, paced
retransmission, replay rejection, and bounded handshake reconnection.

`make pony-crosed-variant` also produces an explicit L5 binary and restores the
default binary. Its immutable `CrosedGrant` is an OCAP attenuation boundary:
build level, signed request, requested level, per-Mod level, named capability,
and source/target domain policy must all agree. Plugin RPC, full A/B/C,
and external-address deployment are implemented as explicitly bounded runtime
paths. `--plugin-rpc ID CAPABILITY JSON` exists only in the L5 binary and starts
the fixed Shadow6 plugin manager. That manager rechecks the signed manifest,
attenuates the requested capability, and alone starts the plugin in its
resource-bounded network/user/IPC/UTS namespace over stdin/stdout JSON.

This remains an exploratory stack, not Go/Rust data-plane parity: the broker is
single-tunnel and UDP-only, initial peers require configured reachable IPs, and
there is no WSS multi-tenant control plane, automatic NAT rendezvous, QUIC/KCP
congestion controller, or measured high-throughput claim. Stop-and-wait ARQ is
reliable but intentionally conservative on high-bandwidth-delay paths.
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
