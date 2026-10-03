# OCaml External Privacy Envelope (S6EPE v3)

S6EPE is an optional, separate authenticated encrypted outer component. Native
Core bytes and datagram boundaries remain opaque; no twelve-Core wire protocol
changes. Guard owns perimeter/exposure policy, S6EPE owns outer sessions, Gate
owns routing/relay/BrokerSet realization, and Core owns its native data plane.

V3 deliberately rejects v2's authentication-only wire. Upgrade both outer ends
together. Core peers retain their native protocols. Encryption is mandatory;
there is no authenticated plaintext forwarding mode.

## Build and run

Requirements: OCaml 4.14+, Dune 3.8+, Digestif and libsodium development files.
The opam manifest declares `conf-libsodium`. Explicit operator setup may install
these dependencies; ordinary `shadow6 run` never invokes a toolchain or builds.

```sh
make privacy-envelope
shadow6 privacy-envelope feature-report
shadow6 privacy-envelope run --config /absolute/private/server.conf
```

Configuration is bounded to 16 KiB, owner-controlled, regular, single-link,
non-symlink and mode 0600, with strict unknown/duplicate field rejection.
Example server (replace the placeholder with a cryptographically generated PSK):

```ini
role=server
mode=stream
listen=127.0.0.1:19443
upstream=127.0.0.1:19444
auth_key=REPLACE_WITH_A_RANDOM_SHARED_SECRET
key_epoch=1
max_frame=16384
handshake_timeout=5
max_preauth=16
max_sessions=32
idle_timeout=30
session_timeout=3600
metrics_path=/absolute/private/server.metrics
```

Client: set `role=client`, listen on its private application endpoint, and set
`upstream` to the server envelope. Both ends use the same PSK and key epoch.
`mode=datagram` wraps UDP instead. Numeric IPv4 and bracketed IPv6 are supported;
`unix:/absolute/private/socket` supports stream handoff. Unix datagrams are
explicitly unavailable. Unix local handoff requires a private owner-controlled
directory. A loopback/Unix declaration is policy, not ownership evidence:
Deployment separately verifies the processes and their owned sockets.

The server's upstream and client's listen endpoint must be loopback/private.
WebRTC/ICE and SCTP are not implemented by a TCP/UDP envelope; choose an actual
compatible application socket or its dedicated adapter explicitly.

## Stream contract

A hello is direction magic (8 bytes), random nonce (32), ephemeral X25519 public
key (32) and hexadecimal key epoch (16). PSK HMAC-SHA256 client/server proofs bind
both hellos and direction. Libsodium `crypto_kx` generates separate directional
material. HKDF-SHA256 binds that material to the authenticated transcript/PSK.
Each direction exchanges a 24-byte secretstream header after mutual proofs.
The server opens no native upstream before successful authentication/key setup.

Records have a four-byte bounded length prefix and libsodium XChaCha20-Poly1305
secretstream ciphertext. The encrypted inner header carries application/cover
type and payload length; padding is removed before native forwarding. Sequence
state rejects replay, deletion/reordering and tampering. Every 4096 sent records
requests a key ratchet; a session is bounded to one million records. Authenticated
FINAL carries no application bytes, implements half-close and erases state.
Unauthenticated EOF is truncation. Empty application records do not mean EOF.

Each direction holds at most one bounded pending record. Backpressure stops
reads until output drains. Maximum sessions/pending authentications are 128;
idle timeout is 1..300 seconds and total session lifetime is 1..86400 seconds.
Failures close the session. Fresh ephemeral keys/nonces prevent replaying old
stream transcripts after process restart.

## Datagram contract and replay storage

A capsule is direction-independent magic (8), Unix timestamp hex (16), key epoch
hex (16), random 192-bit nonce (24), ciphertext and 16-byte AEAD tag. Direction is
bound into both HKDF key derivation and associated data. Responses cannot replay
as requests. Epoch mismatch, malformed capsules, wrong keys, stale timestamps
(outside 30 seconds) and duplicate nonces fail closed before native forwarding.
Zero-length and full-size native packets retain their exact boundaries.

The replay cache admits at most 4096 nonce hashes, retained for 61 seconds;
capacity exhaustion rejects rather than evicting live entries. Each peer has one
connected reply socket with bounded idle/session expiry. Response wire bytes
consume a capped per-peer credit, at most three times received authenticated
wire bytes. Unsolicited native replies cannot produce unbounded amplification.
Clock synchronization remains required.

Optional `replay_path=/absolute/private/replay.state` enables restart-spanning
UDP protection. Its private directory and mode-0600 file are checked. A separate
private lock prevents concurrent state writers. Bounded state contains version,
epoch, nonce hashes and expiration only; no payload, PSK or credentials. Accepted
nonce state is written through a private temporary file, fsync, atomic rename
and directory fsync **before forwarding**. Corrupt state, unsupported persistence
or an epoch rollback fails closed. Increasing the explicit authorized epoch
retires old replay state; both peers must be reconfigured/relocked together.

## Optional bounded stream shaping

Defaults disable padding, jitter and cover traffic. To enable explicitly:

```ini
padding_block=128
jitter_ms=2
cover_interval=10
cover_limit=8
shaping_budget=1048576
```

Padding uses classes 64..4096 (powers of two), jitter is at most 20 ms, cover
interval is 1..60 seconds with an explicit limit of 1..64 cover records per
session. Cover and padding consume a session byte budget (64..16777216).
Exhaustion closes the session. Datagram shaping is rejected. These controls
reduce some length/framing clues; they do not guarantee anonymity, DPI evasion,
undetectability or resistance to blocking. IP addresses, timing and volume remain
observable. The v3 hello itself is identifiable.

## Runtime truth and verification

Feature reports declare encryption, transports, endpoint support, replay,
persistence capability, shaping and limits; they are claims, not OS observation.
Metrics v2 is a private atomic snapshot with sample time, session/authentication/
rejection/byte/record/timeout counters, shaping overhead and enabled state.
Control Center retains strict v1 compatibility for older installed artifacts and
reports current/stale/unavailable separately. No secret or native payload is
written to telemetry. Configuration/key epoch changes invalidate DeploymentLock;
Named Service revalidates admission and files during supervision.

```sh
make privacy-envelope-test
# Verify an already-built executable without rebuilding:
S6EPE_BINARY=/absolute/path/main.exe \
  .venv/bin/python -m unittest discover -s OCaml/privacy_envelope/test -p 'test_*.py' -v
```

Tests use actual OCaml processes, an independent libsodium test peer, and owned
loopback/Unix sockets. Native twelve-Core/platform matrices remain Actions work.
See [named services](named-services.md), [composition](service-connections.md)
and [exposure review](privacy-envelope-exposure-audit.md).
