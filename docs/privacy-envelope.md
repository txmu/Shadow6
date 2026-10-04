# OCaml External Privacy Envelope (S6EPE v3)

S6EPE is an optional, separate authenticated encrypted outer component. Native
Core bytes and datagram boundaries remain opaque; no twelve-Core wire protocol
changes. Guard owns perimeter/exposure policy, S6EPE owns outer sessions, Gate
owns routing/relay/BrokerSet realization, and Core owns its native data plane.
The [native capability matrix](native-security-capabilities.md) documents
existing Core encryption/authentication and its mode-specific limits. S6EPE
does not imply that the enclosed native transport lacks cryptographic security.

V3 deliberately rejects v2's authentication-only wire. Upgrade both outer ends
together. Core peers retain their native protocols. Encryption is mandatory;
there is no authenticated plaintext forwarding mode.

## Build and run

Requirements: OCaml 4.14+, Dune 3.8+, Digestif, libsodium and OpenSSL 3 development files.
The opam manifest declares `conf-libsodium` and `conf-openssl`. Explicit operator setup may install
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
The Linux SCTP message adapter can preserve a compatible native message
boundary. The Linux WebRTC/ICE/DTLS/DataChannel executable path is available
for an explicitly bound Nim/WebRTC Profile. It consumes SDP through a private
Unix socket owned by the Named Service signalling broker, pairs each envelope
DataChannel with a native Nim DataChannel, and admits concurrent pairs under
`max_sessions`, `max_preauth`, and the provider's aggregate queue budget. Each
pair receives a fresh random signalling ID. `signal_id` in the config is a
service prefix, not a session identifier. The default raw carrier and the
other Core Profiles remain unchanged. See the signalling handoff contract
below and the [Carrier/Adapter Contract](privacy-envelope-carrier-contract.md).
The [Carrier/Adapter Contract](privacy-envelope-carrier-contract.md) separates
the stream security engine from transport I/O. Its default raw provider remains
identifiable; the TLS 1.3 provider encapsulates the hello in a real encrypted
TLS connection; the dedicated Linux SCTP message provider preserves native
records. The WebRTC provider preserves native DataChannels. Its executable
session starts only after the configured signalling broker returns an SDP
answer, completes ICE/DTLS/DataChannel admission, and authenticates the S6EPE
message handshake. Named Service startup waits for a fresh authenticated
session observation.

## Native SCTP message carrier

On Linux with kernel SCTP available, both outer ends can select:

```ini
mode=message
carrier=sctp
sctp_streams=4
message_channels=0:ordered:reliable,1:unordered:retransmits:0,2:unordered:reliable
```

The local handoff must itself be an established compatible SCTP association;
this is not a twelve-Core application ABI or a TCP socket conversion. Stream 0
must admit ordered reliable controls. Channels and receive reliability policy
are explicit on both endpoints; SCTP receive metadata does not report the
sender's partial-reliability budget. Native data retains boundaries, stream,
ordering and uint32 PPID. Reset confirmations remain directional and streams
are reusable; reset does not mean channel close or reset cryptographic state.

Mutual PSK-authenticated fresh X25519 establishes independent directional keys.
Each channel has bounded sequence replay state and a key ratchet every 4096
records. Metadata and encrypted controls are authenticated. FINAL carries all
channel watermarks; reliable delivery and authenticated partial-reliability
abandonment notices must resolve before graceful association shutdown. Unknown
events, restart, missing FINAL, authentication failures and budget exhaustion
close the session. Padding, jitter and cover have the same explicit session
budgets as stream mode. Fresh session keys reject prior-session ciphertext;
datagram mode requires persistent nonce state for the corresponding
restart-spanning replay guarantee.

The hello is inside SCTP messages but remains passively identifiable: SCTP is
not encrypted carrier camouflage. No ICE/DTLS lifecycle or Native Core private
protocol is inferred from this adapter. Unsupported platforms reject this
configuration and omit SCTP from the executable's message capabilities.

## Standard TLS Carrier

Stream endpoints can explicitly select `carrier=tls` on both sides. Add:

```ini
carrier=tls
tls_cert=/absolute/private/server-cert.pem
tls_key=/absolute/private/server-key.pem
tls_ca=/absolute/private/ca.pem
tls_peer_name=epe-client
```

The client supplies its own certificate/key and the expected server SAN instead.
Material is single-certificate PEM and unencrypted PKCS8 Ed25519 key; local
certificates and the trusted CA use Ed25519 signatures. The CA must be a CA.
Each material file is distinct, absolute, owner-controlled, single-link, regular,
non-symlink, mode 0600 and at most 16 KiB. The expected peer identity is verified
against an exact SAN (DNS or numeric IP); CN fallback and wildcards are rejected.
These files are included in the local DeploymentLock and rechecked by the
supervisor. They never enter portable S6P1 intent. Datagram TLS is rejected.

The outer connection uses TLS 1.3 with X25519 key agreement and mutual
certificate authentication. Tickets, session caching, resumption and early data
are disabled. The complete S6EPE hello, proofs, secretstream headers and records
travel inside that connection. The independent envelope PSK remains required;
a valid TLS certificate alone cannot reach the native upstream. There is no
fallback to raw on TLS failure. Handshake and close have explicit time budgets;
nonblocking partial I/O and backpressure preserve every byte. Authenticated
close_notify is consumed after the envelope FINAL to avoid TCP reset truncation;
raw EOF or application data after FINAL fails closed.

Loopback wire recordings verify genuine TLS handshake records and absence of
inner hello/payload markers; tests also verify mutual authentication failures,
wrong SAN/CA, actual large-payload half-close and blocked write retry. These
checks establish encryption of the inner hello, not browser fingerprint matching,
anonymity or resistance to active identification and blocking.

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

Datagram mode requires `replay_path=/absolute/private/replay.state`; startup
fails closed without it. The parent directory must already exist, be owned by
the service user and have no group/other permissions; the state file is checked
as a bounded mode-0600 regular file. A separate private lock prevents concurrent state writers. Bounded state contains version,
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
observable. The raw v3 hello itself is identifiable; TLS conceals that inner hello, while
TLS handshake properties and connection metadata remain observable.

## Runtime truth and verification

Feature reports declare encryption, transports, endpoint support, replay,
persistence capability, shaping and limits; they are claims, not OS observation.
Metrics v2 is a private atomic snapshot with sample time, session/authentication/
rejection/byte/record/timeout counters, shaping overhead and enabled state.
TLS metrics v3 additionally declare `carrier=tls` and
`wire_appearance=standard-tls13`; SCTP metrics v4 add `carrier=sctp`,
`wire_appearance=standard-sctp`, native send abandonment and established-session
rejection counters. WebRTC metrics v5 report `carrier=webrtc` and
`wire_appearance=standard-webrtc-datachannel` with bounded message failure
counters and `active_sessions`; Named Service uses that live counter for
authenticated WebRTC readiness. Snapshots capture counters under one lock. Raw
remains v2. Control Center strictly recognizes v1 through v6 and reports
current/stale/unavailable separately. No secret or native payload is
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
