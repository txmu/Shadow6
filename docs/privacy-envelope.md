# OCaml External Privacy Envelope (S6EPE)

S6EPE is an optional authenticated outer layer between a configured public
transport and a local Shadow6 endpoint. It provides an explicit client/server
pair for streams and datagrams; native Core bytes remain opaque. The envelope
never changes Core wire formats, cryptography, ACKs or peer compatibility.

The privacy goal is to reduce unauthenticated disclosure and provide a bounded,
authenticated entry point. IP addresses, timing, lengths and traffic shape remain
observable. The current layer authenticates access and datagram integrity; it
does not encrypt the outer stream. Payload confidentiality still depends on the
native Core or a separately configured encrypted transport. The encrypted outer
transport goal remains outstanding; it must not be inferred from the word
“Privacy” or the authenticated transcript.

## Build and launch

Requirements: OCaml 4.14 or later, Dune 3.8 or later, Digestif, Unix and threads.
The opam package declares these dependencies. On a prepared development machine:

```sh
opam install . --deps-only
```

Run that command from `OCaml/privacy_envelope`; it installs dependencies only
when the operator explicitly chooses to do so. From the repository root:

```sh
make privacy-envelope
shadow6 privacy-envelope feature-report
shadow6 privacy-envelope run --config /absolute/path/server.conf
# Direct invocation is equivalent:
OCaml/privacy_envelope/shadow6-privacy-envelope --config /absolute/path/server.conf
```

`make privacy-envelope` is optional and never enables Gate or changes L0 Core
flags. `make install-prebuilt` includes an already-built envelope without
compiling one. `feature-report` reports availability of the actual executable;
it does not treat a static declaration as proof of installation.

## Configure both ends

The native receiving endpoint must already exist. Use the transport of that
specific endpoint, not an inferred protocol based only on its Core name.
For example, a TCP local application boundary and a native QUIC UDP endpoint
require different envelope modes even when exposed by the same Core family.
WebRTC signaling/ICE and native SCTP require dedicated endpoint adapters; a
plain TCP/UDP socket does not implement them.

```text
local sender -> client envelope -> server envelope -> local native receiver
                 loopback          explicit bind        loopback
```

Both configuration files must be regular, non-symlink, singly linked files,
owned by the runtime account with mode `0600`, at most 16 KiB. Parsing rejects
unknown or duplicate keys and malformed lines. Blank lines and `#` comments
are allowed. Generate a shared secret with a cryptographic generator and place
it directly in each private file; do not use the placeholder below.

Server configuration:

```ini
role=server
mode=stream
listen=127.0.0.1:19443
upstream=127.0.0.1:19444
auth_key=REPLACE_WITH_A_RANDOM_SHARED_SECRET
max_frame=16384
handshake_timeout=5
max_preauth=16
max_sessions=32
idle_timeout=30
session_timeout=3600
metrics_path=/absolute/private/directory/server.metrics
```

Client configuration:

```ini
role=client
mode=stream
listen=127.0.0.1:19442
upstream=127.0.0.1:19443
auth_key=REPLACE_WITH_THE_SAME_RANDOM_SHARED_SECRET
metrics_path=/absolute/private/directory/client.metrics
```

For datagrams change `mode=datagram` at both ends and configure the native
receiver as UDP. On separate hosts change the server's public bind and the
client's remote address explicitly. Numeric IPv4 endpoints are currently
implemented. Unix descriptors and IPv6 remain planned endpoint extensions.
The server's upstream and the client's listen address are required to be
loopback; native Core listener configuration must also be reviewed separately
so it cannot bypass the envelope through another public listener.

`auth_key` is 16..256 bytes. Each instance permits at most 128 sessions and at
most 128 pending stream authentications. `max_frame` is 256..65507 bytes for
streams and at most 65427 payload bytes for datagrams (80 bytes of capsule
overhead). Idle timeout is 1..300 seconds; per-session lifetime is 1..86400
seconds. Stream read/write buffers, worker count and datagram peer maps are
bounded. Stream limits apply per chunk, not to the total application message.

## Wire version 2

Version 2 deliberately rejects the old prototype's one-way HMAC handshake and
bare HMAC datagrams. Upgrade both envelope ends together; native Core peers
keep their existing protocols.

For streams, the server sends a fresh 32-byte OS-random nonce immediately. The
client returns its own nonce and HMAC-SHA256 over `S6EPE/2 client` plus both
nonces. The server verifies it before opening the native upstream and returns
a proof using the distinct `S6EPE/2 server` label. Reads and writes handle
fragmentation under one handshake deadline. Bidirectional forwarding propagates
half-close and applies idle/session time limits. The proofs authenticate the
handshake; subsequent stream integrity/confidentiality remains the native
transport's responsibility.

For UDP each record is a 32-byte HMAC, 16-byte hexadecimal Unix timestamp,
32-byte OS-random nonce, and the original payload. The MAC covers the directional
label (`S6EPE/2 request` or `S6EPE/2 response`) and the complete body. Both ends
verify the MAC before forwarding, accept timestamps within 30 seconds, and
reject repeated nonces. The cache holds at most 4096 entries for 61 seconds;
capacity exhaustion rejects new records rather than evicting live replay state.
Clock synchronization is required. Replay state is process-local: restart both
ends with a rotated key if restart-spanning replay protection is needed.

Each authenticated remote peer gets a connected UDP upstream socket, with
bounded idle and lifetime eviction. Replies return to the original peer with
fresh authentication. Zero-length native datagrams and exact payload boundaries
are preserved. Malformed, oversize or replayed packets do not terminate the
listener and do not create native upstream sockets.

## Observe and verify

Metrics are atomically replaced at most twice per second in an owner-controlled
directory. Existing output files must be private regular files. Observations
contain only schema, integer sample time, session/authentication/rejection
counts, and forwarded payload byte totals. Counters reset on process restart.
A client UDP session becomes authenticated after its first verified reply.

```sh
shadow6 privacy-envelope status --metrics /absolute/private/directory/server.metrics
make privacy-envelope-test
```

The test target builds only the optional envelope and runs real loopback stream
and UDP E2E. To verify an existing executable without building:

```sh
S6EPE_BINARY=/absolute/path/shadow6-privacy-envelope \
  .venv/bin/python -m unittest discover -s OCaml/privacy_envelope/test -p 'test_*.py' -v
```

These tests cover a local echo endpoint, hostile authentication inputs and
resource handling. They do not establish interoperability for every native Core
or certify network anonymity. See [named services](named-services.md),
[exposure review](privacy-envelope-exposure-audit.md) and
[the current verification record](review-2026-10-03.md).
