# Core-D standalone authenticated stack

Core-D is a bounded BetterC broker/agent/client stack that runs without the
Network Adapter. Its authenticated WebSocket control plane authorizes a client
for a configured agent, then the client and agent establish a directly
authenticated X25519 secure stream. The client exposes a loopback TCP proxy and
the agent forwards it to its configured loopback target. `make test-d` builds
the stack and transfers a nontrivial random byte stream through three separate
Core-D processes and a real TCP echo target.

The native stream splits arbitrary TCP input into bounded 1,024-byte records.
Each direction has a distinct HKDF-derived ChaCha20-Poly1305 key, monotonically
increasing sequence numbers, authenticated close records, a 24-hour maximum
lifetime, and bounded socket/config operations. The broker never receives the
application plaintext. The optional Network Adapter remains available for
uniform multi-stream message semantics, but is not required for deployment.

Protocol version 2 replaces public-key-as-cipher-key data frames. A signed
Ed25519 hello authenticates an ephemeral X25519 exchange. The broker accepts
only identities in its configured clients/agents allowlists. The request
binds the intended broker key; the signed response binds the complete request.
HKDF-SHA256 derives separate client-to-server and server-to-client keys from
the shared secret and signed transcript. Old `S6DUDP01` frames are rejected.

The retained embedded UDP driver holds one active session, bound to the authenticated source address,
for at most sixty seconds. Only handshakes perform Ed25519 operations; the data
plane uses ChaCha20-Poly1305. Duplicate data receives authenticated ACKs, never
duplicate delivery. Session keys, handshake attempts, packet lengths and
sequence spaces remain bounded. The signed hello has a thirty-second validity
window and at most sixteen hello operations are accepted per second.

Data packets are `S6DUDP02`, kind byte, 16-byte session ID, big-endian 32-bit
sequence, big-endian 64-bit timestamp, big-endian 16-bit ciphertext length,
and RLE plaintext encrypted with a 16-byte AEAD tag. The nonce is kind followed
by three zeros, sequence, and the timestamp's low 32 bits. The entire header
is authenticated. A sequence identifies immutable content within a session;
retransmit its exact wire image. Sequence wrap closes the session.

`S6DHEL02` hellos contain kind (1 request, 2 response), 16-byte session ID,
64-bit timestamp, 32-byte Ed25519 identity, 32-byte X25519 ephemeral key,
32-byte binding (broker identity for request, request SHA256 for response),
and a 64-byte Ed25519 signature over all preceding bytes. Both signed hellos
form the HKDF salt transcript. This migration requires updated peers; it has
no unsigned or public-key-derived fallback.
