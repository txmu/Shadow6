# Core-D authenticated UDP driver

Core-D is a bounded BetterC UDP driver and benchmark, not a Go/Rust-equivalent
broker/agent/client service. Its default feature report keeps optional
capabilities disabled. `make test-d` builds the driver and runs real loopback
cryptographic and protocol tests.

Protocol version 2 replaces public-key-as-cipher-key data frames. A signed
Ed25519 hello authenticates an ephemeral X25519 exchange. The broker accepts
only identities in its configured clients/agents allowlists. The request
binds the intended broker key; the signed response binds the complete request.
HKDF-SHA256 derives separate client-to-server and server-to-client keys from
the shared secret and signed transcript. Old `S6DUDP01` frames are rejected.

The driver holds one active session, bound to the authenticated source address,
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
