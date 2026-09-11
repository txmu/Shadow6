# Core-Carp

L0 Carp 0.5.5 core, compiled to C and linked with libsodium. Build with
`bash Core-Carp/compile.sh`; provision Carp separately using `CARP_DIR` and
optionally `CARP`. Ordinary builds never download a toolchain.

`compile-schema` reads `api_schema.json` at macro expansion and emits nested C
switch statements. The currently supported finite JSON Schema is the const
object `{"op":"forward","version":1}`. Its canonical wire form is exactly 28
bytes; unsupported schemas fail the build. Each consumed byte takes one state
transition; an unexpected byte rejects immediately. Reading a complete frame
is O(n), not O(1). This is not a general-purpose JSON Schema implementation.

Onion frames are 1144 bytes: three 40-byte headers (24-byte nonce, 16-byte
XChaCha20-Poly1305 tag), followed by a 1024-byte body. Each layer authenticates
its index, protocol version and entire nested ciphertext. A failed tag clears
the complete packet and keys before returning. Carp passes packet references
to the C cryptographic boundary; runtime authentication is explicit, not a
property automatically enforced by the borrow checker. Packet processing uses
fixed stack buffers, no allocator, no runtime evaluator and no plugin hooks.

Offline codec:

```
shadow6-carp --gen-key keys.bin
shadow6-carp --encode keys.bin < input > packet
shadow6-carp --decode keys.bin < packet > output
```

The 96-byte key file must be owned, regular, non-symlink and exactly mode 0600.
Offline keys are three independent symmetric keys. Payloads are bounded to 994
bytes. Offline decoding intentionally has no session or replay state.

Online commands: `--listen CONFIG LOCAL_PORT PEER_PORT` and
`--send CONFIG LOCAL_PORT PEER_PORT`. They bind/connect IPv4 loopback only.
The sender streams stdin; the listener writes authenticated payloads to stdout.
Online CONFIG is a distinct 96-byte format: own Ed25519 seed, pinned peer public
key, then a shared 32-byte deployment binding. Configure reciprocal peer keys.
The signed challenge/response authenticates ephemeral X25519 keys; the
transcript, shared secret, deployment binding and layer index derive fresh
layer keys. Online packets reserve eight payload bytes for a strictly increasing
sequence; replay state advances only after all tags and the schema pass.

Each process admits one peer/session, at most one million iterations and five
minutes. A hard process deadline also bounds blocked I/O. This is a unidirectional
UDP byte-stream adapter, not a reliable transport, broker or anonymity network.
Loss and reordering can discard data. Three-layer cryptography does not itself
provide three independent routing hops. Only Linux is currently tested; other
POSIX platforms require a compatible C/linker toolchain and libsodium.
