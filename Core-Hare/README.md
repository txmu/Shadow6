# Core-Hare

L0 Linux/FreeBSD emergency proxy. UDP datagrams are exactly 1024 bytes:
32-byte keyed session authenticator, 12-byte monotonic nonce, and 980-byte
ChaCha20 payload. Ed25519 remains the identity/session authorization primitive;
the 32-byte field is a fixed-size authenticator because Ed25519 signatures are
64 bytes and cannot be safely truncated.
The core has no Extensions/Crosed or Android integration. `hare` is optional;
`make core-hare` builds when installed and otherwise reports the toolchain gap.
