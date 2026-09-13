# Core-Pony (incomplete prototype)

Pony reference-capability prototype for Shadow6. `Main` splits `Env` into
opaque `NetAuth` and `FileAuth` authorities; actors cannot obtain ambient OS
authority through these interfaces. Example payloads cross actor boundaries as
consumed `iso` values and OCapToken stores immutable bytes. `crypto/session.c`
now contains a bounded Ed25519/X25519/ChaCha20-Poly1305 handshake/data-frame
boundary with replay and lifetime checks, covered by native negative tests. It
is wired into real UDP actors and a strict configuration loader. A two-process
loopback integration test verifies encrypted binary payload round trips.

The explicit build reports L0 and supports a pinned-peer loopback UDP tunnel.
L5 builds fail explicitly; Plugin RPC, full A/B/C, external network deployment,
reconnection and Go/Rust feature parity remain unimplemented.
Future Plugins must remain signed, bounded and out-of-process.
OCap does not prohibit arbitrary native FFI syscalls; that needs a compiler FFI
allowlist and OS isolation. Immutable tokens are shared immutable memory.
No end-to-end zero-copy or throughput advantage over Go has been measured.

Build with `make core-pony` (requires `ponyc`, or the pinned tool under
`.tools/ponyc-0.72.0`). Windows IOCP and Termux portability depend on Pony's
platform runtime and are deployment properties, not claims made by this
source-only prototype.
