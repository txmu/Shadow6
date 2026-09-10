# Core-Gleam

`shadow6-gleam` is Shadow6's BEAM/Gleam core for Linux x86_64 and aarch64. Its
data plane is UDP `micro-mux`: every datagram is decoded in a temporary Actor
and every 16-bit StreamID has an isolated stream Actor. Malformed headers and
failed authentication terminate only that Actor.

The release binary is a musl static PIE. The build configures OTP 29 with
`--disable-jit`, compiles application BEAM files into C byte arrays, and links
the arrays and two static NIFs into ERTS. A patched primitive loader reads this
read-only in-memory ROM. It does not use Burrito, escript, a release directory,
or runtime extraction. OTP's external `inet_gethost` helper is replaced with a
pure BEAM resolver so the executable remains self-contained.

The default build has Crosed disabled. Set all three build variables for L5:

```sh
CROSED_LEVEL=5 APP_TRANSPORT=1 QUBES_ISOLATION=1 ./compile.sh
```

Toolchain downloads are explicit and digest-pinned. Run
`tools/fetch_toolchain.sh`, then `tools/build_toolchain.sh`; ordinary builds do
not access the network. `make test-gleam BUILD_GLEAM=1` runs Gleam tests, CLI
contract tests, and builds the final ELF.

The control plane accepts bounded WebSocket JSON-RPC 2.0 frames. Peers and the
broker authenticate each other with Ed25519 challenges. Config, trust, and
private-key files are opened with `O_NOFOLLOW | O_CLOEXEC`, then checked twice
for ownership, regular-file type, exact mode `0600`, identity, and size.
