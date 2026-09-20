# Core-Gleam

`shadow6-gleam` is Shadow6's BEAM/Gleam core for Linux x86_64 and aarch64. Its
standalone deployment data plane is an authenticated, direction-keyed TCP
secure stream. The retained UDP `micro-mux` packet engine is available for
bounded datagram applications: its active-once listener authenticates before
creating a stream Actor, and invalid packets allocate no actors. A 128-packet
replay bitmap per stream survives Actor termination; the session retains at
most 4096 replay records and fails closed at capacity.

Replay state is currently in memory for one key-owning session. Restarting
with the same configured key does not preserve it; a fresh authenticated
session-key exchange is required before claiming protection across restarts.
Broker, agent and client roles form a complete standalone forwarding path.
Mutually authenticated WebSocket control authorizes the requested agent;
Ed25519-signed ephemeral X25519 keys then establish a direct encrypted TCP
stream between client and agent. Directional HKDF keys, bounded 32 KiB records,
authenticated close records and a fixed stream lifetime protect the native
data path. The release tests launch three separate Core-Gleam processes and
transfer more than 256 KiB through a real TCP echo target. The Network Adapter
is optional and is not part of this deployment path.

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
The contract tests invoke `--test-packet-security` against the static NIF,
including invalid-tag floods across 4097 stream IDs and replay tombstones.

The control plane accepts bounded WebSocket JSON-RPC 2.0 frames. Peers and the
broker authenticate each other with Ed25519 challenges. Config, trust, and
private-key files are opened with `O_NOFOLLOW | O_CLOEXEC`, then checked twice
for ownership, regular-file type, exact mode `0600`, identity, and size.
