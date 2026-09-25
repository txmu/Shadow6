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

Online commands: `--listen CONFIG LOCAL_PORT PEER_PORT [A|B|C]` and
`--send CONFIG LOCAL_PORT PEER_PORT [A|B|C]`. Omitting the mode preserves the
legacy simplex A contract. B and C are explicit bidirectional/full-duplex
contracts; the selected mode is authenticated in the handshake and packet
associated data, so mismatched modes fail closed. They bind/connect IPv4
loopback only.
The sender streams stdin; the listener writes authenticated payloads to stdout.
Online CONFIG is a distinct 96-byte format: own Ed25519 seed, pinned peer public
key, then a shared 32-byte deployment binding. Configure reciprocal peer keys.
The signed challenge/response authenticates ephemeral X25519 keys; the
transcript, shared secret, deployment binding and layer index derive fresh
layer keys. Online packets reserve eight payload bytes for a strictly increasing
sequence; replay state advances only after all tags and the schema pass.

Each process admits one peer/session, at most one million iterations and five
minutes. A hard process deadline also bounds blocked I/O. This is a unidirectional
UDP byte-stream adapter, not a reliable transport or anonymity network.
Loss and reordering can discard data. Three-layer cryptography does not itself
provide three independent routing hops. Only Linux is currently tested; other
POSIX platforms require a compatible C/linker toolchain and libsodium.

## Native broker/agent/client mode

The offline codec and online `--send`/`--listen` A/B/C modes remain available.
New roles expose real bidirectional UDP application sockets:

```sh
shadow6-carp --broker broker.pins 41000 41002 41004
shadow6-carp --agent agent.keys 41004 41000 9000
shadow6-carp --client client.keys 41002 41000 8000
```

All addresses are IPv4 loopback. Applications send to UDP port 8000 and the
agent forwards to the UDP service on 9000. All three configuration files are
96-byte owner-controlled, non-symlink, mode-0600 regular files. Endpoint files
contain their own Ed25519 seed, the other endpoint's public key and an equal
random 32-byte deployment binding. Broker files contain 32 zero reserved bytes,
the client's public key and the agent's public key; never private keys.

The broker verifies both signed ephemeral handshake messages and their shared
challenge before routing fixed-size ciphertext between configured ports. It
has no decryption key. Endpoints derive distinct client-to-agent and
agent-to-client layer keys under a separate `T` contract, retain the compiled
Carp schema check and enforce monotonic replay state. The maximum application
datagram is 986 bytes. One application source, one session and one fixed route
are supported. Five-minute/one-million-iteration bounds apply; broker admission
expires after five seconds and route inactivity after 60 seconds. The `T`
contract now uses a bounded 256-datagram selective-repeat send window and a
256-datagram reorder buffer. It retransmits each exact authenticated ciphertext
packet every 200 ms up to eight times, delivers in sequence, and ACKs only after
application delivery. An authenticated marker in the otherwise-zero padding
distinguishes ACKs from empty application datagrams; the signed `S6W2` marker is
required in both handshake legs. Retry exhaustion ends the session; multi-client
routing and stream semantics remain unsupported.

`integration/stack_test.py --engine shadow6-carp --benchmark` evaluates all
three backend paths through the real native trio, without stdin/stdout routing
or an internal benchmark protocol.
