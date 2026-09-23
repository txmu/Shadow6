# Core capability matrix

Shadow6 has twelve independently compiled Core implementations. They share
feature-report and security-contract vocabulary, but their native protocols
are independent and are not implicitly wire-compatible. A topology must use
one Core family consistently at every hop.

| Core | Native roles | Native data path | Important boundary |
| --- | --- | --- | --- |
| Go | broker, agent, client | WebSocket control; authenticated encrypted KCP | Linux default build; bounded KCP tunnels and sessions |
| Rust | broker, agent, client | WebSocket JSON-RPC control; certificate-pinned QUIC | Unix/Unix-like target; Linux is the exercised CI platform |
| Gleam | broker, agent, client | Mutually authenticated WebSocket control; encrypted TCP stream | BEAM-based static PIE; Linux x86_64/aarch64 release path |
| Ada | broker, agent, client | Authenticated WebSocket control; bounded encrypted cell relay | SPARK-oriented implementation; native Unix toolchain required |
| Nim | broker, agent, client | Authenticated WebSocket control; libdatachannel-backed UDP | Optional Nim/libdatachannel toolchain; bounded native profile |
| Pony | broker, agent, client | Authenticated reliable UDP with session routes and retransmission | UDP-only; no WSS/QUIC/KCP compatibility claim |
| Zig | broker, agent, client | Go/Rust control dialects; authenticated reliable UDP | Optional Zig toolchain; data plane is not Go/Rust wire-compatible |
| D | broker, agent, client | Authenticated WebSocket control; X25519/ChaCha20-Poly1305 stream | BetterC profile; retained UDP driver is single-session |
| C++ | broker, agent, client | TLS 1.3 WebSocket control; SCTP tunnel data | Kernel SCTP support is required; independent C++ protocol |
| Idris | broker, agent, client; legacy relay | Signed X25519 admission and encrypted fixed-peer UDP | 1024-byte application datagrams; bounded signed-chain ACK/retry, no multi-client routing |
| Hare | broker, agent, client; legacy endpoint | Signed fixed-route IPv6-loopback UDP | 978-byte datagrams; bounded ACK/retry, one session, no discovery/multiplexing |
| Carp | broker, agent, client; legacy codec/adapter | Signed fixed-route IPv4-loopback UDP with directional layer keys | 986-byte datagrams; native three-role ACK/retry, one session |

“Can deploy independently” means that a Core's documented native path can run
without the Network Adapter or any other Companion. It does not mean that all
Cores have the same reliability, multiplexing, platform support, or
wire format. The optional Network Adapter supplies uniform authenticated
message semantics for callers that need them; it is never a prerequisite for a
Core's native network capability.

The default build keeps Crosed, application transport and Qubes-inspired
domain policy disabled. Explicit `*-crosed` or Public6 variants are separate
build products. Optional toolchains may be unavailable on a given host; use
`shadow6 features`, the component doctor, and each Core README to inspect what
is actually installed and enabled.

Benchmark defaults cover all 36 core/backend pairs, using actual native trios
and identical bounded application workloads. Companions remain optional in
deployment; tests select them explicitly without changing installed settings.
See [Benchmark contracts](../Benchmark/README.md) for pressure semantics and
the distinction between independent-trio concurrency and session multiplexing.

See the [runtime and reliability review](network-runtime-review-2026-09.md) for
retry bounds, legacy-mode differences and verification scope.
