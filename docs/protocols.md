# Shadow6 protocol collection

Shadow6 contains several bounded protocols. They serve different layers and
are not one universal wire format. Unless a document says otherwise, a Core
protocol is compatible only with the same Core family and protocol version.

## Control and native Core protocols

| Protocol family | Used by | Purpose and boundary |
| --- | --- | --- |
| Go control WebSocket | Go and compatible Zig endpoints | Broker/agent/client authentication and access requests; Go's KCP data grant is not a generic Core wire |
| Rust control WebSocket/JSON-RPC 2.0 | Rust and compatible Zig endpoints | Strict control RPC and signed access authorization; Rust's QUIC data grant remains family-specific |
| Gleam WebSocket JSON-RPC | Gleam broker, agent and client | Mutual authentication and authorization before a direct encrypted TCP stream |
| Ada authenticated WebSocket | Ada broker, agent and client | Access authorization for the bounded cell relay |
| Nim WebSocket control | Nim broker, agent and client | Broker authorization and bounded libdatachannel-backed UDP forwarding |
| D WebSocket control | D broker, agent and client | Signed request/response authorization for the X25519 secure stream |
| C++ `shadow6-cpp-wss-v1` | C++ broker, agent and client | TLS 1.3 WebSocket control with pinned Ed25519 identities; data uses SCTP |
| Zig dual control dialects | Zig with Go- or Rust-style brokers | Zig can speak the Go or Rust control dialect, but grants must keep the matching data plane; it does not make those planes compatible |

These control protocols authenticate identities, bind the requested client and
agent, and enforce allowlists before the data path starts. They are bounded
control messages, not arbitrary command channels. Cross-family conversion of a
signed request is rejected when it would invalidate the authorization binding.

## Native data protocols

| Protocol | Core | Shape |
| --- | --- | --- |
| KCP encrypted tunnel | Go | Reliable encrypted data with bounded tunnel/session windows |
| Certificate-pinned QUIC | Rust | Multiplexed encrypted streams with bounded connection and stream windows |
| Authenticated TCP stream | Gleam | Direction-keyed records, authenticated close, fixed stream lifetime |
| Cell relay | Ada | Bounded authenticated cells over the Ada control/data path |
| Reliable UDP v2 (`S6Q1`/`S6Q2`, `S6E`) | Pony | Authenticated handshake, ordered window, ACKs and bounded retransmission |
| ENet-style v2 (`S6EN`) | Zig | Custom reliable UDP with authenticated channels, ordering and congestion bounds; not upstream ENet wire format |
| D secure stream (`S6DHEL02`, `S6DUDP02`) | D | Signed X25519 hello and directional ChaCha20-Poly1305 records |
| TLS/SCTP tunnel | C++ | TLS-protected SCTP association per tunnel with TCP half-close semantics |
| Fixed-peer authenticated UDP relay | Idris | One configured client/agent pair; no native broker or multi-client routing |
| Fixed-peer authenticated UDP proxy | Hare | One pinned peer/session; no broker discovery or multiplexing |
| Carp online adapter | Carp | Fixed-frame authenticated UDP byte stream; no broker topology |

Native paths are independently deployable and intentionally retain different
transport limits. The Network Adapter can normalize messages above these paths,
but it does not translate one native wire protocol into another.

## S6NA/1 Network Adapter protocol

`S6NA/1` is the optional shared normalization protocol implemented by the
Python and Node.js companions. A record has the `S6NA` magic, version, kind,
stream and message identifiers, chunk metadata, and plaintext length. The
header is authenticated as associated data with ChaCha20-Poly1305. Directional
keys come from a unique 32-byte session key; key replacement is out of band.

The protocol supports 64 streams, 16 MiB aggregate state, 16 MiB logical
messages, duplicate suppression, ordered reassembly, bounded ACK/retransmit
state, and typed extension events. It is not a public service protocol and
does not permit arbitrary callbacks or commands. See
[`Network-Adapter/SPEC.md`](../Network-Adapter/SPEC.md).

## Application and policy protocols

| Protocol | Purpose |
| --- | --- |
| ProtocolFactory framing | Versioned bounded 32-bit application frames; unknown versions and malformed lengths fail closed |
| ShadowChat | Ed25519 identity plus ChaCha20-Poly1305 encrypted chat messages with replay control |
| ShadowIdentity | Expiring signed identity assertions for application-level authorization |
| Crosed grant protocol | Signed requests reduced by build level, Mod level, capabilities and domain policy; it is a compile-time Core boundary, not plugin loading |
| Public6 capability negotiation | Bounded signed Ed25519 offers; exact Core family/version is the base compatibility gate and optional capabilities negotiate by intersection |
| Plugin/Slot RPC | Signed, out-of-process, resource-bounded JSON contracts; providers cannot inject code into a Core |

## Gate protocol

Gate is an independently compiled, default-disabled authenticated middle hop.
Its TCP path uses ephemeral encrypted frames and its UDP path uses signed
envelopes. Gate can be placed before a Client, behind an Agent or Broker, or
between them; it forwards an existing Core path and does not rewrite the Core
wire protocol. High-port mutation is deterministic and bounded, and Gate must
never be enabled silently by a build or install step.

## Compatibility rules

- A Core family is compatible with itself only when its protocol version and required configuration agree.
- Go, Rust and Zig control dialects have explicit adapters in Zig, but Go KCP, Rust QUIC and Zig ENet data planes remain distinct.
- S6NA/1 is cross-backend compatible between Python and Node.js, not a universal replacement for native Core protocols.
- Public6 negotiates optional features; it does not make unrelated native protocols wire-compatible.
- Unknown versions, fields, record kinds, floats in signed portable JSON, invalid lengths and replayed credentials fail closed.
