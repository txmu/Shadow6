# OCaml External Privacy Envelope (S6EPE)

S6EPE is an optional authenticated outer layer between a configured public
transport and a local Shadow6 endpoint. The reference runtime requires a
configured secret key, performs a nonce/HMAC challenge for stream sessions, and
requires an HMAC-prefixed datagram before forwarding. It reduces unnecessary
Shadow6-specific identity exposure and authenticates before forwarding any bytes. Native Core
wire protocols, magic values, frame layouts, cryptography, ACKs,
retransmission, and peer compatibility are unchanged.

The envelope does not provide traffic invisibility, DPI bypass, or third-party
protocol impersonation. IP addresses, timing, packet sizes, traffic shape and
endpoint relationships remain observable. Unauthenticated failures are bounded
and deliberately generic. Native payloads are opaque bytes and are never parsed
by the envelope.

`privacy = "native"` remains the default. Explicit deployments may select
`privacy = "envelope"`; the local Core endpoint should use loopback, Unix or
an inherited descriptor. UDP-only Core families use the datagram-preserving
capsule mode; stream Core families use stream mode. Both preserve native
message boundaries. A deployment must provide `auth_key` (16..256 bytes) and
must treat the key as a protected secret reference; pre-auth failures are
closed without reaching the Core.
