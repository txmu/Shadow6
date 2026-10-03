# OCaml External Privacy Envelope (S6EPE)

S6EPE is an optional authenticated outer layer between a configured public
transport and a local Shadow6 endpoint. It reduces unnecessary Shadow6-specific
identity exposure and authenticates before forwarding any bytes. Native Core
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
message boundaries.
