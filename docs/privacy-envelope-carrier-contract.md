# S6EPE Carrier/Adapter Contract v1

The carrier boundary separates S6EPE authentication, encryption, replay and
shaping from transport I/O and external appearance. It is implemented as typed
OCaml module interfaces in [carrier.mli](../OCaml/privacy_envelope/src/carrier.mli).
Handshake and stream record engines instantiate those interfaces; native Core
bytes are opaque application content. No Core protocol, control grant or ABI is
parsed by a carrier. Providers are compiled component implementations, not Slots,
Plugins, operator-supplied callbacks or host commands.

## Stream operations

`STREAM` supplies nonblocking read/write, deadline-bound handshake waiting,
joint local/carrier readiness polling and send-half shutdown. A partial read or
write is normal; zero bytes from read means transport EOF and never an empty
message. Providers own buffering and their physical readiness mapping. A buffered
TLS/WebSocket/QUIC provider must report available decoded bytes even when the
physical socket has no new readable bytes, and must bound all buffering. The
security engine must receive only decoded carrier bytes, including the complete
S6EPE hello. It must not open a second raw connection to exchange proofs.

The handshake is generic in `Forward.Make_handshake`; the record bridge is
generic in `Session.Make`. The active default wrappers instantiate `Raw_stream`,
preserving the existing v3 wire and least-privileged configuration. Partial
handshake I/O is tested with a separate provider type and the resulting keys
are tested in both directions. Raw-provider tests exercise readiness and
half-close. This abstraction alone does **not** provide camouflage. The implemented
`Carrier_tls` provider uses genuine mutually authenticated TLS 1.3, including
S6EPE hello encapsulation, buffered readiness, partial I/O, backpressure and
authenticated half-close. Its bounded finish step consumes peer close_notify
and rejects further application bytes after envelope FINAL. See the
[configuration and tested limits](privacy-envelope.md#standard-tls-carrier).

## Message operations

`MESSAGE` is a separate interface. It receives complete events and sends complete
messages with channel ID, ordered/unordered delivery and reliable, retransmission
limited or lifetime limited delivery. Messages have a strict size budget; channel
IDs and reliability budgets are checked. Empty messages remain messages.
`None` means no event available, while channel-close and association-close are
explicit separate events. A send returns `Accepted` or `Backpressure`; a refused
send retains caller ownership and cannot silently discard or partially emit a
message. Close requests obey the same bounded admission rule.

An SCTP provider owns association establishment, stream mapping, message
reassembly, notifications and stream reset. A WebRTC provider owns signalling,
ICE, DTLS and SCTP establishment, negotiated channel policy and lifecycle. Neither
may concatenate messages to satisfy `STREAM`. Delivery metadata must be bound
to the authenticated encrypted envelope record, not trusted merely because the
carrier reports it. Ordered channels can maintain independent sequence/ratchet
state; unordered channels require replay windows and independently decryptable
records. Do not apply one ordered secretstream state across unordered messages.

The message interface and metadata bounds are present. Dedicated SCTP/WebRTC
providers and an authenticated message engine are not yet implemented by this
change; they remain required for completion. Interface declarations are not
transport capability reports.

## Wire appearance and evidence

Raw v3 exposes its hello magic. Moving it into a genuine standard carrier means
the outer endpoint first establishes that carrier and the hello travels as
carrier content. A natural encrypted carrier can conceal the inner hello from
passive wire inspection; an unencrypted framing change alone cannot. Deleting or
randomizing magic is not camouflage. SCTP alone exposes its message content;
WebRTC/DTLS, authenticated TLS or an explicitly authenticated encrypted SCTP
carrier have different observable security/appearance properties.

Keep these claims separate in configuration, observations and exposure audits:
native identity disclosure, traffic-analysis shaping and actual carrier
camouflage. Certificate properties, SDP/signalling, IPs, timing, volume and
active response behavior may still identify a deployment. Standards compliance
does not establish anonymity, DPI resistance or blocking resistance. Each real
provider needs its own interoperability, failure, boundary, backpressure and
wire-observation tests before advertising support. See the
[exposure audit](privacy-envelope-exposure-audit.md).
