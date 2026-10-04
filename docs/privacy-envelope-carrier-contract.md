# S6EPE Carrier/Adapter Contract v2

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
messages with channel ID, portable uint32 PPID, ordered/unordered delivery and reliable, retransmission
limited or lifetime limited delivery. Messages have a strict size budget; channel
IDs and reliability budgets are checked. Empty messages remain messages.
`None` means no event available, while channel-close, stream-reset, association-closing/closed/restarted and send
abandonment are explicit separate events. Native SCTP reset does not become a
channel-close and does not reset an authenticated envelope replay counter. A send returns `Accepted` or `Backpressure`; a refused
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

The Linux native SCTP provider is implemented in `Carrier_sctp` and conforms to
`MESSAGE`. It accepts only established one-to-one SCTP associations explicitly
prepared with at most 64 streams. It preserves PPID and ordered/unordered flags,
reassembles at most one bounded message until native EOR, refuses empty SCTP user
messages, and rejects oversized or abandoned partial messages without emitting
a prefix. Kernel queues and buffers, application assembly and message size are
bounded. Send refusal is whole-message backpressure. PR-SCTP retransmission/time
budgets are native send options; receive metadata cannot reveal the sender's
budget, so the provider takes an explicit agreed per-stream receive policy.

Stream reset requests retain direction and denial/failure notifications and
streams remain reusable afterwards. Association shutdown/EOF and restart are
separate events. Restart needs a fresh authenticated envelope session; it is
not evidence that old key/replay state can continue. Descriptors remain caller
owned and providers release their own native state. The Linux backend is
unavailable on other systems; raw/TLS compilation remains supported there.
`Raw_stream` rejects Linux SCTP even though that socket reports `SOCK_STREAM`.

Actual loopback C and OCaml tests verify stream IDs, ordering, full uint32 PPID,
PR send options, 128 KiB native fragmentation, whole-message backpressure retry,
reset notifications/reuse, shutdown, unestablished/TCP rejection and oversized
receive rejection. The source-built envelope now integrates this provider in
`mode=message,carrier=sctp` with a complete-message handshake and independent
directional AEAD, per-channel replay windows and ratchets, authenticated reset
watermarks, partial-reliability abandonment notices and FINAL. Whole-message
retry retains identical pending ciphertext. Sender-dry events are checked
against current kernel send allocations after earlier failure events have been
consumed; a stale event cannot certify later sends. Real envelope loopback tests
verify opaque messages, metadata, wrong-proof rejection before opening native
upstream, and authenticated association close. Feature reports advertise SCTP
only where the native backend is available. These component tests do not certify
twelve-Core deployment compatibility. WebRTC's dedicated provider and actual
ICE/DTLS/DataChannel deployment integration remain required.

## Native WebRTC provider and current integration boundary

`Carrier_webrtc` implements `MESSAGE` using the pinned libdatachannel 0.23 C API.
It creates and owns a genuine PeerConnection and explicitly negotiated
DataChannels; no Native Core signalling format is inspected. It accepts bounded
standard SDP offers/answers, waits for complete nontrickle ICE gathering, and
reports establishment only after native ICE, DTLS and all admitted channels are
open. Transient ICE/peer disconnection remains pending under the handshake or
session deadline; an explicit failed state closes immediately. DTLS verifies the fingerprint in the remote SDP. The independent S6EPE
PSK proof remains mandatory after transport establishment. A wrong DTLS
fingerprint and a wrong envelope PSK are distinct tested failures.

Channel ID, ordered/unordered policy and reliable/retransmit/lifetime policy
are fixed before negotiation. Peers must explicitly agree those negotiated
channel attributes. Native binary/text messages retain individual boundaries;
the adapter uses logical PPIDs 53/51 and does not expose a byte stream. A
DataChannel has fixed ordering/reliability, so a send with different attributes
is rejected. Empty binary and text messages are supported. The C API's text
send uses a NUL-terminated string: embedded-NUL text cannot be sent and is
explicitly rejected rather than truncated. Standard text must be valid UTF-8;
overlong encodings, surrogates and invalid scalar values are rejected. Binary
messages have no such text limit.
Opaque send context is local metadata, not transmitted; this API does not
provide per-message PR abandonment confirmations. No such evidence is invented.

Whole-message send admission checks native buffered amount against a 256 KiB
bound. One native accepted message is never partially retried. Receive callbacks
copy into a bounded queue and never access OCaml values. Queue exhaustion is
terminal, rather than silent message loss. Each peer admits at most 64 channels,
73,728 bytes per message, 128 queued events and 16 MiB queued payload; all peers
together reserve at most 64 MiB of queue budget and 128 peer slots. The pinned
backend uses a fixed worker pool based on online CPU count (minimum four);
initialization rejects hosts above 256 online CPUs. The provider supplies no
STUN/TURN servers implicitly. Application/session deadlines still belong to
the security engine and operator realization.

`rtcClose` starts native DataChannel closure; a closed callback proves native
completion. This is distinct from an authenticated S6EPE close command and
watermark. Closing one channel leaves other channels usable. Peer destruction
removes the callback registry before deleting native channels and the peer, so
late callbacks cannot dereference freed provider state. SDP renegotiation and
peer restart require a fresh security session rather than reusing ratchet state.

Source-built C/OCaml loopback tests establish actual ICE/DTLS connections and
verify channel metadata, text/binary and empty message boundaries, PR policies,
whole-message backpressure/retry, closure, queue exhaustion, DTLS fingerprint
failure and independent encrypted envelope authentication/replay/close controls.
`Webrtc_bridge` now joins an established encrypted S6EPE DataChannel session to
an independently established native DataChannel association. It keeps at most
one pending complete message in each direction, preserves channel metadata and
native backpressure, forwards authenticated close requests to the local peer,
and requires authenticated close/FINAL before successful return. A six-peer
loopback test covers two independent ICE/DTLS associations per process. This is
still a library boundary: executable `carrier=webrtc` configuration, a standard
signalling handoff, deployment integration and process-owned ICE/runtime
observation remain unimplemented. `message_adapters` continues to advertise
only deployable SCTP. Core-specific boundaries remain independently declared.

To source-build this optional Linux provider with the pinned dependency in a
private prefix, set `S6EPE_RTC_INCLUDE` to its `include` directory and include its
`lib` directory in the build/test library search path. The executable resolves
only `libdatachannel.so.0.23`, with no configurable library filename. Without
these headers/runtime the provider reports unavailable; raw/TLS/SCTP builds
continue to work. `S6EPE_WEBRTC_REQUIRED=1` makes the dedicated CI tests fail if
this optional backend is missing, rather than accepting a skip as coverage.

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
