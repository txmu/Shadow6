# S6NA/1 network-adapter protocol

S6NA is the optional shared normalization layer for all twelve Shadow6
Cores. Python and Node.js are equal backends. An implementation is conforming
only when it passes the same cross-backend vectors and failure tests.

## Record format

All integers are unsigned network byte order. A record is the 32-byte header,
encrypted payload, and 16-byte Poly1305 tag.

| Field | Bytes | Rule |
|---|---:|---|
| magic | 4 | ASCII `S6NA` |
| version | 1 | `1` |
| kind | 1 | `1` data, `2` ACK, `3` extension |
| reserved | 2 | zero |
| stream | 8 | 0..63 |
| message | 8 | monotonic per direction and stream; exhaustion requires rekey |
| chunk index | 2 | less than chunk count |
| chunk count | 2 | 1..65535 |
| plaintext length | 4 | within the selected Core policy |

ChaCha20-Poly1305 authenticates the entire header as associated data. The
nonce is the first 12 bytes of SHA-256(`shadow6-network-nonce-v1` || header).
The two direction keys are HMAC-SHA-256(master,
`shadow6-network-v1:` || direction-byte). Side 0 transmits with direction 0
and receives direction 1; side 1 does the reverse. A 32-byte master key is
unique to one session and must not be reused after either side restarts its
message counters. Rotation means establishing a new session with a freshly
generated key; in-band key replacement is deliberately forbidden.

## State and reliability

- Messages are 1 byte through 16 MiB and callers never segment them.
- At most 64 streams, 16 MiB aggregate outbound/reassembly state, and the
  policy window may be outstanding at once.
- Queues are serviced round-robin across streams. ACKs release window space.
- Duplicate chunks are ACKed but never delivered twice. The last 4096 complete
  message identities form the replay window.
- Incomplete messages expire after 30 seconds. Eight failed retransmissions
  fail visibly; no message is silently discarded.
- Initial RTO is 200 ms. Non-retransmitted ACK samples update SRTT/RTTVAR using
  RFC 6298-style coefficients, clamped to 50 ms..5 seconds. Retransmission uses
  exponential backoff.
- A carrier processes at most 64 datagrams per poll and accepts packets only
  from its configured numeric peer. Deployments provide firewall/VM policy.

## Extensions

Extension records never execute callbacks. They return typed events to the
caller, which may pass them to the signed out-of-process Extension/Slot system.
Names require an explicit session allowlist. Values use canonical portable
JSON: no floats, duplicate keys, nonportable integers, excessive nesting, or
payloads above 4 KiB. Extensions default off.

## Core policy

Every Core is independently deployable with its documented native bounds.
S6NA may be selected when uniform reliable segmentation, multiplexing, larger
logical messages, or common backpressure behavior is desired; no policy mode
requires an external companion.
