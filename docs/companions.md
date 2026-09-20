# Companion capability boundaries

Shadow6 has two interchangeable Network Adapter companions. They implement
the same `S6NA/1` protocol and are optional normalization layers; no Core must
load or depend on either companion to obtain native network capability.

| Companion | Runtime boundary | What it provides | What it does not provide |
| --- | --- | --- | --- |
| Python Network Adapter | Python 3, `Network-Adapter/shadow6_network.py` | Reference `S6NA/1` codec, carrier integration, installed-Core audit, conformance vectors and bounded retransmission state | It does not replace a Core, translate native Core protocols, or start an implicit public listener |
| Node.js Network Adapter | Node.js 20+, `Network-Adapter/shadow6_network.mjs` | Wire-compatible high-concurrency `S6NA/1` codec and carrier integration using built-in modules only | It does not add a private wire extension, replace Core authorization, or require npm runtime dependencies |

Both companions provide the same bounded message contract:

- up to 64 logical streams per session;
- 16 MiB aggregate in-flight/reassembly state and 16 MiB maximum logical message;
- authenticated ChaCha20-Poly1305 records with independent direction keys;
- segmentation, ordered reassembly, duplicate suppression, ACKs and bounded retransmission;
- eight failed retransmissions before a visible session failure;
- 30-second expiry for incomplete messages and bounded SRTT/RTTVAR-based RTO;
- extension events only as typed data for the signed out-of-process Extension/Slot system.

The companions accept a complete caller message and emit transport-sized
records. They must preserve the selected Core's endpoint and deployment
limits, and they must not silently add a public listener, firewall rule, route,
or host service. A datagram carrier pins the configured numeric peer and
authenticates before allocating reassembly state.

The 32-byte adapter key is session-specific and must be stored separately from
Core identity keys in an owner-controlled `0600` secret file. Python and Node
are cross-tested against the same vectors; a backend is conforming only when it
decodes the other backend's records and applies the same failure rules. The
normative record format and limits are in [`Network-Adapter/SPEC.md`](../Network-Adapter/SPEC.md).
