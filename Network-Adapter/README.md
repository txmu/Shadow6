# Unified network adapter

Python and Node.js are equal, wire-compatible backends for one bounded message
API. They automatically
segments, encrypts, numbers, acknowledges, retransmits, deduplicates and
reassembles data while applying per-Core payload and window limits. Up to 64
logical streams share a session; a 16 MiB in-flight ceiling provides
backpressure and each message is limited to 16 MiB.
Only a bounded sliding window is released to the carrier; ACKs open space for
queued chunks, and exhausting eight retransmissions fails the session visibly.
Streams are scheduled round-robin, incomplete reassembly expires after 30
seconds, and non-retransmitted ACKs update a bounded SRTT/RTTVAR-based RTO.

Policies are capability-based. All twelve Cores have independently deployable
native transports, so every catalog mode is `native`. The adapter is an
optional normalization layer for shared reliable-message, segmentation,
multiplexing and backpressure semantics; it is never a deployment prerequisite.
D and Gleam provide native authenticated broker/agent/client streams, while
the smaller datagram/cell cores retain their documented native bounds.

Frames use a versioned strict header and ChaCha20-Poly1305 AEAD. Directional
keys are independently derived from the 32-byte master key, so equal stream and
message numbers in opposite directions cannot reuse an AEAD key/nonce pair.
Deployments must provision an independent random 32-byte adapter key through
an owner-controlled secret file; do not reuse Core identity keys. Extension
events have a distinct frame type, portable JSON bound to 4 KiB, and an
explicit per-session allowlist. Extensions and the adapter itself are disabled
until selected by policy.

`ReliableAdapter.send(stream, data)` accepts the complete caller buffer and
returns transport-sized frames. Feed received frames to `receive`; send its ACK
frames back through the same Core path and deliver only completed messages.
Call `retransmit` from a bounded timer. Transport integrations must preserve
the Core family's documented endpoints and must not expose a new public
listener.

`DatagramEndpoint` is an optional ready-to-use carrier for datagram families.
It accepts numeric bind and peer addresses, pins every
received packet to that peer, authenticates before allocating reassembly state,
and exposes completed messages rather than chunks. Binding a non-loopback
address is an explicit deployment choice; firewall and VM boundaries remain
the operator's responsibility.

The normative protocol and state limits are in `SPEC.md`. Python is the
reference carrier and installed-core auditor; Node.js 20+ is the equal
high-concurrency backend and uses only built-in modules—there are no npm runtime
dependencies. `test_conformance.py` and `test_node.mjs` enforce the same fixed
AEAD vector, cross-backend decoding, large-message behavior and failure rules.
Neither backend may introduce a private wire extension.

`benchmark_backends.py` runs the same 4 KiB, 64 KiB and 1 MiB codec-loop cases
at requested concurrency 1/16/64, capped by the shared 16 MiB state budget. It
is a regression comparison, not an end-to-end network claim. Backend status is
based on protocol conformance and carrier behavior, not on declaring whichever
runtime wins one machine's microbenchmark. Use the repository performance
matrix for real Core paths, RTT/loss conditions and WAN deployments.

Inspect policies and the installed executables without compiling anything:

```sh
python3 Network-Adapter/shadow6_network.py catalog
python3 Network-Adapter/shadow6_network.py audit --bin-dir "$HOME/.local/bin"
PYTHONPATH=Network-Adapter python3 -m unittest Network-Adapter/test_network.py
PYTHONPATH=Network-Adapter python3 -m unittest Network-Adapter/test_conformance.py
node --test Network-Adapter/test_node.mjs
PYTHONPATH=Network-Adapter python3 Network-Adapter/benchmark_backends.py
```
