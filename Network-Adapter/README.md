# Unified network adapter

This pure-Python layer gives callers one bounded message API. It automatically
segments, encrypts, numbers, acknowledges, retransmits, deduplicates and
reassembles data while applying per-Core payload and window limits. Up to 64
logical streams share a session; a 16 MiB in-flight ceiling provides
backpressure and each message is limited to 16 MiB.
Only a bounded sliding window is released to the carrier; ACKs open space for
queued chunks, and exhausting eight retransmissions fails the session visibly.

Policies are capability-based. Ada, Pony, Hare and Carp require the adapter;
Gleam may enable it for shared concurrency/backpressure behavior. Go, Rust,
Zig, Nim and C++ normally retain their native reliable stream/fragmentation.
D and Idris use `companion-required`. D's installed executable proves only its
fixed 4-byte benchmark input; Idris has authorization and diagnostic loopbacks
but no production broker/agent/client data plane. For both, `DatagramEndpoint`
provides the adapter-owned authenticated, pinned-peer UDP carrier rather than
pretending that the native Core implements a transport it does not have.

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

`DatagramEndpoint` is the ready-to-use carrier for Idris/D companion mode and
for datagram families. It accepts numeric bind and peer addresses, pins every
received packet to that peer, authenticates before allocating reassembly state,
and exposes completed messages rather than chunks. Binding a non-loopback
address is an explicit deployment choice; firewall and VM boundaries remain
the operator's responsibility.

Inspect policies and the installed executables without compiling anything:

```sh
python3 Network-Adapter/shadow6_network.py catalog
python3 Network-Adapter/shadow6_network.py audit --bin-dir "$HOME/.local/bin"
PYTHONPATH=Network-Adapter python3 -m unittest Network-Adapter/test_network.py
```
