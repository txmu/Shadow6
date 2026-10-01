# Unified network adapter

Python and Node.js are equal, wire-compatible backends for one bounded message
API. They automatically
segment, encrypt, number, acknowledge, retransmit, deduplicate and
reassembles data while applying per-Core payload and window limits. Up to 64
logical streams share a session; a 16 MiB in-flight ceiling provides
backpressure and each message is limited to 16 MiB.
Only a bounded sliding window is released to the carrier; ACKs open space for
queued chunks, and exhausting eight retransmissions fails the session visibly.
Both backends retain queued message bytes and encrypt each chunk only when it
enters the send window, avoiding full-message ciphertext allocation on send.
Only active streams are visited while scheduling; reassembly byte accounting
is constant-time per chunk.
Streams are scheduled round-robin, incomplete reassembly expires after 30
seconds, and non-retransmitted ACKs update a bounded SRTT/RTTVAR-based RTO.

Those values are safe defaults, not immovable deployment limits. Both backends
accept the same `shadow6.s6na-limits.v1` document (see
`s6na-limits.example.json`) at process startup. Message, stream, in-flight,
window, expiry and extension limits can be raised within compiled absolute
caps. The file is strictly parsed, bounded, owner-controlled and rechecked
after opening. A running adapter keeps an immutable limits object: changing the
file has no effect until the companion is deliberately restarted.

Policies are capability-based. All twelve Cores have independently deployable
native transports, so every catalog mode is `native`. The adapter is an
optional normalization layer for shared reliable-message, segmentation,
multiplexing and backpressure semantics; it is never a deployment prerequisite.
All twelve provide native authenticated broker/agent/client paths; each keeps
its documented stream/datagram/cell, platform and resource bounds.

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
reference carrier and installed-core auditor; Node.js 24 LTS (minimum 22) is the equal
high-concurrency backend and uses only built-in modules—there are no npm runtime
dependencies. `test_conformance.py` and `test_node.mjs` enforce the same fixed
AEAD vector, cross-backend decoding, large-message behavior and failure rules.
Neither backend may introduce a private wire extension.

`benchmark_backends.py` and `benchmark_node.mjs` delegate to the common
12-core × 3-path Benchmark runner. Both companions traverse the same real
native trio as the native row; no codec-loop result substitutes for network
throughput. Deployments need not enable companions to test them: activation is
explicit and isolated to the test. `Benchmark/performance_matrix.py` applies
the same 4 KiB/64 KiB/1 MiB logical workloads, response-delay scenarios and
bounded independent-trio concurrency to all 36 pairs. Reports include library
driver IPC and distinguish application writes from native datagram limits.
See [Benchmark](../Benchmark/README.md); codec conformance and 64-stream state
tests remain separate correctness tests.

Inspect policies and the installed executables without compiling anything:

```sh
python3 Network-Adapter/shadow6_network.py catalog
python3 Network-Adapter/shadow6_network.py audit --bin-dir "$HOME/.local/bin"
PYTHONPATH=Network-Adapter python3 -m unittest Network-Adapter/test_network.py
PYTHONPATH=Network-Adapter python3 -m unittest Network-Adapter/test_conformance.py
node --test Network-Adapter/test_node.mjs
PYTHONPATH=Network-Adapter python3 Network-Adapter/benchmark_backends.py
```

### Python runtime modes

The Python CLI and Python Companion prefer an installed, dependency-compatible
CPython 3.14 free-threaded runtime (`.venv-ft`, then installed interpreters).
They probe cryptography imports and the **actual** GIL state before selecting.
If unavailable, they use compatible regular Python 3.14 or the existing Python
3.11+ environment. Nothing is downloaded automatically. `SHADOW6_PYTHON` selects
an explicit interpreter; `PYTHON_GIL=1` enables the GIL in a free-threaded build.
Do not force `PYTHON_GIL=0` to bypass an incompatible extension. Selection is
reported on stderr, preserving Companion JSON IPC on stdout. Library imports
always retain the caller's interpreter.

`ReliableAdapter` serializes public state changes with a per-instance reentrant
lock, including sequence allocation, ACK processing and backpressure accounting.
Independent adapters can be driven by independent threads; a single adapter's
ordered state is intentionally serialized. Do not mutate its internal containers
or share a `DatagramEndpoint` socket between polling threads. Removing the GIL
does not itself guarantee a throughput improvement.

CI tests regular 3.14, 3.14t with GIL enabled, and 3.14t with its default GIL
disabled on Linux, macOS and Windows x64. Post-import GIL assertions prevent
mislabelled results. Windows runs portable codec/concurrency checks and component
benchmarks; platform-specific secret-file deployment checks remain separate.

### Gleam transport profiles

The catalog's `profiles` distinguishes `gleam` (secure stream) and `gleam-mux`
(Micro-Mux UDP). Both Python and Node constructors accept the explicit profile
name; callers using `gleam` can pass `transport="micro-mux"` in Python or the
final `transport` argument in Node. DatagramEndpoint accepts the same selection.
The UDP profile uses 1100-byte payloads and a 64-frame window, authenticated
ACK/retry, deduplication and reassembly under existing message/memory/retry
limits. Payload overrides above 1100 bytes fail closed. Deterministic tests
cover missing, reordered, duplicate and tampered chunks in both backends.

Micro-Mux transport itself provides **no availability guarantee whatsoever**.
The adapters also expose local producer credit (`application_credit()` in
Python, `applicationCredit()` in Node) and flow-controlled send helpers. ACKs
restore credit; this local API adds no wire message and does not alter the
1100-byte profile or native Core flow control.
The native path stays native; Companion features are explicit and require both
endpoints. The network-chain benchmark now has 39 combinations (12 cores,
13 transport profiles, 3 backends). Component-only matrices with 12 families
retain their own declared dimensions.

`application_credit()` / `applicationCredit()` is measured in complete S6NA data
frames that may be admitted within the configured window, including queued and
in-flight messages. `send_flow_controlled()` / `sendFlowControlled()` accepts a
message only when all of its fragments fit the currently available frame
credit; ordinary `send()` retains bounded queueing behavior. ACKs restore one
frame of credit. After close, available credit is zero and operations fail with
`S6NA_CLOSED`; exhausted credit or bounded queue pressure uses
`S6NA_BACKPRESSURE` in both language bindings; retry exhaustion is
`S6NA_RETRY_EXHAUSTED`. Endpoint close is idempotent and
clears endpoint timers, queues, pending frames, and reassembly state. This is local
producer admission for the optional Gleam Micro-Mux companion path; it changes
neither the Micro-Mux nor native Core wire format.
