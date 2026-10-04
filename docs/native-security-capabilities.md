# Native security capabilities

The [machine-readable inventory](../Crosed/security_capabilities.json) covers the
twelve independent native families. It describes source contracts of the native
broker/agent/client data paths, with explicit legacy-mode limitations. It does
not certify a deployed process, prove a cryptographic implementation correct,
or imply interoperability. The existing feature-report catalog supplies family
and transport names; this inventory does not add a shared wire format or ABI.

Statuses have precise scope:

- `native`: a control is implemented by the family itself.
- `transport`: the native transport library provides the control. A library
  capability does not prove a configured update schedule or platform behavior.
- `limited`: a relevant control exists but does not cover the full stated threat.
- `mode-dependent`: the selected native or retained legacy mode changes the claim.
- `not-declared`: the source contract makes no positive capability claim. This
  is neither a proof of absence nor permission to assume that the control exists.

<!-- matrix:start -->
| Core / native transport | authentication | encryption | fresh_keys | persistent_replay | rekey | replay | session_lifecycle | shaping |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| shadow6-go / kcp | native | native | native | not-declared | not-declared | limited | native | not-declared |
| shadow6-rust / quic | native | transport | transport | not-declared | transport | transport | transport | not-declared |
| shadow6-gleam / secure-stream | native | native | native | not-declared | not-declared | native | native | not-declared |
| shadow6-cpp / sctp-tls13 | native | transport | transport | not-declared | transport | transport | transport | not-declared |
| shadow6-zig / enet | native | native | native | not-declared | not-declared | native | native | not-declared |
| shadow6-ada / cell-relay | native | native | native | not-declared | not-declared | native | native | native |
| shadow6-d / secure-stream | native | native | native | not-declared | not-declared | native | native | not-declared |
| shadow6-nim / webrtc | native | transport | transport | not-declared | not-declared | transport | native | not-declared |
| shadow6-pony / udp | native | native | native | not-declared | not-declared | native | native | not-declared |
| shadow6-hare / udp | native | native | native | not-declared | not-declared | native | native | native |
| shadow6-carp / udp | native | native | native | not-declared | not-declared | mode-dependent | native | native |
| shadow6-idris / udp | native | native | mode-dependent | not-declared | not-declared | native | native | not-declared |
<!-- matrix:end -->

Each JSON row supplies bounded descriptions, source references and legacy-mode
limitations. Read those descriptions before making a deployment decision. In
particular, Go's ordered KCP transport and discovery replay cache do not imply
an independent AEAD receive-counter check. Carp's offline symmetric transform
has no session or replay state. Idris's legacy PSK link requires key rotation
before restart for cross-restart replay threats. Gleam actor replay tombstones
survive actor termination inside one live key-owning session, not a process
restart with the same configured key. Hare/Carp/Idris retained datagram modes
have their own boundaries and lifecycles.

No family here declares a durable native **data** replay ledger. Crosed signed
request replay ledgers protect authorization, not arbitrary native data. Fresh
handshake traffic secrets prevent old-session ciphertext from authenticating in
a fresh session; that is distinct from persisting a nonce ledger across restarts.
Transport key updates, new connections and application ratchets are different
controls. Padding caused by fixed native cells is distinct from bounded outer
jitter/cover and does not establish resistance to traffic analysis.

S6EPE v3 is an independent authenticated encrypted outer security domain. Its
keys, replay state, ratchet and resource budgets are independent of native Core
cryptography. Rust QUIC, C++ TLS/SCTP and Nim WebRTC/DTLS already provide native
security. An outer envelope is an explicit policy choice, not evidence that
those Cores were plaintext or insecure. Guard controls perimeter/exposure; Gate
routes and selects; S6NA manages pacing/credit/backpressure. Those responsibilities
must not be counted as additional payload encryption domains. Preserve natural
native wire appearance when an extra outer domain is unnecessary. See
[composition](service-connections.md) and [S6EPE](privacy-envelope.md).

Verify schema, family coverage, source references and documentation without
building a Core:

```sh
.venv/bin/python Crosed/security_capabilities.py --check-sources --markdown
PYTHONPATH=Crosed .venv/bin/python -m unittest -v Crosed/test_security_capabilities.py
.venv/bin/python shadow6_audit.py --source-only
```

The verifier rejects unknown/duplicate fields, numeric JSON values, cross-family
or escaping source paths, missing controls, transport mismatches and oversized
input. Source-marker checks detect stale references; they do not prove all
semantic assertions. Runtime and cryptographic negative tests remain necessary.
The table is generated from the inventory and a test rejects documentation drift.
