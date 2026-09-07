# Core-Cpp

`shadow6-cpp` is the C++20 Shadow6 core. It is built with exceptions and RTTI
disabled and uses SCTP as its data-plane transport. SCTP streams are mapped to
tunnel channels and the transport API keeps a bounded set of peer addresses for
multi-homing failover. TLS and Ed25519 WebSocket authentication are represented
by explicit interfaces so the control-plane contract remains independent of the
platform TLS/SCTP implementation.

The default build is least privileged: Crosed, application transport, and
Qubes-inspired policy are disabled. The binary supports `--feature-report` and
`--check-config FILE`, matching the core CLI contract.
