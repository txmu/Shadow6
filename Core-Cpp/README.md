# Core-Cpp

`shadow6-cpp` is an independent C++20 broker/agent/client stack. It is built
with exceptions and RTTI disabled. The control plane uses mutually authenticated
TLS 1.3 WebSockets with pinned Ed25519 identities. The broker applies client to
agent policy and signs 30-second, nonce-bearing access tickets. The data plane
uses a TLS 1.3 protected SCTP association per tunnel and preserves TCP
half-close semantics.

The default build is least privileged: Crosed, application transport, and
Qubes-inspired policy are disabled. The binary supports the common
`--feature-report`, `--config FILE --check-config`, and `--config FILE`
contracts. It also provides `--keygen` and `--init-demo NEW_DIRECTORY`; the
latter writes owner-only example broker, agent, and client configurations
without starting listeners.

Core-Cpp has its own versioned `shadow6-cpp-wss-v1` control protocol. It is a
complete alternative stack and is not wire-compatible with Core-Go or
Core-Rust. Agent targets and client entry listeners are loopback-only. All
configuration files must be regular, non-symlink, current-owner files with
exact mode `0600` and a maximum size of 1 MiB.

Example:

```sh
./shadow6-cpp --init-demo /tmp/shadow6-cpp-demo
./shadow6-cpp --config /tmp/shadow6-cpp-demo/broker.json
./shadow6-cpp --config /tmp/shadow6-cpp-demo/agent.json
./shadow6-cpp --config /tmp/shadow6-cpp-demo/client.json
```

The generated target defaults to loopback port 22. Review all addresses before
starting the processes. Run `bash test.sh` for strict parser, ticket/replay,
mutual-authentication, ACL, half-close, concurrency, and three-process loopback
SCTP tests. The host kernel must support SCTP.
