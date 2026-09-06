# Core-Zig

`shadow6-zig` is a third, complete broker/agent/client stack. It requires Zig
0.16.0 and a POSIX libc. Build with `make core-zig`; run the unit and loopback
integration tests with `make test-zig`. `make build BUILD_ZIG=1` and
`make install BUILD_ZIG=1 DESTDIR=...` opt into ecosystem builds/installations.
The existing default Go/Rust builds are unchanged.

## Contracts

The CLI supports `--config`, `--gen-key`, `--init-config ROLE`, `--check-config`,
`--feature-report`, `--crosed-request`, `--crosed-trust`, and `--daemon`.
Templates use `transport: "enet"`. Generated private files are mode 0600 and
existing template files are not overwritten. Configuration reads reject
symlinks, wrong owners, non-0600 modes, non-regular files, files over 1 MiB,
floats, duplicate/unknown fields, invalid UTF-8, numeric strings, and excessive
nesting. Integers are limited to the portable JSON safe-integer range.

Feature reports have the existing schema and `core: "shadow6-zig"`. This build
is L0: Crosed, application transport, and Qubes policy are disabled. Crosed
requests return the same flattened L0 denial contract. There is no Zig L5
variant and no in-process Plugin loading.

The existing Go and Rust **control wires differ**. Zig supports both without
changing either legacy core:

| Endpoint | Control contract |
| --- | --- |
| `/ws` | Go v1 text messages, Go signature domains |
| `/ws?control=rust` | Rust binary authentication challenges, JSON-RPC 2.0, Rust signature domains |

Zig agents/clients detect the broker's challenge dialect. Use matching
`broker_addrs` endpoints for both ends of a grant. Broker forwarding rejects
mixed-dialect grants: converting a signed request would invalidate its
end-to-end authorization. Methods are `Broker.UpdateIP`,
`Broker.RequestAccess`, and `Agent.GrantAccess`, including independent agent
authorization (the Rust wire spelling is `AgentRPC.GrantAccess`) and client
verification of the agent's access signature.
Go brokers rewrite transport to KCP; they cannot provision the Zig data plane.
Rust brokers likewise require QUIC access responses and reject ENet grants.
This does not make Go, Rust, and Zig data planes wire-compatible.

Non-loopback broker connections require WSS with hostname and system-CA
verification. Broker TLS termination is provided by an operator-managed reverse
proxy, as in the existing stacks. Optional HTTPS webhooks are bounded to four
workers. Owner-authored `on_success` hooks use argv parsing and fixed variable
substitution, with no implicit shell. Local discovery is rejected when enabled,
in accordance with the repository's prohibition on introducing scanning.

## ENet data plane

Shadow6 ENet v1 is a custom ENet-style reliable UDP protocol, **not** an
implementation of upstream ENet's wire format. The authenticated control grant
exchanges ephemeral X25519 keys under Ed25519 signatures. A SHA-256/HMAC
extract/expand schedule binds both ephemeral keys and the ENet protocol domain;
each random 128-bit channel identifier derives separate directional keys.
ChaCha20-Poly1305 authenticates the entire header and payload.

Datagrams are at most 1200 bytes:

| Bytes | Field |
| --- | --- |
| 0–3 | `S6EN` magic |
| 4–7 | Version 1, OPEN/DATA/ACK/FIN command, two zero reserved bytes |
| 8–23 | Random channel identifier |
| 24–31 | Directional AEAD nonce counter, big endian |
| 32–35 | Reliable sequence / acknowledged sequence, big endian |
| 36–39 | Reserved zero bytes |
| 40… | Encrypted payload followed by 16-byte authentication tag |

There is a 32-packet reliable window, ordered reassembly, authenticated ACKs,
exponential retransmission (200 ms to 3 s, at most eight attempts), congestion
backoff, half-close support, and wraparound rejection. Retransmission preserves
the original ciphertext. Duplicate reliable sequences are ACKed again without
being delivered twice. Retired channel IDs remain reserved for the grant's
lifetime. The loopback backend is contacted only after authenticated OPEN.

Linux uses native `io_uring` for UDP and tunnel TCP operations, batches up to
32 UDP sends per submission, and drains cancellation completions before
reusing request buffers. A denied/unavailable ring fails closed; Linux does
not silently switch to poll. Other POSIX targets use poll and nonblocking
socket operations. No host routes, firewall rules, or services are changed.

## Resource and deployment limits

Allocators are passed explicitly. Each control connection and tunnel owns a
bounded, lifecycle-scoped `ArenaAllocator`; packet processing does not allocate.
Application allocation errors propagate to connection/operation boundaries,
where OOM rejects work instead of panicking. Allocation-failure tests cover
parser unwinding. This cannot prevent a kernel OOM killer from terminating the
process or guarantee behavior of every external libc/kernel implementation.

Limits: 32 control peers, 32 pending broker calls, 16 active grants, 16 channel
IDs per grant, 64 KiB control frames, and 10-second control read deadlines.
Grant lifetime is bounded by `auto_close_after` (1–86400 seconds); individual
idle channels close after 60 seconds. This initial implementation favors bounded
resources; multi-gigabit throughput is not claimed without deployment benchmarks.

Android native build integration produces PIE executables packaged under
`libshadow6_zig.so`, matching the existing child-process runtime (not a JNI
library). The build needs a complete NDK sysroot and uses
`zig build -Dtarget=aarch64-linux-android -Dndk-sysroot=...` (also x86_64).
Android may deny io_uring through kernel or SELinux policy; ENet then refuses
startup. Android App and native cross-builds were not run for this change.
