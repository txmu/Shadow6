# Core-blind in both directions

Shadow6 has twelve independently compiled Native Cores. They share a
feature-report and security-contract vocabulary, but their native wire
protocols are not implicitly compatible. The surrounding components should
select a Core by its declared contract without depending on its scheduler,
packet layout, or transport implementation. Equally, a Core should be able to
run without knowing which control plane, identity service, or user interface
prepared its inputs. This is **bidirectional Core blindness**.

```text
Shadow6 reference stack ─┐
                         ├── Core boundary ── Native Core family
Other compatible stack ──┘

Shadow6 reference stack ── Core boundary ── future compatible engine
```

The diagrams describe an architectural goal. They do not mean that every
current Core, or an arbitrary transport engine, already implements a complete
common ABI.

## What can be replaced

An alternative outer stack could provide its own identity store, access
policy, discovery, orchestration, observability, and reliable-message layer.
It could drive one Shadow6 Core without running S6P1, S6AR1, Public6, S6NA,
or Control Center. The Core would still require valid native configuration,
credentials, endpoints, and role-specific bootstrap. Its own authentication,
wire format, resource bounds, and peer assumptions would still apply.

Conversely, Shadow6's outer components can use capability and data-flow
contracts without knowing the internals of all twelve implementations. A
future Core-X could participate after it implements the required contracts
and its own native peer path. A feature report alone does not make different
Core families wire-compatible. Public6 still requires a compatible native
family and exact version for a path, then negotiates optional capabilities
the peers share.

| Question | Meaning |
| --- | --- |
| Core compatibility | Can an outer stack configure and drive this engine through its local boundary? |
| Outer-stack compatibility | Can a component use the relevant Shadow6 control, identity, or message contracts? |
| Full-stack compatibility | Are the selected Core family, peers, and outer components compatible as a deployed path? |

Passing one of these checks does not imply the others.

## The boundary is the reusable asset

The intended boundary has three parts:

1. **Discovery:** `--feature-report` describes the compiled Core, version,
   and available ingress modes. Callers must also check documented role and
   platform limits.
2. **Control and bootstrap:** strict, bounded configuration supplies peer,
   credential, route, and lifecycle parameters. Current formats and startup
   conventions remain Core-specific in several places.
3. **Data and pressure:** a producer submits complete bounded messages. The
   Core reads them only while its native send window can admit more work.
   Output delivery, error signaling, and final completion need equally
   explicit contracts before this becomes a general-purpose Core ABI.

Control-plane requests can set up a flow; they should not sit on every packet
of a high-rate data path. An inherited local descriptor is a small operating
system primitive that an independent supervisor can create and hand to a
Core. The Core does not need to identify that supervisor as Shadow6.

## Current application ingress

The 2026-10-01 change `f16f7758` introduced the advertised `udp` and
`seqpacket-fd` ingress vocabulary and the first Carp runtime path. The
follow-up `deb6b12c` connected the Pony, Hare, and Idris client runtimes and
aligned bounded reads, EOF, and errors. These paths use
`SHADOW6_APP_FLOW_FD` as a strict decimal number for an inherited
`SOCK_SEQPACKET` socket. The variable is optional; UDP remains the default.
The descriptor mode currently supports the documented **client** roles, not
every broker or agent role.

Each record is one application message. The per-Core size limits remain:
Pony 1172 bytes, Hare 978 bytes, Carp 986 bytes, and Idris 1024 bytes. The
runtime stops reading the flow descriptor when its native reliable send
window is full. A bounded socket queue then blocks the producer or gives it
`EAGAIN`. The producer must handle retry according to its socket API.
`EAGAIN` and `EINTR` on the Core read side are transient; malformed or
oversized records are rejected. An empty record is treated as the local EOF
marker: new admission stops and accepted native frames drain before clean
completion. Invalid descriptors and hard read failures fail closed.

This is an **ingress and backpressure primitive**. A successful local send
means the kernel accepted a record into the socket queue. It does not prove
that the Core has read it, that it was authenticated for the remote path, or
that a peer received it. A crash can occur between those steps. A stronger
ownership guarantee would require an explicit admission acknowledgment and
defined recovery semantics. The reverse application path also retains
Core-specific UDP behavior; `seqpacket-fd` is not yet a universal egress ABI.

For Gleam Micro-Mux, local producer credit lives in the optional S6NA
companion. Python `application_credit()` and Node `applicationCredit()` count
available S6NA data-frame slots after accounting for queued and in-flight
fragments.
Flow-controlled send requires enough credit for every fragment of a message.
Both bindings report `S6NA_BACKPRESSURE` when capacity is exhausted,
`S6NA_CLOSED` after close, and `S6NA_RETRY_EXHAUSTED` at the retry limit.
These signals belong to S6NA; the native Gleam Micro-Mux wire
protocol did not gain an ACK or retransmission scheme.

## What still needs a stable contract

An independently replaceable Core boundary needs more than a mode name in a
feature report. Future versions should state, in machine-readable form where
practical:

| Area | Required meaning |
| --- | --- |
| Scope | Which binary, role, and platform actually accepts each ingress mode? |
| Messages | Maximum record size, framing, ordering, and malformed-record behavior. |
| Pressure | Credit unit, queue bound, blocking and `EAGAIN` behavior, and whether an accepted write has reached the Core. |
| Lifetime | Descriptor ownership, half-close, drain, restart, and failure signaling. |
| Egress | Destination, message boundaries, output pressure, and completion semantics. |
| Bootstrap | Credential encoding, native peer compatibility, route setup, and strict configuration versioning. |

The `app_transport` build flag and `app_transport_modes` list are different
concepts; a caller must not infer that `app_transport: false` disables a
separately reported local ingress mode. The mode list also does not express
client-only scope. Those ambiguities should be resolved before third parties
treat the vocabulary as a frozen ecosystem ABI.

The long-term shape is three independently replaceable layers: policy and
identity, adapter or reliability companion, and Native Core. Shadow6 ships a
reference combination of them. Replacing a layer remains the integrator's
responsibility: the replacement must preserve the relevant authentication,
bounded-resource, lifecycle, and native peer contracts.
