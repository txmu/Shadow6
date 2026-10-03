# S6P1 services, connection plans and BrokerSets

S6P1 is the portable logical/admission context: Core scope, role, identity,
routes, components and credentials (including Passport, Visa and Public6
invitations). A concrete Core id constrains the local binding; `all` or a bounded
list of candidate ids permits filtering. Multiple compatible candidates require
an explicit selection. Imported Core descriptors use the same catalog contract.
`shadow6 core import FILE` persists a private local descriptor index
so subsequent service and connect commands can use that identity.

Core-Blind does not imply native wire compatibility. Ordinary topology nodes
and BrokerSet members use the same engine family, validated by Deployment's
shared `topology_contract` and Auto-Orchestrator. A portable BrokerSet route's
optional `engine` fixes that family even when the context permits several
candidate Cores. Legacy Deployment generates this route engine from BrokerSet
intent and rejects incompatible node bindings. Zig's explicit Go/Rust Broker
control declaration retains the Go/Rust native invocation; it is not a general
cross-Core translator. Distinct independent BrokerSets may describe separate
topologies, each with its own enforced family.

A Named Service is the persistent local lifecycle object. Registry v2 embeds
`protocolContext` and keeps only TTL and peripheral configuration references in
`spec`. It has no duplicate role, identity, credentials or routes. CoreBinding
holds the explicit native executable/config realization. DeploymentLock v2
includes the S6P1 context digest, descriptor/binary/native configuration digests,
privacy and optional EPE/Gate/Guard configuration/binary digests. Runtime holds
PID/process identity, actual sockets, ready events and observations. None of
those local facts belongs in S6P1, and telemetry is excluded from the lock.

S6P1 component intent constrains local realization: `gate`, `guard` and `s6epe`
set to `false` cannot be enabled by local config references; `true` requires the
corresponding explicit realization (`s6epe` requires envelope privacy). Omitted
flags retain unspecified legacy intent. Lock/apply/run validate Passport/Visa
scope for the actual role and each deployed component using the existing S6P1
admission validator. Credential-bearing deployment with neither a logical nor an
observable native role is rejected. Public6 Gate provisioning enforces the same
Gate component and requested-role admission before lookup or file generation.

Legacy intent-free registries migrate automatically on the next transaction.
Records with ambiguous native intent, declared endpoint addresses or simulated
runtime state fail closed with an explicit recreation error. They never become
running merely because a recorded PID exists.

## One connect resolver

`shadow6 connect home/nas` resolves the name into its S6P1 context, locked binding
and actual runtime endpoint. `shadow6 connect --protocol-envelope S6P1...`
resolves portable intent. Invitations and join codes retain Public6 provisioning,
then return the same `shadow6.connection-plan.v1` model. A name and a token are
resolve sources for one pipeline.

The plan distinguishes `planned`, `provisioned` and a real application session.
It reports Core, context digest, binding, observed endpoint/readiness, declared
application boundary/S6ABI and BrokerSet realization. A plan never claims
`connected:true`. Public6 config generation is provisioning, not a running
session. Native Broker listeners are not application sockets.

For a running native client that emits the existing loopback TCP application
ready event, `shadow6 connect home/nas --stdio` actually opens its observed
application proxy and forwards stdin/stdout. `libshadow6.Shadow6.connect(name)`
returns a bounded session with `send`, `receive` and `close`. Both recheck the
endpoint's process ownership. Sessions are limited to 300 seconds, 30 seconds
of socket inactivity and 16 MiB. Unsupported/message/credited boundaries return
an explicit plan/capability error; their native adapters remain available through
their existing interfaces.

Readiness progresses only with evidence: `process-alive`, process-owned
`listener-ready`, or an owned endpoint with a validated `application-ready`
event. Transport/application readiness otherwise remains `unknown`; absent or
stale observations are unavailable. No desired route is copied into runtime.

## Explicit local lifecycle example

Prepare a working native **client** config for an existing Broker/Agent path,
using one explicitly selected Core consistently. The example selects Go as an
operator choice; the resolver has no default or preference for it.

```sh
umask 077
mkdir -p "$HOME/.config/shadow6"
# Prepare /absolute/path/client.json using that Core's README first.
printf '%s\n' '{"config_path":"/absolute/path/client.json"}' > "$HOME/.config/shadow6/binding.json"
python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, 'Public6')
from join_code import pack_protocol
context = {'schema':'shadow6.protocol-envelope.v1','version':1,
 'purpose':'local-service','core':'go','role':'client','identity':{},
 'routes':[{'boundary':'stream'}], 'components':{}, 'credentials':{}}
path = Path.home()/'.config/shadow6/nas.s6p1'
path.write_text(pack_protocol(context)+'\n'); path.chmod(0o600)
PY
shadow6 init --json
shadow6 service create home/nas --core go \
  --config "$HOME/.config/shadow6/binding.json" \
  --protocol-file "$HOME/.config/shadow6/nas.s6p1" --ttl 3600
shadow6 lock home/nas
shadow6 apply home/nas
shadow6 run home/nas
shadow6 status home/nas --json
# Equivalent idempotent setup: same context, config, privacy and binding reuse PID.
shadow6 setup home/nas --core go \
  --config "$HOME/.config/shadow6/binding.json" \
  --protocol-file "$HOME/.config/shadow6/nas.s6p1" --ttl 3600
shadow6 connect home/nas --json
# Only when status reports an observed application-ready stream endpoint:
shadow6 connect home/nas --stdio
shadow6 restart home/nas
shadow6 stop home/nas
```

The token-generation snippet runs from a source checkout. Installed users can
import an existing portable S6P1 file. A changed logical identity, config, Core or
privacy policy requires `stop` and explicit `service configure`, followed by a
new lock/apply. Changing Core never happens as a fallback.

## BrokerSet route intent

A BrokerSet is a route inside S6P1, not `NamedService.brokers[]`:

```json
{"kind":"broker_set","id":"home","policy":"round_robin","boundary":"stream",
 "members":[
  {"identity":"broker-a","endpoint":"tcp://192.0.2.10:14433","public_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  {"identity":"broker-b","endpoint":"tcp://192.0.2.11:14433","public_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
 ]}
```

Replace example addresses/keys with operator-controlled endpoints and trust
material. `priority` uses bounded integer member priorities; `round_robin` and
`random` select among available members. Observed availability is supplied
separately to the selector; unknown health remains unknown. The native-single
adapter accepts one member and explicitly rejects more. Peripheral selection
supports multiple members without rewriting twelve native wire protocols.

Gate realizes TCP/UDP pools through its existing `remote_hosts`/`upstreams` and
`load_balance` fields. The remote-host adapter requires matching transport and
port and an explicit common trust key; it produces actual Gate config fields,
including a fixed MTD range for that declared port. Different per-endpoint trust
identities and priority policy remain unavailable through this Gate adapter.
Named Service locking validates this Gate configuration against S6P1 and checks
that the native broker address targets the explicit private Gate listener.
Named connection resolution derives its adapter from that locked realization;
an incompatible explicit adapter is rejected. Neither pool selection nor
short-lived health observations enter the deployment digest.

TCP paths try the selected member first, then each remaining explicit member on
connection failure, within a shared ten-second budget. Retries stop when a TCP
connection is established; authentication failures fail closed, and established
sessions are never replayed or migrated. UDP retains per-path selection without
retrying application datagrams. This does not fabricate endpoint health checks,
quorum, state replication or seamless migration of existing sessions.

Legacy Deployment `brokerSets` and single-Broker topologies remain accepted.
`node_context` projects their existing intent into S6P1; an explicit node context
must match the same BrokerSet. Auto-Orchestrator accepts multiple Brokers through
`global.broker_adapter` with `kind: gate`, an S6P1 `context`, owner-only absolute
`config_path`, and a private `local_endpoint`. The supplied enabled Gate client
config must match the route-derived hosts/trust/policy and local endpoint. It
emits native configs targeting that stable endpoint and per-node Gate sidecars.
Its native-only SSH activator explicitly refuses to attest/activate a multiple
process stack; local Named Service supervision can own Gate with the native
process, while `init_system: none` can stage artifacts for operator activation.
Native datagram trio adapters retain their explicit cardinality limit.

## Perimeter and cryptographic layers

Legal optional stacks are `S6EPE -> Core`, `Guard -> S6EPE -> Core`,
`S6EPE -> Gate -> Core`, and `Guard -> S6EPE -> Gate -> Core`.

Guard provides exposure/perimeter policy: SPA/IP windows, rate control,
AntiProbe, Broker Shield and TLS/Web facade. An unlocked IP window is not a
session authentication decision. S6EPE supplies authenticated encrypted outer
sessions; unauthenticated input never allocates a native upstream. Gate supplies
an authenticated encrypted Shadow6 path with peer identity,
Ed25519/X25519/HKDF/AES-GCM, relay, MTD and multiple endpoints. Core owns native
protocol/data-plane semantics. Every layer remains optional where compatible.

Named services take explicit `--gate-config`/`--guard-config` references. Gate
must explicitly be enabled. Under `privacy=envelope`, the admission endpoint is
EPE, Core listeners must be literal loopback, and an intermediate Gate server
must also listen privately. EPE upstream must match an actually observed
Core/Gate listener; Guard forwarding features must target EPE. All critical
processes share supervision and terminate if one exits. EPE config/binary drift
invalidates the lock.

S6EPE v3 encrypts its outer stream/datagram payloads, with explicit bounded
optional stream padding/jitter/cover records. It does not provide anonymity,
DPI-proof transport or undetectability. Gate retains routing/relay/BrokerSet
responsibilities; S6EPE does not translate native wire families. See the
[versioned wire and replay/shaping limits](privacy-envelope.md).

## Verification state

Focused tests use Python fixtures, process-owned loopback sockets, staged
installation and existing optional native binaries. Existing local Core binaries
may predate current source contracts; no fabricated feature report is used to
make them pass. Native rebuilding, all-Core audits and platform matrices run in
GitHub Actions. Passing local source/fixture tests is not evidence that stale
native binaries implement the new source contract.

Observed application readiness is checked against the selected Core descriptor
and S6P1 role/boundary intent before a session launcher is advertised. A stream
ready event must match a process-owned TCP listener; a UDP socket cannot prove
stream readiness. Linux socket observations decode native-endian address words
on both little- and big-endian hosts. These checks do not change native protocols.

The local supervisor launch plan carries only the file digests already committed
by CoreBinding/DeploymentLock. It rechecks native and all deployed EPE/Gate/Guard
configuration and executable bytes before spawning, and again before startup
success. Launch schema, component pairs and lifetime bounds are strict. This
closes ordinary drift between apply and launch without adding local paths or
binary digests to S6P1. Files remain owner-controlled deployment inputs; these
checks do not claim protection against a malicious process with the operator's
own privileges continuously racing file replacement.

Runtime observations have an exact bounded schema: nonempty unique critical PID
identities, socket facts and defined readiness levels. Status rechecks child
ownership and actual listener ownership; stale/missing observations and stopped
processes expose unavailable readiness. A fresh file alone cannot turn a desired
route or another live process into a ready endpoint. Envelope observations keep
EPE as the public endpoint and cannot substitute a native application endpoint.

The observer bounds 4096 FDs, 65536 rows per proc socket table, 4096 bytes per
row and 64 owned listeners. Exceeding these budgets produces an explicit error;
results are not silently truncated into a claim of private exposure or readiness.
Transport authentication readiness remains unknown until a supported proof
contract exists; a socket alone does not establish it.

Explicit `connect --role` enters the same role/admission/capability resolver for
Named Service, S6P1 and Public6 sources. A role-neutral S6P1 context can constrain
a request without being rewritten; its context digest stays unchanged. Named
Service role requests must match the locked native realization; an opaque or
unspecified native role returns capability unavailable. Named connection inputs
are captured and checked under one registry transaction, and failed connection
to a stopped service leaves it stopped.

The supervisor preserves the original S6P1 in its locked launch plan, rechecks
admission during runtime and rehashes material at bounded five-second intervals.
Expired admission or material drift shuts down the critical component group.
Restart verifies approved material before stopping an existing healthy group.
