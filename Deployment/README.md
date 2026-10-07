# Shadow6 deployment and S6ABI/1

Optional S6EPE v3 deployment preserves opaque native stream, datagram or message
semantics with mandatory encrypted payloads. Raw/TLS, Linux SCTP, and Linux
libdatachannel WebRTC have distinct carrier contracts. Named Service owns the
bounded private S6SG1 broker for an explicit Nim/WebRTC Profile, requires fresh
v6 active authenticated-session telemetry plus an owned UDP socket for startup,
and rejects WebRTC/Gate composition. Configuration, native/component materials
and fixed runtime inputs are locked and rechecked; a repository-local optional
WebRTC provider is included when present. See the
[envelope guide](../docs/privacy-envelope.md) and
[Named Service lifecycle](../docs/named-services.md) for provider/platform limits.

S6SG1 binds each SDP state to both session ID and E/N leg; outer and native
offers/answers cannot overwrite each other. Its waiting clients and read deadlines
are bounded. The [Test Lab](../docs/wan-pcap-test-lab.md) exercises release S6EPE
endpoints across directional namespace/veth links at the Native Agent application
target, with explicit workload attachments and dual outer/inner capture evidence.

CLI `status`/`doctor` and the read-only Control Center service page share the
validated readiness evidence view. Runtime/application readiness and availability
of a new attachment remain distinct, including an already active one-flow session.
Doctor exposes the existing locked LimitResolution and component capacity model;
human CLI output shows protocol/host ceilings, recommendations, operator requests,
effective values and enforcers. Web UI limit values come from the locked resolution.
S6SG1 waiter capacity is derived from resolved sessions and included in host
descriptor/memory admission; Lab probe/capture fixture limits do not become daily
service ceilings. Drift still requires explicit stop, review and relock.

`shadow6.deployment.v1` is a strict, Core-neutral intent document. It names
logical Broker endpoint sets, node identities, loopback services, policies and
application requirements. It never contains private keys or native Core
arguments. `shadow6 deployment plan` translates it into a bounded plan that an
installed Core driver can apply without rebuilding the Core.

`S6ABI/1` is a process-boundary application contract. Control frames are
length-prefixed canonical JSON; data frames are bounded binary records. The
ABI reports the selected Core and its guarantees instead of pretending that
the twelve native wire protocols are compatible. S6AR1 carries control-plane
requests and S6P1 carries admission context.

Use the single acceptance gate:

Reference deployments are Core-explicit. Core-Blind means the data path does
not need to know the control UI; it does not make Core identity invisible.
There is no implicit Core selection: automation may eliminate incompatible
candidates, but it must not choose among multiple compatible Core families.
Every locked deployment and named service carries a CoreBinding and normalized
configuration digest.

An ordinary topology uses one engine family. Each node CoreBinding must match
its BrokerSet's Core; Gate failover does not translate native protocols.
`topology_contract.py` is the shared fleet/node admission authority. The explicit
legacy Zig Broker control declaration may accompany Go or Rust, with that
Go/Rust engine still owning the native invocation. It does not permit mixed
Agent/Client data planes. A BrokerSet S6P1 route may declare `engine` to retain
this constraint when portable Core scope is `all` or a candidate list.

Auto-Orchestrator remains a topology/fleet controller and operational executor
(SSH/SFTP, init activation, credentials, MTD, SPA, RPC and dashboard). Deployment
owns node/service realization; it does not acquire fleet scheduling or SSH.

```sh
shadow6 acceptance --manifest Deployment/example.deployment.json --source-only
```

CI supplies native feature reports and checksums with `--artifact-dir`. Cases
that cannot be run are explicitly `unavailable` or `not-run`; they are never
silently treated as native verification.

## Named service implementation

Use [the install/run lifecycle guide](../docs/named-services.md) for actual local
process supervision, explicit locks, drift rejection and privacy observations.
`shadow6_driver.invocation` describes the S6ABI external-driver contract; Named
Service uses each built-in family's native CLI and does not assume every native
executable accepts S6ABI driver flags. Application readiness consumes validated ready events and checks process ownership of
the announced endpoint. Listener observations and process liveness remain distinct;
transport/application facts without evidence stay unknown.

## S6P1 context and lock v2

Named Services embed S6P1 portable intent; CoreBinding holds explicit native
realization, and Runtime holds process/endpoint observations. DeploymentLock v2
locks the logical context digest, including BrokerSet routes. Legacy manifests
project to S6P1 through `node_context`; explicit node contexts must agree with
their realization. See [the shared contract](../docs/service-connections.md) for
connection plans, four optional perimeter stacks and a complete lifecycle.
