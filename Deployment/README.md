# Shadow6 deployment and S6ABI/1

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
