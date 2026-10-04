# Unified tools, Connect and native datagram adapters

`shadow6 tools` lists the fixed component routes and their availability.
`shadow6 TOOL --help` forwards help/options directly to that tool. The router
includes Connect, Crosed, extensions, EasyBuild, Detector Neo, Virtual Adapter,
interface setup, Guard control, iperf tools, performance collection, audit,
Python runtime inspection, the four-core native configuration adapter and
native key generation. Existing control, plugin, package, security,
infrastructure, Slot, Public6, init and all twelve Core routes remain available.
Availability depends on the installed components; listing never starts them.

The `extensions` route is the component-layer integration point for the
2026-09-01 to 2026-09-06 Extension integration. It validates the signed Crosed request,
then delegates to the signed Plugin/Slot boundary; it does not add a Core wire
mode or accept arbitrary host commands. For a complete transaction use
`shadow6-extensions` directly or Control Center's `extensions.invoke`.

```sh
shadow6 connect CODE --core carp --role client --output ./new-peer
shadow6 connect CODE --core idris --role client --profile ./profile.json --pin PUBLIC_HEX --check
shadow6 native-key CODE --core carp --role broker --output ./new-broker.key
shadow6 native-config --config ./client.json --check-config
shadow6 native-config --config ./client.json --emit ./new-native-files
shadow6 native-config --config ./client.json
shadow6 ppb catalog
```

Connect accepts directory and manually pinned profiles. `--check` resolves and
validates without writing; ordinary Connect installs Gate/Virtual Peer files
for Carp/Idris too, and generates their separate native key files. Gate is only
enabled by the explicitly requested Connect operation. Connect does not start
services or invent a native Core config: native routing/ports require an
operator's configuration. `--carrier s6na` fails explicitly because Virtual
Peer's current strict schema has no such carrier option; the old implementation
wrote an invalid `gate.carrier` field. Configure S6NA separately with its native
API. No unsupported field is inserted into Virtual Peer configuration.

`native-key` is the extracted Carp/Idris key utility. Both endpoint files use
the same domain-separated binding derived from the invitation; their peer
pins are reciprocal. The broker has zero reserved bytes and the two public
keys, never an endpoint's private seed. Files are created exclusively at 0600;
existing files and symlinks are rejected. An invitation is a secret and grants
the same access as before; deriving keys does not add entropy to it.

## Orchestrator

Use `shadow6 auto apply -f topology.yaml`. For Hare/Pony/Carp/Idris the initial
adapter supports one loopback broker/agent/client trio. Unsupported fields are
rejected instead of being silently lost. No extension to each Core's native
configuration language or wire protocol is needed.

```yaml
version: '1.0'
global:
  output_dir: generated-native
nodes:
  - {name: broker, type: broker, engines: [shadow6-carp], listen_port: 41000}
  - {name: agent, type: agent, engines: [shadow6-carp], listen_port: 41004, target_port: 9000}
  - {name: client, type: client, engines: [shadow6-carp], listen_port: 41002}
```

Choose the same family for all roles. Client applications use client
`listen_port + 1`; Pony's broker also reserves broker `listen_port + 1`.
Ports must not collide. Hare uses IPv6 loopback; the other adapters use IPv4
loopback. Pony's native external/multiple-peer features remain available to
operators using native configuration; this initial topology adapter deliberately
supports a smaller explicit contract. Domain policy, host hooks, discovery and
custom lifetimes are not translated for these four cores.

Add `global.named_service_namespace` to this topology to bind generated local
configuration to the Named Service authority. Auto creates one
`namespace/node` record per local Broker/Agent/Client, binds the selected
Profile and S6P1 role/identity, locks and applies each record, and leaves
startup explicit. It refuses remote nodes, Gate-adapted topologies, existing
service names and unavailable Profile artifacts; if a batch fails it removes
all records created by that batch. Generated config files remain owner-only
under `output_dir`. Set `SHADOW6_SERVICE_REGISTRY` to choose the private
registry file. Start each node separately with `shadow6 run namespace/node`.
No Core is built and no service manager is activated.

```yaml
global:
  output_dir: generated-native
  named_service_namespace: lab
nodes:
  - {name: broker, type: broker, engines: [shadow6-go], listen_port: 41000}
  - {name: agent, type: agent, engines: [shadow6-go], listen_port: 41004, target_port: 9000}
  - {name: client, type: client, engines: [shadow6-go], listen_port: 41002}
```

For an existing stopped service, `shadow6 service upgrade NAME --core CORE
--profile PROFILE --config BINDING` validates, locks and applies a replacement
as one registry transaction. Failure restores the prior record and lock;
success does not start the Core. `shadow6 run NAME` remains explicit.

Generated JSON is the adapter contract, with a `core` field. Hare/Pony are
rendered into the exact flat native JSON fields. Carp/Idris JSON includes a
192-hex-character `key_material` value and port fields; Idris also has explicit
loopback hosts and a bounded iteration count. `--emit` creates a native file
and `argv.json` in a new directory. Without `--emit`, the fixed family binary
is launched with an argv list; no shell is involved. Runtime native key files
live in a private temporary directory and are cleaned after process exit.
The deployment path installs the same standalone wrapper, so service init
escaping and `--config` invocation stay consistent.

## Gleam

Set `global.gleam_transport: micro-mux` to select UDP. `secure-stream` remains
the default. The generated strict Gleam document includes all three role slots;
unused roles are null. Current native Gleam control requires loopback `ws`.

**Micro-Mux transport itself provides no availability guarantee whatsoever.**
Authentication does not guarantee delivery, ordering, congestion recovery or
uptime. The orchestrator prints this warning when selecting it.
Python and Node S6NA APIs accept `gleam-mux`, or `gleam` with explicit
`transport="micro-mux"` (Node's final constructor argument). This profile adds
bounded ACK/retry, duplicate suppression, reassembly and per-stream queues.
Its 1100-byte payload accounts for both envelopes within IPv6's minimum MTU;
64 frames are in flight by default. Larger configured payloads are rejected.
The native benchmark path remains the original native transport; optional
Companions do not turn its availability disclaimer into a guarantee.

### Connect operational additions

`shadow6 connect --code-file invitation.txt --list-routes` resolves an invitation
and prints only offered core/transport pairs without provisioning. The invitation
file uses the same bounded owner-only, non-symlink 0600 reader as native config.
`--core … --role … --check --native-config native.json` validates matching core,
role, ports and supported native fields without writing files. Without `--check`,
Connect also exports native input and a fixed `native/argv.json` alongside its
Virtual Peer configuration; no service is started. Native endpoint/key material
must describe the separately provisioned matching native path. The Virtual Peer
and native path are distinct deployments, not automatically wire-compatible.
