# Getting started

## First Named Service without global installation

Use a trusted **prebuilt tar** for your platform, verify its published digest,
and extract it. The text-only ZIP cannot run Core binaries. Python 3.11+ and
the selected Core's runtime libraries are needed; no compiler or global install
is required. From any directory, invoke the extracted CLI by its absolute path:

```sh
python3 /absolute/path/Shadow6/CLI/shadow6.py doctor --human
python3 /absolute/path/Shadow6/CLI/shadow6.py core profiles --installed
```

If the package has a compatible `.venv`, use its `bin/python` instead of
`python3`. `doctor` reports available Core/Profile pairs and missing prerequisites;
choose your Core explicitly. All peers on the native path use the same family.
Prepare the selected Core's native configuration using its README as an
owner-controlled regular file, mode `0600`. `setup --native-config` uses that
file directly through the existing CoreBinding contract. The advanced
`--config BINDING` path accepts a private binding JSON containing
`{"config_path":"/absolute/path/core.json"}`; relative `config_path` resolves
beside the binding file, independently of your working directory.

```sh
# Example only: explicitly choose Go/KCP if doctor reports it available.
python3 /absolute/path/Shadow6/CLI/shadow6.py setup home/nas --core go --profile go-kcp --native-config /absolute/path/core.json --run --human
python3 /absolute/path/Shadow6/CLI/shadow6.py status home/nas --human
python3 /absolute/path/Shadow6/CLI/shadow6.py doctor home/nas --human
python3 /absolute/path/Shadow6/CLI/shadow6.py connect home/nas --human
```

`setup --check` preflights without creating a service. `setup --run` prepares,
locks, applies and explicitly starts it. `connect NAME` returns an observed
connection plan; use `--stdio` for a stream or `--records` for a message boundary
to attach data. A live process alone does not prove application readiness, and
a broker still needs its configured peers. Named Service supervision currently
requires Linux pidfd; other platforms report unavailable and retain native/init
paths. JSON remains the default; lifecycle summaries accept `--human`.

For a stopped service whose material changed, review `doctor NAME` before
`relock NAME`, `apply NAME`, then `run NAME`. `stop`, `restart` and `remove` also
have `--help`. Optional installation reuses `install --prefix /absolute/writable/prefix`;
package-manager and build/install paths remain available. See the
[full lifecycle guide](named-services.md) for credentials and manual setup.


To install existing artifacts without rebuilding, use `shadow6 install --prefix
/home/admin/shadow6-local` (on one line), then follow the [named service lifecycle](named-services.md).
The [Privacy Envelope guide](privacy-envelope.md) covers both ends, actual local
telemetry, resource limits and its E2E checks.

Welcome to Shadow6. You do not need to understand every component before your
first check. Begin with the installed feature report; it is read-only and tells
you exactly which Core variants are present.

```sh
shadow6 guide --lang en
shadow6 features
shadow6 privacy
shadow6 control -- status
```

In a source checkout, replace `shadow6` with `.venv/bin/python CLI/shadow6.py`.
If a component is missing, run `shadow6 doctor --human` and supply the matching prebuilt artifact and runtime libraries. Source builds are an optional advanced path.

Shadow6 ships twelve independently compiled Core implementations: Go, Rust,
Gleam, Ada, Nim, Pony, Idris, Zig, D, C++, Hare, and Carp. All twelve provide a
native broker/agent/client path. Idris, Hare and Carp retain their older modes
alongside bounded, signed fixed-route datagram trios. These profiles are
all valid, but they are not wire-compatible and they do not promise the same
reliability, multiplexing, or broker behavior. Pick one family for every hop
and use its README as the authority for deployment limits.
The compact [Core capability matrix](core-matrix.md) summarizes this role and
transport split in one place.

Default builds keep Crosed, application transport and domain policy disabled.
The explicit `*-crosed` binaries enable the L5 feature contract where that
Core provides it; an optional toolchain may be required for a Core to be built.

The unified network adapter has equal Python and Node.js backends and removes caller-visible packet sizing.
Run `shadow6 network catalog` to inspect each Core's native payload and window
bounds. All twelve Cores can deploy independently, and no Core requires the
adapter or another Companion to obtain native network capability. The adapter
is an optional authenticated layer for uniform reliability, segmentation and
multiplexing. See
`Network-Adapter/README.md` for security and deployment requirements.
Both backends implement the normative `Network-Adapter/SPEC.md`; use
`shadow6 network catalog` or `shadow6 network-node catalog` explicitly.

The Control Center starts read-only. Its HTTP API listens only on loopback and
requires a bearer token stored in a regular, owner-controlled `0600` file. Keep
`--allow-mutations` off until you have reviewed the exact operation you intend to
run. See [the Control Center guide](../Control-Center/README.md) for a working RPC
example.

If something feels unclear, these three checks usually point to the next step:

```sh
shadow6 features
shadow6 doctor --human
shadow6 control -- --help
```

The doctor only observes the local tree. It does not change services, firewall
rules or routes. For a quick check or the full release sequence, follow the
[verification and release guide](verification.md).

[阅读中文指南](getting-started.zh-CN.md)

## Deployment and application entry

Use a strict `shadow6.deployment.v1` manifest for multi-node installations.
A broker set is one logical Broker identity with bounded physical endpoints;
independent Broker authorities in one topology are rejected. Validate without
building a Core:

```sh
shadow6 deployment validate Deployment/example.deployment.json
shadow6 deployment lock Deployment/example.deployment.json
shadow6 deployment plan Deployment/example.deployment.json
shadow6 acceptance --source-only --manifest Deployment/example.deployment.json
```

The acceptance command distinguishes source-only results from CI native
feature-report and loopback verification. `shadow6 abi catalog` prints the
bounded `S6ABI/1` contract. It reuses S6P1 admission and S6AR1 signed control
requests; native Core wire protocols remain independent.

Applications request `stream`, `message`, or `credited` boundaries through
`libshadow6`. Feature reports select a compatible boundary and a bounded
capability capsule returns a loopback endpoint. VCore and the driver accept
separately shipped Core names that satisfy the common contract, so applications
do not enumerate the twelve built-in names. Node IPC exposes a read-only `abi`
contract adapter; Control Center mutations remain explicitly gated.

Before sharing diagnostics, read [privacy across interfaces](privacy-interfaces.md).
