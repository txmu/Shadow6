# Shadow6

For install/run, named services, real privacy telemetry and their current platform
limits, start with [the lifecycle guide](docs/named-services.md). The optional
[OCaml Privacy Envelope](docs/privacy-envelope.md) has a client/server E2E test
suite; [the review record](docs/review-2026-10-03.md) separates implemented controls
from remaining native-artifact and deployment checks.

Welcome. If this is your first visit, begin with the
[English guide](docs/getting-started.en.md) or [中文入门指南](docs/getting-started.zh-CN.md).
You can also run `shadow6 guide --lang en` or `shadow6 guide --lang zh` offline.
For a shareable health summary, use `shadow6 privacy`. See the bilingual
[privacy and interface guide](docs/privacy-interfaces.md) for permissions,
CLI/MCP mappings and compatibility notes.

Shadow6 is a multi-component remote-access and UDP-relay project with
deterministic builds, strict configuration validation, bounded resource use,
and offline tests.

The shortest way in is the unified CLI. `shadow6 features` shows what the
available Core builds and Gate actually contain; `shadow6 <component> -- <arguments>`
passes arguments to a known component without invoking a shell. The same entry
point exposes Control Center's MCP, LSP, OpenAI function-calling, JSONL RPC and
loopback Web API transports. `shadow6 workflow release` runs the fixed release
stages in order.

Gate is deliberately present but quiet. A normal build includes it, while its
runtime configuration starts with `enabled: false`. Once enabled, it can sit in
front of a Client, behind an Agent or Broker, or between them as an authenticated
middle hop. Multiple Gate and Broker addresses can be selected round-robin or
randomly. See [Gate/README.md](Gate/README.md) for the wire and MTD details.

Packages can stay offline or come from a self-hosted signed HTTPS directory.
The repository index has its own Ed25519 signature; every download is bounded
and checked by size and SHA-256 before the Package Manager performs the package's
separate signature check. See [Online-Repository/README.md](Online-Repository/README.md).

## Components

### The twelve Core implementations

Shadow6 maintains twelve independently compiled Core implementations. They
share the feature-report and security-contract vocabulary, but they are not
implicitly wire-compatible: use one family consistently across a broker,
agent, and client path, and consult that Core's README for its transport and
platform limits.

| Core | Primary profile | Build/availability note |
| --- | --- | --- |
| Core-Go | full broker/agent/client stack | default Linux build; L0 and explicit Crosed/Public6 variants |
| Core-Rust | full broker/agent/client stack | default Linux/Unix build; L0 and explicit Crosed/Public6 variants |
| Core-Gleam | BEAM authenticated broker/agent/client stream | Linux x86_64/aarch64; L0 and Crosed variants |
| Core-Ada | SPARK-oriented broker/agent/client cell stack | native Unix build; L0 and Crosed variants |
| Core-Nim | broker/agent/client authenticated UDP stack | optional libdatachannel/toolchain; L0 and Crosed variants |
| Core-Pony | reference-capability broker/agent/client UDP stack | optional `ponyc`; L0 and Crosed variants |
| Core-Idris | dependent-type checked broker/agent/client UDP path | optional Idris 2/Chez; legacy two-endpoint mode retained |
| Core-Zig | ENet-style reliable UDP stack | optional Zig toolchain; L0 profile |
| Core-D | BetterC authenticated broker/agent/client stream | optional D toolchain; L0 profile |
| Core-Cpp | C++20 TLS/WebSocket control and SCTP data stack | optional C++ toolchain; L0 profile |
| Core-Hare | small authenticated broker/agent/client UDP path | optional Hare; L0 and legacy endpoint modes |
| Core-Carp | compact authenticated broker/agent/client UDP path | optional Carp; L0 and legacy codec/adapter modes |

The twelve-core catalog is a capability matrix, not a promise that every
binary is present in every installation. `shadow6 features`, the component
doctor, and the release SBOM report the exact locally installed subset.
For role-by-role transport boundaries, see
[`docs/core-matrix.md`](docs/core-matrix.md).
The two optional Network Adapter companions are described in
[`docs/companions.md`](docs/companions.md), and the complete protocol index is
in [`docs/protocols.md`](docs/protocols.md).
The [Core-blind architecture note](Core-Blind.md) describes how Native Cores
and their surrounding stacks can evolve independently, and documents the
machine-readable stream, message, and credited application boundaries.

The dependency-free [Node IPC companion](Node-IPC/README.md) adds bounded local
FastRPC and encrypted RawIPC for Control Center and C11Relay. It is available
through `shadow6 ipc`, the Control Center schema, MCP, LSP, OpenAI function
tools, JSONL, and the loopback HTTP API; it does not replace any Native Core
wire protocol or require a Core rebuild.

| Component | Implemented role | Protocol / important boundary |
| --- | --- | --- |
| Core-Go | broker, agent, client, dual-stack local discovery | WebSocket control and authenticated encrypted KCP data; IPv6 LPD uses `ff02::1` with interface scope |
| Core-Rust | broker, agent, client, dual-stack local discovery | WebSocket JSON-RPC control and certificate-pinned QUIC data; scoped link-local IPv6 is preserved |
| Core-Gleam | broker, agent, client | Mutually authenticated WebSocket control and encrypted TCP stream; BEAM/musl static PIE release |
| Core-Ada | broker, agent, client | Authenticated WebSocket control and bounded encrypted cell relay; SPARK-oriented implementation |
| Core-Nim | broker, agent, client | Authenticated WebSocket control and bounded libdatachannel-backed UDP path |
| Core-Pony | broker, agent, client | Authenticated reliable UDP with bounded sessions, routes and retransmission |
| Core-Zig | broker, agent, client | Go/Rust control dialects plus authenticated reliable UDP data plane |
| Core-D | broker, agent, client | Authenticated WebSocket control and X25519/ChaCha20-Poly1305 stream |
| Core-Cpp | broker, agent, client | Mutually authenticated TLS 1.3 WebSocket control and SCTP tunnel data |
| Core-Idris | broker, agent, client | Signed ephemeral admission; fixed-route UDP with bounded ACK/retry; legacy PSK relay retained |
| Core-Hare | broker, agent, client | Signed fixed-route IPv6-loopback UDP; one peer/session, bounded authenticated ACK/retry |
| Core-Carp | broker, agent, client, codec/adapter | Signed fixed-route IPv4-loopback UDP with bounded ACK/retry; separate directional layer keys |
| Guard | agent SPA/LPD/probe monitor, client TLS cover traffic, broker reverse proxy | Bounded maps/concurrency; public broker binds require TLS |
| C11Relay | multi-client bidirectional UDP relay | Normal/high-speed pass-through; data-saving mode requires a paired relay |
| Auto-Orchestrator | topology validation, key/config generation, SSH deployment, MTD rotation, RPC/TUI | SSH host-key verification is mandatory for remote nodes |
| Detector | packet features, safe JSON random forest, weights-only LSTM, bounded decoy, log watcher | Live capture requires root or `CAP_NET_RAW` |
| Plugin System | signed out-of-process JSON plugins, hooks, capability policy, bundled games | Ed25519 trust store, digest verification, resource limits, Linux namespace isolation |
| Crosed | compile-time Core Hook negotiation, independent of plugins | signed requests, levels 0–5, per-Mod policy, optional compartment-domain enforcement |
| Application Layer | ProtocolFactory, ShadowChat, ShadowIdentity | bounded UTF-8 framing, Ed25519 identity, ChaCha20-Poly1305 chat, replay control |
| Security Assistants | deployment doctor, CycloneDX SBOM, policy evaluator, signed audit ledger | read-only checks, strict JSON policy, hash chain and signed checkpoint |
| Infrastructure Assistants | component eyes, drift snapshots, signed fixed-action hands | exact binary/process identity, short-lived signed plans, replay journal, no arbitrary commands |
| Slots | typed extension points across lifecycle, transport, protocols, identity, policy, telemetry, assistants, init and UI | signed isolated Plugin providers, fixed contracts/levels/limits, fail-closed composition |
| Control Center | one-stop CLI, MCP, LSP, OpenAI functions, JSONL RPC and loopback Web API | shared strict tool schema, bearer authentication, default read-only remote/tool transports |
| Package Manager | signed Crosed Mod, Plugin, and App installation/version selection | Ed25519 manifests, per-file hashes, bounded archives, atomic version activation |
| EasyBuild | guided full-feature local build, verification, signing bootstrap, and install | L5 variants are explicit; Qubes-style policy and compliance are opt-in prompts |
| Android | adaptive Material 3 app with selectable packaged Cores in the app sandbox | module-selectable build, bilingual UI, ShadowChat/search/games/packages/AI surfaces |
| Network Adapter | equal Python/Node.js authenticated reliable backends for all twelve Cores | optional shared S6NA semantics; all twelve Cores remain independently deployable with native transports |
| Public6 | explicit all-components, dual-Core distribution and compatibility negotiation | only identical Core family/version is mandatory; all optional parameters negotiate by intersection |
| Virtual Adapter | out-of-process TUN/TAP packet carrier over S6NA | never creates routes or interfaces; startup-only bounded configuration |
| Public6 Virtual Broker | guarded multi-tenant admission and opaque E2EE relay to twelve same-family Brokers | Guard and Gate required; tenant quotas; optional C11Relay supervision |
| Gate | independently compiled, default-disabled TCP/UDP Broker forwarding | Ed25519 mutual auth, ephemeral encrypted TCP frames, signed UDP envelopes, deterministic high-port MTD |
| Migration | scoped one-stop plan/export/import CLI | manifest hashes, safe archive extraction, dry-run import, explicit secret inclusion |
| I18n | shared CLI/plugin and Android contribution contract | strict locale/key validation, English fallback, bounded third-party bundles |

Each Core's native transport is independently deployable, but Core families
are not wire-compatible halves of one stack. One topology must use the same
Core family at every hop. All twelve provide native broker/agent/client paths.
Hare, Carp and Idris retain their older modes and bounded datagram semantics;
three roles do not imply identical reliability or multiplexing.
No Core requires the Network Adapter or another Companion to obtain
its native network capability; the adapter is an optional uniform semantics
layer. C11Relay does not translate between Core protocols.

The [Benchmark suite](Benchmark/README.md) evaluates twelve cores × three paths
(native, Python Companion, Node.js Companion) through actual native trios.
Every path receives the same application workload and pressure cases, regardless
of deployment enablement. Missing binaries/runtime support are reported as
failures, not omitted or replaced with internal benchmark loopbacks.

Public6 packages both alternatives but does not translate between them. Peers
using the same Core family and exact Core version remain base-compatible even
when Crosed level, application protocols, optional transports, isolation, or
extensions differ. Optional functions negotiate their intersection and are
disabled individually when no common version exists. Run `make public6` for
the explicit all-components build; compliance remains disabled.

## Platform scope and portability

Core-Rust is explicitly Unix/Unix-like only. Its IPv6 local-discovery interface
indices come from the host's POSIX `if_nametoindex(3)`/`if_nameindex(3)` APIs,
not Linux sysfs, so the same source path covers Linux (including OpenWrt, WSL
and suitable rooted Android userlands), the BSD family, macOS, illumos/Solaris,
AIX and sufficiently complete POSIX RTOS targets. Only Linux is exercised by
this repository's current CI/test environment; dependency availability,
multicast routing, sandbox permissions and init integration remain target
deployment requirements. See `Core-Rust/PORTABILITY.md` for exact support tiers
and the components that intentionally remain Linux-specific.

## Throughput profile

Both data planes use one centralized high-throughput contract sized for a
10,000,000,000 bit/s target at 50 ms round-trip time. Core-Go uses the maximum
protocol-safe 65,535-packet KCP send/receive windows (about 84.4 MiB at the
configured 1350-byte MTU), 32 MiB UDP socket requests, 256 KiB pooled copy
buffers, 1 MiB authenticated frames, and bounded 512-tunnel/256-session
limits. Core-Rust uses a 64 MiB QUIC connection window, 16 MiB stream windows,
and matching bounded tunnel/stream counts (with 4,096 control connections).
Unit tests enforce that each connection window covers the 62.5 MB
bandwidth-delay product.

This is a software capacity target. Actual throughput depends on CPU
cryptographic performance, NIC/driver/kernel buffers, packet loss, RTT, MTU,
thermal limits, and peer settings; validate sustained 10Gbps on the intended
hardware and deployment path.

## Build and verify

Required native tools are Go, Rust/Cargo, GCC, Make, and Python 3. Create an
isolated Python environment before running Python component tests:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-ml.txt
./configure --enable-all
make build
make test
make check
make audit
```

`make integration-test` (also included by `make test`) runs a single-host
full-stack simulation for both engines. The orchestrator generates ephemeral
credentials and configs, then real Broker, Agent, and Client processes connect
to a loopback TCP target and exchange `ping`/`pong` through KCP and QUIC.

`setup_test.sh` runs those four repository verification stages without killing
unrelated processes, opening long-lived listeners, or changing the firewall.
`make audit` is offline and returns nonzero for a failed check.

## Plugins and bundled games

`Plugin-System/shadow6_plugins.py` discovers versioned manifests under
`plugins/`. Plugin code is never imported into a privileged Shadow6 process.
Before execution the manager verifies the code digest and an Ed25519 signature,
checks the requested capabilities, then applies `no_new_privs`, CPU/memory/file
limits, a wall-clock timeout, a clean environment, and separate Linux user,
network, IPC, and UTS namespaces. The hook protocol provides narrow extension
points for MTD lifecycle, authorization mediation, and telemetry readers.

Three signed, offline games demonstrate the same extension boundary:

```sh
.venv/bin/python Plugin-System/shadow6_plugins.py game number-guess
.venv/bin/python Plugin-System/shadow6_plugins.py game rock-paper-scissors
.venv/bin/python Plugin-System/shadow6_plugins.py game maze-runner
```

See `Plugin-System/README.md` for the manifest schema, signing workflow, trust
store management, hook dispatch, and plugin development guidance.

`Slot-System` expands this boundary into a comprehensive typed slot catalog.
Providers remain signed Plugins running out of process; slot bindings cannot
inject Core code or arbitrary commands. See `Slot-System/README.md`.

## Crosed and application protocols

Crosed is disabled in default Core builds. ~~Enable identical orthogonal options
for both cores with `CROSED_LEVEL=1..5`, `APP_TRANSPORT=1`, and/or
`QUBES_ISOLATION=1`.~~ Crosed options are implemented and compiled per Core; use
the matching Core target and README, then confirm its actual build with
`--feature-report`. `CROSED_LEVEL`, `APP_TRANSPORT`, and `QUBES_ISOLATION` are
orthogonal build flags, and support varies by Core. The report returns the Core version, maximum
compiled Crosed level, exact capabilities, UTF-8 support, and optional feature
state. Signed Mod requests are then reduced by a per-Mod trust policy and, in
Qubes isolation mode, source/target compartment rules.

The application layer adds versioned ProtocolFactory framing, encrypted and
signed ShadowChat messages, and expiring ShadowIdentity assertions. It remains
off at Core compile time unless explicitly enabled. See `Crosed/README.md` and
`Application-Layer/README.md` for the security model and APIs.

## Component hands, eyes, and security infrastructure

`Security-Assistants/shadow6_security.py` supplies a deployment doctor, offline
CycloneDX inventory, maximum-policy validation, and an Ed25519-signed hash-chain
audit ledger with signed tail checkpoints. `Infrastructure-Assistants` observes
all Shadow6 component source/binary digests, feature contracts, permissions and
exact running processes, then detects drift against a saved snapshot.

Mutating operations are restricted to fixed build/test/check/audit/integration/
package runbooks. A hand requires a short-lived Ed25519-signed plan bound to the
exact repository and a single-use nonce; plans cannot carry commands or shell
arguments. See the two assistant README files and the
[verification and release guide](docs/verification.md). For a read-only
source check before a full build, run `Tools/security_preflight.sh`.

## Service integration and one-stop control

The orchestrator renders and deploys systemd, OpenRC, runit, SysV, FreeBSD
rc.d, OpenWrt procd and macOS launchd definitions. It also emits a Guix System
Shepherd service fragment; Guix activation remains an explicit declarative OS
reconfiguration step. Paths are escaped for the target format and service names
are restricted before they reach shells, XML, Scheme, labels or remote paths.

`Control-Center/shadow6_control.py` exposes all component, build-feature,
configuration-validation, init, Plugin, Crosed, Slot, assistant and signed
runbook operations through a versioned schema. CLI frontends can use direct
calls or JSONL; Claude/Cursor can use MCP stdio, IDEs can use LSP
`workspace/executeCommand`, OpenAI Responses clients can use emitted function
definitions/call outputs, and GUI/Web UI backends can use the bearer-authenticated,
loopback-only `/v1` HTTP API. MCP, LSP, OpenAI and HTTP mutations are disabled
by default. See `Control-Center/README.md`.

For staged installation, use for example; the
[verification and release guide](docs/verification.md) also validates the
installed entrypoints:

```sh
make install DESTDIR=/tmp/shadow6-package PREFIX=/usr/local
```

## Configuration

Use the core binaries' `--gen-key`, `--init-config`, and `--check-config`
commands. Secret-bearing configuration files must be regular, owned by the
effective user, and mode `0600`.

Agent configurations must include `client_pubkeys` for every client permitted
to open a data-plane tunnel, even when local discovery is disabled. ~~Both core
engines verify the client's signed access request at the Agent;~~ Core-Go and
Core-Rust verify that request at the Agent; the Rust engine
also binds its ephemeral QUIC certificate to that request with an Agent
signature. This prevents a compromised control-plane broker from minting an
independent tunnel or substituting a QUIC certificate.

The orchestrator provides loopback Go and Rust examples under
`Auto-Orchestrator/`. Remote nodes require a `known_hosts` path and `wss://`;
plain `ws://` is restricted to loopback tests. Generated files are written
atomically with owner-only permissions.

Guard examples are under `Guard/etc/`. Its generated controller accepts
`start`, `stop`, and `status`, validates its PID file, and never uses global
process matching.

## Deployment baseline

Release verification covers the repository's input, file, TLS, process, and
resource controls. Deployments still depend on protected private keys, TLS at
public control endpoints, current dependencies, suitable OS isolation, and
periodic operational review.

See the [network reliability and Python runtime review](docs/network-runtime-review-2026-09.md) for
GIL-mode coverage, measured performance scope and remaining platform limits.
## Security components without Cores

Use `./configure --disable-cores` before `make install` to install Guard, Gate,
Detector, Security Assistant, and the other selected components with zero Core
binaries. The installed tree filters out stale Core executables from an earlier
build. Gate still starts disabled until an operator explicitly enables its
configuration.

The unified CLI accepts `shadow6 standalone guard`, `shadow6 standalone gate`,
`shadow6 standalone detector`, and `shadow6 standalone security` with the
component's normal arguments. For an external installation prefix, run
`shadow6 standalone security doctor --standalone --root /path/to/prefix
--component guard --component gate --component detector --component security`.
This mode checks only the selected executable entry points; use the regular
`doctor` for a complete Shadow6 deployment audit. A copied CLI can also route
to companion `shadow6-*` binaries beside it without a Shadow6 source tree.

## Linux iperf chain snapshot

The third performance run on 2026-09-30 (CI 36732325902, commit `4cf9d7b`)
is recorded below. `Base` is the direct baseline; rows use
`Core Proto Dir(F/R) Base? Gbps Loss/Retrans CPU(s) Mem(MB)`.

> **UDP loss measurement note:** These runs predate the 2026-10-01 native
> ingress backpressure and Micro-Mux credit commit (`f16f7758`) and the
> follow-up client runtime integration (`deb6b12c`). These changes could
> improve measured UDP Loss in future runs that use flow-controlled ingress or
> S6NA credit. Legacy UDP ingress remains the default and has no new producer
> backpressure. The table has not been rerun on those revisions, so no
> reduction in loss, increase in delivered goodput, or improvement magnitude
> can be inferred from these older numbers. A new comparison should report
> offered and admitted load,
> delivered goodput, local drops, producer stalls/`EAGAIN`, and native retries
> separately.

```text
zig tcp F base 12.86 - 0 0.00 0
zig tcp F node 0.82 - 0 4.58 28
zig tcp R base 12.43 - 0 0.00 0
zig tcp R node 0.81 - 0 4.46 28
ada tcp F base 12.72 - 0 0.00 0
ada tcp F node 1.45 - 0 5.16 8
ada tcp R base 11.64 - 0 0.00 0
ada tcp R node 1.53 - 0 5.21 8
d tcp F base 11.70 - 0 0.00 0
d tcp F node 5.02 - 1 5.49 7
d tcp R base 12.93 - 0 0.00 0
d tcp R node 5.19 - 3 5.47 7
nim tcp F base 12.48 - 0 0.00 0
nim tcp F node 0.79 - 3 7.41 44
nim tcp R base 12.83 - 0 0.00 0
nim tcp R node 0.85 - 2 7.58 41
cpp tcp F base 12.19 - 0 0.00 0
cpp tcp F node 4.91 - 0 5.56 9
cpp tcp R base 12.12 - 0 0.00 0
cpp tcp R node 4.87 - 0 5.40 9
pony udp F base 1.10 0.0% - 0.00 0
pony udp F node 0.07 93.2% - 7.95 47
pony udp R base 1.10 0.0% - 0.00 0
pony udp R node 0.08 91.5% - 8.46 41
hare udp F base 1.10 0.0% - 0.00 0
hare udp F node 0.44 59.4% - 5.39 2
hare udp R base 1.10 0.0% - 0.00 0
hare udp R node 0.57 48.0% - 6.88 2
carp udp F base 1.10 0.0% - 0.00 0
carp udp F node 0.34 69.1% - 5.43 2
carp udp R base 1.10 0.0% - 0.00 0
carp udp R node 0.40 63.3% - 6.74 2
gleam tcp F base 12.58 - 0 0.00 0
gleam tcp F node 2.02 - 37 8.59 69
gleam tcp R base 11.72 - 0 0.00 0
gleam tcp R node 1.97 - 27 8.69 73
idris udp F base 1.10 0.0% - 0.00 0
idris udp F node 0.56 48.9% - 0.00 2
idris udp R base 1.10 0.0% - 0.00 0
idris udp R node 0.67 38.7% - 0.00 2
go tcp F base 11.88 - 0 0.00 0
go tcp F node 1.00 - 227 7.98 166
go tcp R base 12.03 - 0 0.00 0
go tcp R node 1.02 - 214 8.08 174
rust tcp F base 12.21 - 0 0.00 0
rust tcp F node 4.97 - 39 6.03 47
rust tcp R base 12.47 - 0 0.00 0
rust tcp R node 1.50 - 19 1.82 14
gleam-mux udp F base 1.10 0.0% - 0.00 0
gleam-mux udp F node 0.24 77.9% - 7.62 77
gleam-mux udp R base 1.10 0.0% - 0.00 0
gleam-mux udp R node 0.29 72.8% - 7.89 75
```

## S6P1 命名服务与统一连接

Named Service v2 持有 S6P1 逻辑/准入上下文；CoreBinding 显式锁定本机 Core，Runtime 只记录实际进程、端点和 readiness。`shadow6 connect home/nas` 与 S6P1/invitation 汇入同一 connection-plan resolver；已观测到的本地 client stream 可通过 `--stdio` 或 libshadow6 真正建立会话。多 Broker 使用 S6P1.routes BrokerSet 和显式 Gate 适配，不承诺既有 session 无缝迁移。参见 [完整链路与边界](docs/service-connections.md)。
