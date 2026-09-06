# Shadow6

Welcome. If this is your first visit, begin with the
[English guide](docs/getting-started.en.md) or [中文入门指南](docs/getting-started.zh-CN.md).
You can also run `shadow6 guide --lang en` or `shadow6 guide --lang zh` offline.
For a shareable health summary, use `shadow6 privacy`. See the bilingual
[privacy and interface guide](docs/privacy-interfaces.md) for permissions,
CLI/MCP mappings and compatibility notes.

Shadow6 is a multi-component remote-access and UDP-relay project with
deterministic builds, strict configuration validation, bounded resource use,
and offline tests.

The shortest way in is the unified CLI. `shadow6 features` shows what the two
Core builds and Gate actually contain; `shadow6 <component> -- <arguments>`
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

| Component | Implemented role | Protocol / important boundary |
| --- | --- | --- |
| Core-Go | broker, agent, client, dual-stack local discovery | WebSocket control and authenticated encrypted KCP data; IPv6 LPD uses `ff02::1` with interface scope |
| Core-Rust | broker, agent, client, dual-stack local discovery | WebSocket JSON-RPC control and certificate-pinned QUIC data; scoped link-local IPv6 is preserved |
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
| Android | adaptive Material 3 app with selectable Go/Rust Core and Root/non-Root modes | module-selectable build, bilingual UI, ShadowChat/search/games/packages/AI surfaces |
| Public6 | explicit all-components, dual-Core distribution and compatibility negotiation | only identical Core family/version is mandatory; all optional parameters negotiate by intersection |
| Gate | independently compiled, default-disabled TCP/UDP Broker forwarding | Ed25519 mutual auth, ephemeral encrypted TCP frames, signed UDP envelopes, deterministic high-port MTD |
| Migration | scoped one-stop plan/export/import CLI | manifest hashes, safe archive extraction, dry-run import, explicit secret inclusion |
| I18n | shared CLI/plugin and Android contribution contract | strict locale/key validation, English fallback, bounded third-party bundles |

Core-Go and Core-Rust are complete alternative stacks, not wire-compatible
halves of one stack. One orchestrator topology must use the same core engine on
all broker/agent/client nodes. C11Relay is a generic UDP relay; it does not
translate KCP into QUIC.

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

Crosed is disabled in default Core builds. Enable identical orthogonal options
for both cores with `CROSED_LEVEL=1..5`, `APP_TRANSPORT=1`, and/or
`QUBES_ISOLATION=1`. `--feature-report` returns the Core version, maximum
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
arguments. See the two assistant README files and repository `AGENTS.md` for
the complete release workflow.

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

For staged installation, use for example:

```sh
make install DESTDIR=/tmp/shadow6-package PREFIX=/usr/local
```

## Configuration

Use the core binaries' `--gen-key`, `--init-config`, and `--check-config`
commands. Secret-bearing configuration files must be regular, owned by the
effective user, and mode `0600`.

Agent configurations must include `client_pubkeys` for every client permitted
to open a data-plane tunnel, even when local discovery is disabled. Both core
engines verify the client's signed access request at the Agent; the Rust engine
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
