# Native Profile Runtime implementation and evidence ledger

## Current integration checkpoint (2026-10-04, local commit `bccbecb6`)

The user has prioritized integration work across the existing Profile-driven
architecture. This checkpoint records the latest local evidence and supersedes
older statements below about the current Linux failure and source state; it does
not claim completion of the full architecture or CI acceptance.

- The `Crosed/native_profiles.py` authority remains the 13-Profile source for
  Deployment, Core Catalog, feature contracts, connection planning, Detector,
  Control Center, CLI, benchmark selection, and installation availability.
  S6P1 routes feed BrokerSet realization, and the resulting realization and
  resolved limits are part of the Named Service lock/runtime/Detector path.
- Read-only Control Center service list/status/doctor/connect and authenticated
  loopback HTTP views use the same Registry/lock/observation as the CLI. The
  APIs remain read-only by default. Control Center returns installed Profile
  prerequisites separately from source contracts.
- Local regression evidence for this checkpoint: Profile/attachment group 39
  passed; Deployment lifecycle/context group 65 passed (one explicit skip);
  Control Center group 35 passed; Network Adapter group 10 passed;
  Auto-Orchestrator group 19 passed; Service-Init group 7 passed; Detector
  service compliance 1 passed; Hare and Pony source-only contract checks passed.
  Idris FFI passed GCC syntax-only validation. No Hare, Idris, or Pony Core
  binary was compiled locally.
- Nine Profile lifecycles previously passed against matching installed
  artifacts: Go, Rust, both Gleam Profiles, Ada, Nim, Zig, D, and C++. Hare,
  Pony, Carp, and Idris still lack a current full Named Service lifecycle
  result. The Idris CI artifact passed a direct lightweight stack test, but the
  updated FFI return path needs a newly built CI artifact and Named Service
  rerun.
- Commit `bccbecb6` fixes the latest observed Linux provider-digest failure by
  applying the bounded executable-material contract to the compiled WebRTC
  provider. It also fixes installed-tree adapter resolution and the Idris
  launcher/application-response path. Actions run `37197057798` predates this
  commit; its Linux job failed on the provider digest, so this repair has no CI
  result yet. The run's Idris success also predates the current launcher/FFI
  source.
- Cross-platform Native Supervisor remains best-effort. Linux uses pidfd,
  process identity, owned sockets and readiness evidence. Other platforms
  expose partial/degraded capability and do not infer readiness from a live
  PID or service-manager active bit. No cross-platform lifecycle parity is
  claimed.

Still open: intent-only native config/credential realization, all 13 real
Profile lifecycle runs on current CI artifacts, credited S6NA application
attachment, executable S6EPE WebRTC signalling plus Named Service integration,
complete peripheral-resource consumption of Limits, and full stopped-service
upgrade/reconfiguration transaction coverage. Platform matrix, public6/crosed
release variants, full release workflow and archive packaging were not run in
this checkpoint. No push or fresh CI run was performed.

The dated audit sections below are historical evidence; where their status
differs from this checkpoint, use this section for the local state at
`bccbecb6` and query Actions before stating current CI status.

The active objective is the operator's full Profile-driven Named Service and
Application Runtime. This ledger preserves its scope across continuations.
No row may pass on code existence, a catalog count, process liveness, benchmark
success, or a toolchain skip alone. Current changes are uncommitted and have no
CI result. Every available Profile must pass one complete lifecycle contract.

| Requirement | Authoritative completion evidence | Current status / next work |
| --- | --- | --- |
| Producer failures first | Latest Actions job/step results and logs for the reviewed commit | Actions run 37172827272 completed successfully, including OpenBSD arm64. The present worktree remains uncommitted and unverified by CI. |
| Single Native Profile Registry | All 13 complete contracts; every consumer derives Profile facts from it; no duplicate transport maps or implicit selectors | Source registry and initial consumers implemented. Audit remaining integration, Service-Init, Detector, S6ABI and network catalog; add concrete component admission and platform/runtime requirements. |
| Strong family/Profile binding | Illegal mixed trios and Profile/config mismatches rejected before any spawn | Existing family checks preserved; explicit topology Profile selection and config transport conflict checks added. Named Service ProfileBinding is now explicit and checked against config, S6P1 boundary, lock, launch plan, runtime identity and connection observation; real all-Profile integration remains open. |
| Unique Named Service authority | ServiceSpec + embedded S6P1 + CoreBinding + ProfileBinding + DeploymentLock; run only locked material | ProfileBinding and explicit stopped reconfiguration implemented. Auto-Orchestrator can materialize generated all-local topologies into locked/applied services when `named_service_namespace` is set; it does not start them. Remote topology and Gate compositions are rejected pending explicit realization. |
| Complete material lock | Native binaries/configs, peripheral binaries/configs, credentials/CA/adapters hashed and revalidated before spawn and readiness | Profile contract digest, native Ada/Nim/D TLS references and Guard TLS references added to existing binary/config/EPE TLS locks. Replacement admission preserves old locked record on failure. Finish full schema/material/provider audit. |
| Portable intent separation | Negative tests reject local paths/private keys/material in exported S6P1 | Audit all setup/export/import/install paths against strict portable contract. |
| All application attachments | Real eight stream, four seqpacket and Gleam Micro-Mux attach; CLI/libshadow6 with message sizes/backpressure/EOF/drain/errors | Added `libshadow6.Shadow6.open_credited()` for an explicit owner-only S6NA attachment document, with bounded loopback UDP, credit/backpressure and close tests. It is a companion endpoint and is not yet transparently bridged into a Named Service application proxy. |
| S6EPE v3/WebRTC executable deployment | Source-built real raw/TLS/SCTP/WebRTC providers; signalling, boundary adapters, lock, observation, metrics/doctor and restart/negative CI tests | Existing WebRTC library evidence is historical, not executable deployment. Implement config/signalling/adapter lifecycle without native wire translation. |
| Peripheral composition | Policy/capability/order/private/public/transport/boundary validation for every declared legal stack | Added cumulative Gate/S6EPE descriptor and memory estimates to DeploymentLock, revalidated at apply and supervisor launch, and surfaced in Detector compliance. Estimates are conservative configuration checks, not runtime memory attestation; Guard and per-platform Supervisor resource enforcement remain separate work. |
| Gate/BrokerSet portable routes | Only S6P1.routes drives realized route intent and bounded failover | Audit consumers and drift tests; no migration/quorum/replication claims. |
| Shared supervisor state machine | Linux pidfd/identity/child/owned socket/transport/readiness; honest native-init capabilities on other platforms | Existing Linux observation retained. Audit platform abstraction, lifecycle parity and stale/degraded/failed transitions for every crash/drift condition. |
| One-command installed experience | Intent-based setup/run for available Profiles, ordered sidecars, idempotence, actionable missing-runtime diagnostics | Setup still requires operator-supplied native config; now prepares lock/apply and run starts separately. Implement registry-driven intent realization with no install/build during run. |
| Upgrade/reconfiguration safety | Explicit stop/upgrade-or-configure/relock/apply/run; drift detection and failure rollback | Added explicit `service upgrade` as stopped configure→lock→apply with record rollback on failure. It does not build, install or start runtime processes; full UI entry points and end-to-end failure injection remain open. |
| Shared consumer truth | Detector/Control Center/CLI/libshadow6/fleet/Deployment/Service-Init consume the same spec/bindings/lock/observation | Initial registry consumer migration only; remaining authority and GUI/API drift audit outstanding. |
| Architecture completion matrix | All legal Profiles pass registry/config/lock/apply/run/status/connect/restart/stop/remove/doctor; boundary, crash/stale/drift, capabilities and peripheral matrices | Registry pair tests and focused realization tests added to CI/default gate. Real lifecycle, library, optional composition and provider matrices outstanding. Toolchain absences must produce explicit reasons. |
| Current documentation | README/getting-started/core-matrix/named-services/service-connections/Deployment/S6EPE/security/audit describe implementation plus verified CI | Current source registry documentation added. Broad documentation update follows actual implementation and CI evidence; historical claims must stay labeled. |
| Complete operator UI/UX | Clear intent setup, explicit available Profile selection, actionable field diagnostics, observed states, connection and stopped upgrade/reconfiguration actions; accessible existing UI surfaces | User's continuation explicitly requires the full UI/UX work. Read-only Control Center service list/status/doctor/connection APIs now share Registry truth, with authenticated loopback HTTP list/status and strict name queries. Full intent setup and UI integration are still open. |

Local validation so far: 19 registry/feature tests passed; 78 existing
Deployment/Core-explicit/topology/service/native-tool tests passed with one
explicit `S6EPE_BINARY` environment skip; 49 CLI/Benchmark/fleet tests passed;
45 registry/feature/Profile-realization/fleet tests passed after selection
normalization. Test groups overlap. Expected fixture output includes rejected
missing binaries and unavailable SCTP; these are negative-test observations,
not successful real native Profile deployment. Staged installed-import tests
passed and were extended to inspect all 13 source Profiles. No twelve-Core
build or full release/package workflow ran.

Next implementation stage: complete message and credited attachment with a
shared boundary contract, remove remaining process-only startup acknowledgement,
and add real all-Profile lifecycle/config/provider CI coverage.
Keep the overall objective active until every row is proved by current sources
and real CI/runtime evidence.

Latest focused run after strict numeric boundary validation: 24 registry,
feature-report and Profile realization tests passed. The installed-import test
passed with `core profiles` and isolated installed registry imports. Source-only
audit: 7 passed, 0 failed, 1 explicit binary-hardening skip. Whitespace checks
passed. No package archives were generated.

Final workflow/install-tree/CLI regression group: 20 tests passed. The live
Actions re-query still reports OpenBSD arm64 in progress and no failed jobs.

2026-10-04 ProfileBinding continuation: strict ProfileBinding now survives the
full local service/lock/launch/runtime/connection/Detector path. A null locked
Profile ID is rejected rather than choosing a primary Profile. Legacy records
cannot run or relock until explicitly reconfigured; stop remains possible.
Run requires an existing lock. Setup prepares/applies and has an explicit --run
option. The same bounded actual feature probe is shared by Detector and named
service doctor. Native and Guard external TLS credentials are included in
launch material and checked before spawn and acknowledgement. Stale/degraded/
failed states no longer claim running after binding drift, observation failure,
process-only readiness or early component exit. Process-only supervisor startup
acknowledgement itself is still a remaining gate; native init support on other
platforms and message/credited attachments are also incomplete.

Focused evidence: 76 service/context/ProfileBinding/Detector tests passed with
one explicit S6EPE_BINARY environment skip; 21 ProfileBinding/launch-lock tests
passed; actual staged installed-import validation passed. Fixture lock matrix
coverage for 13 Profiles proves binding/material admission only. Real existing
Go broker setup/run/status/connect/doctor/stop tests exercise a real native
binary, without rebuilding it. These local changes have no CI result yet.

Final combined focused regression for this continuation: 121 tests passed with
one explicit missing-S6EPE_BINARY runtime skip. Separate ProfileBinding/runtime
truth/Guard-material suite: 14 tests passed. Source-only audit: 7 passed, 0
failed, 1 binary-hardening skip. The exact OpenBSD arm64 job 111349127606 was
queried and remains live in Test OpenBSD components; no replacement/restart was
triggered. No Native Core build variant, dependency download, full release
workflow, package or archive was produced. Next continuation should start with
message/credited attachment and the executable boundary contracts, while
preserving all remaining rows in this ledger.

The material completion gate still includes hashing/rechecking local Python
adapter/supervisor implementation material and native config-schema admission
at setup/lock. The current Profile matrix uses fixture configurations and must
not be presented as proof that all native parsers accept them. Installed CLI
setup/doctor help and isolated package imports passed in the final staged
install-prebuilt test. No archive paths/sizes exist for this continuation.

2026-10-04 message attachment / real lifecycle continuation:

- The previously incomplete local record adapter now has passing fixture-engine
  lifecycle/library/stdio tests for Pony/Hare/Carp/Idris and best-effort Micro-Mux.
  Record limits, single-flow consumption, native FD ownership, strict binding
  handshake, bounded per-direction backpressure and EOF/drain remain explicit.
  Two additional tests fill the real kernel queues, prove backpressure/recovery
  without record splitting, and reject a mismatched lock before native ingress.
- Startup no longer acknowledges process liveness alone. Client admission
  waits for the observed application endpoint; other roles require owned native
  endpoints. Sidecars launch in dependency order (Gate client before Core;
  Gate server before EPE) and require owned listeners. Before each spawn and
  final acknowledgement, all locked runtime/config/native/peripheral material
  is checked again. This is not yet complete per-Profile/peripheral transport
  and exact-listener admission for all combinations.
- A real gate exposed the Go agent's startup dependency: its data listener is
  allocated after client admission. The observer now checks an actual owned
  TCP connection to the declared broker when that agent has no listener.
  `control-ready` proves only that connection, never broker authentication or
  an application/data session. The Registry records this distinction. Actual
  control peer ownership and wrong-peer/closed-peer tests were added.
- `install --json`, `core profiles --installed` and setup preflight now use the
  shared Profile authority for bounded binary feature probes, kernel SCTP and
  supervisor prerequisite diagnostics. Build toolchains are informational and
  are never installed or called by run. These probes do not certify a complete
  native deployment. Older local Rust and several optional artifacts fail the
  current feature contract; Idris's binary is absent. No fallback was added.
- The required Linux CI gate `integration/test_named_profiles.py` derives its
  13 cases from the Registry, realizes coordinated native configurations and
  drives public CLI setup/run/status/doctor/restart/stop/remove plus real
  libshadow6 traffic twice. It requires artifacts, never skips a missing Core,
  never compiles, and keeps drift/lock preservation assertions. The focused
  existing Go binary case passed after the agent startup fix. Other newly
  changed native binaries and the full gate have no current CI proof yet.
- Integration/benchmark artifact and transport maps now consume the Registry.
  Installed imports include the adapter and availability module. Read-only
  Control Center methods and authenticated HTTP list/status use Registry
  observations; no mutation transport was enabled and no UI state machine was
  introduced. HTTP tests verify auth, real shared records and duplicate/unknown
  query rejection.

Focused completed groups so far: 48 service/message/ProfileBinding tests passed
with one explicit missing-S6EPE_BINARY skip; two added record-negative tests
passed; 41 availability/Control Center/installed-import tests passed; 44
availability/CLI/Benchmark/CI-contract tests passed. Groups overlap. The updated
negative readiness fixtures now expect startup rejection rather than historical
process-only success. Source-only audit: 7 passed, 0 failed, one binary-hardening
skip; whitespace and Python compile checks passed. Additional final regression
results follow below once their exact live sessions complete.

No native default/Crosed/Public6 build variants, full release workflow, Android
build, dependency downloads, host changes or packages ran. Archive paths/sizes:
none produced. Existing config keeps L0, application transport and Qubes policy
disabled. Optional system tools observed: Zig, GNAT, Nim, Hare and LDC available;
Gleam, Pony, Idris2 and Carp absent from PATH (vendored availability was not
re-provisioned). Registry entries remain source contracts, not all-Profile proof.

The full objective remains open: intent-only config/credential realization,
native init supervisor parity, actual all-Profile and optional-stack CI,
complete credential/provider/local material closure, credited attachment,
executable WebRTC signalling/carrier adapters, upgrade/reconfiguration
transactions and the complete existing UI/UX/documentation pass. In particular,
client stream attachment combined with an EPE public admission endpoint still
needs separate typed application/public observations; the current refusal is
not to be reported as supported lifecycle completion.

## Integration pass (2026-10-04)

- Auto-Orchestrator's local generated topology can now be materialized as
  Named Services under an explicit namespace. Each node gets its selected
  Profile, generated native configuration and S6P1 role/identity, then is
  locked and applied as a batch. No service starts implicitly. Remote nodes
  and generated Gate compositions fail with an actionable explicit error.
- `libshadow6` exposes an explicit credited S6NA companion attachment. The
  private attachment document pins endpoints/key path and role; send credit,
  bounded receive, backpressure/recovery and facade close are covered by a
  loopback integration test. The application-side named-service bridge is
  still missing, so this does not close the full attachment matrix.
- Gate and S6EPE resource configuration now feeds one component-limit
  resolution. The lock, `apply`, immutable launch plan, supervisor pre-spawn
  validation and Detector recompute it. Limits are aggregated across enabled
  Gate/EPE components and compared with the same host snapshot and Core
  `process_fds` ceiling. This is a bounded estimate; Guard memory/FD budgets
  and non-Linux runtime enforcement are still open.
- `shadow6 service upgrade NAME --core CORE --profile PROFILE --config ...`
  performs a stopped configure/lock/apply transaction and restores the exact
  previous registry bytes on failure. It does not start, build or install.
- S6EPE WebRTC remains library-only. `Config.load` does not admit a WebRTC
  carrier and `main` has no bounded offer/answer signaling lifecycle. The
  current tests establish native carrier/session library behavior only; do
  not treat this area as integrated until signaling, executable startup,
  local application boundary, lock/observation and negative lifecycle tests
  exist.
- Targeted verification for this pass: Deployment ProfileBinding plus local
  topology tests (20); Detector compliance test (1); credited libshadow6
  integration suite (12, from the preceding focused run); Crosed Limits tests
  (7 after adding aggregate Gate/EPE cases). No Hare, Idris or Pony binary was
  built. Full release workflow, platform CI and archive generation were not
  run.

2026-10-04 unified Limits continuation: user additionally requires all Profile
resource dimensions, Gate/S6EPE/Supervisor/Deployment/Detector/Control consumers,
strict migration, platform CI, Chinese historical documentation, git push and
local source package. The new Crosed/limits.py authority and Profile models are
connected to named locks, CLI policy, supervisor FD enforcement and record
adapters. Initial focused group: 56 tests passed. All 13 Profile policies resolve
against bounded fixture budgets. Full peripheral dimension coverage and platform
resource backends remain open; no completion or push/package claim is warranted.
