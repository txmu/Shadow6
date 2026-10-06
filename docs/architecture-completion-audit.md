# Architecture integration audit

## Current documentation scope — 2026-10-06

S6EPE currently implements mandatory encrypted wire v3 with raw/TLS stream,
raw datagram and Linux SCTP/WebRTC message carriers. The executable's real
libdatachannel ICE/DTLS/SCTP/DataChannel bridge and explicit Nim/WebRTC Deployment
binding are implemented. Named Service owns the bounded S6SG1 broker, rechecks
locked runtime material, and waits for fresh v6 active authenticated-session
telemetry plus an owned UDP socket. These are source/test contracts, not a new
claim that platform CI or the entire architecture has passed. See the
[current guide](privacy-envelope.md) for deployment and provider limits.

## Source snapshot — 2026-10-05

The current worktree integrates the Native Profile registry with Named Service
setup and lock checks, multi-stream S6NA reflection, dynamic service-count
budgeting, fixed typed external system operations, a loopback read-only Control
Center dashboard, Android Profile/traffic visibility, broader ARM64 lifecycle
CI, and bounded Windows iperf3 retry/reporting. All thirteen real Linux Named
Service Profile lifecycle cases passed locally against existing Actions-built
artifacts (no native Core rebuild). A fresh Actions run for these source changes
is required before release claims; see the dated integration review.

The S6SG1 client reflector and bounded, owner-only Named Service broker are
implemented. Native ICE/DTLS/DataChannel pairing still needs platform CI.
Linux remains the only platform with
the pidfd Named Service process supervisor; other platforms expose typed,
fixed system-operation plans and capability diagnostics. AIX SRC has a generated
foreground definition and typed contract, without a tested native provider.
Android surfaces its
four packaged Core Profile IDs and S6NA VPN observations, but does not embed the
Python Named Service registry, S6EPE runtime, or signaling broker.

The source checkout supports read-only `setup --check`; `install-prebuilt`
admits existing artifacts without compiling or automatically starting services.
The sections below are historical audit snapshots. Their dated implementation
details remain useful evidence, but any older “active” or “still open” status
is superseded by this current summary and the
[completion ledger](native-profile-runtime-plan.md).

## Unified Limits implementation status (2026-10-04)

`Crosed/limits.py` is the shared bounded resolver, exposed to Deployment by the
`Deployment/profile_registry.py` import facade. Named Service locks record the
resolution; its supervisor enforces the process file-descriptor ceiling and
record adapter, while runtime observation checks the same resolution. Host
changes require an explicit relock and do not trigger an implicit shrink.
Gate, S6EPE, Detector, Control Center and other components do not yet consume
all their resource dimensions from this result. This is an implementation
milestone, not completion of the requested cross-component Limits rollout.

## Active Profile-driven Runtime completion gate (2026-10-04)

Latest continuation adds strict ProfileBinding across records/locks/launch and
runtime identities/connection plans/Detector; explicit legacy reconfiguration;
run-from-existing-lock; setup preparation plus explicit --run; shared bounded
feature probing for named doctor; native/Guard external TLS material locks; and
truthful stale/degraded/failed observation states. Focused and installed-source
checks pass, including an existing real Go broker. Thirteen real Profile
lifecycle integration, message/credited sessions, executable WebRTC, remaining
startup acknowledgement and cross-platform supervisor gates are still open.
The requirement ledger supersedes earlier next-work descriptions below.


The current operator objective is the full Named Service/Application Runtime
for twelve native families and thirteen explicit Profiles. The acceptance rule
is: every Profile advertised as **available** by features/network catalog must
pass the same setup/run/status/connect/restart/stop/remove/doctor contract.
Adding a future Profile must require a registry entry and contract compliance,
not new lifecycle branches. Completion remains **unproven**.

Current source progress: `Crosed/native_profiles.py` is the shared Native
Profile source authority. Feature-report boundary validation, Core Catalog,
Deployment transport realization, Auto-Orchestrator Profile selection, CLI Core
artifact routing, native datagram family selection, Benchmark artifact and
pressure-profile lists now derive their facts from it. C++ config `sctp` and
feature transport `sctp-tls13` remain distinct. Gleam secure-stream and Micro-Mux
have explicit IDs and separate boundaries; the legacy Gleam topology selector
normalizes immediately through the registry, with conflicts rejected.
`shadow6 core profiles [CORE]` exposes source contracts without asserting host
availability. Source contracts reference existing security/composition/platform
authorities; peripheral compatibility still requires implementation admission.

Focused evidence: registry tests exercise all 12 by 13 family/Profile pairs,
unknown and conflicting selection, contract drift and detached records;
realization tests verify distinct Gleam transports, legacy normalization and
conflicting config rejection. Existing feature, CLI, Benchmark, fleet and
Deployment regressions have passed. Actual staged `install-prebuilt` checks
verify the new module from outside the source tree and under isolated Python
imports. These are source and existing-service regressions, **not** proof of
thirteen real Named Service lifecycle integrations. CI includes the new focused
contracts and the default test gate includes them.

Authoritative Actions observation: run `37172827272` at commit
`b42cae9e776676b1238f2a05133e313d967fee4a` is now completed successfully, including
OpenBSD arm64. Its successful Linux and envelope producers cover that
commit, not the present uncommitted registry changes. No Native Core build,
dependency installation, release workflow or archive packaging ran locally.

The current worktree adds a required Linux CI gate that drives public Named
Service setup/run/status/doctor/restart/stop/remove and real libshadow6 data
through both Gleam Profiles and every other built Profile. It has no CI result
yet. A focused existing-binary Go run passed both lifecycle cycles. The older
local Rust binary predates structured application readiness and failed that
gate; setup now rejects mismatched installed feature contracts earlier. No
fallback or local twelve-Core rebuild was introduced. Message fixture tests
prove FD ownership, record boundaries, bounded backpressure, EOF/drain and
handshake binding for the local adapter, not native wire/trio interoperability.

The requirement ledger and remaining implementation gates are in
[native-profile-runtime-plan.md](native-profile-runtime-plan.md). The sections
below record earlier milestones; their historical test totals and CI states
must not be taken as the current completion verdict.

# Architecture completion evidence

This is an incomplete implementation audit against the operator's twelve-item
architecture request. It records starting evidence, not a release certification.
An existing implementation or passing old test does not prove the complete
requested behavior. Native Core wire formats and least-privileged defaults
remain constraints throughout this work.

## CI priority

Run `37124037391`, commit `12479b84`, failed only its Linux producer and dependent
platform summary. The job logs API showed `make audit`: 112 passed, 2 failed,
15 skipped. Both failures were missing application boundary lists in tracked
Go/Rust Public6 products. Linux rebuilt default/Crosed products but did not
rebuild Public6. Commit `1a7dfa4d` adds `make public6-variants` before tests/audit;
the existing target preserves L5 products then restores L0. Six focused Linux
workflow tests passed. Run `37162771822` is the verification handle; its complete
result has not yet been established. No local Core build or packaging ran.

Subsequent live polling of that run found two additional producer failures:
OCaml's persistent-replay restart test observed no replay rejection counter;
Windows ARM64 MSYS2 setup failed while invoking its missing `paccache` command.
The latter now explicitly installs `pacman-contrib`. The restart test now proves
fresh authenticated forwarding after restart, sends at most five identical
replay probes, requires a rejection counter, checks zero replayed native bytes
in both directions, and requires the process to remain alive. The original
test passed thirty local repeats; packet loss/startup timing remains an
inference, not an established production root cause.

Prior carrier-refactor validation: 22 matrix/feature tests, seven Linux/Windows workflow
tests, seven portable PPB tests including exported native security validation,
and ten EPE E2E tests passed. EPE E2E used the existing executable and therefore
does not validate the newly refactored OCaml source. Source-only audit: seven
passed, zero failed, one explicit binary-check skip. Changed Python AST,
workflow YAML and diff checks passed. OCaml compilation/new carrier tests and
the full platform matrix remain Actions gates; no OCaml toolchain is present
on the local PATH. No archive was produced and no native build variant was
compiled locally in this work.

## TLS Carrier progress

Run `37163881988` has passed the OCaml producer and Windows ARM64 producer;
several native jobs remain pending/in progress and no final green result has
been established. The TLS change is not yet part of that run.

An existing extracted OCaml 5.3 toolchain was found under `/tmp`; no dependency
was downloaded. Only the small privacy-envelope component was source-built.
Its dune crypto/datagram/carrier tests and focused Python suites passed: actual
raw/TLS envelope processes, TLS native binding tests, private aggregate metrics,
and Deployment lifecycle/admission tests: 19 envelope/native-TLS tests, 66
source-built Deployment tests and seven Control Center observation tests passed.
Source-only audit: seven passed, zero failed, one explicit binary-check skip. The baseline Deployment suite without
`S6EPE_BINARY` had one explicit unavailable-binary skip; the source-built combined
rerun supplies the binary. No Native Core build, full release workflow, platform
package or archive ran locally.

TLS encapsulation now uses one genuine mTLS 1.3 channel for all envelope bytes,
keeps the independent S6EPE proof mandatory, enforces SAN verification/private
bounded Ed25519 material, and supports nonblocking buffered I/O/backpressure.
A real half-close test found unread TLS close_notify causing TCP reset truncation;
consuming the authenticated alert after envelope FINAL fixed the test without
accepting unauthenticated EOF. Wire recordings verify standard TLS records and
absence of inner hello/payload markers. Browser mimicry and DPI resistance are
not established. TLS material digests stay in local DeploymentLock/launch plans;
TLS metrics v3 identify the configured carrier and appearance.

## Native SCTP provider progress

Linux loopback SCTP is available locally. Only the small provider C binding and
OCaml Envelope were built, without a Core build or dependency download. Nine
native C tests and the source-built typed OCaml test verify real SCTP message
semantics, including 128 KiB fragmentation and whole-message retry. Stream-reset
notifications required explicit per-association reconfiguration negotiation;
request acceptance alone was not completion evidence. Tests wait for incoming
and outgoing confirmations on both sides before proving stream reuse. Carrier
contract v2 distinguishes reset, channel close and association lifecycle, and
uses portable int64 values for bounded uint32 PPID/context. The raw provider
rejects SCTP rather than flattening a one-to-one SOCK_STREAM association.

SCTP now has source-built runtime integration: complete-message mutual proofs,
fresh directional keys, per-channel AEAD/ratchet/replay windows, authenticated
reset/final watermarks and PR abandonment controls. Pending ciphertext survives
whole-message backpressure. An actual E2E failure exposed use of unsupported
Linux SCTP `SIOCOUTQ`; sender-dry now rechecks current send allocations and
drains earlier failure events before reporting completion. A stale-notification
regression test verifies this behavior. Actual wire tests show encrypted native
payload but identifiable SCTP hello, and reject injected replay/tampering.
Native SCTP itself is not encryption or camouflage. Run `37165460928` completed
successfully on commit `1fee4fc2` on 2026-10-04. It predates the uncommitted
message-provider and WebRTC bridge work and does not validate those changes.

Linux Named Service observation now includes process-owned one-to-one SCTP
listeners, requires listener state and actual descriptor inode ownership, and
includes them in the existing observation limits. Envelope upstream matching
requires the configured transport; TCP on the same port cannot prove SCTP
realization. Deployment admits explicit bounded message channel configuration.
The supervisor now uses the shared duplicate-rejecting envelope parser rather
than rebuilding a dictionary that could overwrite repeated fields. Control
Center strictly parses aggregate SCTP v4 counters; snapshots use one lock.

Current local checks: source-built dune component tests; 70 Deployment
context/lifecycle/Core-explicit/SCTP observation tests; eight Control Center
observation tests; seven Linux workflow tests. Source-only audit: seven passed,
zero failed, one explicit binary-check skip. Only the small OCaml envelope/C
provider was compiled, using the existing extracted OCaml 5.3 toolchain. No
dependency download, Native Core variant build, full release stage, package or
archive was produced. All 37 source-built envelope Python tests passed.
Core-specific SCTP integration and
cross-platform verification still require CI evidence.

## Requirement evidence and remaining gates

### WebRTC provider evidence

Historical provider-stage evidence (2026-10-04): the v5 and rejected/unfinished
executable claims below applied at this stage only. Current configuration,
feature reports, Deployment admission and Named Service broker integration
supersede them; WebRTC now emits v6 active-session telemetry. This section's
test totals remain the recorded totals, not verification of today's checkout.

After explicit operator approval, the existing CI-pinned libdatachannel commit
`9e6a13abbb6846c003d817d0387b6706466e2b03` and pinned submodules were downloaded
and source-built solely in `/tmp/shadow6-webrtc.FTsiIy`, with no global package
installation or host service/network changes. The optional native provider and
OCaml bindings are source-built against that actual 0.23.2 backend. Seven native
loopback tests pass: ICE/DTLS readiness, message/channel/order/PR/text/binary
semantics, callback overflow, actual backpressure/retry, native channel closure,
and wrong-DTLS-fingerprint rejection, including global queue reservations and
their release. A separate compiled-out-backend test proves explicit
unavailability rather than successful dummy operations. Typed OCaml tests verify independent PSK
proofs, directional AEAD, replay rejection and authenticated channel close/FINAL.
Testing discovered and fixed the C API's negative text-size convention and
NULL zero-length binary callback handling. Channel-zero application closure
now allows later envelope control records and FINAL while rejecting further
application data; a focused crypto regression verifies this distinction.

The Core-blind `Webrtc_session` now owns an established native peer and runs the
independent mutual proof, directional record encryption, per-channel replay and
authenticated close/FINAL protocol. Source-built actual DataChannel tests prove
bidirectional opaque messages across ordered, unordered and partial-reliability
channels, complete authenticated shutdown, rejection of unexpected native close,
and native peer release after an incorrect independent proof or idle timeout.
`Webrtc_bridge` now connects that authenticated session to another actual native
DataChannel association with one pending whole message per direction and bounded
channel-close state. A six-peer source-built loopback test proves bidirectional
opaque text forwarding across all admitted channel policies and propagation of
native close through authenticated close/FINAL. It exposed and fixed a race where
native reset completed before its queued callback was consumed. Repeated native
close requests are accepted without synthesizing completion; only the original
native event is delivered, and closed channels still reject data. A dedicated C
regression checks this property. The independent wrong-key session test now uses
a valid-length server key, so the failure exercises mutual proof rather than
key-length admission. These are library milestones, not deployment readiness.

WebRTC telemetry has a distinct strict Control Center schema v5 identifying
`standard-webrtc-datachannel`; it reuses the bounded native-abandonment and
session-rejection counters without claiming camouflage. Source-built OCaml
snapshot and nine Control Center tests pass. The main executable and Deployment
parser still reject WebRTC realization, so this is a telemetry contract only.

The complete source-level bridge is now tested, but CLI configuration, standard
signalling handoff, Deployment admission/lock, PR abandonment observation and
Named Service WebRTC realization remain unfinished. Runtime configuration
rejects WebRTC and the feature report does not advertise a completed WebRTC
adapter. This does not prove item 4 or the whole architecture goal complete.
The CI envelope producer provisions the pinned private dependency and requires
real WebRTC tests rather than allowing missing-backend skips. The current
uncommitted bridge, SCTP and telemetry changes have no CI result.

Latest source-built regression: 45 envelope Python tests and 78 Deployment /
Control Center tests passed with the real optional backend required, plus seven
Linux workflow tests. Source-only audit: seven passed, zero failed, one explicit
binary-hardening skip. No Native Core variant, release build or archive ran.

On 2026-10-04 the authoritative Actions query confirmed run `37165460928`
(commit `1fee4fc2e3380ff22b48046d972614d8187ce014`) completed successfully.
This supersedes the earlier in-progress observations above; it does not cover
the current uncommitted SCTP/WebRTC implementation. Current source-built dune
tests, including the new session failure-path tests, passed using the existing
private OCaml 5.3 and libdatachannel installations. The 45 envelope Python
tests passed with the optional native backend required. No dependency download,
Native Core build, package or archive was performed in this continuation.

### Datagram replay restart guarantee

An audit of the actual datagram packet path found `replay_path` was optional even
though persistent replay protection is a required envelope control. Datagram
configuration now fails closed unless a dedicated absolute replay-state path
has an existing owner-controlled private directory; non-datagram modes reject
that field. Deployment performs the matching admission check and validates an
existing state file before locking. The E2E launcher provisions per-instance
state by default, retains the explicit same-file restart/replay test, and adds a
negative executable test proving missing state creates no metrics/listener.
Source-built dune component tests, the 46-test Envelope Python suite, five
targeted Deployment admission tests and the 80-test Deployment/Control Center
regression set passed (one existing environment-conditional skip). The source
build validates the feature report's required-state declaration.

The same component run exposed an intermittent WebRTC shutdown failure. The
libdatachannel peer state callback reports `DISCONNECTED` transiently during
authenticated bilateral close before `CLOSED`; treating that intermediate state
as terminal rejected the valid close path. The provider now lets bounded S6EPE
handshake/session deadlines govern disconnection recovery and fails immediately
only on `FAILED`. Full source-built component and 46-test Python reruns passed.

The repository-wide `make audit` was checked against the current worktree:
92 checks passed, 16 failed on stale prebuilt Core feature reports missing the
current application-boundary contract, and 19 were skipped for unavailable
optional artifacts. The focused `.venv/bin/python shadow6_audit.py
--source-only` run passed 7, failed 0 and skipped 1 binary-hardening check.
No Core binaries were rebuilt locally. The latest remote full CI run predates
these uncommitted changes, so current CI validation remains outstanding.

### Additional operator requirement: UI/UX

The operator has also requested substantial UI/UX improvement after making the
WebRTC channel robust and completing the remaining architecture goal. The
existing Control Center, Named Service flows, CLI and Android UI are being
located; priority clarification is pending. This requirement is added to the
completion scope and has not yet been implemented or verified. Actual ready,
stale, unavailable and degraded states must remain truthful in every interface,
and Web API least-privilege defaults remain constraints on the UI work.

| Item | Starting implementation evidence | Completion evidence still required |
| --- | --- | --- |
| 1. Native independence | Deployment/topology_contract.py admits native families; OCaml envelope forwards opaque bytes | Review all new carrier paths for absence of native wire parsing or translation |
| 2. S6EPE v3 security | OCaml/privacy_envelope/src/{forward,session,replay_store,metrics}.ml implement directional crypto, stream ratchet/final, bounded replay/persistence/shaping and observations | Source-built negative tests for every requested control, including carrier integration and restart behavior; verify the newly required datagram state across every deployment setup path |
| 3. Carrier contract | carrier.mli defines separate stream/message interfaces; Forward.Make_handshake and Session.Make use stream provider operations; raw default plus explicit mTLS 1.3 provider; source-built loopback wire observation verifies inner hello concealment, independent PSK admission, backpressure and authenticated half-close | Continue dedicated message-provider work and CI interoperability verification; raw identification stays explicit |
| 4. SCTP and WebRTC | Linux Carrier_sctp and authenticated message runtime preserve streams/PPID/order/PR/boundaries/reset/reuse/shutdown/backpressure and budgets; native Carrier_webrtc and typed message security now pass actual ICE/DTLS/DataChannel failure/lifecycle tests | Full WebRTC bridge/configuration/signalling/PR close/runtime observation; Core-specific deployment interoperability and CI gates remain required |
| 5. Composition | docs/service-connections.md describes Guard/EPE/Gate/Core stacks | Validate nested composition and document native/outer encryption domains separately from S6NA adaptation and routing |
| 6. Portable admission | Deployment/protocol_context.py and Detector/service_compliance.py share realization admission | Recheck required/forbidden components and credential scopes across setup/lock/run/connect/install; demonstrate local facts cannot enter portable intent |
| 7. Named lifecycle | Deployment service tests and docs/named-services.md exist | Inspect setup through init implementation and verify real identity/socket/ready chain on Linux and explicit platform degradation elsewhere |
| 8. Real connections | Prior service review documents observed stream attachment and capability errors | Recheck current connect/libshadow6 boundaries against live ownership, feature declaration and S6P1 scope, including negative boundary cases |
| 9. BrokerSet | Auto-Orchestrator/shadow6_auto.py validates explicit Gate realization and rejects unsupported activation | Verify shared selection/failover paths and failure tests; no established-session migration, quorum or replication claim |
| 10. Shared authority/drift | Auto imports Deployment.topology_contract and native_realization; Detector reads admission/lock | Verify no alternate generated facts and full intent/feature/binding/lock/config/socket/runtime drift coverage |
| 11. Native security matrix | Crosed/security_capabilities.json covers twelve families and legacy limits; strict loader, generated docs, source audit and portable export share it; 22 matrix/feature tests passed | CI verification of integration; source references are not cryptographic proofs or runtime attestations |
| 12. Current documentation | privacy-envelope.md describes v3 and identifiable hello; exposure audit distinguishes encrypted payload from public hello | Update README/architecture/security/deployment/named-service guides against final implementations and label historical v2/process-only claims |

## Historical next work (2026-10-04)

The WebRTC configuration, S6SG1 handoff, DeploymentLock/runtime observation and
Named Service broker work listed below has since been implemented. The table
above records starting evidence and gates at that date, not current omissions.

Complete WebRTC CLI configuration and standard signalling handoff, connect both
local Native Core boundary and remote outer DataChannel through the existing
bridge, and add matching DeploymentLock/runtime observation. Then audit the
remaining admission, Native Service, BrokerSet, drift and documentation gates.
The last published Actions run is green; submit the final reviewed worktree for
CI and repair producer failures before claiming the architecture is complete.
