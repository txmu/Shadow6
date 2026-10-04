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

## Requirement evidence and remaining gates

| Item | Starting implementation evidence | Completion evidence still required |
| --- | --- | --- |
| 1. Native independence | Deployment/topology_contract.py admits native families; OCaml envelope forwards opaque bytes | Review all new carrier paths for absence of native wire parsing or translation |
| 2. S6EPE v3 security | OCaml/privacy_envelope/src/{forward,session,replay_store,metrics}.ml implement directional crypto, stream ratchet/final, bounded replay/persistence/shaping and observations | Source-built negative tests for every requested control, including carrier integration and restart behavior; optional datagram persistence must satisfy explicit deployment requirements |
| 3. Carrier contract | carrier.mli defines separate stream/message interfaces; Forward.Make_handshake and Session.Make use stream provider operations; raw default plus explicit mTLS 1.3 provider; source-built loopback wire observation verifies inner hello concealment, independent PSK admission, backpressure and authenticated half-close | Continue dedicated message-provider work and CI interoperability verification; raw identification stays explicit |
| 4. SCTP and WebRTC | docs/privacy-envelope.md explicitly declares these adapters unavailable | Dedicated implementations and real integration tests preserving messages, streams/channels, ordering, close, budgets, backpressure and ICE/DTLS/SCTP lifecycle |
| 5. Composition | docs/service-connections.md describes Guard/EPE/Gate/Core stacks | Validate nested composition and document native/outer encryption domains separately from S6NA adaptation and routing |
| 6. Portable admission | Deployment/protocol_context.py and Detector/service_compliance.py share realization admission | Recheck required/forbidden components and credential scopes across setup/lock/run/connect/install; demonstrate local facts cannot enter portable intent |
| 7. Named lifecycle | Deployment service tests and docs/named-services.md exist | Inspect setup through init implementation and verify real identity/socket/ready chain on Linux and explicit platform degradation elsewhere |
| 8. Real connections | Prior service review documents observed stream attachment and capability errors | Recheck current connect/libshadow6 boundaries against live ownership, feature declaration and S6P1 scope, including negative boundary cases |
| 9. BrokerSet | Auto-Orchestrator/shadow6_auto.py validates explicit Gate realization and rejects unsupported activation | Verify shared selection/failover paths and failure tests; no established-session migration, quorum or replication claim |
| 10. Shared authority/drift | Auto imports Deployment.topology_contract and native_realization; Detector reads admission/lock | Verify no alternate generated facts and full intent/feature/binding/lock/config/socket/runtime drift coverage |
| 11. Native security matrix | Crosed/security_capabilities.json covers twelve families and legacy limits; strict loader, generated docs, source audit and portable export share it; 22 matrix/feature tests passed | CI verification of integration; source references are not cryptographic proofs or runtime attestations |
| 12. Current documentation | privacy-envelope.md describes v3 and identifiable hello; exposure audit distinguishes encrypted payload from public hello | Update README/architecture/security/deployment/named-service guides against final implementations and label historical v2/process-only claims |

## Next work

Observe the concrete CI handle and repair any producer failure before declaring
green. Design and implement the carrier boundary using existing S6EPE security
primitives and actual native SCTP/DataChannel facilities, then verify dedicated
adapters with bounded loopback tests. Complete the native security matrix from
source evidence and audit the existing service/admission/drift paths. Local
validation stays focused; native/platform builds belong in Actions.
