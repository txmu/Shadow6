# Native Profile and Named Service completion ledger

Updated 2026-10-04. This is the current status ledger; earlier progress notes
and repeated next-step lists were removed. Completed items are struck through
as requested. A source implementation or local test does not imply platform
parity or a passing post-change CI run.

## Completed

- ~~One source registry defines all thirteen Native Profiles and their IDs,
  application boundaries, limits, realizations, transports, and platform
  requirements. Core catalogs, configuration realization, Deployment,
  connection planning, feature reports, and the CLI use this authority.~~
- ~~Named Services bind an explicit Core and Profile, retain strict S6P1
  context and deployment locks, detect material drift, and expose observed
  readiness through setup, run, status, doctor, connect, restart, stop, and
  remove.~~
- ~~The S6NA client facade can select a lock-bound attachment automatically;
  it supports multiple bounded application streams and retains native access
  through `connect_native`. An explicit WebRTC signaling client reflector
  exposes the lock-bound S6SG1 offer/poll/answer contract.~~
- ~~Named Service capacity no longer uses the arbitrary 128-entry ceiling.
  Admission derives the service count from host memory and descriptor budgets,
  within a 64 MiB registry-file bound and a 131,072-record absolute cap.~~
- ~~Non-Linux operators have typed, fixed system-operation interfaces and
  plan/inspect/apply boundaries for supported managers. Windows and macOS CI
  exercise this contract; it does not claim that their service lifecycle is
  equivalent to Linux pidfd supervision.~~
- ~~Control Center has a responsive, accessible, bilingual read-only web
  dashboard over its loopback-only authenticated API. Android identifies the
  shared Native Profile and displays S6NA VPN packet/byte observations with
  adaptive navigation and accessible state announcements.~~
- ~~The Windows iperf3 matrix retries bounded transient loopback bind/startup
  failures, records each attempt, and emits its report even when the pressure
  step fails.~~

## Still active

| Area | Current state | Completion evidence |
| --- | --- | --- |
| Full Profile runtime gate | Thirteen Linux Named Profile lifecycles are exercised against existing Linux Actions artifacts; current-source local artifact run is recorded in the dated review. | Fresh CI for the committed source, including Linux x86_64 and ARM64. Missing optional libraries or binaries must be reported as unavailable, not silently skipped. |
| WebRTC signaling | Named Service owns a bounded owner-only S6SG1 broker for the explicitly bound Nim/WebRTC Profile. It creates and removes the socket with the supervised runtime, enforces peer identity, bounded SDP/session state, and offer/poll/answer cleanup. | Full native ICE/DTLS/DataChannel validation remains a GitHub Actions responsibility because the native WebRTC toolchain is optional locally. |
| Portable lifecycle | Typed system-operation abstractions exist for non-Linux targets. Linux remains the only platform with the pidfd-based Named Service process supervisor. | Add native lifecycle backends only where the platform contract can be implemented and tested; until then surface capability diagnostics and operator-controlled fixed actions. |
| Android | Android shows the shared Profile ID and transport, uses its existing Core client proxy, and exposes optional authenticated S6NA VPN traffic observations. Its VPN carrier remains a single-peer IP tunnel. The APK does not embed the Python Named Service registry, S6EPE runtime, or S6SG1 signaling broker. | Verify the updated APK in Android CI. Any future Android Named Service support must consume an explicit portable contract rather than claiming Linux supervisor parity. |
| Platform UX | The read-only Control Center web UI is available on hosts that run its local service. Android has adaptive phone/tablet navigation and accessible live state. | Review fresh CI/build results and keep platform-specific unavailable states visible; no UI may imply runtime or peer reachability from a process bit alone. |
| Release evidence | Source changes and local evidence are prepared for commit and packaging. New Actions results are pending the push. | Record exact post-push jobs, warnings, audits, and archive inspection in the dated review and Chinese project history. |

## Limits and security boundaries

The source catalog is not a claim that all thirteen Profiles run on every
platform. The twelve Core protocols remain independent. S6NA is an optional
application adapter and does not alter a Core wire protocol. External
system-operation plans do not execute arbitrary commands. The WebRTC client
reflector is not itself a signaling server, and current Android code does not
embed Named Service or S6EPE lifecycle support.

See [Named Services](named-services.md), [Core matrix](core-matrix.md),
[system operations](supervisor-system-operations.md), and the dated
[integration review](review-2026-10-04-integration.md) for implementation and
verification details.
