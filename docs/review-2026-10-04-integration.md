# Integration review — 2026-10-04

## Scope

This source update completes the cross-component wiring for all thirteen
Native Profiles, the multi-stream S6NA client reflector, lock-bound S6SG1
signaling entry points, dynamic Named Service capacity, fixed system-operation
adapters, read-only Control Center UX, Android Profile/traffic visibility,
ARM64 Profile lifecycle CI, and bounded Windows iperf3 retries.

The Named Service now owns the bounded S6SG1 signaling broker for explicit
Nim/WebRTC bindings. Native ICE/DTLS/DataChannel validation still requires
the optional native toolchain. Windows/macOS expose typed operator actions but do
not claim Linux pidfd process-supervision parity. Android reports its four
packaged Profile IDs and S6NA VPN observations; the APK does not embed the
Python Named Service registry or S6EPE runtime.

## Verification performed before push

No native Core or Android APK was built locally. Existing Linux artifacts from
GitHub Actions were unpacked into an isolated temporary tree and exercised
against the current Python source. All thirteen real Named Service lifecycle
tests passed: `13 passed` in 289.435 seconds. This ran the profile's actual
Broker/Agent/Client processes and covered two run/restart cycles, connection,
status/doctor, stop, configuration drift, and record/stream boundaries.

The run exposed and fixed the shared feature-report probe's missing artifact
runtime environment for Idris/Chez and Nim/libdatachannel. Idris and Nim used
their matching libraries from the downloaded artifacts/runtime tree; no
toolchain build was invoked.

Other recorded focused checks:

- Control Center: 36 passed.
- `libshadow6`: 16 passed, including multi-stream shared S6NA transport.
- Service-Init discovery: 10 passed; portable system-operation contract added
  to Windows/macOS/ARM64 CI.
- Network Adapter: 11 passed.
- Deployment/Profile/context/lifecycle/native-profile group: 91 passed,
  1 skipped for its explicit missing optional runtime.
- Windows iperf matrix tests: 6 passed.
- Android manifest/string XML and multiplatform workflow YAML parsed.
- `shadow6_audit.py --source-only`: 7 passed, 0 failed, 1 binary-hardening
  check skipped by the requested source-only mode.
- `git diff --check`: passed.

Android Gradle/SDK is unavailable on this host. The new APK changes therefore
need the post-push Android CI job. The prior Actions baseline, run
`37206529353` at `b437a0ae`, passed Linux x86_64/ARM64 release work and the
Android debug job; the only producer failure was the Windows-amd64 iperf3
loopback pressure job. Those results predate this source update.

## Post-push CI and package (historical observation)

Actions run `37235236319` at `fef48804` completed the Linux build, Crosed
variants, `make test`, `make check`, offline audit, assistant checks, and staged
installation. The audit reported 115 passed, 0 failed, 15 skipped. Twelve of
thirteen real Named Service Profile lifecycles passed; Carp briefly returned a
degraded health observation during `doctor`. Android APK, Windows-amd64 iperf3,
Gleam x86_64/ARM64 and multiple BSD/QEMU jobs passed before the run was
cancelled for the health retry fix.

Commit `bce9e0cd` adds a bounded three-second retry for a live supervisor and a
regression test. Full validation was submitted as [Actions run
37238710525](https://github.com/txmu/Shadow6/actions/runs/37238710525). This records the earlier handoff, not a current observation of that
run. Its final matrix, toolchain availability, audit counts, warnings and package
results require a separate CI/release observation. The final source-only
`Shadow6.zip` has not yet been generated; record its path, size and SHA-256
here and in the Chinese project history after inspection.
