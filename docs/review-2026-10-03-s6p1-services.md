# Historical S6P1 service/topology and Actions review — 2026-10-03

This dated review records its then-current EPE v2 state. Later v3 envelope and
carrier work is tracked in `architecture-completion-audit.md`.

## Architecture changes

Registry v2 embeds the existing strictly validated S6P1 context. No parallel
role/routes/identity/credentials fields were added to ServiceSpec. CoreBinding
checks concrete/all/candidate-list scope, catalogs imported descriptors across
invocations, and includes descriptor/native binary/config identity. Lock v2
includes logical context and explicit peripheral material, excluding telemetry.
Legacy intent-free records migrate; ambiguous/native-simulated records fail
closed. No twelve-Core native wire format was changed.

Named Service, S6P1 and Public6 sources share `resolve_connection` and one
connection-plan model. Provisioning remains provisioning. Observed ready local
client streams can actually attach through bounded CLI stdio/libshadow6 sessions;
other boundaries return plans/capability errors. Runtime reads process-owned
Linux sockets and bounded ready JSONL, with explicit unknown/unavailable states.
EPE native/Gate loopback exposure and actual upstream ownership are checked.
All explicitly included critical processes share bounded fail-closed supervision.

S6P1 BrokerSet routes provide identities/endpoints/trust/policy; observed health
stays separate. Native-single adapters reject multi-member sets. Gate config
patches use its existing TCP/UDP selection, with explicit common trust/port
constraints. Auto-Orchestrator accepts that peripheral realization and emits Gate
sidecars; its native-only SSH activation and datagram trio cardinality limitations
remain explicit capability errors. No session migration/quorum/replication is claimed.

## Actual remote evidence

Read the latest run for starting HEAD b3234df:
https://github.com/txmu/Shadow6/actions/runs/37088493984

`gh run list` and `gh run view --json jobs` succeeded. `gh --log-failed` returned
empty output; GitHub job logs API supplied all four failing-job logs:

| Failed job | Evidence/root cause | Fix |
| --- | --- | --- |
| linux | PPB exported source assertions could not read twelve Core runtime/consumer files; Public6 fixture lacked strict application boundaries | Include actual source assertion inputs in the portable bundle and update the fixture to the existing strict contract |
| Linux ARM64 complete component matrix | Same PPB export/fixture failure, in `make test` invoked by the non-Core build step | Same fixes; portable export regression remains enabled |
| Network Adapter and IPC (ubuntu-latest, Node 24) | RPC error was hidden by dereferencing an undefined result; the fixture used a 200ms timeout and no startup mapping headroom | Assert RPC errors explicitly and use bounded 2s timeout/startup headroom; exact original RPC error was not preserved in the old log, so timing/slot exhaustion is an inference, not a confirmed native defect |
| Cross-platform support summary | Platform/performance producer jobs above failed; both summary steps propagated their failures | Preserve failure propagation; fix producer causes rather than making the summary green independently |

Latest logs did not show a Deployment import exception or an audit failure:
Linux/ARM64 stopped earlier at PPB. Staged import coverage nevertheless exposed
and fixed the installed `libshadow6` dependency on an uninstalled Deployment
package. Deployment modules now install into Python's site directory and derive
the real installed tree. Exact marker-byte comparison fixes repeat install
rejection caused by command substitution stripping the newline.

## Local validation

Python focused suites: 117 tests passed (49 deployment/service/import/connect/
install tests; 8 join-code; 9 unified CLI; 7 PPB, including the exported internal
contract suites; 6 Public6; 22 Auto-Orchestrator; 11 libshadow6; 5 EPE E2E).
Node IPC: 20 tests passed, including real existing C11Relay normal/high-speed,
control integration and both IPC paths. EPE and Go loopback lifecycle tests used
existing binaries; no native source rebuild was inferred from those results.

Actual `make install-prebuilt` ran twice in a temporary stage with every BUILD_*
toggle disabled. Entrypoints and Python package imports ran outside checkout cwd,
including Python isolated mode. No host install/service/firewall change occurred.
Python AST/compile, changed workflow YAML/Bash syntax, ShellCheck on the changed
installer, Markdown local links and `git diff --check` passed.

No local `make build/all/test/package/crosed-variants`, Core rebuild, Android,
container/VM/platform matrix, toolchain bootstrap or benchmark was run. OCaml
source was unchanged; existing EPE binary E2E ran, with OCaml rebuild/runtest in
Actions. Full source-built feature-report audits and platform matrices remain
Actions verification. Stale local artifacts have not been relabelled or forged.

Residual support limits are documented in [service connections](service-connections.md):
Linux pidfd supervision, explicit private listener contracts for envelope service
realizations, supported observed stream attachment, Gate pool trust/policy limits,
and native-only remote activation. At that historical checkpoint EPE v2 was an
admission model. It has since been replaced by the authenticated encrypted
[v3 implementation](privacy-envelope.md), whose bounded shaping does not provide
anonymity or carrier camouflage. The new remote run's result must be
observed after submission; local tests cannot certify that matrix.

## Broker realization follow-up

Named Service now locks deterministic BrokerSet realization: route-derived Gate
hosts/trust/policy must match its explicit config, and native broker addresses
must point to its private listener. The shared named resolver derives the adapter
from that realization and rejects conflicting overrides. Tests cover real
registry locking and mismatch rejection, not only planner mocks.

Gate TCP selection retries remaining explicit pool members after dial failure
within a ten-second budget. It never retries authentication failures or migrates
established sessions; UDP datagrams are not replayed. Explicit remote-host pools
no longer require an unused fallback host. The small offline Gate package suite
passed, including a loopback encrypted application path whose first address was
unavailable. No Core or deployment binary was rebuilt.

Remote run [37105054349](https://github.com/txmu/Shadow6/actions/runs/37105054349)
for commit 5b9a85c was read directly. Its previously failing Ubuntu Node 24 job,
Deployment/S6ABI/OCaml job, zero-Core protocol job and OCaml EPE contract job
succeeded. Remaining matrix jobs were queued/running at observation time;
this is not evidence that the entire run has passed or that this follow-up has
already been verified remotely.

Follow-up validation: 67 focused Python tests passed with the existing EPE binary
explicitly supplied, including lifecycle and isolated staged imports; no skips.
The full small Gate package tests passed with `GOTOOLCHAIN=local GOPROXY=off`.
Changed Python AST/bytecode compilation, all workflow YAML parsing and
`git diff --check` passed. No shell or workflow file changed in this follow-up.

## Component admission and latest EPE CI failure

Lock/apply/run now enforce S6P1 Gate/Guard/S6EPE intent and signed credential
scope against actual local component/role realization. Explicit disablement
cannot be overridden by local config; declared required components need a
realization. Public6 Gate provisioning applies the same admission before lookup
or generation. A role-neutral credential-bearing service needs an explicit
logical or verifiable native role. No second component or credential model was
introduced.

The latest run 37105836493 failed its OCaml EPE job (job 111154049319) at
`test_named_envelope_starts_real_runtime_and_reads_observed_metrics`: the counter
was observed but freshness was `stale`. The job log was fetched through the
GitHub API. The metrics writer formatted `Unix.gettimeofday()` with `%.0f`,
rounding timestamps into the next second while the reader floors its current
time. Metrics now floors the timestamp; the real formatter has deterministic
OCaml coverage for six fractional-second phases. Python regression keeps future
timestamps stale; freshness validation was not relaxed. The lifecycle test waits
for both the measured counter and a current observation within its existing
three-second deadline. No local OCaml compiler/Dune was available; the existing
Actions `dune runtest` stage runs the new source test.

A second failed job in the same run, macOS Python 3.14t/GIL=0
(job 111154049510), failed in `actions/setup-python` before project commands:
`getaddrinfo ENOTFOUND raw.githubusercontent.com`. Its log was also fetched.
This is runner DNS/toolchain acquisition failure, not a project test exception;
no tests or failure propagation were disabled to hide it. Verification needs a
runner with working DNS.

Local admission/CI follow-up: 74 focused Python tests passed without skips,
including existing-binary EPE lifecycle and isolated staged imports; six privacy
telemetry tests passed, including the future-timestamp regression. Changed Python
AST/compile, workflow YAML parsing and diff checks passed. The new OCaml formatter
regression has source/static review here and awaits the existing CI build.

## Observed application boundary follow-up

The shared planner rejects observed application readiness when the selected Core
has not declared the client role or boundary, or when it conflicts with S6P1
role/routes. The supervisor only accepts stream readiness backed by the native
process's TCP listener; a loopback UDP fixture reporting stream-ready remains
listener-ready with application readiness unknown. Owned socket address decoding
now respects host byte order; IPv4/IPv6 little- and big-endian cases are covered.
No native protocol or feature report was changed.

77 focused Python tests passed without skips, including the real supervisor UDP
negative case, EPE lifecycle using the existing binary, and isolated staged
imports. AST/compile, all workflow YAML parsing and diff checks passed. Run
37106295322 and its concrete OCaml/Deployment job handles were re-read and remain
queued; no source-built OCaml or full-matrix success is inferred from that state.

## Locked supervisor launch material

The supervisor now verifies exact native and peripheral config/binary digests
from the existing lock before spawning and before success acknowledgement.
Executable hashing uses a bounded open descriptor with metadata/path rechecks;
config hashing uses the existing strict private reader. Launch fields, component
pairs and TTL are validated; no arbitrary command input was introduced.
Regression tests mutate config after apply but before start (Core never starts),
and from the fixture Core during startup (Core is stopped and no success is
reported). EPE/Gate/Guard digest drift and malformed launch material are covered.
Same-owner malicious replacement races remain an operator trust assumption;
these checks do not introduce an in-Core loader or change native protocols.

81 focused Python tests passed without skips, including source/staged imports,
real lifecycle and launch drift regressions, and existing-binary EPE tests.
Changed Python AST/compile, all workflow YAML and diff checks passed. No shell
or workflow was modified, no heavyweight build/package was run, and the concrete
latest CI run 37106440035 remained queued with no completed jobs when re-read.

## Runtime observation truth and bounds

Observation reading now rejects unknown fields, empty/duplicate critical PID
lists and foreign application owners. Freshness is necessary but not sufficient:
status rechecks supervisor-child relationships, deployment component count and
actual owned listener sockets. Missing observations and stopped processes clear
readiness/endpoint. Envelope public observations cannot substitute the native
application endpoint. Unsupported transport-ready claims are rejected.

FD scanning and proc table parsing are bounded without whole-directory or
whole-table reads. Capacity overflow raises explicitly rather than hiding
listeners beyond the report limit. Regression tests cover forged socket claims,
foreign live processes, missing critical components, missing/stopped readiness
and FD/row/listener capacity limits. No Core wire or privilege default changed.

87 focused Python tests passed without skips; the six observation-specific tests
also passed after the final transport-readiness validation change. Changed
Python AST/compile, workflow YAML and diff checks passed. No shell/workflow edit,
heavy build or package command ran. The concrete run 37106654298 was polled and
remained queued with no completed jobs; full-matrix/OCaml success remains unproven.

## Unified role resolution and transaction snapshots

All connect sources now pass the requested role through shared admission and
capability filtering. S6P1 scope is retained without rewriting its digest; named
requests also match the locked native realization. Context/binding/runtime/lock
inputs are captured under one registry transaction with a second material digest
check. Failed connection to a stopped service leaves it stopped. An instance
RLock with a timeout prevents another API thread from treating the first
thread's nesting depth as its own transaction.

Tests cover role-neutral requests, signed role rejection, capability filtering,
actual named role realization, drift during connection input capture, stopped
state preservation and two-thread serialization. The multiplatform workflow has
workflow/ref concurrency for superseded branch/PR runs. Its complete jobs,
matrices and validation steps are unchanged (24 job definitions). Six unfinished
older main runs were observed before the change; their status is not a pass.

94 focused Python tests passed without skips, including isolated staged imports
and existing-binary EPE lifecycle. AST/compile, all workflow YAML and diff checks
passed. Static comparison confirms all 24 multiplatform job definitions and their
matrix/step contents are unchanged. No heavy build/package command ran. Full
source-built matrix completion remains a remote verification gate.
