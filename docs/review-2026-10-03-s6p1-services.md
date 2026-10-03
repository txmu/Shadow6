# S6P1 service/topology and Actions review — 2026-10-03

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
and native-only remote activation. EPE v2 remains an admission model, not complete
outer encrypted cover traffic or anonymity. The new remote run's result must be
observed after submission; local tests cannot certify that matrix.
