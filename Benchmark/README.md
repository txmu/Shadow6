# Shadow6 Benchmark

`benchmark.py` runs fixed, bounded commands for any subset of the twelve cores.
Use a JSON config to select `cores`, `roles` (`feature-report`, `version`, or
`network-chain`), `repeats` (1..1000), fixed network load, and optional
string-array `args`. `network-chain` invokes each core's native adapter in
`integration/stack_test.py`; it must carry bytes from a local client through
the core transport to a loopback target and return the target's response.
Missing binaries and failed paths make the command fail. Results use schema
`shadow6.benchmark.v2`. One run writes matching JSON, text, and Markdown
reports, so formats always describe the same samples.

Use `--require-network` for a release gate: every selected core must complete
the requested loopback exchange with valid finite metrics (unsupported
protocols such as SCTP are then failures, not silently skipped). Reports carry
the commit/runner identity, exact transport path, and state that measurements
are loopback-only; they are not WAN saturation claims.

C++ requires kernel SCTP. Before benchmarking it, a loopback socket probe
checks support; an unsupported protocol is explicitly reported as
`not_applicable`, without substituting TCP or claiming a successful measurement.
Permission and other unexpected socket errors still fail. Component tests
continue to cover C++ configuration and TLS on platforms without SCTP.

On POSIX, nonblocking `wait4` collects usage for the particular child while
preserving the deadline. Network measurements include the harness and its
reaped children, not only the core. Peak RSS follows the OS's child-usage
semantics; it is not the sum of simultaneous process RSS. Platforms without
`wait4` report unavailable counters explicitly. Failed commands print bounded
stdout/stderr diagnostics as well as saving them in the JSON report.

```sh
python3 Benchmark/benchmark.py --output benchmark.json
python3 Benchmark/benchmark.py --config Benchmark/example.json
```
