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

The existing default remains a 4-byte protocol-correctness and tiny-message
latency regression gate. `performance_matrix.py` is a separate throughput and
long-flow suite: it runs 4 KiB, 64 KiB, and 1 MiB payloads over a 16 MiB flow at
0/20/80/150 ms RTT and 0/0/1/3 percent loss-recovery conditions. Its bounded,
deterministic userspace response model never changes host qdiscs, routes, or
firewalls, and reports this limitation explicitly; it is not a WAN claim.
The zero-impairment rows carry the full byte stream through the real local Core
path and are the local-bandwidth measurements.

All twelve cores are present in the matrix. Go, Rust, Zig, Ada, Nim, and C++
use their three-role paths. D/Gleam use native relay/crypto loopbacks, Carp uses
its paired authenticated byte-stream channels, and Pony/Hare use authenticated
datagrams at their real 1,024-byte and 978-byte application limits. Unsupported
payload or impairment combinations remain explicit `not_applicable` rows with
reasons. D remains represented by its fixed 4-byte diagnostic. Idris now runs
its real encrypted native client/agent/echo path at the 1,024-byte datagram
limit for the complete long-flow byte budget; the companion backend separately
exercises 4 KiB, 64 KiB and 1 MiB reliable messages. This is capability-aware equality,
not a preferred-core list and not fabricated comparability.

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
python3 Benchmark/performance_matrix.py --core zig --stream-bytes 16777216
```

For an already deployed multi-node topology, run the matrix on each client
node against one or more local Core proxy ports. An external config is strict
JSON such as `{"version":1,"targets":[{"name":"wan-a","core":"rust","endpoint":"127.0.0.1:1080"}]}`.
`--external-config FILE` runs the same three payload sizes and long-flow budget
without starting local broker/agent/client processes. Endpoints must resolve
only to loopback, so the authenticated Core—not this benchmark—crosses the WAN.
Merge the resulting JSON reports in the observability system using `target`,
environment, and run identity. Shadow6 never opens an unauthenticated public
benchmark listener or remotely executes node commands.
