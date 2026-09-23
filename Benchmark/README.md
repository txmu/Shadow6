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
0/20/80/150 ms RTT and 0/0/1/3 percent response-recovery-delay conditions. Its bounded,
deterministic userspace response model never changes host qdiscs, routes, or
firewalls, and reports this limitation explicitly; it is not a WAN claim.
The zero-impairment rows carry the full byte stream through the real local Core
path and are the local-bandwidth measurements.

All twelve cores are present in the matrix, and every row uses a real
broker/agent/client trio. Stream cores (Go, Rust, Gleam, Ada, Nim, Zig, D, C++)
carry the requested byte budget on their native reliable transports. Pony, Hare,
Carp and Idris keep their authenticated datagram bounds (1024, 978, 986 and 1024
bytes). Companion backends wrap those same native trios with S6NA/1, so 4 KiB,
64 KiB and 1 MiB logical messages still traverse the Core path. Missing binaries
or runtime support fail the run; they are not omitted, not converted into
internal codec loopbacks, and not treated as a nine-core ABC subset.

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

### Component matrix and Python GIL comparisons

`python Benchmark/component_benchmark.py --flow-bytes 131072` emits 884 rows:
12 S6NA profiles × 2 backends × 3 payloads × 3 concurrency levels × 4 fault
scenarios (864), plus 18 actual Virtual Broker/direct TCP echo measurements and
2 signed-admission measurements (empty and populated replay cache). Adapter tests
use real AEAD, fragmentation and discarded frames with a virtual retry clock;
they measure library work, not WAN throughput. Concurrency there means multiple
independent logical adapters, driven deterministically by one worker. It is not
a threaded scalability claim. Virtual Broker lanes are concurrent real TCP
connections through one shared Broker. All rows verify delivery and report
failures explicitly; unavailable native transports remain separate.

The `python-network-runtime` CI matrix runs this identical 884-row workload for
regular 3.14, free-threaded 3.14 with GIL enabled, and free-threaded 3.14 with GIL
disabled, on Linux/macOS/Windows x64. JSON records the actual post-import GIL state,
interpreter build, dependencies, OS, commit and runner. Each mode uploads its own
artifact. Compare within the same OS and workload; hosted runners differ, so use
repeated paired measurements on fixed hardware before drawing speedup conclusions.
Node rows are an unchanged-workload reference in every mode. CI asserts actual
GIL state and complete coverage; extension-triggered GIL fallback is not silently
counted as a successful no-GIL measurement. Normal application startup can fall
back safely; CI's explicitly requested no-GIL gate must pass as requested.

`virtual_broker_datagram_benchmark.py` adds a small, bounded loopback relay
measurement for Hare, Carp, Pony and Idris across Gate and S6NA listener modes,
each with signed or anonymous admission. It checks every returned payload and
reports throughput and p95 latency. The echo target is synthetic; the numbers
exclude the Gate envelope, S6NA codec and native Core runtime. For end-to-end
transport measurements, use the native network matrix.

The native network matrix's impairment model is `application-response-pacing-v2`:
response delay is charged once per logical request, equally across backends,
not per TCP receive chunk. It does **not** drop packets. Delayed-case request
counts are capped by a 30-second artificial-delay budget; reports give effective
bytes and concurrency totals. Workload timing excludes process startup for both
serial and parallel cases, with lifecycle time retained separately.

See the [network reliability and Python runtime review](../docs/network-runtime-review-2026-09.md) for
GIL-mode coverage, measured performance scope and remaining platform limits.
