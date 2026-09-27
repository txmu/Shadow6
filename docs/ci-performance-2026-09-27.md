# CI performance evidence and changes

Source: [multiplatform run 36321917427](https://github.com/txmu/Shadow6/actions/runs/36321917427), commit `81d01085501b6663afdf84b07a39639b5794f0b9`. Downloaded through `gh run download`, without waiting for the workflow.

The Linux job passed its native builds and integration tests, then failed on `assert len(rows) == 36`. Its actual adapter report has 39 successful rows: twelve cores, a second Gleam transport, and three backends. CI now checks the exact 13 × 3 set as well as status, byte counts and concurrency.

## Platform ceiling, not Shadow6 throughput

These 15 iperf3 artifacts explicitly exclude Shadow6 and external NICs. Their 480 matrix rows contain 464 measurements and 16 Windows multi-stream UDP cases marked not applicable by the existing platform policy. Peak figures select different workloads; they are runner observations, not a cross-platform ranking.

| Platform artifact suffix | Successful / total | Peak loopback TCP Gbit/s |
| --- | ---: | ---: |
| alpine-aarch64 | 32 / 32 | 188.13 |
| alpine-x86_64 | 32 / 32 | 142.30 |
| freebsd-arm64 | 32 / 32 | 6.04 |
| freebsd-x86-64 | 32 / 32 | 54.72 |
| linux-arm64 | 32 / 32 | 169.12 |
| linux-x86_64 | 32 / 32 | 90.06 |
| macos-arm64 | 32 / 32 | 137.72 |
| macos-x86_64 | 32 / 32 | 85.91 |
| netbsd-arm64 | 32 / 32 | 1.74 |
| netbsd-x86-64 | 32 / 32 | 10.89 |
| omnios-x86-64 | 32 / 32 | 47.79 |
| openbsd-arm64 | 32 / 32 | 1.32 |
| openbsd-x86-64 | 32 / 32 | 28.57 |
| windows-amd64 | 24 / 32 | 90.33 |
| windows-arm64 | 24 / 32 | 50.41 |

## Native chain findings

The Linux adapter workload is a small request/response test, not saturated bandwidth. Rust, Zig and Gleam stream Companion rows take about 2.54–2.58 seconds versus 0.008–0.015 seconds for native rows. Delayed ACK/Nagle interaction is a source-based hypothesis: TCP_NODELAY was absent on their forwarding sockets. Python/Node IPC is also included, so its overhead must not be attributed entirely to the Core.

Pony’s actual iperf3 receiver reports 15.21 Mbps forward with 96.82% loss, and 9.06 Mbps reverse with 64.06% loss under a 1.1 Gbps offered workload. Matching fixture baselines are 1.066/1.093 Gbps with 0.044%/0% loss. `status: ok` means a valid measurement, not acceptable delivery. Both targets were missed.

The latest Linux job never reached its full-core iperf chain stage. No all-platform native-throughput results are invented from the loopback ceilings. The preceding run also published no native iperf-chain artifact. Go reverse and Nim improvements therefore rely on identified source costs, and require subsequent CI evidence.

## Lightweight changes to measure in CI

- Go batches independently authenticated 32 KiB records into one bounded KCP write per copy batch. Wire format, nonce counters, EOF and reverse half-close remain unchanged; CI exercises bulk transfer in both directions after half-close.
- Rust, Zig, Gleam and Nim forwarding sockets enable TCP_NODELAY. Companion stream writes coalesce frames already available in a batch; UDP datagram boundaries are preserved.
- Nim avoids zeroing a 64 KiB scratch buffer on every RTC poll, validates actual lengths before copying, and reduces idle poll sleep from 2 ms to 1 ms. CPU cost of the shorter sleep must be measured.
- Pony uses a 200 ms initial RTO, a 20 ms adaptive floor and at most 32 retransmissions per 10 ms scheduler tick, sent in existing 16-frame batches. The 4096-frame window, admission quotas, authentication and eight-retry bound are unchanged. This trades faster recovery for potential additional retransmissions; it does not promise 1 Gbps or lossless overload.
- Gleam UDP S6NA gets a distinct 1100-byte/64-frame profile in Python and Node with loss/reorder/duplicate regression coverage. Existing Hare/Carp/Idris wire formats and resource ceilings remain unchanged.

All performance gains remain unmeasured until the pushed commit runs in CI. No local native compilation, release build, full audit or release packaging was run.

## Reproduce evidence download

```sh
gh run download 36321917427 --pattern "shadow6-iperf3-*" --dir ./iperf-evidence
gh run download 36321917427 --pattern "*network-benchmark*" --pattern "*iperf-chain*" --dir ./native-evidence
```

[Machine-readable summary](../Benchmark/results/ci-36321917427/summary.json) retains each platform report hash, measurements and the native/Companion observations. Original raw iperf files remain in the downloadable GitHub artifacts.
