# Shadow6 Benchmark

`benchmark.py` runs fixed, bounded commands for any subset of the twelve cores.
Use a JSON config to select `cores`, `roles` (`feature-report`, `version`, or
`loopback`), `repeats` (1..1000), and optional string-array `args`. Missing
binaries are reported as `unavailable`; no shell is invoked. Results use schema
`shadow6.benchmark.v1` and include elapsed/user/system time, child peak RSS,
exit status, stderr tail, and JSON emitted by the core as `native`.

```sh
python3 Benchmark/benchmark.py --output benchmark.json
python3 Benchmark/benchmark.py --config Benchmark/example.json
```
