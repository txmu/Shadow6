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

```sh
python3 Benchmark/benchmark.py --output benchmark.json
python3 Benchmark/benchmark.py --config Benchmark/example.json
```
