# Native ABC iperf3 evidence: run 36074824050

Source: [GitHub Actions run](https://github.com/txmu/Shadow6/actions/runs/36074824050), artifact `shadow6-linux-iperf-chain`, commit `34cba4aa82acb09682b6b014f25c75dd532a75a4`. These are archived CI measurements, not a new local benchmark or results for the latest code.

The client TCP `sum_received.sender` flag was true in forward tests even though the server reported valid received bytes. Forward cases now use `server_output_json.end.sum_received`; reverse cases use the receiving client. UDP loss is recomputed from receiver `lost_packets / packets`, preserving the original percentage as `reported_lost_percent`: even the receiving client could report a percentage using the remote sender denominator. No sender throughput is substituted. All 48 archived baseline/native reports parsed successfully; forward receive bytes and rates matched the separate server JSON.

| Core | Forward Gbps | Reverse Gbps | Forward loss % | Reverse loss % | Both directions meet gate |
|---|---:|---:|---:|---:|---|
| zig | 0.281900 | 0.278126 | 0.0000 | 0.0000 | no |
| ada | 0.720636 | 0.716732 | 0.0000 | 0.0000 | no |
| d | 0.693205 | 0.642554 | 0.0000 | 0.0000 | no |
| nim | 0.398264 | 0.411610 | 0.0000 | 0.0000 | no |
| cpp | 1.980270 | 2.083860 | 0.0000 | 0.0000 | yes |
| pony | 0.000079 | 0.000079 | 97.8203 | 97.9426 | no |
| hare | 0.071534 | 0.070931 | 93.4145 | 93.4743 | no |
| carp | 0.059977 | 0.062798 | 94.4703 | 94.2106 | no |
| gleam | 1.074860 | 1.188587 | 0.0000 | 0.0000 | yes |
| idris | 0.070728 | 0.072137 | 93.4775 | 93.3554 | no |
| go | 0.034934 | 0.195376 | 0.0000 | 0.0000 | no |
| rust | 2.866917 | 2.751064 | 0.0000 | 0.0000 | yes |

The gate requires receiver throughput >= 1 Gbps and UDP observed loss <= 0.1%. UDP sequence-based loss does not count an unobserved dropped tail; receiver throughput remains essential. TCP uses a bounded Python bridge and its matched baseline, which adds a measurement ceiling. Each native case is one real broker/agent/client trio with one data flow. Independent trios do not prove internal worker scaling.

The archived commit predates the Hare/Carp/Idris 256-packet window change and the Idris broker accounting repair. These figures therefore cannot establish their post-fix performance. Pony and the sub-Gbps stream cores still need transport profiling and optimization. Gate verification has since moved inside its existing bounded concurrent tasks; this is not a measured Gate throughput claim. No evidence here establishes all twelve cores or Guard/Gate/C11Relay at 1–10 Gbps.
