# Paranoid-Proxy-Benchmark

A standalone, standard-library Python tool for bounded checks against one
explicit proxy/node and an operator-controlled echo service. Copy
`paranoid_proxy_benchmark.py` to a host with Python 3.11+; no Shadow6 checkout,
Core binary, dependency installation or build is required.

```sh
shadow6 ppb catalog
shadow6 ppb run --node tcp://127.0.0.1:1080 --output observation.json
shadow6 ppb run --node socks5://127.0.0.1:1080 --target tcp://127.0.0.1:9000
python3 paranoid_proxy_benchmark.py run --node udp://127.0.0.1:8000
```

`make install` also installs `paranoid-proxy-benchmark` and
`shadow6-paranoid-proxy-benchmark`. The short unified route is `shadow6 ppb`.
TCP/UDP/TLS nodes must forward to a byte-exact echo service. SOCKS5 and HTTP(S)
CONNECT take an explicit `--target`. Numeric IPv4/IPv6 only; no host discovery.
Non-loopback endpoints require `--allow-remote`. Use only authorized nodes and
echo targets; the tool cannot provision someone else's echo service.

The 42 cases adapt the externally observable contracts exercised by Shadow6's
integration/unit tests: exact receive accounting, integrity, payload bounds,
fragmentation, independent connections, EOF, replay-independent fresh
connections, and strict proxy handshakes. There are 36 payload/pattern/concurrency
combinations plus six stream/handshake checks, **not 42 distinct vulnerability
classes**. Internal cryptographic, plugin, authorization and VM contracts
cannot be inferred from a generic black-box proxy and remain in the original
Shadow6 suite. That suite is retained in CI.

| Contract | Checks |
| --- | --- |
| Integrity and byte accounting | Random/zero/counter payloads; 1/63/512/978/4096/65536 bytes |
| Connection isolation | One and four independent connections, fresh reconnects |
| Stream behavior | Seven-byte writes, authenticated-proxy negotiation, half-close and EOF |
| Malformed handshakes | Unsupported version/command/address; timeout is inconclusive |
| UDP limits | <=978-byte messages; oversized and stream-only cases explicitly unsupported |
| TLS | Default CA and hostname/IP validation, optional `--ca-file`; no bypass |
| Resource control | At most four workers, 64 KiB receive, 8 KiB HTTP headers, 10 seconds/case, 300 seconds total maximum |

Defaults are three seconds/case and a 120-second total budget. `--case` selects
one or more catalog entries. An exhausted budget produces `not-run` rows;
unsupported checks stay separate from passes. Output is a new mode-0600 file,
never an overwrite. Exit status is 1 on failure, inconclusive results, budget
exhaustion, or no applicable successful check; invalid input exits 2.

No external network test runs automatically. Local regression tests use
loopback echo fixtures only. A successful report is evidence for the exercised
contracts, not a vulnerability-free or availability certification.
