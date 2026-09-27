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

The initial 42 cases adapted the externally observable contracts exercised by Shadow6's
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
| UDP limits | Configurable payload limit (default 1200 bytes); oversized and stream-only cases explicitly unsupported |
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

## Expanded portable contracts

The network catalog now has **88 cases**: the original 42, thirteen opaque
protocol/Unicode/JSON payloads, two persistent workloads, fifteen boundary sizes,
five fragmentation sizes, coalesced reads, repeated identical messages and a
delayed reader, abandoned-session recovery and two sustained bulk workloads. None requires Shadow6 on the tested node. Each
persistent worker performs 32 sequence-tagged exchanges before a final echo.
Opaque malformed payloads must traverse an echo path unchanged; their successful
transport is not a parser-rejection result.

```sh
shadow6 ppb contracts --budget 120 --output contracts.json
shadow6 ppb contracts --suite adversarial --suite interop
shadow6 ppb export --destination ./ppb-portable
# Copy the entire exported directory to another host, without a source checkout:
python3 ppb-portable/Paranoid-Proxy-Benchmark/paranoid_proxy_benchmark.py contracts
```

Contracts execute fixed, bounded subprocesses (60 seconds per suite, 300 seconds
total maximum). Python `cryptography` is required; interop also needs Node.js.
No installation, native compilation, plugin execution or namespace creation is
performed. Missing dependencies fail visibly. POSIX-only suites are unsupported
on Windows; skipped checks remain unsupported and prevent an all-pass exit.
The exported bundle contains production implementations, original tests, PPB
vectors, and a SHA-256 manifest; hashes describe the bundle, not a trusted signature.

| Suite | Original techniques reused |
| --- | --- |
| adapter | bounded retention, backpressure, reorder/retry, duplicate suppression, concurrency, secret-file permissions, loopback pinned peers, Gleam UDP |
| interop | fixed AEAD vector, Python ↔ Node, Unicode/path escaping, symlinked entry paths |
| application | Ed25519 identity, domain binding, expiry, chat AEAD/replay, UTF-8/NFC, bounded framing |
| public6 | strict offers, unknown schemas/types, family/version boundaries, optional capability intersection |
| features | all core families, missing/unknown/mistyped fields, contradictory capabilities |
| plugins | signed manifests, code hashes, deny-by-default grants, symlinks/oversize requests, RPC capability/replay boundaries; execution tests excluded |
| slots | explicit privileged approval, signed providers, strict bindings, empty safe defaults |
| extensions | signed domain binding, missing providers, capability intersection; orchestration calls mocked as in the original tests |
| adversarial | 13 adapter profiles × 30 individual header/ciphertext/tag mutations, wrong key/reflection/backpressure/loss-reorder-duplicate checks; strict JSON, frame truncations, native-config unknown fields, replay saturation/time bounds |

These local contracts cover the bundled implementations. They do not prove that
an arbitrary remote proxy uses them. Native compiler/runtime, VM, namespace,
platform packaging and real plugin-execution tests remain in Shadow6 CI; PPB
cannot truthfully substitute an echo observation for those controls.

`--udp-limit 978` reproduces the conservative Shadow6 datagram workload; the
generic default is 1200 and the operator may select 1..65507 bytes. Unsupported
payload sizes are reported, never silently split into different UDP datagrams.

The sustained workloads send 32 separately verified 64 KiB blocks per worker
(2 MiB cumulative, at most four workers), retaining the 64 KiB per-operation
bound. Cancellation recovery abandons unread responses, then checks fresh
connections for stale data. These stress observations still obey the case
deadline; slower authorized nodes can use `--timeout 10`.

SOCKS5 grammar vectors additionally exercise a nonzero reserved byte, an
unsupported authentication method, zero methods and incomplete IPv4/IPv6
addresses followed by EOF. Explicit rejection is required for a pass; silence
is inconclusive. These variants are explicitly unsupported on other protocols.
