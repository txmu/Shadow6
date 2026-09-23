# Native reliability, Python runtimes and networking review

This review covers the September 2026 native datagram changes, S6NA component
optimizations, Virtual Broker admission/relay controls, and Python runtime matrix.
Default builds remain level 0. No new privileged socket, host network setting,
plugin loading, or automatic dependency installation is introduced.

## Native reliability inventory

| Core | Established native data path |
|---|---|
| Go | KCP reliable transport |
| Rust | QUIC reliable streams |
| Gleam | TCP |
| C++ | SCTP; kernel availability remains a deployment condition |
| Zig | Native ENet-style reliable window |
| Ada | TCP cells |
| Nim | Ordered SCTP data channels / native TCP path |
| Pony | Reliable v2 native frames |
| D | TCP; retained authenticated UDP ACK path |
| Hare | Added authenticated ACK, duplicate suppression and bounded retry |
| Carp | Added authenticated ACK/retry to the native three-role path |
| Idris | Added authenticated ACK/retry to the signed `--chain` path |

Hare/Carp/Idris keep one outstanding application datagram per direction, pause
application ingress while waiting, and stop after eight retransmissions.
This is bounded established-session recovery, not an unlimited reliable stream:
handshake loss still requires reconnecting, local UDP queues can overflow, and
one outstanding datagram imposes an RTT-dependent throughput ceiling. Upgrade
both endpoints together; the families are not wire-compatible. Carp legacy modes
and Idris legacy native CLI retain their documented contracts. Network Adapter
normalization remains optional.

Loopback fault tests drop the first ciphertext in each direction, exercise lost
ACK recovery and run three successive transactions to expose duplicate delivery
or a blocked pending slot. ACKs must not advance Hare's DATA nonce watermark:
an ACK can overtake an earlier lost DATA frame. Idris brokers retain a bounded
final-ACK grace period when the data quota is exhausted.

## Performance and resource controls

S6NA Python and Node defer fragmentation/encryption until window slots are
available, track active streams rather than scanning every stream, and keep
constant-time reassembly byte accounting. Both retain the full message's budget
until every fragment is acknowledged; releasing budget early would undercount
retained buffers. Queued/incoming messages are bounded. Node snapshots caller
buffers. Completed-message duplicates do not create fresh reassembly allocations.
Python public state transitions use a per-instance reentrant lock.

Virtual Broker uses cached public-key objects and heap-based replay expiration
instead of copying the whole replay map on every admission. Nonce insertion is
atomic after verification. Live nonces, connections, frames, reads, handshakes,
upstream connects and rate waits are bounded. Quotas are decremented only after
successful increment; failed copy tasks are cancelled and joined. TCP half-close
is preserved. Shared tenant rate debt is reserved before an await, so concurrent
connections cannot spend the same tokens. Relay state belongs to one event loop.

Five paired local before/after samples during development gave these medians:

| Component measurement | Before | After | Interpretation |
|---|---:|---:|---|
| Admission, empty replay map | 5,113/s | 5,713/s | Modest local improvement |
| Admission, 32,768 live nonces | 209/s | 5,727/s | Removed linear replay-map scan |
| TCP relay, 16 MiB, 64 KiB, 1 lane | 2.727 Gbit/s | 3.023 Gbit/s | Local sample only |
| Same relay, 4 lanes | 2.989 Gbit/s | 2.909 Gbit/s | No bulk speedup established |
| Python S6NA initial window, 16 MiB message | 110.036 ms | 0.189 ms | Lazy initial emission, not full-transfer throughput |

These development samples preceded the final concurrency locks and are not a
release performance guarantee. The final 884-row component matrix validates
correct delivery across workloads. Re-run paired samples on fixed hardware for
performance decisions; hosted CI timing and cross-OS results are not interchangeable.

## GIL and free-threaded support

Both Virtual Broker and the S6NA Python CLI/Companion can use regular Python or
CPython 3.14 free-threaded. A shared installed-runtime probe imports dependencies
before recording effective GIL state. It prefers healthy 3.14 free-threaded and
falls back to a compatible GIL environment; an explicit `SHADOW6_PYTHON` is
respected. No downloads or forced no-GIL extension loading occur at startup.
Library callers retain their interpreter. `PYTHON_GIL=1` is supported explicitly.
`.venv-ft` is excluded from installation copies and both archive formats.

The CI matrix has Linux/macOS/Windows x64 × regular 3.14, 3.14t GIL-on, and 3.14t
GIL-off. All nine combinations run identical component benchmarks and save actual
runtime metadata. No-GIL jobs assert that dependencies did not enable the GIL.
Windows tests portable codecs, concurrent adapter state and in-memory Broker
benchmarks; POSIX secret-file loading is not presented as a Windows deployment.
BSD and other unsupported runners keep their compatible packaged Python fallback.
Free-threading does not change the Broker's event-loop ownership or guarantee
multi-core speedup. Threaded replay and sequence-allocation tests cover shared
state correctness separately from the deterministic component timing harness.

## Verification scope

Local checks use the existing Python 3.13 GIL environment. No Python 3.14 toolchain
was installed and no full local rebuild was run. Targeted checks passed: 42 Python
unit/contract tests, 7 Node tests, 884 component benchmark rows, Hare and Carp
native tests (including loss recovery), Idris C FFI security tests (9 tests with
1 skipped executable test), shell checks, YAML parsing and diff whitespace checks.
The offline audit reports 110 passed, 0 failed, 18 optional-artifact skips.
Staged installation reused existing products without invoking `build`; installed
network/Broker entry points and plugin/security/control/slot commands passed.
Read-only doctor, CycloneDX SBOM and infrastructure observation also completed.
Idris 2 is unavailable locally: the changed C FFI compiles and tests locally,
while the Idris executable and full platform rebuilds remain CI responsibilities.
Carp's generated C continues to emit existing toolchain warnings.

Packaging reuses available compiled products; it is not evidence that every
optional native executable was rebuilt from these sources. Full release
qualification, new GIL-mode results and platform-specific build results require
the new GitHub Actions run. Existing archives are replaced atomically only after
both new archives are created. No vulnerability-free or universally faster claim
is made by this review.
