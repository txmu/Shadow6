# Public6

Public6 is the explicit all-components Shadow6 suite. It includes both complete
Core engines, compiles every optional Core feature, and leaves jurisdiction-
specific compliance actions disabled. Core-Go and Core-Rust remain alternative
stacks: peers must use the same Core family and exact Core version.

Only that Core identity is a compatibility gate. Crosed level, application
protocols, optional transports, capability lists, isolation flags, and
namespaced extensions may all differ. Public6 negotiates their intersection;
an absent or incompatible optional item is disabled without rejecting the base
Core connection. Local authorization, signed Crosed grants, domain policy, and
Plugin capability checks still apply independently.

Extensions are bounded namespaced data offers. Extension code remains a signed,
isolated, out-of-process Plugin and is never loaded into a Core process.

Use `make public6` for the explicit suite build. It preserves full-feature Core
artifacts as `Core-Go/shadow6-go-public6` and
`Core-Rust/shadow6-rust-public6`, then restores the least-privileged default
Core binaries. Use `shadow6-public profile`, `shadow6-public offer REPORT`, and
`shadow6-public negotiate LOCAL PEER` for the suite contract.

## Virtual Broker compatibility layer

`virtual_broker.py` is an optional out-of-process Public6 front layer for a
shared service. It does not translate Core wire protocols and does not decrypt
tenant payloads. A short Ed25519-signed admission record declares the client's
Core family; the layer maps it only to an installed real Broker of that same
family and then relays opaque E2EE bytes. A keyed virtual identity prevents
exposing deployment keys to tenants.

Tenants choose `default-approved` or `approval-required`; approvals are a
bounded startup catalog. Each tenant has independent connection and token-
bucket byte quotas, so constrained datagram Cores cannot evict another
tenant's sessions even when S6NA is disabled. Configuration requires loopback
real-Broker targets and a loopback listener behind both Guard and Gate. The
admission replay index expires entries in deadline order and caps live entries
at 65,536. Verified public keys are cached at startup; relay copies use bounded
write buffering and a shared per-tenant byte budget in both directions. The
C11Relay control socket is declared for the supervised deployment boundary.
No Core process or Core protocol is modified. The supplied hardened systemd
unit refuses to run without Guard and Gate services.

An offer has this strict versioned form:

```json
{
  "schema_version": 1,
  "suite": "public6",
  "core": {"family": "shadow6-go", "version": "1.1.0"},
  "applications": {"shadow.chat": [1, 2]},
  "dimensions": {"transport.optional": ["kcp", "quic"], "crosed.level": ["5"]},
  "extensions": {"org.example.codec": [1, 3]}
}
```

Application and extension maps negotiate the highest shared version. Generic
dimensions negotiate all shared values. A map may be empty, and keys or values
present on only one peer are ignored. Consequently two same-Core peers with no
common application, Crosed, transport, or extension values are still base-
compatible. Offers are limited to 1 MiB, reject floats and unknown top-level
fields, bound every collection/string, and reject symlink input files.

### Virtual Broker runtime and concurrency

The executable uses the same installed-runtime selection as S6NA: prefer Python
3.14 free-threaded with compatible cryptography, otherwise fall back to a working
GIL runtime (Python 3.11+). Set `SHADOW6_PYTHON` for an explicit interpreter and
`PYTHON_GIL=1` to test a free-threaded build with its GIL enabled. Probes inspect
GIL state after dependency imports; startup does not install packages or force
incompatible extensions into no-GIL operation.

Replay admission reserves nonces under a lock, after signature verification,
so concurrent submissions cannot accept the same credential twice. Replay state
is capped at 65,536 live entries and expires through a heap. Relay connections,
shared tenant rate accounting and connection quotas remain owned by one asyncio
event loop per Broker. Do not share a Broker's relay across event loops. Both GIL
modes use the same authentication and resource limits; no-GIL mode is not an
implicit multi-process or multi-loop deployment.

CI benchmarks both modes with identical workloads on Linux, macOS and Windows
x64. Windows covers the portable in-memory-config relay; production configuration
loading still requires POSIX ownership, mode and no-follow file protections and
is not claimed as a Windows deployment path.
