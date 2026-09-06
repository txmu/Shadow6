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
