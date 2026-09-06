# Shadow6 security assistants

This module supplies defensive infrastructure shared by every Shadow6
component. Assistants are explicit CLI operations with versioned JSON output;
they do not load third-party code or mutate Core processes.

- `doctor` checks component presence, Core feature parity, least-privileged
  defaults, L5 variants, signed plugins, and the offline source audit.
- `sbom` creates an offline CycloneDX 1.5 inventory from Go modules, Cargo.lock,
  pinned Python requirements, and hashes of compiled products.
- `policy-check` evaluates exact-schema baseline/high/maximum policies across
  default Core builds, Crosed variants, plugins, UTF-8, application transport,
  compartment isolation, and optional audit-ledger requirements.
- `ledger-*` manages an Ed25519-signed, sequence-numbered hash-chain ledger.
  Every append updates a separately signed head checkpoint, detecting record
  edits, insertion, reordering, replay, and tail truncation.

Examples:

```sh
.venv/bin/python Security-Assistants/shadow6_security.py list
.venv/bin/python Security-Assistants/shadow6_security.py doctor
.venv/bin/python Security-Assistants/shadow6_security.py sbom --output /tmp/shadow6-sbom.json
.venv/bin/python Security-Assistants/shadow6_security.py policy-check \
  --policy Security-Assistants/policy.maximum.example.json
```

The maximum-policy example intentionally requires a real signed ledger. Copy it
to an owner-controlled deployment path and replace its `/secure/shadow6/...`
ledger paths before evaluation.

Ledger private keys and ledger/checkpoint files must be owner-controlled mode
`0600`. Keep signing keys outside the repository and back them with an OS key
store, hardware token, or dedicated Qubes vault in real deployments.
