# Getting started

Welcome to Shadow6. You do not need to understand every component before your
first check. Begin with the installed feature report; it is read-only and tells
you exactly which Core variants are present.

```sh
shadow6 guide --lang en
shadow6 features
shadow6 privacy
shadow6 control -- status
```

In a source checkout, replace `shadow6` with `.venv/bin/python CLI/shadow6.py`.
If a component is missing, run `make build` from the repository root and retry.

Shadow6 ships twelve Core implementations: Go, Rust, Gleam, Ada, Nim, Pony,
Idris, Zig, D, C++, Hare, and Carp. Go and Rust are the two complete reference
stacks; the other Cores are independently documented profiles with their own
toolchain and platform requirements. Pick one family for a connection and use
it at every hop. Default builds keep Crosed, application transport and domain
policy disabled. The explicit `*-crosed` binaries enable the L5 feature contract
where that Core provides it.

The Control Center starts read-only. Its HTTP API listens only on loopback and
requires a bearer token stored in a regular, owner-controlled `0600` file. Keep
`--allow-mutations` off until you have reviewed the exact operation you intend to
run. See [the Control Center guide](../Control-Center/README.md) for a working RPC
example.

If something feels unclear, these three checks usually point to the next step:

```sh
shadow6 features
.venv/bin/python Security-Assistants/shadow6_security.py doctor
shadow6 control -- --help
```

The doctor only observes the local tree. It does not change services, firewall
rules or routes. For the full build and verification sequence, follow the
repository `AGENTS.md`.

[阅读中文指南](getting-started.zh-CN.md)

Before sharing diagnostics, read [privacy across interfaces](privacy-interfaces.md).
