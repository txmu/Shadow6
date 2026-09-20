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

Shadow6 ships twelve independently compiled Core implementations: Go, Rust,
Gleam, Ada, Nim, Pony, Idris, Zig, D, C++, Hare, and Carp. All twelve provide a
native broker/agent/client path. Idris, Hare and Carp retain their older modes
alongside bounded, signed fixed-route datagram trios. These profiles are
all valid, but they are not wire-compatible and they do not promise the same
reliability, multiplexing, or broker behavior. Pick one family for every hop
and use its README as the authority for deployment limits.
The compact [Core capability matrix](core-matrix.md) summarizes this role and
transport split in one place.

Default builds keep Crosed, application transport and domain policy disabled.
The explicit `*-crosed` binaries enable the L5 feature contract where that
Core provides it; an optional toolchain may be required for a Core to be built.

The unified network adapter has equal Python and Node.js backends and removes caller-visible packet sizing.
Run `shadow6 network catalog` to inspect each Core's native payload and window
bounds. All twelve Cores can deploy independently, and no Core requires the
adapter or another Companion to obtain native network capability. The adapter
is an optional authenticated layer for uniform reliability, segmentation and
multiplexing. See
`Network-Adapter/README.md` for security and deployment requirements.
Both backends implement the normative `Network-Adapter/SPEC.md`; use
`shadow6 network catalog` or `shadow6 network-node catalog` explicitly.

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
rules or routes. For a quick check or the full release sequence, follow the
[verification and release guide](verification.md).

[阅读中文指南](getting-started.zh-CN.md)

Before sharing diagnostics, read [privacy across interfaces](privacy-interfaces.md).
