# Shadow6 Slots

Slots were integrated into the Extension contract during the 2026-09-01 to
2026-09-06 transition and became the typed provider registry used by the later
Core family. They remain independent of Native Core wire compatibility: a Slot
adds a bounded component hook, not a new Core protocol.

Slots are typed extension points spanning lifecycle, configuration, transport,
ProtocolFactory, ShadowChat, ShadowIdentity, policy, telemetry, assistants,
service integration and GUI panels. They are independent contracts, but their
providers reuse the signed, isolated Plugin runtime: Slots never load provider
code into either Core and never grant host commands.

Each slot fixes its risk level, composition mode and provider limit. A binding
is exact-schema, owner-controlled and resolves only to a plugin whose signed
manifest declares the same slot as both hook and capability. Level 3/4 calls
require an explicit approval flag. Required providers and policy/pipeline slots
fail closed; requests, responses, depth, runtime, output, processes and network
access inherit Plugin-System limits.

```sh
shadow6-slots catalog
shadow6-slots validate --bindings Slot-System/bindings.example.json
```

The catalog is available through `shadow6-slots catalog`, Control Center's
`slots.catalog`, and the shared MCP/LSP/OpenAI tool schemas. `slots.invoke` and
the combined `extensions.invoke` path are mutating operations; they require
the existing explicit mutation/privileged gate. Required, pipeline, and
all-must-pass slots fail closed when a provider fails, while observational
fanout slots report bounded per-provider results.
