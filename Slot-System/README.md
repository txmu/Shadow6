# Shadow6 Slots

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
