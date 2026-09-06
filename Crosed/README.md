# Crosed

Crosed is a compile-time Core extension boundary. It is separate from the
Shadow6 plugin system: plugins are unprivileged, network-isolated JSON workers;
Crosed Mods may request explicitly compiled Core hooks and therefore require a
separate owner-only trust policy.

Crosed never uses `ptrace`, `LD_PRELOAD`, writable executable memory, arbitrary
native libraries, or process-memory patching. A Mod submits a time-bounded
Ed25519-signed request. Core-Go and Core-Rust independently verify it and return
their Core name/version, compiled maximum level, compiled optional features,
and the exact granted capabilities.

## Levels

| Level | Scope | Capabilities |
| --- | --- | --- |
| 0 | disabled | none |
| 1 | observation | `observe.version`, `observe.health` |
| 2 | policy | `policy.request`, `policy.config` |
| 3 | transport | `transport.metadata`, optionally `transport.application` |
| 4 | identity | `identity.assert`, `identity.resolve` |
| 5 | lifecycle | `core.lifecycle`, `core.hook` |

The effective grant is the intersection of the Core build, requested level,
per-Mod maximum, per-Mod capability allowlist, application-transport build
flag, and optional compartment-domain policy. No level implies a higher
orthogonal feature.

## Build matrix

All features default off. Both cores accept the same build environment:

```sh
CROSED_LEVEL=4 APP_TRANSPORT=1 QUBES_ISOLATION=1 make core-go core-rust
Core-Go/shadow6-go --feature-report
Core-Rust/shadow6-rust --feature-report
```

Go maps these to build tags `crosed`, `crosed_l2`…`crosed_l5`,
`app_transport`, and `qubes_isolation`. Rust maps them to Cargo features
`crosed`, `crosed-level-2`…`crosed-level-5`, `app-transport`, and
`qubes-isolation`.

## Trust policy and requests

Both JSON files must be regular, owned by the effective user, and mode `0600`.
Each trust entry contains `pubkey`, `max_level`, `capabilities`, and optional
`allowed_domains`. `crosedctl.py request` creates signed canonical requests;
`negotiate` invokes a local Core without a shell and validates its response.

With `QUBES_ISOLATION=1`, every request must bind valid `source_domain` and
`target_domain` labels. Same-domain requests are allowed by policy; cross-domain
requests additionally require the target in that Mod's `allowed_domains`.
This is a Qubes-inspired application policy and complements—rather than
pretends to replace—real Qubes OS qubes, qrexec policy, and VM isolation.

```sh
.venv/bin/python Crosed/crosedctl.py features Core-Go/shadow6-go Core-Rust/shadow6-rust
.venv/bin/python Crosed/crosedctl.py request --mod-id example-mod --level 3 \
  --capability observe.version --capability transport.application \
  --source-domain work-vm --target-domain chat-vm --payload '{"mode":"chat"}' \
  --private-key mod-key.pem --output request.json
.venv/bin/python Crosed/crosedctl.py negotiate --core Core-Go/shadow6-go \
  --request request.json --trust trust.json
```
