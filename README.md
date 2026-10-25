# Shadow6

[简体中文](README.zh-CN.md) · [Documentation](docs/README.md) · [Component reference](README.reference.md)

Shadow6 provides twelve independently compiled native networking Cores and the tools to configure, observe and operate them. Its broker, agent and client roles form a native data path without requiring Ziokt or the optional Network Adapter. Applications attach through explicit native or credited companion boundaries.

## Pick the path you actually need

| Layer | Responsibility |
| --- | --- |
| Native Cores | Go, Rust, Gleam, Ada, Nim, Pony, Idris, Zig, D, C++, Hare and Carp provide their documented transports |
| Named Services and Application SDK | Reviewed configurations, content-addressed material, lifecycle locks and explicit application attachment |
| Control Center | Shared CLI/tool schema, diagnostics and loopback, authenticated, read-only-by-default service interfaces |
| Optional components | Guard, Gate, C11Relay, signed Plugins, Crosed, Slots, adapters, assistants and Android |

Use one Core family consistently across a native topology. The twelve families are not implicitly wire-compatible. Thirteen Native Profiles describe application boundaries; they do not give every Core identical reliability, multiplexing or platform support. See the [Core matrix](docs/core-matrix.md) and the selected Core's README.

## Start without compiling

Download a trusted prebuilt tar for your platform, verify its digest and extract it. The text-only ZIP contains no runnable Core binaries. Python 3.11+ and the selected Core's runtime libraries are required.

```sh
python3 /absolute/path/Shadow6/CLI/shadow6.py doctor --human
python3 /absolute/path/Shadow6/CLI/shadow6.py core profiles --installed
```

Prepare an owner-controlled native configuration for the Core you selected. Check before explicitly starting a Named Service:

```sh
python3 /absolute/path/Shadow6/CLI/shadow6.py setup home/nas --core go --profile go-kcp --native-config /absolute/path/core.json --check --human
```

Only choose Go/KCP if the installed feature report and doctor say it is available. The [getting started guide](docs/getting-started.en.md) explains setup, run, status and application attachment. Named Service supervision currently requires Linux pidfd; other platforms retain their documented native/init paths.

## Defaults and authority

Default Core builds keep Crosed, application transport and Qubes-inspired domain policy disabled. Explicit `*-crosed` and `*-public6` variants declare their own feature contracts; inspect the actual feature report. Plugins remain signed, isolated, out-of-process and bounded. Gate is default-disabled. Local policy does not replace a Qubes hypervisor or hide network metadata by itself.

## Documentation

- [Architecture](docs/architecture.en.md): Core independence, Profiles and control/data boundaries.
- [Operations](docs/operations.en.md): material review, lifecycle locks, restart and migration.
- [Security and privacy](docs/security.en.md): credentials, capabilities, anonymous carriers and exposure.
- [Verification](docs/verification.en.md): native tests, Ada/SPARK, Idris, Lean and release evidence.
- [All documents](docs/REFERENCE.en.md): every maintained component, platform guide and dated report.

The joint ecosystem release remains **v1.0**. Shadow6 retains its native component versions and independent distribution. Consult the [release catalog](https://github.com/txmu/Ziokt-Releases) and exact [Actions results](https://github.com/txmu/Shadow6/actions); an available source contract is not a claim that every platform binary or physical deployment has been verified.
