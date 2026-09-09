# Native CI portability fixes (2026-09-09)

## Changes

- Linux builds the Ada L5 variant before the integration suite, then restores
  the default Ada binary. ZIP entry validation uses literal suffix matching.
- Zig keeps `SIG_IGN`/`SIG_ERR` inside a small C translation unit, so the target
  C compiler handles SDK function-pointer annotations. Signal setup errors
  fail startup. IPv4/IPv6 addresses initialize BSD length fields when present;
  the same address-layout tests run on every native Zig CI platform.
- C++ includes the public `netinet/in.h` header on every platform, including
  OpenBSD. Unix jobs share `compile.sh`: strict diagnostics, PIE and stack
  protection are common; ELF linker flags and Linux fortification remain
  platform-specific. Optional compiler flags must pass a warning-free probe.
- FreeBSD uses the 14.4 image, the `go` metapackage, Cargo supplied by `rust`,
  base-system Clang, and an explicit Python dependency. It no longer bypasses
  package OS-version checks. BSD variant builds restore default L0 binaries.
- OpenBSD installs Python 3.12 explicitly; NetBSD installs Python 3.11 and
  invokes it by absolute path. C++ tests honor `PYTHON`. NetBSD checks Python
  before building and uses the action's `cpa.sh` custom shell.
- NetBSD runner unit tests isolate optional host toolchains and cover missing
  Python, build failure propagation, and preservation of L0/L5 artifacts.
- D builds explicitly set executable mode `0755`, so a permissive operator
  umask cannot leave a group-writable Core that fails the shared audit.

## Local validation

- Offline `make build`, `make crosed-variants`, and all four Go/Rust feature
  reports passed. Default features are off; L5 capabilities match.
- `make test` passed, including components, ML, plugin/assistant contracts,
  build matrix tests and both Go/Rust three-role end-to-end data paths.
- `make test-zig test-ada` passed: Zig has 8 unit tests and 6 integration tests;
  Ada includes SPARK proof, cell mutation tests and 6 integration tests.
- `make core-nim core-d test-nim` completed. D was built; libdatachannel was
  unavailable, so Nim was not rebuilt. Nim protocol tests and 3 Python tests
  ran against the existing local Nim binary.
- `make check`, ShellCheck, Zig formatting and workflow YAML parsing passed.
  Offline hardening audit: 61 passed, 0 failed, 0 skipped. Component doctor:
  12/12 passed. Offline SBOM and infrastructure observation were generated.
- Final C++ build/test and the NetBSD runner regression suite were rechecked.
  GCC reported serial LTO compilation, a performance warning.
- Installation paths did not change; staged installation was not required.

## Verification boundaries

This Linux workspace cannot execute macOS, FreeBSD, OpenBSD or NetBSD native
jobs. Their SDK/package availability and kernel behavior require the next CI
run after the operator pushes. GitHub CLI was unavailable; investigation used
the supplied failure logs and repository files. Windows and Android were not
rebuilt. Packaging includes the existing Android APK, not a newly verified APK.
The pre-existing user modification to `Core-Cpp/shadow6-cpp` is excluded from
the source commit and preserved separately from the release build.

References: [FreeBSD Go metapackage](https://cgit.freebsd.org/ports/tree/lang/go/Makefile),
[public IP header contract](https://man.openbsd.org/inet), and
[cross-platform action releases](https://github.com/cross-platform-actions/action/releases).
