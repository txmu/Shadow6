# Shadow6 repository instructions

These instructions apply to the entire Shadow6 tree. Preserve user changes and
keep default builds least-privileged. Do not introduce scanning, exploitation,
credential collection, stealth persistence, arbitrary process injection, or
unbounded listeners/resources.

## Architecture invariants

- Core-Go and Core-Rust are alternative complete stacks. They are not
  wire-compatible halves and must expose matching feature contracts.
- Default `shadow6-go` and `shadow6-rust` builds keep Crosed, application
  transport, and Qubes-inspired domain policy disabled.
- `shadow6-go-crosed` and `shadow6-rust-crosed` are explicit L5 variants. A
  Crosed Mod grant is always the intersection of build features, signed request,
  per-Mod level, capability allowlist, and domain policy.
- Plugins remain separate, signed, out-of-process, resource-bounded, and
  network-isolated. Never load plugin code into a Core process.
- Application frames are versioned, bounded, authenticated, UTF-8/NFC, and
  fail closed on unknown schemas.
- Qubes-inspired labels complement real Qubes OS/qrexec/VM boundaries; never
  claim that an application policy replaces hypervisor isolation.
- Security and infrastructure assistants use fixed commands and signed plans.
  Do not add arbitrary shell or command execution to assistant inputs.
- Slots are typed contracts whose providers remain signed, isolated Plugins.
  Do not turn Slots into in-Core loading, arbitrary callbacks, or host commands.
- The Control Center Web API remains loopback-only, bearer-authenticated,
  bounded, and read-only unless mutations are explicitly enabled.
- Init content must use context-specific shell/systemd/XML/Scheme escaping.
  Guix System reconfiguration and runit activation remain explicit operator
  actions rather than implicit remote mutations.

## Editing and security rules

- Use strict parsing with unknown-field rejection for security-sensitive data.
- Secret-bearing files must be regular, non-symlink, owner-controlled, mode
  `0600`, bounded in size, and rechecked after opening.
- Use Ed25519 signatures, cryptographic nonces, short validity windows, replay
  state, explicit capability lists, and canonical portable JSON.
- Reject floats in cross-language signed JSON. Bound integer range, nesting,
  strings, frames, output, concurrency, and timeouts.
- Never use `shell=True`, `sh -c` with untrusted data, `LD_PRELOAD`, `ptrace`,
  writable executable memory, global process matching, or TLS verification
  bypasses.
- Keep network-facing tests loopback-only. Do not change host firewall, routes,
  services, or global package state as part of verification.
- Do not delete or overwrite unrelated files. Temporary work belongs under a
  path created with `mktemp -d` and must be cleaned when safe.

## Toolchain and environment

Expected tools are Go, Rust/Cargo, GCC, Make, Python 3, `zip`, `tar`,
`readelf`, and ShellCheck. Python commands should use `.venv/bin/python` when
the virtual environment exists.

Initial setup when dependencies are not already installed:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-ml.txt
./configure --enable-all
```

Do not download or upgrade dependencies during an ordinary verification run.
Request authorization if network access or system package installation is
actually required.

## Canonical build, test, audit, and package workflow

Run from the repository root. Stop on the first failure, fix the cause, then
restart at the narrowest affected stage before repeating the full workflow.

1. Build default least-privileged artifacts:

   ```sh
   make build
   ```

2. Build and preserve full Crosed variants, then automatically restore default
   Core binaries:

   ```sh
   make crosed-variants
   ```

3. Verify feature contracts:

   ```sh
   Core-Go/shadow6-go --feature-report
   Core-Rust/shadow6-rust --feature-report
   Core-Go/shadow6-go-crosed --feature-report
   Core-Rust/shadow6-rust-crosed --feature-report
   ```

   Default binaries must report Crosed level 0 with optional features false.
   Crosed variants must both report level 5, application transport true, Qubes
   isolation true, UTF-8 true, and identical capability lists.

4. Run every unit, component, ML, plugin, assistant, build-matrix, and local
   end-to-end test:

   ```sh
   make test
   ```

   This stage creates local TCP/UDP/KCP/QUIC listeners and Linux namespaces.
   In a restricted execution environment, obtain permission for loopback
   sockets and namespace creation; never weaken or skip the tests silently.

5. Run static checks and offline hardening audit:

   ```sh
   make check
   make audit
   shellcheck configure setup_test.sh Core-Go/*.sh Core-Rust/*.sh \
     C11Relay/*.sh Guard/*.sh Tools/*.sh
   ```

6. Run the read-only component doctor and generate the offline CycloneDX SBOM:

   ```sh
   .venv/bin/python Security-Assistants/shadow6_security.py doctor
   .venv/bin/python Security-Assistants/shadow6_security.py sbom \
     --output /tmp/shadow6-sbom.json
   .venv/bin/python Infrastructure-Assistants/shadow6_infra.py observe \
     --output /tmp/shadow6-observation.json
   ```

7. Validate staged installation when install paths changed:

   ```sh
   stage_dir=$(mktemp -d /tmp/shadow6-install.XXXXXX)
   make install DESTDIR="$stage_dir" PREFIX=/usr/local
   "$stage_dir/usr/local/bin/shadow6-plugins" list
   "$stage_dir/usr/local/bin/shadow6-security" list
   "$stage_dir/usr/local/bin/shadow6-control" schema
   "$stage_dir/usr/local/bin/shadow6-slots" catalog
   ```

   Remove only the exact `stage_dir` created for this run.

8. Package only after every preceding stage passes:

   ```sh
   make package
   ```

   `../Shadow6.tar.gz` contains source, documentation, scripts, and all compiled
   products while preserving Unix modes. `../Shadow6.zip` is source-only and
   excludes binaries, dependency environments, caches, generated credentials,
   and Rust `target` output. Every regular file in the ZIP has `.txt` appended
   to its complete original name (`README.md` becomes `README.md.txt`), whether
   or not it originally had a suffix. This transformation occurs only inside
   the packaging temporary directory: never rename the working tree or alter
   the tar layout. Packaging is atomic and replaces existing archive names only
   after both temporary archives are successfully created.

9. Inspect archives:

   ```sh
   tar -tzf ../Shadow6.tar.gz
   unzip -Z1 ../Shadow6.zip
   ```

   Confirm the tar contains both default and Crosed Core binaries. When the
   Android APK build has been run, also confirm it contains
   `Android/dist/shadow6-android-debug.apk`. Confirm the zip contains no Android
   APK, Core/Guard/Relay executable, `.venv`, `.tools`, Rust target,
   generated configuration, or `__pycache__` entry, and confirm every non-
   directory ZIP entry ends in `.txt`.

`./setup_test.sh` remains the compact build/test/check/audit entry point, but a
release run must additionally execute `make crosed-variants`, assistant checks,
staged installation when relevant, and `make package` as listed above.

## Android APK build contract

The supported headless Android build uses JDK 17, Android command-line tools,
platform `android-36`, Build Tools `36.0.0`, NDK `28.2.13676358`, and Gradle
`9.4.1`. Install only these packages plus the Rust Android targets
`aarch64-linux-android` and `x86_64-linux-android`; do not install Android
Studio or an emulator for CI. After accepting SDK licenses, set
`ANDROID_SDK_ROOT`, `ANDROID_NDK`, and optionally `ANDROID_GRADLE` to absolute
tool paths, then run `make android-apk`. The target cross-builds both Go/Rust
cores for `arm64-v8a` and `x86_64`, assembles the debug APK, and leaves it at
`Android/app/build/outputs/apk/debug/app-debug.apk`. `make package` copies an
existing APK to `Android/dist/shadow6-android-debug.apk` so it is included in
`../Shadow6.tar.gz`; the source-only ZIP always excludes APKs and generated
native libraries. Local Android toolchains may reside in `.android-toolchain`;
release packaging must exclude that directory from both archives.

## Completion report

Report exactly which build variants and test stages ran, any warnings or tools
that were unavailable, audit totals, archive paths/sizes, and remaining known
limitations. Never state that software is guaranteed vulnerability-free;
describe the verified controls and residual platform/deployment assumptions.
