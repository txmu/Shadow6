# Shadow6 repository instructions

These instructions apply to the entire Shadow6 tree. Preserve user changes and
keep default builds least-privileged. Do not introduce scanning, exploitation,
credential collection, stealth persistence, arbitrary process injection, or
unbounded listeners/resources.

## Architecture invariants

- Shadow6 maintains twelve independently compiled Core implementations that
  share the feature-report and security-contract vocabulary but are not
  implicitly wire-compatible. Every Core has an independently deployable native
  data path; Go, Rust, D and Gleam expose complete broker/agent/client streams,
  while the other families retain their documented bounded native roles. Use
  one family consistently across a path and consult each Core's README for its
  transport and platform limits. The Network Adapter is optional normalization,
  never a deployment prerequisite.
- Default `shadow6-*` builds keep Crosed, application transport, and
  Qubes-inspired domain policy disabled (`CROSED_LEVEL=0`, `APP_TRANSPORT=0`,
  `QUBES_ISOLATION=0`).
- `shadow6-*-crosed` and `shadow6-*-public6` binaries are explicit level-5
  variants. A Crosed Mod grant is always the intersection of build features,
  signed request, per-Mod level, capability allowlist, and domain policy.
- Every variant build flow restores the default level-0 Core binary afterward.
  `make crosed-variants` (and `ada-crosed-variant`, `nim-crosed-variant`,
  `pony-crosed-variant`, `idris-crosed-variant`) rebuild and preserve the
  level-5 binary under the variant name, then rebuild the default L0 binary.
- Plugins remain separate, signed, out-of-process, resource-bounded, and
  network-isolated. Never load plugin code into a Core process.
- Slots are typed contracts whose providers remain signed, isolated Plugins.
  Do not turn Slots into in-Core loading, arbitrary callbacks, or host
  commands.
- Application frames are versioned, bounded, authenticated, UTF-8/NFC, and fail
  closed on unknown schemas.
- Qubes-inspired labels complement real Qubes OS/qrexec/VM boundaries; never
  claim that an application policy replaces hypervisor isolation.
- Security and infrastructure assistants use fixed commands and signed plans.
  Do not add arbitrary shell or command execution to assistant inputs.
- The Control Center Web API (`/v1`) remains loopback-only, bearer-
  authenticated, bounded, and read-only; MCP, LSP, OpenAI function-calling, and
  HTTP mutations stay disabled unless explicitly enabled.
- Gate is compiled but its runtime configuration starts with `enabled: false`.
  An enabled Gate can sit in front of a Client, behind an Agent or Broker, or
  between them as an authenticated middle hop; it must never be enabled
  silently by a build or install step.
- Public6 capability negotiation exchanges bounded, strict-parsed,
  Ed25519-signed offers; floats are rejected and identifiers/strings/groups are
  bounded.
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

Required native tools are Go, Rust/Cargo, GCC/G++, Make, and Python 3. Optional
Cores additionally need Gleam, Zig, Ada/GNAT, Nim (with libdatachannel), Pony
(`ponyc`), Hare, D, Idris 2/Chez, and Carp; vendored copies live under `.tools`
and are enabled automatically when present. Python commands should use
`.venv/bin/python` when the virtual environment exists.

Initial setup when dependencies are not already installed:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-ml.txt
./configure --enable-all
```

`configure` writes `config.mk` with per-component `BUILD_*` toggles and
feature flags (`CROSED_LEVEL`, `APP_TRANSPORT`, `QUBES_ISOLATION`,
`BUILD_COMPLIANCE`). The Makefile reads these and also auto-detects optional
toolchains (Gleam/Pony/Carp under `.tools`, system Hare/Idris); Zig and Ada
default to disabled. Do not download or upgrade dependencies during an
ordinary verification run. Request authorization if network access or system
package installation is actually required.

## Canonical build, test, audit, and package workflow

Run from the repository root. Stop on the first failure, fix the cause, then
restart at the narrowest affected stage before repeating the full workflow. The
unified CLI can drive the same fixed stages in order via
`shadow6 workflow release`.

1. Build default least-privileged artifacts:

   ```sh
   make build
   ```

2. Build and preserve full Crosed variants for the Go/Rust/Gleam cores (and
   any enabled optional cores), then automatically restore default Core
   binaries:

   ```sh
   make crosed-variants
   ```

3. Verify feature contracts. Default binaries must report Crosed level 0 with
   optional features false; Crosed variants must report level 5, application
   transport true, and capability lists valid for their declared level (each
   capability must not exceed the reported level):

   ```sh
   Core-Go/shadow6-go --feature-report
   Core-Rust/shadow6-rust --feature-report
   Core-Go/shadow6-go-crosed --feature-report
   Core-Rust/shadow6-rust-crosed --feature-report
   ```

   For any enabled optional Crosed core (Gleam/Pony/Nim/Ada/Idris), run the
   same pair of reports. `shadow6 features` and `shadow6_audit.py` validate
   the shared schema. Note: Qubes isolation is only forced on for Public6
   variants (`make public6-variants` uses `QUBES_ISOLATION=1`); Crosed variants
   use `CROSED_VARIANT_QUBES`, so assert the value actually compiled in rather
   than assuming it.

4. Run every unit, component, ML, plugin, assistant, build-matrix, and local
   end-to-end test:

   ```sh
   make test
   ```

   This stage runs `test_compliance.py`, the Tools unittests, per-Core tests,
   the Detector/ML tests, assistant tests, and (when build flags allow)
   `make integration-test`. It creates local loopback TCP/UDP/KCP/QUIC
   listeners and Linux namespaces. In a restricted environment, obtain
   permission for loopback sockets and namespace creation; never weaken or
   skip the tests silently.

5. Run static checks and the offline hardening audit:

   ```sh
   make check
   make audit
   shellcheck configure setup_test.sh Core-Go/*.sh Core-Rust/*.sh \
     C11Relay/*.sh Guard/*.sh Tools/*.sh
   ```

6. Run the read-only component doctor, generate the offline CycloneDX SBOM,
   and capture an infrastructure observation:

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

   `make package` runs `Tools/package_release.sh` and emits the archives into
   `SHADOW6_PACKAGE_OUTPUT_DIR` (default the repository parent directory,
   `../Shadow6.tar.gz` and `../Shadow6.zip`).

   - The tar (`Shadow6.tar.gz`) contains source, documentation, scripts, and
     compiled products while preserving Unix modes. When an Android debug APK
     exists it is copied to `Android/dist/shadow6-android-debug.apk` so it is
     included. The tar excludes `.venv`, `.git`, `.tools`, any
     `.android-toolchain`, `.tmp`, `.runtime`, Rust `target`, Gleam/Nim/Ada
     build objects, Zig caches, Android build/`.gradle`/JNI output, generated
     credentials, and `__pycache__`.
   - The zip (`Shadow6.zip`) is a source-only text exchange artifact. It
     excludes every compiled binary (Core/Guard/Gate/Relay binaries, the APK,
     `Android/dist`, `Android/app/src/main/jniLibs`), the dependency
     environments, `config.mk`, and caches. `Tools/prepare_text_zip.py` then
     keeps only strict UTF-8 text files and appends `.txt` to each kept file's
     complete original name (`README.md` becomes `README.md.txt`); every non-
     text/binary file is removed. This transformation happens only in the
     packaging temp directory; the working tree and tar layout are never
     renamed.
   - Packaging is atomic: both temporary archives are built first and replace
     the existing archive names only after both are created, then the temp
     directory is removed.

9. Inspect archives:

   ```sh
   tar -tzf ../Shadow6.tar.gz
   unzip -Z1 ../Shadow6.zip
   ```

   Confirm the tar contains both default and Crosed Core binaries, and (when
   the Android APK build ran) `Android/dist/shadow6-android-debug.apk`. Confirm
   the zip contains no APK, Core/Guard/Gate/Relay executable, `.venv`, `.tools`,
   Rust target, generated configuration, or `__pycache__` entry, and confirm
   every non-directory zip entry ends in `.txt`.

`./setup_test.sh` remains the compact build/test/check/audit entry point, but
a release run must additionally execute `make crosed-variants`, assistant
checks, staged installation when relevant, and `make package` as listed above.

## Android APK build contract

The supported headless Android build uses JDK 17, Android command-line tools,
platform `android-36`, the Android Gradle Plugin defined in
`Android/build.gradle.kts`, and Go/Rust Android targets `aarch64-linux-android`
and `x86_64-linux-android` (matching `arm64-v8a` and `x86_64` ABIs). Install
only the minimal command-line toolchain (no Android Studio or emulator for
CI). After accepting SDK licenses, set `ANDROID_SDK_ROOT`, `ANDROID_NDK`, and
optionally `ANDROID_GRADLE` to absolute tool paths, then run `make android-apk`.
The target cross-builds the Go/Rust cores for both ABIs
(`Android/build_android_cores.py`), assembles the debug APK, and leaves it at
`Android/app/build/outputs/apk/debug/app-debug.apk`. `make package` copies an
existing APK to `Android/dist/shadow6-android-debug.apk` so it is included in
`../Shadow6.tar.gz`; the source-only zip always excludes APKs and generated
native libraries. Local Android toolchains may reside in `.android-toolchain`;
release packaging must exclude that directory from both archives.

## Completion report

Report exactly which build variants and test stages ran, which optional cores
and toolchains were enabled or unavailable, any warnings, audit totals, archive
paths/sizes, and remaining known limitations. Never state that software is
guaranteed vulnerability-free; describe the verified controls and residual
platform/deployment assumptions.
