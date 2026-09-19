# Verification and release paths

Shadow6 has two useful verification modes. A quick check answers whether the
working tree still builds and passes local tests. A full release proves the
exact variant matrix, assistant reports, staged installation, and package
contents. Pick the smallest mode that answers your question; never skip or
weaken a stage to make a restricted environment appear green.

## Quick check

Use this after ordinary source changes when the build configuration is already
initialized:

```sh
make build
make test
make check
make audit
```

`make test` creates only loopback TCP/UDP/KCP/QUIC listeners and, when the
platform permits it, isolated Linux namespaces. It does not open a long-lived
listener, change the firewall or routes, or match unrelated processes.

For a read-only health summary:

```sh
.venv/bin/python Security-Assistants/shadow6_security.py doctor
```

## Full release

The sequence is fixed. Stop at the first failure, fix the cause, and restart
at the narrowest affected stage:

```sh
make build
make crosed-variants
make test
make check
make audit
shellcheck configure setup_test.sh Core-Go/*.sh Core-Rust/*.sh \
  C11Relay/*.sh Guard/*.sh Tools/*.sh
.venv/bin/python Security-Assistants/shadow6_security.py doctor
.venv/bin/python Security-Assistants/shadow6_security.py sbom \
  --output /tmp/shadow6-sbom.json
.venv/bin/python Infrastructure-Assistants/shadow6_infra.py observe \
  --output /tmp/shadow6-observation.json
```

Run staged installation when install paths or installed entrypoints change:

```sh
stage_dir=$(mktemp -d /tmp/shadow6-install.XXXXXX)
make install DESTDIR="$stage_dir" PREFIX=/usr/local
"$stage_dir/usr/local/bin/shadow6-plugins" list
"$stage_dir/usr/local/bin/shadow6-security" list
"$stage_dir/usr/local/bin/shadow6-control" schema
"$stage_dir/usr/local/bin/shadow6-slots" catalog
rm -rf "$stage_dir"
```

Package only after every relevant preceding stage passes:

```sh
make package
```

The output directory is the repository parent unless
`SHADOW6_PACKAGE_OUTPUT_DIR` is set. The tar archive is the complete release
artifact, including compiled default Core binaries and preserved Crosed
variants. The ZIP is a text-only source exchange artifact: every regular file
is strict UTF-8 and its complete original name receives a `.txt` suffix. It
deliberately excludes binaries, APKs, generated native libraries, dependency
environments, generated configuration, and caches.

## Feature contracts

After `make crosed-variants`, verify the four baseline reports:

```sh
Core-Go/shadow6-go --feature-report
Core-Rust/shadow6-rust --feature-report
Core-Go/shadow6-go-crosed --feature-report
Core-Rust/shadow6-rust-crosed --feature-report
```

Default Go/Rust binaries must report Crosed level 0 and optional features
false. Crosed binaries must report level 5 and application transport true.
Every reported capability must not exceed its reported level.

`CROSED_VARIANT_QUBES` controls Qubes isolation for Crosed variants; Public6
variants explicitly set it to `1`. Assert the value in the feature report
rather than assuming a particular build default.

For enabled optional Crosed Cores, run the same pair of reports for the
default and `*-crosed` binaries. `shadow6 features` and `shadow6_audit.py`
validate the shared schema.

## Android boundary

`shadow6 workflow release` is convenient, but its `release` stage includes
`make android-apk`. Use it only when JDK 17, Android SDK platform 36, the NDK,
and Go/Rust Android targets are present. For a non-Android release, run the
individual release stages above and package afterward. If an APK already
exists, `make package` copies it into the tar as
`Android/dist/shadow6-android-debug.apk`; the text-only ZIP never contains it.

## Bounded preflights

`Tools/security_preflight.sh` is a read-only source gate. It checks secret-key
modes, executable-script modes, ShellCheck, and the offline source audit before
a full build. `Tools/archive_preflight.py` is invoked by `make package` and
rejects path traversal, unsafe links, oversized archives, missing release Core
binaries, generated ZIP files, and non-text ZIP members. Neither tool opens a
network socket or changes host state.

## Archive acceptance

Inspect both artifacts before publishing:

```sh
tar -tzf ../Shadow6.tar.gz
