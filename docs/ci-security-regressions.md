# NetBSD CI and configuration-file regressions

## NetBSD startup

The run for `6d66752f` spent approximately five hours in the NetBSD VM action.
That commit changed only Android steps in the workflow. The reported repeated
`Connection reset by 127.0.0.1 port 2847` matches upstream
[issue 158](https://github.com/cross-platform-actions/action/issues/158):
NetBSD startup can hang when QEMU exposes AMX on some Intel hosts, and the old
action can remain alive after its startup timeout. Full job logs require GitHub
authentication; the matching error and public job metadata support this diagnosis,
but do not prove which CPU was used for this particular failure.

The NetBSD job now pins cross-platform-actions v1.4.0 to its commit, retains
NetBSD 10.1, bounds the VM step to 20 minutes and the job to 30 minutes, and
prints the runner CPU and available serial log on failure. The action's legacy
`run` input remains supported but emits a deprecation warning. The actual VM
boot must be validated on GitHub; the local shell tests emulate the compiler,
and cross-compilation is not a substitute for a native NetBSD test run.

The old Go 1.23.5 fallback was below the module's required Go version. CI now
selects Go through `Core-Go/go.mod` on the host, fetches the matching NetBSD
archive over HTTPS, checks its published size and SHA-256 before extraction,
and disables implicit guest toolchain upgrades. Download sizes, network reads,
CI steps, build parallelism and individual Go test runs have limits. Checksums
come from Go's official HTTPS metadata; they are integrity checks, not an
independent signature or a guarantee against compromise of the publisher.

## Fixed local configuration-file weaknesses

1. **Medium: file replacement could block startup.** Core-Go used an ordinary
   `os.Open` after `Lstat`. A process able to replace that path could substitute
   a FIFO and block before the descriptor was validated, or substitute a
   symlink. Unix opens now use `O_NOFOLLOW | O_NONBLOCK`, followed by existing
   descriptor, owner and inode checks. Core-Rust already used `O_NOFOLLOW`; it
   now also uses `O_NONBLOCK`. These changes do not protect a compromised
   account that can legitimately rewrite its own configuration.
2. **Low: configuration modes did not match the documented contract.** Both
   cores rejected group/other access but accepted owner execute bits and
   special mode bits. Both now require exactly `0600` on Unix, including at
   descriptor revalidation. Existing `0400` or `0700` configurations must be
   changed explicitly to `0600`. Windows retains its existing owner/ACL checks;
   no new claim about Windows reparse-point race protection is made.

The workflow token is explicitly read-only, and the NetBSD checkout no longer
persists Git credentials for synchronization into the VM. Other VM jobs and
upstream image/resource release assets remain outside this pinning change.

## Regression coverage

- NetBSD Go metadata: exact version/platform, duplicate entries, path-like
  filenames, invalid checksums and oversized/non-integer lengths.
- Downloads: truncation, extra bytes, equal-length tampering, interruptions,
  preservation of the previous verified archive and temporary-file cleanup.
- NetBSD shell flow: test failures stop builds; Core-Go, Guard and Gate tests
  have deadlines; default and Crosed artifacts are retained separately.
- Go: exact Unix modes, symlink replacement at open, bounded FIFO-open test,
  strict JSON fuzz seeds and fuzzing entry point.
- Rust: unsafe modes, symlinks, directories, oversized files and invalid UTF-8.
- Android: both ABIs retain thread support; the pthread compatibility archive
  exists during linking and is removed after both success and linker failure.

Run the full regression suite with `make test`. The new Tools tests are part
of that target. This is a focused hardening change, not a claim that every
component or deployment is vulnerability-free.

## Local verification (2026-09-08)

`make build` passed for the enabled Go, Rust, C++, Gate, Relay, Guard and Python
components. `make crosed-variants` rebuilt Go/Rust L5 variants and restored the
default cores; all four feature reports matched their expected contracts.
`make test` passed, including 145 Python unittest cases, Go race tests,
20 Rust tests, C++/Relay tests, ML tests, signed plugin/assistant/extension tests
and both Go/Rust loopback end-to-end data paths. The JSON fuzzer ran for
15 seconds (21,811 executions) without failure.
Go test binaries also cross-compiled successfully for NetBSD/amd64 (default
and L5) and Windows/amd64. The provisioning selector was checked against the
live official Go metadata and selected the NetBSD Go 1.25.14 archive within
the configured metadata/archive limits; no toolchain archive was downloaded.

`make check` and the complete prescribed ShellCheck command passed. Offline
`make audit`: **61 passed, 0 failed, 0 skipped**. Doctor: **12/12 passed**.
The offline CycloneDX SBOM and infrastructure observation were generated in
the session's temporary verification directory. No dependencies were installed
or upgraded during verification. Scapy emitted an FFDH cryptography deprecation
warning; it did not fail tests.

No native NetBSD VM or Android APK build ran locally. QEMU, `gh` and `actionlint`
were unavailable; public GitHub API data, upstream source, YAML parsing, shell
regression tests and NetBSD Go cross-compilation were used instead. Optional
Ada/Zig/D/Nim build targets were not rebuilt by this configured `make build`.
Install paths did not change, so staged installation was not run. This was not
a release packaging run: no tar/ZIP archives were generated or replaced.
