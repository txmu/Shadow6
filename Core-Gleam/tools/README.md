# Local toolchain provisioning

Run these explicit provisioning commands from the repository root:

```bash
bash Core-Gleam/tools/fetch_toolchain.sh
bash Core-Gleam/tools/build_toolchain.sh
source Core-Gleam/tools/env.sh
bash Core-Gleam/tools/verify_toolchain.sh
```

Fetching requires network authorization. Downloads are pinned by SHA-256;
ordinary build and test targets must not invoke provisioning automatically.
Prerequisites are GCC/G++, make, musl-tools, autoconf, automake, libtool,
pkg-config, Perl, curl, tar, ncurses development headers, OpenSSL development
headers, and zlib development headers. ShellCheck, readelf and strace support
verification. No system Erlang service is installed.

Versions: Gleam 1.18.1, OTP 29.0.6, Rebar3 3.27.0, OpenSSL 3.5.7,
libsodium 1.0.22. Rebar3 is a development-only escript; it is not shipped
inside the Core or used as a Core runtime packaging mechanism.
All local products and logs reside in `.tools/gleam`, excluded from Git.
The build is single-job, limits BEAM scheduler counts, and checks for at least
1 GiB free space between dependency stages. This is a stage-boundary check,
not a disk quota. Do not use a memory-backed `/tmp` for source builds on small
machines.

The host OTP compiler runtime explicitly disables JIT. It is a conventional
development installation, **not** the final musl static embedded Core runtime.
OpenSSL and libsodium archives are built separately with musl. The final Core
still requires a memory loader, static NIF integration, static PIE linking,
and independent ELF/runtime security verification. Installing this toolchain
does not establish those properties.

Verification runs libsodium's upstream self-tests during installation and a
dependency-free Gleam compilation/execution smoke test afterward. It checks
the host emulator flavor and links a separate musl static PIE crypto probe
with ELF hardening assertions. OpenSSL is built without its upstream test
suite to bound build resources; the crypto probe is not a substitute for that
suite or a complete OTP test run. Diagnostics are kept in `.tools/gleam/logs`.
