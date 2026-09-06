# Shadow6 EasyBuild

Run `.venv/bin/python EasyBuild/shadow6_easybuild.py`. It checks the existing
offline toolchain, enables every buildable component, creates both full L5 Core
variants, runs verification, installs to the current user's `~/.local` by
default, and creates owner-only identity and local package-signing material.

Qubes-inspired policy and the compliance selection are asked interactively and
default to disabled. Compliance is never applied automatically. The ordinary
`shadow6-go` and `shadow6-rust` names remain least-privileged; full features are
available as the explicit `-crosed` variants, preserving Shadow6's security
contract while making the complete installation immediately available.

## Termux

On Termux, run the same command with `--termux` (normally auto-detected).
EasyBuild uses Termux's `$PREFIX` and current Python, builds and installs both
Core engines plus the largest locally supported component set, and writes an
owner-only `termux-capabilities.json`. It does not run `pkg`, `apt`, or `pip`:
install Go, Rust, Cargo, Clang/GCC, Make, Python/cryptography, zip, and tar first.
Root-only packet capture and Guard functions remain capability-dependent;
Plugin management works everywhere, while isolated Plugin execution requires
the relevant Linux namespace support from the Android kernel.
