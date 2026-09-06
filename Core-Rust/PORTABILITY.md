# Core-Rust portability

Core-Rust is intentionally limited to Unix and Unix-like operating systems. It
uses Unix ownership/mode checks, non-following file opens, POSIX sockets and
process semantics; a non-Unix build stops with an explicit compile-time message.
This is a platform boundary, not a reduction of the Core feature contract.

IPv6 link-local Scope IDs use the operating system's `if_nametoindex(3)` and
`if_nameindex(3)` APIs. No `/sys`, `/proc`, netlink, shell command, or external
utility is needed. Numeric zones such as `%7` remain accepted. This preserves
the existing Linux behavior while making the same discovery path source-level
portable across targets whose libc and Rust ecosystem provide those APIs:

- Linux distributions, OpenWrt and WSL; rooted Android userlands can use the
  ordinary Android/Linux network API and do not inherently require a custom
  kernel, though Android sandbox/VPN permissions and WSL multicast networking
  still determine whether link-local discovery packets can pass.
- FreeBSD, OpenBSD, NetBSD, DragonFly BSD, macOS/Darwin, illumos/Solaris and
  AIX, subject to availability of the Rust target and all Cargo dependencies.
- POSIX-oriented RTOS targets such as QNX only where Rust `std`, libc, Tokio,
  QUIC/TLS and the required socket features are all supplied by that target.

The repository's current automated build and network tests verify Linux. The
other systems above are portability targets, not claims of completed CI or
deployment certification. Small/no-`std` RTOS environments and non-Unix
systems should currently use a separately ported stack (or Core-Go where its
dependencies support the target); emulating Unix file-security semantics is
not accepted as a reason to weaken secret-file checks.

Some surrounding Shadow6 components remain deliberately platform-specific:
Linux namespace isolation in the Plugin manager, Linux `AF_PACKET` live capture
in Detector, and the Guard controller's `/proc` identity checks keep their
fail-closed behavior. Their portable offline/configuration functions remain
usable independently, and no fallback silently removes isolation or identity
verification.
