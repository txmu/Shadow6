use fs;

// Hare 0.24.2 uses the generic Linux NOFOLLOW value on AArch64.
// Linux arm64's UAPI defines O_NOFOLLOW as 1 << 15 instead (fcntl.h).
// Keep NONBLOCK and the standard library's default CLOEXEC behavior.
fn secure_open_flags() fs::flag =
	fs::flag::RDONLY | (0o100000: fs::flag) | fs::flag::NONBLOCK;
