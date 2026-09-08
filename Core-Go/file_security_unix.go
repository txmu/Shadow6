//go:build !windows

package main

import (
	"os"
	"syscall"
)

func secureConfigFile(info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func secureConfigPath(string) bool { return true }

func openConfigFile(path string) (*os.File, error) {
	// Reject a symlink swap at open time and never block on a substituted FIFO.
	// readConfig rechecks type, ownership and inode before reading the handle.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
