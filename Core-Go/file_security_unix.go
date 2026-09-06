//go:build !windows

package main

import (
	"os"
	"syscall"
)

func secureConfigFile(info os.FileInfo) bool {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func secureConfigPath(string) bool { return true }
