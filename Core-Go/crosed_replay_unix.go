//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// crosedReplayParentOwnerOK requires the directory that will hold the replay
// store to be owned by the current user and not writable by group or others,
// matching the Ada and Nim cores.
func crosedReplayParentOwnerOK(path string) bool {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return false
	}
	return info.Mode().Perm()&0o022 == 0
}
