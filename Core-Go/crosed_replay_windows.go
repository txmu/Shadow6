//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// Windows permission bits are only a coarse compatibility projection, so the
// effective owner is enforced through the native security descriptor, matching
// the configuration-file checks in this package.
func crosedReplayParentOwnerOK(path string) bool {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	return err == nil && info.IsDir() && secureConfigPath(parent)
}
