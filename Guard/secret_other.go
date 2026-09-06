//go:build !unix && !windows

package main

import "errors"

// POSIX mode bits cannot validate a Windows ACL. Fail closed until a native
// owner/ACL implementation is available rather than silently ignoring policy.
func readSecretFile(path string, maximum int64) ([]byte, error) {
	return nil, errors.New("secret-file owner and permission validation is unsupported on this platform")
}
