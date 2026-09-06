//go:build !unix

package main

import (
	"errors"
	"io"
	"os"
)

// POSIX mode bits cannot validate a Windows ACL. Fail closed until a native
// owner/ACL implementation is available rather than silently ignoring policy.
func readSecretFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("secret file must be regular and bounded")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("secret file changed during validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("secret file exceeds size limit")
	}
	return data, nil
}
