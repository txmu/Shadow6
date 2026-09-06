//go:build unix

package main

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// Open without following a last-component symlink or blocking on a substituted
// FIFO; validate the opened object as well as the pre-open identity.
func readSecretFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	safe := func(info os.FileInfo) bool {
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 &&
			int(stat.Uid) == os.Geteuid() && info.Size() > 0 && info.Size() <= maximum
	}
	if !safe(before) {
		return nil, errors.New("secret file must be owned by the effective user, regular, mode 0600, and bounded")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !safe(opened) || !os.SameFile(before, opened) {
		return nil, errors.New("secret file changed during validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !safe(after) || !os.SameFile(opened, after) ||
		opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(data)) > maximum {
		return nil, errors.New("secret file changed while reading or exceeds size limit")
	}
	return data, nil
}
