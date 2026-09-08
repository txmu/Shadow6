//go:build !windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSecureConfigExactMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o600, 0o400, 0o700, 0o644, 0o660, 0o600 | os.ModeSetuid, 0o600 | os.ModeSetgid} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := secureConfigFile(info); got != (mode == 0o600) {
			t.Errorf("mode %v: secure=%v", mode, got)
		}
	}
}

func TestConfigOpenRejectsSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	path, target := filepath.Join(dir, "config"), filepath.Join(dir, "target")
	for _, name := range []string{path, target} {
		if err := os.WriteFile(name, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
	// Emulate replacement between readConfig's lstat and open calls.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if file, err := openConfigFile(path); err == nil {
		file.Close()
		t.Fatal("open followed a substituted symlink")
	}
}

func TestConfigOpenDoesNotBlockOnFIFO(t *testing.T) {
	if path := os.Getenv("SHADOW6_TEST_CONFIG_FIFO"); path != "" {
		file, err := openConfigFile(path)
		if err != nil {
			return // Refusing the FIFO at open time is also safe.
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || secureConfigFile(info) {
			t.Fatalf("FIFO must be rejected before reading: %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConfigOpenDoesNotBlockOnFIFO$")
	command.Env = append(os.Environ(), "SHADOW6_TEST_CONFIG_FIFO="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("FIFO open blocked or failed: %v %s", err, output)
	}
}
