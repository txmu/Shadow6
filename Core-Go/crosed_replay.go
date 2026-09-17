package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// A Crosed request is signed and short lived, but the same signed request stays
// valid for its whole window. Without recorded state an identical request can be
// replayed. Ada and Nim already keep a bounded replay store; Go records the same
// nonce commitment so all cores share one contract.
const (
	crosedReplayRetentionSeconds = 600
	crosedReplayMaxEntries       = 4096
	crosedReplayDirMode          = 0o700
	crosedReplayEntryMode        = 0o600
)

// crosedReplayKey binds a request to both its Mod and its nonce, so a valid
// nonce presented by one Mod cannot reserve a slot used by another.
func crosedReplayKey(modID, nonce string) []byte {
	digest := sha256.Sum256([]byte(modID + "\n" + nonce))
	return digest[:]
}

// crosedReplayRetain atomically reserves digest in the store beside the trust
// store. It returns false with a nil error when the digest was already used, and
// a non-nil error when the store cannot be consulted, so the caller fails closed
// instead of reporting a replay it cannot prove.
//
// Each reservation is one entry created with O_EXCL, which makes the check and
// the commit a single atomic operation. The store is bounded and never evicts a
// live nonce: an entry is only removed once it is older than the retention
// window, and a saturated store refuses new requests.
func crosedReplayRetain(path string, digest []byte, now int64) (bool, error) {
	if now <= 0 || len(digest) != sha256.Size || !crosedReplayParentOwnerOK(path) {
		return false, errors.New("Crosed replay store must be an owner-controlled directory")
	}
	if err := os.Mkdir(path, crosedReplayDirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return false, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != crosedReplayDirMode {
		return false, errors.New("Crosed replay store must be a regular owner-only directory")
	}
	if err := crosedReplayPrune(path, now); err != nil {
		return false, err
	}
	entry := filepath.Join(path, hex.EncodeToString(digest))
	file, err := os.OpenFile(entry, os.O_WRONLY|os.O_CREATE|os.O_EXCL, crosedReplayEntryMode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	_, writeErr := file.WriteString(strconv.FormatInt(now, 10) + "\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(entry)
		return false, errors.Join(writeErr, closeErr)
	}
	return true, nil
}

// crosedReplayPrune removes entries older than the retention window and refuses
// to accept a new request while every slot is still live.
func crosedReplayPrune(path string, now int64) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) < crosedReplayMaxEntries {
		return nil
	}
	cutoff := now - crosedReplayRetentionSeconds
	live := 0
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		if info.ModTime().Unix() < cutoff {
			if removeErr := os.Remove(filepath.Join(path, entry.Name())); removeErr == nil {
				continue
			}
		}
		live++
	}
	if live >= crosedReplayMaxEntries {
		return fmt.Errorf("Crosed replay store is saturated (%d live entries)", live)
	}
	return nil
}

// reserveCrosedNonce commits the request nonce before any grant is released,
// matching the Ada and Nim cores.
func reserveCrosedNonce(trustPath, modID, nonce string, now int64) error {
	retained, err := crosedReplayRetain(trustPath+".replay", crosedReplayKey(modID, nonce), now)
	if err != nil {
		return fmt.Errorf("Crosed replay state unavailable: %w", err)
	}
	if !retained {
		return errors.New("replayed Crosed request")
	}
	return nil
}
