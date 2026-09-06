package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

func rotationSlot(c Config, now time.Time) int64 { return now.Unix() / int64(c.MTD.PeriodSeconds) }
func derivedPort(c Config, slot int64) int {
	unique := map[string]bool{hex.EncodeToString(privateKey(c).Public().(ed25519.PublicKey)): true}
	for _, key := range c.PeerPublicKeys {
		unique[strings.ToLower(key)] = true
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte("shadow6-gate-mtd-v1\x00"))
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(slot))
	h.Write(b[:])
	sum := h.Sum(nil)
	span := c.MTD.MaxPort - c.MTD.MinPort + 1
	return c.MTD.MinPort + int(binary.BigEndian.Uint64(sum[:8])%uint64(span))
}
func activePort(c Config, now time.Time) int {
	return portForSlot(c, rotationSlot(c, now))
}
func portForSlot(c Config, slot int64) int {
	if !c.MTD.Enabled {
		return c.MTD.MinPort
	}
	return derivedPort(c, slot)
}
