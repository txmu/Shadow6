package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMaskIPKeyedIdentifier(t *testing.T) {
	if len(maskingSalt) != 32 {
		t.Fatal("masking key must contain 256 random bits")
	}
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		mac := hmac.New(sha256.New, maskingSalt)
		mac.Write([]byte(ip))
		expected := "IP[MASKED:" + hex.EncodeToString(mac.Sum(nil)[:16]) + "]"
		if got := maskIP(ip, true); got != expected || got != maskIP(ip, true) {
			t.Fatalf("unexpected masked identifier: %q", got)
		}
		if got := maskIP(ip, false); got != ip {
			t.Fatalf("non-masked address changed: %q", got)
		}
	}
	if maskIP("", true) != "" || maskIP("192.0.2.1", true) == maskIP("192.0.2.2", true) {
		t.Fatal("empty and distinct address semantics changed")
	}
}
