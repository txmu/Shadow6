package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	c := defaultConfig()
	c.Enabled = true
	c.PrivateKey = hex.EncodeToString(priv.Seed())
	c.PeerPublicKeys = []string{hex.EncodeToString(pub)}
	return c
}
func TestMTDDeterministicAndBounded(t *testing.T) {
	c := testConfig(t)
	p := derivedPort(c, 123)
	if p < c.MTD.MinPort || p > c.MTD.MaxPort || p != derivedPort(c, 123) {
		t.Fatal(p)
	}
}
func TestPolicyDefaultClosed(t *testing.T) {
	c := testConfig(t)
	c.Enabled = false
	if allowed(c, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, time.Now()) {
		t.Fatal("disabled Gate opened")
	}
}
func TestSecureHandshake(t *testing.T) {
	apub, apriv, _ := ed25519.GenerateKey(nil)
	bpub, bpriv, _ := ed25519.GenerateKey(nil)
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() {
		s, e := handshake(a, apriv, []ed25519.PublicKey{bpub}, true, 4096)
		if e == nil {
			_, e = s.Write([]byte("hello"))
		}
		done <- e
	}()
	s, e := handshake(b, bpriv, []ed25519.PublicKey{apub}, false, 4096)
	if e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 32)
	n, e := s.Read(buf)
	if e != nil || string(buf[:n]) != "hello" {
		t.Fatalf("%q %v", buf[:n], e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
