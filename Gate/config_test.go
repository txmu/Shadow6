package main

import "testing"

func TestBrokerPoolDoesNotRequireUnusedFallback(t *testing.T) {
	c := defaultConfig()
	c.Enabled = true
	c.Role = "client"
	c.RemoteHost = ""
	c.RemoteHosts = []string{"127.0.0.1", "127.0.0.2"}
	c.PrivateKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	c.PeerPublicKeys = []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	if err := validateConfig(c); err != nil {
		t.Fatal(err)
	}
	c.RemoteHosts = nil
	if err := validateConfig(c); err == nil {
		t.Fatal("missing single remote host must still be rejected")
	}
}
