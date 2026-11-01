package main

import (
	"context"
	"net"
	"time"
)

// Keep Shadow6 TCP sockets on ordinary TCP regardless of Go's MPTCP defaults.
// CVE-2026-98432 additionally requires a patched host kernel.
func listenTCP(network, address string) (net.Listener, error) {
	var config net.ListenConfig
	config.SetMultipathTCP(false)
	return config.Listen(context.Background(), network, address)
}

func newTCPDialer(timeout time.Duration) *net.Dialer {
	dialer := &net.Dialer{Timeout: timeout}
	dialer.SetMultipathTCP(false)
	return dialer
}
