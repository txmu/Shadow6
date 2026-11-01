//go:build linux

package main

import (
	"net"
	"syscall"
	"testing"
	"time"
)

func assertOrdinaryTCP(t *testing.T, socket interface {
	SyscallConn() (syscall.RawConn, error)
}) {
	t.Helper()
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var protocol int
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		// Linux SO_PROTOCOL returns the socket protocol, not its address family.
		protocol, socketErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, 38)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	if protocol != syscall.IPPROTO_TCP {
		t.Fatalf("socket protocol = %d; require TCP (6), never MPTCP (262)", protocol)
	}
}

func TestTCPStaysOrdinaryWhenRuntimeEnablesMPTCP(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=1")
	listener, err := listenTCP("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	assertOrdinaryTCP(t, listener.(*net.TCPListener))
	connection, err := newTCPDialer(time.Second).Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	assertOrdinaryTCP(t, connection.(*net.TCPConn))
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	assertOrdinaryTCP(t, accepted.(*net.TCPConn))
	if _, err := connection.Write([]byte("TCP")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 3)
	if _, err := accepted.Read(data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "TCP" {
		t.Fatalf("payload changed: %q", data)
	}
}
