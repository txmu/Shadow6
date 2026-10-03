package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPBrokerPoolFailsOverOnlyBeforeSession(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := closed.Addr().String()
	closed.Close()
	live, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	balanceCounter.Store(0)
	conn, err := dialTCPPool(context.Background(), []string{dead, live.Addr().String()}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	accepted, err := live.Accept()
	if err != nil {
		t.Fatal(err)
	}
	accepted.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err = dialTCPPool(ctx, []string{dead}, "", false); err == nil {
		t.Fatal("cancelled pool dial succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancelled dial did not stop promptly")
	}
}

func TestBrokerPoolTargetsNeverIntroduceImplicitFallback(t *testing.T) {
	balanceCounter.Store(0)
	targets := poolTargets([]string{"a", "b"}, "unrequested", false)
	if len(targets) != 2 || targets[0] != "a" || targets[1] != "b" {
		t.Fatalf("unexpected targets %v", targets)
	}
}

func TestGateBrokerPoolEncryptedPathAfterDialFailure(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, e := backend.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	reserve, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientPort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	serverPub, serverKey, _ := ed25519.GenerateKey(nil)
	clientPub, clientKey, _ := ed25519.GenerateKey(nil)
	server := defaultConfig()
	server.Role, server.Enabled, server.ListenHost = "server", true, "127.0.0.1"
	server.PrivateKey = hex.EncodeToString(serverKey)
	server.PeerPublicKeys = []string{hex.EncodeToString(clientPub)}
	server.Upstream = backend.Addr().String()
	server.MTD.Enabled = false
	server.MTD.MinPort, server.MTD.MaxPort = serverPort, serverPort
	client := server
	client.Role = "client"
	client.PrivateKey = hex.EncodeToString(clientKey)
	client.PeerPublicKeys = []string{hex.EncodeToString(serverPub)}
	client.RemoteHost = ""
	// First member is unavailable; second is a real authenticated Gate server.
	client.RemoteHosts = []string{"127.0.0.2", "127.0.0.1"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- runTCP(ctx, server, serverPort, time.Now().Add(10*time.Second), newGateState(4)) }()
	go func() { done <- runTCP(ctx, client, clientPort, time.Now().Add(10*time.Second), newGateState(4)) }()
	wait := func(port int) {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 50*time.Millisecond)
			if e == nil {
				conn.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("Gate loopback listener unavailable")
	}
	wait(serverPort)
	wait(clientPort)
	balanceCounter.Store(0)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(clientPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	message := []byte("authenticated BrokerSet application path")
	if _, err = conn.Write(message); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(message))
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, message) {
		t.Fatal("application bytes changed")
	}
	conn.Close()
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Gate listener did not shut down")
		}
	}
}
