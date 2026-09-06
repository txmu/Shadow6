package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSPAAuthorizationCacheBoundedAndReclaimed(t *testing.T) {
	state := newSPAState()
	now := time.Unix(1700000000, 0)
	cfg := SPAConfig{Secret: strings.Repeat("s", 32), UnlockWindow: 300}
	for i := 0; i < maxTrackedIPs; i++ {
		state.authorized[fmt.Sprint(i)] = now.Add(time.Second)
	}
	if state.verify(spaPacket(cfg.Secret, "192.0.2.1", now.Unix()), "192.0.2.1", now, cfg) {
		t.Fatal("full authorization cache admitted new source")
	}
	if len(state.authorized) != maxTrackedIPs {
		t.Fatal("cache size changed")
	}
	if !state.verify(spaPacket(cfg.Secret, "192.0.2.1", now.Unix()+2), "192.0.2.1", now.Add(2*time.Second), cfg) {
		t.Fatal("expired authorizations were not reclaimed")
	}
	if len(state.authorized) != 1 {
		t.Fatal("expired authorizations retained")
	}
}

func TestProbeFullTableExistingClientAndExpiry(t *testing.T) {
	tracker := newProbeTracker()
	now := time.Unix(100, 0)
	cfg := ProbeConfig{MaxFails: 2, BanSec: 2}
	for i := 0; i < maxTrackedIPs; i++ {
		key := fmt.Sprint(i)
		tracker.Failures[key] = 1
		tracker.lastSeen[key] = now
	}
	if !tracker.record("0", now, cfg) {
		t.Fatal("full table disabled an existing counter")
	}
	tracker.record("new", now, cfg)
	if len(tracker.Failures) > maxTrackedIPs {
		t.Fatal("probe table exceeded bound")
	}
	if tracker.record("new", now.Add(3*time.Second), cfg) {
		t.Fatal("first failure after eviction should not ban")
	}
	if len(tracker.Failures) != 1 || len(tracker.lastSeen) != 1 {
		t.Fatal("unbanned entries never expired")
	}
}

func TestGuardStrictJSONSecretsAndSPAIPv6Config(t *testing.T) {
	valid := `{"role":"agent_guard","spa_config":{"enabled":true,"listen_host":"::1","secret":"ssssssssssssssssssssssssssssssss","knock_port":1234,"public_tcp_port":1235,"agent_tcp_port":1236,"unlock_window":5}}`
	path := filepath.Join(t.TempDir(), "guard.json")
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{valid + "garbage", strings.Replace(valid, `"role":"agent_guard"`, `"role":"broker_guard","role":"agent_guard"`, 1), strings.Replace(valid, `"role"`, `"Role"`, 1), strings.Replace(valid, `"enabled":true`, `"enabled":null`, 1)} {
		os.WriteFile(path, []byte(bad), 0600)
		if _, err := readConfig(path); err == nil {
			t.Fatal("ambiguous configuration accepted")
		}
	}
	os.WriteFile(path, []byte(valid), 0600)
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(link); err == nil {
		t.Fatal("symlink config accepted")
	}
	if runtime.GOOS != "windows" {
		os.Chmod(path, 0700)
		if _, err := readConfig(path); err == nil {
			t.Fatal("executable secret config accepted")
		}
	}
}

type pipeListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestBrokerListenerBoundAndSlotRelease(t *testing.T) {
	raw := &pipeListener{connections: make(chan net.Conn, 3), done: make(chan struct{})}
	l := newBoundedListener(raw, 1)
	defer l.Close()
	a, b := net.Pipe()
	defer b.Close()
	raw.connections <- a
	first, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	x, y := net.Pipe()
	defer y.Close()
	raw.connections <- x
	done := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); done <- c }()
	y.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := y.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("excess connection not closed: %v", err)
	}
	first.Close()
	first.Close()
	p, q := net.Pipe()
	defer q.Close()
	raw.connections <- p
	second := <-done
	if second == nil {
		t.Fatal("slot was not released")
	}
	l.closeConnections()
	q.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := q.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("hijack-style active connection not closed")
	}
}

func TestIdleConnectionDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &idleConn{Conn: a, idle: 10 * time.Millisecond}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle read did not time out")
	}
}

func TestBrokerRejectsGETBodyWithoutBackend(t *testing.T) {
	handler := brokerHandler(BrokerConfig{LocalBroker: 1, SecretPath: "/hidden", MaxConnPerIP: 2})
	request := httptest.NewRequest(http.MethodGet, "http://guard/hidden", strings.NewReader("body"))
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("GET body reached backend: %d", response.Code)
	}
}

func TestLPDLimiterUsesSuppliedTime(t *testing.T) {
	state := newLPDLimiterState(LPDConfig{Rate: 1, Burst: 1})
	now := time.Now()
	if !state.allow("::1", now) || state.allow("::1", now) || !state.allow("::1", now.Add(time.Second)) {
		t.Fatal("limiter did not honor its clock")
	}
}

func TestProxyCanceledBeforeDial(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	proxyTCP(ctx, a, "127.0.0.1:1")
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("canceled proxy retained the client")
	}
}
