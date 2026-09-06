package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func spaPacket(secret, ip string, timestamp int64) []byte {
	packet := make([]byte, 40)
	binary.BigEndian.PutUint64(packet[:8], uint64(timestamp))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(packet[:8])
	_, _ = mac.Write([]byte(ip))
	copy(packet[8:], mac.Sum(nil))
	return packet
}

func TestSPAAuthenticationBindingReplayAndExpiry(t *testing.T) {
	cfg := SPAConfig{Secret: strings.Repeat("s", 32), UnlockWindow: 10}
	state := newSPAState()
	now := time.Unix(1_700_000_000, 0)
	packet := spaPacket(cfg.Secret, "192.0.2.1", now.Unix())
	if !state.verify(packet, "192.0.2.1", now, cfg) {
		t.Fatal("valid SPA packet rejected")
	}
	if state.verify(packet, "192.0.2.1", now, cfg) {
		t.Fatal("replayed SPA packet accepted")
	}
	if state.verify(spaPacket(cfg.Secret, "192.0.2.1", now.Unix()), "192.0.2.2", now, cfg) {
		t.Fatal("cross-IP SPA replay accepted")
	}
	if !state.isAuthorized("192.0.2.1", now.Add(9*time.Second)) || state.isAuthorized("192.0.2.1", now.Add(11*time.Second)) {
		t.Fatal("SPA authorization window is incorrect")
	}
}

func TestProbeTrackerBoundedBan(t *testing.T) {
	local := newProbeTracker()
	cfg := ProbeConfig{MaxFails: 2, BanSec: 2}
	now := time.Unix(100, 0)
	if local.record("127.0.0.1", now, cfg) {
		t.Fatal("first probe unexpectedly banned")
	}
	if !local.record("127.0.0.1", now, cfg) {
		t.Fatal("threshold did not ban")
	}
	if local.record("127.0.0.1", now.Add(3*time.Second), cfg) {
		t.Fatal("expired ban was not cleared before a new first failure")
	}
}

func TestLPDLimiterBidirectionalIPv6(t *testing.T) {
	echo, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer echo.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buffer := make([]byte, 64)
		count, remote, readErr := echo.ReadFromUDP(buffer)
		if readErr == nil {
			_, _ = echo.WriteToUDP(buffer[:count], remote)
		}
	}()

	public, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	cfg := LPDConfig{Enabled: true, Rate: 100, Burst: 100, AgentPort: echo.LocalAddr().(*net.UDPAddr).Port}
	state := newLPDLimiterState(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveLPDListener(ctx, public, net.ParseIP("::1"), state) }()

	client, err := net.DialUDP("udp6", nil, public.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte("ipv6-lpd")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 64)
	count, err := client.Read(reply)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply[:count]) != "ipv6-lpd" {
		t.Fatalf("unexpected IPv6 LPD reply: %q", reply[:count])
	}
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IPv6 LPD limiter did not stop")
	}
	select {
	case <-echoDone:
	case <-time.After(time.Second):
		t.Fatal("IPv6 echo service did not finish")
	}
}

func TestBrokerPathCloakingAndRewrite(t *testing.T) {
	received := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Forwarded-For") != "192.0.2.1" || request.Header.Get("Forwarded") != "" || request.Header.Get("X-Real-IP") != "" {
			t.Error("untrusted forwarding headers reached the backend")
		}
		received <- request.URL.Path
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	cfg := BrokerConfig{LocalBroker: backend.Listener.Addr().(*net.TCPAddr).Port, SecretPath: "/hidden", MaxConnPerIP: 2}
	handler := brokerHandler(cfg)
	request := httptest.NewRequest(http.MethodGet, "http://guard/", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || response.Header().Get("Server") != "nginx/1.18.0 (Ubuntu)" {
		t.Fatalf("invalid decoy response: %d %q", response.Code, response.Header().Get("Server"))
	}
	request = httptest.NewRequest(http.MethodGet, "http://guard/hidden", nil)
	request.Header.Set("X-Forwarded-For", "attacker")
	request.Header.Set("Forwarded", "for=attacker")
	request.Header.Set("X-Real-IP", "attacker")
	request.RemoteAddr = "192.0.2.1:1234"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("secret path was not proxied: %d", response.Code)
	}
	select {
	case path := <-received:
		if path != "/ws" {
			t.Fatalf("backend path was %q", path)
		}
	case <-time.After(time.Second):
		t.Fatal("backend did not receive request")
	}
}

func TestConfigStrictPermissionsAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.json")
	data := `{"role":"broker_guard","broker_shield":{"enabled":true,"public_host":"127.0.0.1","public_port":8443,"local_broker_port":4433,"secret_path":"/hidden","max_conn_per_ip":8}}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err == nil {
		t.Fatal("world-readable secret config accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(data, "}")+`,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err == nil {
		t.Fatal("unknown field accepted")
	}
	remote := GuardConfig{Role: "broker_guard", BrokerShield: BrokerConfig{Enabled: true, PublicHost: "0.0.0.0", PublicPort: 8443, LocalBroker: 4433, SecretPath: "/hidden", MaxConnPerIP: 8}}
	if err := validateConfig(&remote); err == nil {
		t.Fatal("remote plaintext broker shield accepted")
	}
}

func TestTLSAddressAndControlScript(t *testing.T) {
	address, serverName, err := parseTLSAddress(StealthConfig{BrokerWSS: "wss://example.com:443/ws"})
	if err != nil || address != "example.com:443" || serverName != "example.com" {
		t.Fatalf("unexpected TLS parse: %q %q %v", address, serverName, err)
	}
	if _, _, err := parseTLSAddress(StealthConfig{BrokerWSS: "ws://example.com:80/ws"}); err == nil {
		t.Fatal("plaintext cover endpoint accepted")
	}
	if !strings.Contains(ctlScript, `case "$pid"`) || strings.Contains(ctlScript, "kill $(cat") ||
		!strings.Contains(ctlScript, `/proc/$pid/exe`) || !strings.Contains(ctlScript, "recorded_start") ||
		!strings.Contains(ctlScript, "mapfile -d '' -t process_args") {
		t.Fatal("control script lacks safe PID handling")
	}
}
