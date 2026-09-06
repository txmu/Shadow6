package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxConfigBytes    = 1024 * 1024
	maxLPDPacketBytes = 4096
	maxTrackedIPs     = 50_000
)

type GuardConfig struct {
	Role          string        `json:"role"`
	TargetBackend string        `json:"target_backend,omitempty"`
	SPA           SPAConfig     `json:"spa_config,omitempty"`
	LPDLimiter    LPDConfig     `json:"lpd_limiter,omitempty"`
	AntiProbe     ProbeConfig   `json:"anti_probe,omitempty"`
	StealthTiming StealthConfig `json:"stealth_timing,omitempty"`
	BrokerShield  BrokerConfig  `json:"broker_shield,omitempty"`
}

type SPAConfig struct {
	Enabled       bool   `json:"enabled"`
	ListenHost    string `json:"listen_host,omitempty"`
	Secret        string `json:"secret"`
	KnockPort     int    `json:"knock_port"`
	PublicTCPPort int    `json:"public_tcp_port"`
	AgentTCPPort  int    `json:"agent_tcp_port"`
	UnlockWindow  int    `json:"unlock_window"`
}

type LPDConfig struct {
	Enabled    bool    `json:"enabled"`
	Rate       float64 `json:"rate"`
	Burst      int     `json:"burst"`
	PublicPort int     `json:"public_port"`
	AgentPort  int     `json:"agent_port"`
}

type ProbeConfig struct {
	Enabled    bool `json:"enabled"`
	PublicPort int  `json:"public_port"`
	LocalPort  int  `json:"local_port,omitempty"`
	MaxFails   int  `json:"max_fails"`
	BanSec     int  `json:"ban_duration_sec"`
}

type StealthConfig struct {
	Enabled     bool   `json:"enabled"`
	BrokerWSS   string `json:"broker_wss_addr"`
	ServerName  string `json:"server_name,omitempty"`
	IntervalMs  int    `json:"chaff_interval_ms"`
	JitterMinMs int    `json:"jitter_min_ms"`
	JitterMaxMs int    `json:"jitter_max_ms"`
}

type BrokerConfig struct {
	Enabled      bool   `json:"enabled"`
	PublicHost   string `json:"public_host,omitempty"`
	PublicPort   int    `json:"public_port"`
	LocalBroker  int    `json:"local_broker_port"`
	SecretPath   string `json:"secret_path"`
	MaxConnPerIP int    `json:"max_conn_per_ip"`
	TLSCertFile  string `json:"tls_cert_file,omitempty"`
	TLSKeyFile   string `json:"tls_key_file,omitempty"`
}

func validPort(port int) bool { return port >= 1 && port <= 65535 }

func validateConfig(cfg *GuardConfig) error {
	switch cfg.Role {
	case "agent_guard":
		if !cfg.SPA.Enabled && !cfg.LPDLimiter.Enabled && !cfg.AntiProbe.Enabled {
			return errors.New("agent_guard must enable SPA, LPD limiting, or anti-probe monitoring")
		}
	case "client_guard":
		if !cfg.StealthTiming.Enabled {
			return errors.New("client_guard must enable stealth_timing")
		}
	case "broker_guard":
		if !cfg.BrokerShield.Enabled {
			return errors.New("broker_guard must enable broker_shield")
		}
	default:
		return errors.New("role must be agent_guard, client_guard, or broker_guard")
	}
	if cfg.SPA.Enabled {
		if cfg.SPA.ListenHost != "" && net.ParseIP(cfg.SPA.ListenHost) == nil {
			return errors.New("spa_config.listen_host must be an IP literal")
		}
		if len(cfg.SPA.Secret) < 32 {
			return errors.New("spa_config.secret must contain at least 32 bytes")
		}
		if !validPort(cfg.SPA.KnockPort) || !validPort(cfg.SPA.PublicTCPPort) || !validPort(cfg.SPA.AgentTCPPort) {
			return errors.New("SPA ports must be between 1 and 65535")
		}
		if cfg.SPA.UnlockWindow < 1 || cfg.SPA.UnlockWindow > 300 {
			return errors.New("spa_config.unlock_window must be between 1 and 300 seconds")
		}
	}
	if cfg.LPDLimiter.Enabled {
		if !validPort(cfg.LPDLimiter.PublicPort) || !validPort(cfg.LPDLimiter.AgentPort) {
			return errors.New("LPD ports must be between 1 and 65535")
		}
		if cfg.LPDLimiter.Rate <= 0 || cfg.LPDLimiter.Rate > 10_000 || cfg.LPDLimiter.Burst < 1 || cfg.LPDLimiter.Burst > 10_000 {
			return errors.New("LPD rate and burst are outside safe bounds")
		}
	}
	if cfg.AntiProbe.Enabled {
		port := cfg.AntiProbe.PublicPort
		if port == 0 {
			port = cfg.AntiProbe.LocalPort
		}
		if !validPort(port) || cfg.AntiProbe.MaxFails < 1 || cfg.AntiProbe.MaxFails > 10_000 || cfg.AntiProbe.BanSec < 1 || cfg.AntiProbe.BanSec > 86_400 {
			return errors.New("anti_probe settings are outside safe bounds")
		}
	}
	if cfg.StealthTiming.Enabled {
		if _, _, err := parseTLSAddress(cfg.StealthTiming); err != nil {
			return err
		}
		if cfg.StealthTiming.IntervalMs < 1_000 || cfg.StealthTiming.IntervalMs > 86_400_000 || cfg.StealthTiming.JitterMinMs < 0 || cfg.StealthTiming.JitterMaxMs < cfg.StealthTiming.JitterMinMs || cfg.StealthTiming.JitterMaxMs > 3_600_000 {
			return errors.New("stealth_timing interval or jitter is outside safe bounds")
		}
	}
	if cfg.BrokerShield.Enabled {
		if !validPort(cfg.BrokerShield.PublicPort) || !validPort(cfg.BrokerShield.LocalBroker) {
			return errors.New("broker shield ports must be between 1 and 65535")
		}
		if cfg.BrokerShield.SecretPath == "/" || !strings.HasPrefix(cfg.BrokerShield.SecretPath, "/") || strings.ContainsAny(cfg.BrokerShield.SecretPath, "?#\r\n") {
			return errors.New("broker_shield.secret_path must be a non-root absolute path")
		}
		if cfg.BrokerShield.MaxConnPerIP == 0 {
			cfg.BrokerShield.MaxConnPerIP = 64
		}
		if cfg.BrokerShield.MaxConnPerIP < 1 || cfg.BrokerShield.MaxConnPerIP > 10_000 {
			return errors.New("broker_shield.max_conn_per_ip is outside safe bounds")
		}
		if cfg.BrokerShield.PublicHost == "" {
			cfg.BrokerShield.PublicHost = "127.0.0.1"
		}
		ip := net.ParseIP(cfg.BrokerShield.PublicHost)
		localOnly := cfg.BrokerShield.PublicHost == "localhost" || (ip != nil && ip.IsLoopback())
		if !localOnly && (cfg.BrokerShield.TLSCertFile == "" || cfg.BrokerShield.TLSKeyFile == "") {
			return errors.New("a non-loopback broker shield requires tls_cert_file and tls_key_file")
		}
		if (cfg.BrokerShield.TLSCertFile == "") != (cfg.BrokerShield.TLSKeyFile == "") {
			return errors.New("tls_cert_file and tls_key_file must be configured together")
		}
	}
	return nil
}

func readConfig(path string) (*GuardConfig, error) {
	data, err := readSecretFile(path, maxConfigBytes)
	if err != nil {
		return nil, err
	}
	var cfg GuardConfig
	if err := strictConfigJSON(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %w", err)
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

type spaState struct {
	mu         sync.Mutex
	authorized map[string]time.Time
	replays    map[[32]byte]time.Time
	nextSweep  time.Time
}

func newSPAState() *spaState {
	return &spaState{authorized: make(map[string]time.Time), replays: make(map[[32]byte]time.Time)}
}

func (state *spaState) verify(packet []byte, sourceIP string, now time.Time, cfg SPAConfig) bool {
	if len(packet) != 40 {
		return false
	}
	timestamp := int64(binary.BigEndian.Uint64(packet[:8]))
	if timestamp < now.Unix()-30 || timestamp > now.Unix()+5 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(cfg.Secret))
	_, _ = mac.Write(packet[:8])
	_, _ = mac.Write([]byte(sourceIP))
	var signature [32]byte
	copy(signature[:], packet[8:])
	if !hmac.Equal(signature[:], mac.Sum(nil)) {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !now.Before(state.nextSweep) {
		for key, expires := range state.replays {
			if !now.Before(expires) {
				delete(state.replays, key)
			}
		}
		for key, expires := range state.authorized {
			if !now.Before(expires) {
				delete(state.authorized, key)
			}
		}
		state.nextSweep = now.Add(time.Second)
	}
	if len(state.replays) >= maxTrackedIPs {
		return false
	}
	if _, exists := state.replays[signature]; exists {
		return false
	}
	if _, exists := state.authorized[sourceIP]; !exists && len(state.authorized) >= maxTrackedIPs {
		return false
	}
	state.replays[signature] = now.Add(60 * time.Second)
	state.authorized[sourceIP] = now.Add(time.Duration(cfg.UnlockWindow) * time.Second)
	return true
}

func (state *spaState) isAuthorized(sourceIP string, now time.Time) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	expires, ok := state.authorized[sourceIP]
	if !ok || !now.Before(expires) {
		delete(state.authorized, sourceIP)
		return false
	}
	return true
}

func proxyTCP(ctx context.Context, client net.Conn, target string) {
	defer client.Close()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	backend, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer backend.Close()
	client = &idleConn{Conn: client, idle: 120 * time.Second}
	backend = &idleConn{Conn: backend, idle: 120 * time.Second}
	stop := context.AfterFunc(ctx, func() { client.Close(); backend.Close() })
	defer stop()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, backend); done <- struct{}{} }()
	<-done
	client.Close()
	backend.Close()
	<-done
}

func startSPAShield(ctx context.Context, cfg SPAConfig) error {
	host := cfg.ListenHost
	if host == "" {
		host = "0.0.0.0"
	}
	ip := net.ParseIP(host)
	network := "udp4"
	if ip.To4() == nil {
		network = "udp6"
	}
	udp, err := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: cfg.KnockPort})
	if err != nil {
		return fmt.Errorf("SPA UDP bind failed: %w", err)
	}
	defer udp.Close()
	tcpNetwork := "tcp4"
	if network == "udp6" {
		tcpNetwork = "tcp6"
	}
	tcp, err := net.Listen(tcpNetwork, net.JoinHostPort(host, fmt.Sprint(cfg.PublicTCPPort)))
	if err != nil {
		return fmt.Errorf("SPA TCP bind failed: %w", err)
	}
	defer tcp.Close()
	state := newSPAState()
	go func() {
		<-ctx.Done()
		_ = udp.Close()
		_ = tcp.Close()
	}()
	go func() {
		buffer := make([]byte, 64)
		for {
			count, remote, readErr := udp.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			if state.verify(buffer[:count], remote.IP.String(), time.Now(), cfg) {
				log.Printf("[SPA] temporarily authorized %s", remote.IP)
			}
		}
	}()
	log.Printf("[SPA] UDP %d protects TCP %d -> loopback:%d", cfg.KnockPort, cfg.PublicTCPPort, cfg.AgentTCPPort)
	slots := make(chan struct{}, 256)
	for {
		client, acceptErr := tcp.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		host, _, splitErr := net.SplitHostPort(client.RemoteAddr().String())
		if splitErr != nil || !state.isAuthorized(host, time.Now()) {
			_ = client.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				proxyTCP(ctx, client, fmt.Sprintf("127.0.0.1:%d", cfg.AgentTCPPort))
			}()
		default:
			_ = client.Close()
		}
	}
}

type rateEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type lpdLimiterState struct {
	cfg       LPDConfig
	mu        sync.Mutex
	limiters  map[string]*rateEntry
	slots     chan struct{}
	nextSweep time.Time
}

func newLPDLimiterState(cfg LPDConfig) *lpdLimiterState {
	return &lpdLimiterState{cfg: cfg, limiters: make(map[string]*rateEntry), slots: make(chan struct{}, 256)}
}

func (state *lpdLimiterState) allow(ip string, now time.Time) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.limiters) >= maxTrackedIPs && !now.Before(state.nextSweep) {
		for key, entry := range state.limiters {
			if now.Sub(entry.lastSeen) > 3*time.Minute {
				delete(state.limiters, key)
			}
		}
		state.nextSweep = now.Add(time.Second)
	}
	entry := state.limiters[ip]
	if entry == nil && len(state.limiters) < maxTrackedIPs {
		entry = &rateEntry{limiter: rate.NewLimiter(rate.Limit(state.cfg.Rate), state.cfg.Burst)}
		state.limiters[ip] = entry
	}
	if entry == nil || !entry.limiter.AllowN(now, 1) {
		return false
	}
	entry.lastSeen = now
	return true
}

func serveLPDListener(ctx context.Context, public *net.UDPConn, agentIP net.IP, state *lpdLimiterState) error {
	go func() { <-ctx.Done(); _ = public.Close() }()
	buffer := make([]byte, maxLPDPacketBytes+1)
	for {
		count, remote, readErr := public.ReadFromUDP(buffer)
		if readErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return readErr
		}
		if count == 0 || count > maxLPDPacketBytes {
			continue
		}
		ip := remote.IP.String()
		if !state.allow(ip, time.Now()) {
			continue
		}
		packet := append([]byte(nil), buffer[:count]...)
		remoteCopy := *remote
		select {
		case state.slots <- struct{}{}:
			go func() {
				defer func() { <-state.slots }()
				network := "udp4"
				if agentIP.To4() == nil {
					network = "udp6"
				}
				agent, dialErr := net.DialUDP(network, nil, &net.UDPAddr{IP: agentIP, Port: state.cfg.AgentPort})
				if dialErr != nil {
					return
				}
				defer agent.Close()
				_ = agent.SetDeadline(time.Now().Add(2 * time.Second))
				if _, dialErr = agent.Write(packet); dialErr != nil {
					return
				}
				reply := make([]byte, maxLPDPacketBytes+1)
				replyLen, _, dialErr := agent.ReadFromUDP(reply)
				if dialErr == nil && replyLen > 0 && replyLen <= maxLPDPacketBytes {
					_, _ = public.WriteToUDP(reply[:replyLen], &remoteCopy)
				}
			}()
		default:
		}
	}
}

func startLPDLimiter(ctx context.Context, cfg LPDConfig) error {
	type listener struct {
		connection *net.UDPConn
		agentIP    net.IP
	}
	listeners := make([]listener, 0, 2)
	var bindErrors []error
	if public, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: cfg.PublicPort}); err == nil {
		listeners = append(listeners, listener{connection: public, agentIP: net.ParseIP("127.0.0.1")})
	} else {
		bindErrors = append(bindErrors, fmt.Errorf("IPv4: %w", err))
	}
	if public, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: cfg.PublicPort}); err == nil {
		listeners = append(listeners, listener{connection: public, agentIP: net.ParseIP("::1")})
	} else {
		bindErrors = append(bindErrors, fmt.Errorf("IPv6: %w", err))
	}
	if len(listeners) == 0 {
		return fmt.Errorf("LPD bind failed: %w", errors.Join(bindErrors...))
	}
	defer func() {
		for _, item := range listeners {
			_ = item.connection.Close()
		}
	}()
	state := newLPDLimiterState(cfg)
	errorsChannel := make(chan error, len(listeners))
	for _, item := range listeners {
		item := item
		go func() { errorsChannel <- serveLPDListener(ctx, item.connection, item.agentIP, state) }()
	}
	log.Printf("[LPD] IPv4/IPv6 bidirectional limiter on UDP %d -> loopback:%d", cfg.PublicPort, cfg.AgentPort)
	select {
	case <-ctx.Done():
		return nil
	case err := <-errorsChannel:
		return err
	}
}

func parseTLSAddress(cfg StealthConfig) (string, string, error) {
	value := strings.TrimSpace(cfg.BrokerWSS)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", "", errors.New("stealth_timing.broker_wss_addr is invalid")
	}
	serverName := cfg.ServerName
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "wss" || parsed.Hostname() == "" || parsed.User != nil {
			return "", "", errors.New("broker_wss_addr URL must use wss:// without credentials")
		}
		value = parsed.Host
		if serverName == "" {
			serverName = parsed.Hostname()
		}
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return "", "", errors.New("broker_wss_addr must include a host and port")
	}
	if serverName == "" {
		serverName = strings.Trim(host, "[]")
	}
	return value, serverName, nil
}

func secureJitter(minimum, maximum int) time.Duration {
	if maximum <= minimum {
		return time.Duration(minimum) * time.Millisecond
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum-minimum+1)))
	if err != nil {
		return time.Duration(minimum) * time.Millisecond
	}
	return time.Duration(minimum+int(value.Int64())) * time.Millisecond
}

func startStealthClient(ctx context.Context, cfg StealthConfig) error {
	address, serverName, err := parseTLSAddress(cfg)
	if err != nil {
		return err
	}
	log.Printf("[Stealth] authenticated TLS cover connections enabled for %s", address)
	for {
		delay := time.Duration(cfg.IntervalMs)*time.Millisecond + secureJitter(cfg.JitterMinMs, cfg.JitterMaxMs)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		connection, dialErr := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName})
		if dialErr == nil {
			_ = connection.Close()
		}
	}
}

type ActiveProbeTracker struct {
	mu        sync.Mutex
	Failures  map[string]int
	Bans      map[string]time.Time
	lastSeen  map[string]time.Time
	nextSweep time.Time
}

func newProbeTracker() *ActiveProbeTracker {
	return &ActiveProbeTracker{Failures: make(map[string]int), Bans: make(map[string]time.Time), lastSeen: make(map[string]time.Time)}
}

func (tracker *ActiveProbeTracker) record(ip string, now time.Time, cfg ProbeConfig) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if !now.Before(tracker.nextSweep) {
		for key, last := range tracker.lastSeen {
			expiry, banned := tracker.Bans[key]
			if banned && !now.Before(expiry) || !banned && now.Sub(last) >= time.Duration(cfg.BanSec)*time.Second {
				delete(tracker.Bans, key)
				delete(tracker.Failures, key)
				delete(tracker.lastSeen, key)
			}
		}
		tracker.nextSweep = now.Add(time.Second)
	}
	if expiry, banned := tracker.Bans[ip]; banned && now.Before(expiry) {
		return true
	}
	if _, exists := tracker.Failures[ip]; !exists && len(tracker.Failures) >= maxTrackedIPs {
		return false
	}
	tracker.Failures[ip]++
	tracker.lastSeen[ip] = now
	if tracker.Failures[ip] >= cfg.MaxFails {
		tracker.Bans[ip] = now.Add(time.Duration(cfg.BanSec) * time.Second)
		return true
	}
	return false
}

var tracker = newProbeTracker()

func startAntiProbe(ctx context.Context, cfg ProbeConfig) error {
	port := cfg.PublicPort
	if port == 0 {
		port = cfg.LocalPort
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("anti-probe bind failed: %w", err)
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	log.Printf("[AntiProbe] bounded honeypot monitor listening on TCP %d", port)
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		host, _, _ := net.SplitHostPort(connection.RemoteAddr().String())
		if tracker.record(host, time.Now(), cfg) {
			log.Printf("[AntiProbe] threshold reached for %s", host)
		}
		_ = connection.Close()
	}
}

const decoyBody = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.18.0 (Ubuntu)</center>\r\n</body>\r\n</html>\r\n"

func brokerHandler(cfg BrokerConfig) http.Handler {
	target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", cfg.LocalBroker))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(writer, "bad gateway", http.StatusBadGateway)
	}
	proxy.Transport = &http.Transport{
		DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxConnsPerHost: 256, MaxIdleConnsPerHost: 16, MaxIdleConns: 16,
		IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
	}
	proxy.Director = nil
	proxy.Rewrite = func(request *httputil.ProxyRequest) {
		request.SetURL(target)
		request.Out.Host = target.Host
		request.Out.URL.Path = "/ws"
		request.Out.URL.RawPath = ""
		request.Out.Header.Del("X-Real-IP")
		request.SetXForwarded()
	}
	var mu sync.Mutex
	connections := make(map[string]int)
	active := 0
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != cfg.SecretPath || request.Method != http.MethodGet {
			writer.Header().Set("Server", "nginx/1.18.0 (Ubuntu)")
			writer.Header().Set("Content-Type", "text/html")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, decoyBody)
			return
		}
		if request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
			http.Error(writer, "request body not allowed", http.StatusBadRequest)
			return
		}
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		if active >= 256 || connections[host] >= cfg.MaxConnPerIP {
			mu.Unlock()
			http.Error(writer, "busy", http.StatusServiceUnavailable)
			return
		}
		connections[host]++
		active++
		mu.Unlock()
		defer func() {
			mu.Lock()
			connections[host]--
			active--
			if connections[host] == 0 {
				delete(connections, host)
			}
			mu.Unlock()
		}()
		proxy.ServeHTTP(writer, request)
	})
}

func startBrokerFortress(ctx context.Context, cfg BrokerConfig) error {
	server := &http.Server{
		Addr:              net.JoinHostPort(cfg.PublicHost, fmt.Sprint(cfg.PublicPort)),
		Handler:           brokerHandler(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}
	if cfg.TLSCertFile != "" {
		key, err := readSecretFile(cfg.TLSKeyFile, maxConfigBytes)
		if err != nil {
			return fmt.Errorf("TLS private key: %w", err)
		}
		cert, err := readCertificate(cfg.TLSCertFile)
		if err != nil {
			return err
		}
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return err
		}
		server.TLSConfig.Certificates = []tls.Certificate{pair}
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	bounded := newBoundedListener(listener, 256)
	defer bounded.Close()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		bounded.closeConnections()
	}()
	log.Printf("[Broker-Shield] listening on %s", server.Addr)
	if cfg.TLSCertFile != "" {
		err := server.ServeTLS(bounded, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
	err = server.Serve(bounded)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

const ctlScript = `#!/usr/bin/env bash
set -eu
umask 077
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
binary=${SHADOW6_GUARD_BIN:-"$script_dir/shadow6-guard"}
config=${SHADOW6_GUARD_CONFIG:-"$script_dir/config.json"}
pidfile=${SHADOW6_GUARD_PIDFILE:-"$script_dir/guard.pid"}
logfile=${SHADOW6_GUARD_LOGFILE:-"$script_dir/guard.log"}
process_start_time() {
    [ -r "/proc/$1/stat" ] || return 1
    stat_line=$(sed -n '1p' "/proc/$1/stat")
    stat_tail=${stat_line##*) }
    read -r -a stat_fields <<<"$stat_tail"
    [ "${#stat_fields[@]}" -ge 20 ] || return 1
    printf '%s\n' "${stat_fields[19]}"
}
read_pid() {
    [ -f "$pidfile" ] && [ ! -L "$pidfile" ] || return 1
    pid=$(sed -n '1p' "$pidfile")
    recorded_start=$(sed -n '2p' "$pidfile")
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    case "$recorded_start" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null || return 1
    current_start=$(process_start_time "$pid") || return 1
    [ "$current_start" = "$recorded_start" ] || return 1
    expected_binary=$(readlink -f -- "$binary") || return 1
    process_binary=$(readlink -f -- "/proc/$pid/exe") || return 1
    [ "$process_binary" = "$expected_binary" ] || return 1
    expected_config=$(readlink -f -- "$config") || return 1
    mapfile -d '' -t process_args <"/proc/$pid/cmdline" || return 1
    [ "${#process_args[@]}" -eq 3 ] || return 1
    [ "${process_args[1]}" = "--config" ] || return 1
    process_config=$(readlink -f -- "${process_args[2]}") || return 1
    [ "$process_config" = "$expected_config" ]
}
case ${1:-} in
    start)
        if read_pid; then echo "Already running (PID $pid)."; exit 0; fi
        [ ! -L "$pidfile" ] || { echo "Refusing symlink PID file: $pidfile" >&2; exit 1; }
        [ ! -L "$logfile" ] || { echo "Refusing symlink log file: $logfile" >&2; exit 1; }
        [ -x "$binary" ] || { echo "Missing executable: $binary" >&2; exit 1; }
        [ -f "$config" ] || { echo "Missing config: $config" >&2; exit 1; }
        nohup "$binary" --config "$config" >>"$logfile" 2>&1 </dev/null &
        pid=$!
        start_time=$(process_start_time "$pid") || {
            kill "$pid" 2>/dev/null || true
            echo "Could not verify started process." >&2
            exit 1
        }
        printf '%s\n%s\n' "$pid" "$start_time" >"$pidfile"
        echo "Started (PID $pid)."
        ;;
    stop)
        if ! read_pid; then rm -f -- "$pidfile"; echo "Not running."; exit 0; fi
        kill "$pid"
        i=0
        while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
        if kill -0 "$pid" 2>/dev/null; then echo "Process did not stop cleanly." >&2; exit 1; fi
        rm -f -- "$pidfile"
        echo "Stopped."
        ;;
    status)
        if read_pid; then echo "Running (PID $pid)."; else echo "Not running."; exit 1; fi
        ;;
    *) echo "Usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac
`

func installCtl() error {
	temporary, err := os.CreateTemp(".", ".shadow6-guard-ctl-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o700); err != nil {
		temporary.Close()
		return err
	}
	if _, err := io.WriteString(temporary, ctlScript); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(".", "shadow6-guard-ctl.sh"))
}

func run() error {
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	configPath := flags.String("config", "", "Path to guard config JSON")
	generateCtl := flags.Bool("install-ctl", false, "Generate the management shell script")
	checkConfig := flags.Bool("check-config", false, "Validate configuration and exit")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if *generateCtl {
		return installCtl()
	}
	if *configPath == "" {
		return errors.New("usage: shadow6-guard --config config.json")
	}
	cfg, err := readConfig(*configPath)
	if err != nil {
		return err
	}
	if *checkConfig {
		fmt.Printf("Configuration %s is valid for role %s\n", *configPath, cfg.Role)
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errorsChannel := make(chan error, 3)
	start := func(function func() error) { go func() { errorsChannel <- function() }() }
	switch cfg.Role {
	case "agent_guard":
		if cfg.AntiProbe.Enabled {
			start(func() error { return startAntiProbe(ctx, cfg.AntiProbe) })
		}
		if cfg.SPA.Enabled {
			start(func() error { return startSPAShield(ctx, cfg.SPA) })
		}
		if cfg.LPDLimiter.Enabled {
			start(func() error { return startLPDLimiter(ctx, cfg.LPDLimiter) })
		}
	case "client_guard":
		start(func() error { return startStealthClient(ctx, cfg.StealthTiming) })
	case "broker_guard":
		start(func() error { return startBrokerFortress(ctx, cfg.BrokerShield) })
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errorsChannel:
		stop()
		return err
	}
}

func main() {
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		log.Printf("shadow6-guard: %v", err)
		os.Exit(2)
	}
}
