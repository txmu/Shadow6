package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testKeys struct {
	public     ed25519.PublicKey
	private    ed25519.PrivateKey
	publicHex  string
	privateHex string
}

func generateTestKeys(t *testing.T) testKeys {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKeys{publicKey, privateKey, hex.EncodeToString(publicKey), hex.EncodeToString(privateKey)}
}

func TestPrivateKeyParsing(t *testing.T) {
	keys := generateTestKeys(t)
	parsed, err := parsePrivateKey(keys.privateHex)
	if err != nil || !parsed.Public().(ed25519.PublicKey).Equal(keys.public) {
		t.Fatalf("expanded key parse failed: %v", err)
	}
	parsedSeed, err := parsePrivateKey(hex.EncodeToString(keys.private.Seed()))
	if err != nil || !parsedSeed.Equal(keys.private) {
		t.Fatalf("seed key parse failed: %v", err)
	}
	broken := append([]byte(nil), keys.private...)
	broken[len(broken)-1] ^= 1
	if _, err := parsePrivateKey(hex.EncodeToString(broken)); err == nil {
		t.Fatal("inconsistent expanded private key was accepted")
	}
}

func TestCompiledFeaturesAndSignedCrosedNegotiation(t *testing.T) {
	report := compiledFeatureReport()
	if report.Core != "shadow6-go" || !report.UTF8 || report.CrosedMaxLevel != compiledCrosedLevel() {
		t.Fatalf("invalid compiled feature report: %+v", report)
	}
	keys := generateTestKeys(t)
	request := CrosedRequest{
		Version: 1, ModID: "test-mod", Nonce: "00112233445566778899aabbccddeeff", IssuedAt: time.Now().Unix(),
		RequestedLevel: 1, Capabilities: []string{"observe.version"}, Payload: json.RawMessage(`{"message":"你好"}`),
		SourceDomain: "work-vm", TargetDomain: "work-vm",
	}
	request.Signature = hex.EncodeToString(ed25519.Sign(keys.private, crosedSignedPayload(request)))
	trust := CrosedTrust{Mods: map[string]CrosedTrustEntry{"test-mod": {
		PubKey: keys.publicHex, MaxLevel: 1, Capabilities: []string{"observe.version"}, AllowedDomains: []string{"work-vm"},
	}}}
	directory := t.TempDir()
	requestPath, trustPath := filepath.Join(directory, "request.json"), filepath.Join(directory, "trust.json")
	requestData, _ := json.Marshal(request)
	trustData, _ := json.Marshal(trust)
	if err := os.WriteFile(requestPath, requestData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, trustData, 0o600); err != nil {
		t.Fatal(err)
	}
	response, err := handleCrosedRequest(requestPath, trustPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.CrosedCompiled {
		if response.Status != "granted" || response.GrantedLevel != 1 {
			t.Fatalf("signed request denied: %+v", response)
		}
	} else if response.Status != "denied" || response.FeatureReport.CrosedMaxLevel != 0 {
		t.Fatalf("disabled build incorrectly granted Crosed: %+v", response)
	}
	request.Signature = strings.Repeat("00", ed25519.SignatureSize)
	requestData, _ = json.Marshal(request)
	if err := os.WriteFile(requestPath, requestData, 0o600); err != nil {
		t.Fatal(err)
	}
	if report.CrosedCompiled {
		if _, err := handleCrosedRequest(requestPath, trustPath, time.Now()); err == nil {
			t.Fatal("forged Crosed request was accepted")
		}
	}
}

func TestConfigValidationAndPermissions(t *testing.T) {
	brokerKeys, agentKeys, clientKeys := generateTestKeys(t), generateTestKeys(t), generateTestKeys(t)
	config := Config{Role: "broker", Broker: &BrokerConfig{
		ListenAddr: "127.0.0.1:0", PrivateKey: brokerKeys.privateHex,
		Agents:  []AgentRBAC{{ID: "agent-1", PubKey: agentKeys.publicHex}},
		Clients: []ClientRBAC{{ID: "client-1", PubKey: clientKeys.publicHex, AllowedAgents: []string{"agent-1"}}},
	}}
	if err := validateConfig(&config); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(config)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("insecure config mode was accepted: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err != nil {
		t.Fatalf("secure config rejected: %v", err)
	}
	unknown := append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
	if err := os.WriteFile(path, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
	link := filepath.Join(t.TempDir(), "config-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(link); err == nil {
		t.Fatal("symlink configuration was accepted")
	}
}

func TestClientRequiresAgentKeyAndWebhookURLIsStrict(t *testing.T) {
	clientKeys, brokerKeys := generateTestKeys(t), generateTestKeys(t)
	config := Config{Role: "client", Client: &ClientConfig{
		ID: "client-1", TargetAgent: "agent-1", BrokerAddrs: []string{"ws://127.0.0.1:4433/ws"},
		BrokerPubKey: brokerKeys.publicHex, PrivateKey: clientKeys.privateHex, Transport: "kcp",
	}}
	if err := validateConfig(&config); err == nil || !strings.Contains(err.Error(), "agent public key") {
		t.Fatalf("missing agent key was accepted: %v", err)
	}
	for _, value := range []string{"http://example.com/hook", "https://user@example.com/hook", "https://example.com/hook#secret", "https://"} {
		if err := validateHTTPSURL(value); err == nil {
			t.Fatalf("unsafe webhook URL was accepted: %q", value)
		}
	}
	if err := validateHTTPSURL("https://example.com/hook"); err != nil {
		t.Fatal(err)
	}
}

func TestURLAndIdentityValidation(t *testing.T) {
	if _, err := normalizeBrokerURL("ws://example.com/ws"); err == nil {
		t.Fatal("remote plaintext WebSocket URL was accepted")
	}
	if _, err := normalizeBrokerURL("ws://127.0.0.1:4433/ws"); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeBrokerURL("broker.example:443"); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{"", "../agent", "a b", strings.Repeat("a", 65)} {
		if validIdentity(identity) {
			t.Fatalf("unsafe identity accepted: %q", identity)
		}
	}
}

func TestAEADRoundTripAndMalformedFrames(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	left, right := net.Pipe()
	secureLeft, _ := newAEADConn(left, key)
	secureRight, _ := newAEADConn(right, key)
	go func() { _, _ = secureLeft.Write([]byte("authenticated payload")) }()
	buffer := make([]byte, 64)
	count, err := secureRight.Read(buffer)
	if err != nil || string(buffer[:count]) != "authenticated payload" {
		t.Fatalf("AEAD round trip failed: %v", err)
	}
	left.Close()
	right.Close()

	malformedLeft, malformedRight := net.Pipe()
	secureMalformed, _ := newAEADConn(malformedLeft, key)
	go func() {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], 1)
		_, _ = malformedRight.Write(length[:])
		_, _ = malformedRight.Write([]byte{0})
	}()
	if _, err := secureMalformed.Read(buffer); err == nil {
		t.Fatal("undersized AEAD frame was accepted")
	}
	malformedLeft.Close()
	malformedRight.Close()

	tamperLeft, tamperRight := net.Pipe()
	secureTamper, _ := newAEADConn(tamperLeft, key)
	go func() {
		block, _ := aes.NewCipher(key)
		aead, _ := cipher.NewGCM(block)
		nonce := make([]byte, aead.NonceSize())
		ciphertext := aead.Seal(nonce, nonce, []byte("sensitive"), nil)
		ciphertext[len(ciphertext)-1] ^= 1
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(ciphertext)))
		_, _ = tamperRight.Write(length[:])
		_, _ = tamperRight.Write(ciphertext)
	}()
	if _, err := secureTamper.Read(buffer); err == nil {
		t.Fatal("tampered AEAD frame was accepted")
	}
}

func TestAEADWriteUsesUniqueCounterNonces(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	secure, err := newAEADConn(left, key)
	if err != nil {
		t.Fatal(err)
	}
	nonces := make([][]byte, 0, 2)
	for range 2 {
		result := make(chan error, 1)
		go func() { _, err := secure.Write([]byte("frame")); result <- err }()
		var size [4]byte
		if _, err := io.ReadFull(right, size[:]); err != nil {
			t.Fatal(err)
		}
		frame := make([]byte, binary.BigEndian.Uint32(size[:]))
		if _, err := io.ReadFull(right, frame); err != nil {
			t.Fatal(err)
		}
		nonces = append(nonces, append([]byte(nil), frame[:secure.aead.NonceSize()]...))
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Equal(nonces[0], nonces[1]) {
		t.Fatal("AEAD nonce repeated")
	}
	secure.sendCounter = ^uint64(0)
	if _, err := secure.Write([]byte("exhausted")); err == nil {
		t.Fatal("AEAD counter wrap was accepted")
	}
}

func TestHighThroughputCapacityContract(t *testing.T) {
	required := requiredBandwidthDelayBytes(targetThroughputBitsPerSecond, designRoundTripMilliseconds)
	if configuredKCPWindowBytes() < required {
		t.Fatalf("KCP window %d bytes is below 10Gbps/%dms BDP %d bytes", configuredKCPWindowBytes(), designRoundTripMilliseconds, required)
	}
	if proxyCopyBufferBytes < 256*1024 || maxAEADPlaintext < proxyCopyBufferBytes {
		t.Fatal("copy and authenticated-frame limits are inconsistent with the throughput profile")
	}
}

func startEchoTarget(t *testing.T) (int, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer listener.Close()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil || string(request) != "ping" {
			return
		}
		_, _ = connection.Write([]byte("pong"))
	}()
	return listener.Addr().(*net.TCPAddr).Port, done
}

func TestBrokerAgentClientEndToEnd(t *testing.T) {
	brokerKeys, agentKeys, clientKeys := generateTestKeys(t), generateTestKeys(t), generateTestKeys(t)
	targetPort, targetDone := startEchoTarget(t)
	broker, err := newBroker(&BrokerConfig{
		PrivateKey: brokerKeys.privateHex,
		Agents:     []AgentRBAC{{ID: "agent-1", PubKey: agentKeys.publicHex}},
		Clients:    []ClientRBAC{{ID: "client-1", PubKey: clientKeys.publicHex, AllowedAgents: []string{"agent-1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(broker.websocketHandler())
	defer server.Close()
	brokerURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	agentService, _ := newAgentService(&AgentConfig{
		ID: "agent-1", PrivateKey: agentKeys.privateHex, BrokerPubKey: brokerKeys.publicHex,
		TargetPort: targetPort, AutoCloseAfter: 5, Transport: "kcp",
		ClientPubKeys: map[string]string{"client-1": clientKeys.publicHex},
	})
	agentConnection, agentWrite, err := dialBroker([]string{brokerURL}, "agent-1", agentKeys.private, brokerKeys.public)
	if err != nil {
		t.Fatal(err)
	}
	agentPeer := newRPCPeer(agentConnection, agentWrite, map[string]rpcHandler{"Agent.GrantAccess": agentService.handleGrant})
	agentServe := make(chan error, 1)
	go func() { agentServe <- agentPeer.serve() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	var update map[string]bool
	if err := agentPeer.call(ctx, "Broker.UpdateIP", UpdateIPReq{AgentID: "spoofed", IP: "127.0.0.1"}, &update); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()

	clientConnection, clientWrite, err := dialBroker([]string{brokerURL}, "client-1", clientKeys.private, brokerKeys.public)
	if err != nil {
		t.Fatal(err)
	}
	clientPeer := newRPCPeer(clientConnection, clientWrite, nil)
	clientServe := make(chan error, 1)
	go func() { clientServe <- clientPeer.serve() }()
	clientECDH, _ := ecdh.X25519().GenerateKey(rand.Reader)
	request := AccessReq{ClientID: "spoofed-client", TargetAgent: "agent-1", ClientIP: "127.0.0.1", E2EEPubKey: clientECDH.PublicKey().Bytes()}
	signedRequest := request
	signedRequest.ClientID = "client-1"
	request.ClientSig = ed25519.Sign(clientKeys.private, clientSignaturePayload(&signedRequest))
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	var response AccessResp
	if err := clientPeer.call(ctx, "Broker.RequestAccess", request, &response); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if response.TargetIP != "127.0.0.1" || response.DynamicPort != 0 || response.Transport != "kcp" {
		t.Fatalf("invalid access response: %+v", response)
	}
	if err := verifyAgentAccess(&ClientConfig{AgentPubKey: agentKeys.publicHex}, &signedRequest, &response); err != nil {
		t.Fatal(err)
	}
	agentECDH, _ := ecdh.X25519().NewPublicKey(response.E2EEPubKey)
	shared, _ := clientECDH.ECDH(agentECDH)
	key, _ := deriveSymmetricKey(shared, request.E2EEPubKey, response.E2EEPubKey)
	secure, err := dialSecureKCP(net.JoinHostPort(response.TargetIP, strconv.Itoa(response.KCPPort)), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secure.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	_ = secure.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(secure, reply); err != nil || string(reply) != "pong" {
		t.Fatalf("KCP data path failed: %q %v", reply, err)
	}
	secure.Close()
	select {
	case <-targetDone:
	case <-time.After(2 * time.Second):
		t.Fatal("target echo service did not finish")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	var roleResponse map[string]bool
	err = clientPeer.call(ctx, "Broker.UpdateIP", UpdateIPReq{AgentID: "agent-1", IP: "127.0.0.2"}, &roleResponse)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "authenticated agents") {
		t.Fatalf("client role escalation was not rejected: %v", err)
	}
	clientPeer.close()
	agentPeer.close()
	select {
	case <-clientServe:
	case <-time.After(time.Second):
	}
	select {
	case <-agentServe:
	case <-time.After(time.Second):
	}
}

func TestAgentRejectsBrokerForgedAccessRequest(t *testing.T) {
	agentKeys, clientKeys := generateTestKeys(t), generateTestKeys(t)
	service, err := newAgentService(&AgentConfig{
		ID: "agent-1", PrivateKey: agentKeys.privateHex, TargetPort: 22, AutoCloseAfter: 1,
		ClientPubKeys: map[string]string{"client-1": clientKeys.publicHex},
	})
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := &AccessReq{
		ClientID: "client-1", TargetAgent: "agent-1", ClientIP: "127.0.0.1",
		E2EEPubKey: ephemeral.PublicKey().Bytes(),
	}
	if _, err := service.grantAccess(request); err == nil || !strings.Contains(err.Error(), "client access signature") {
		t.Fatalf("unsigned broker-forged request was accepted: %v", err)
	}
	request.ClientSig = ed25519.Sign(clientKeys.private, clientSignaturePayload(request))
	if _, err := service.grantAccess(request); err != nil {
		t.Fatalf("valid end-to-end client signature was rejected: %v", err)
	}
}

func TestLocalDiscoverySignatureAndReplay(t *testing.T) {
	agentKeys, clientKeys := generateTestKeys(t), generateTestKeys(t)
	service, err := newAgentService(&AgentConfig{
		ID: "agent-lpd", PrivateKey: agentKeys.privateHex, TargetPort: 9, AutoCloseAfter: 1,
		ClientPubKeys: map[string]string{"client-lpd": clientKeys.publicHex},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveAgentLPD(ctx, server, service) }()
	clientECDH, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	request := lpdRequest{Version: 1, AgentID: "agent-lpd", ClientID: "client-lpd", Timestamp: time.Now().Unix(), Nonce: nonce, E2EEPubKey: clientECDH.PublicKey().Bytes()}
	request.Signature = ed25519.Sign(clientKeys.private, lpdRequestPayload(&request))
	encoded, _ := json.Marshal(request)
	if _, err := client.WriteToUDP(encoded, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	count, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var offer lpdOffer
	if err := decodeStrict(buffer[:count], &offer); err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(agentKeys.public, lpdOfferPayload(&offer, request.E2EEPubKey), offer.Signature) {
		t.Fatal("valid local discovery offer signature failed")
	}
	if _, err := client.WriteToUDP(encoded, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, _, err := client.ReadFromUDP(buffer); err == nil {
		t.Fatal("replayed local discovery request received a second offer")
	}
	cancel()
	server.Close()
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("local discovery server did not stop")
	}
}

func TestLocalDiscoveryOverIPv6(t *testing.T) {
	agentKeys, clientKeys := generateTestKeys(t), generateTestKeys(t)
	service, err := newAgentService(&AgentConfig{
		ID: "agent-v6", PrivateKey: agentKeys.privateHex, TargetPort: 9, AutoCloseAfter: 1,
		ClientPubKeys: map[string]string{"client-v6": clientKeys.publicHex},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveAgentLPD(ctx, server, service) }()

	clientECDH, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := &ClientConfig{
		ID: "client-v6", TargetAgent: "agent-v6", AgentPubKey: agentKeys.publicHex,
	}
	access, remoteIP := performLocalDiscoveryTo(
		config,
		clientECDH.PublicKey().Bytes(),
		clientKeys.private,
		server.LocalAddr().(*net.UDPAddr),
	)
	if access == nil || !access.Success || access.Transport != "kcp" {
		t.Fatalf("IPv6 LPD returned an invalid offer: %#v", access)
	}
	if remoteIP != "::1" {
		t.Fatalf("IPv6 LPD returned the wrong peer: %q", remoteIP)
	}
	cancel()
	server.Close()
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("IPv6 LPD server did not stop")
	}
}

func TestWebhookMaskedAndCommandSafe(t *testing.T) {
	received := make(chan map[string]string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		var payload map[string]string
		_ = json.NewDecoder(request.Body).Decode(&payload)
		received <- payload
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	broker := &Broker{config: &BrokerConfig{WebhookURL: server.URL, StealthMode: true}}
	broker.sendWebhook("Access Granted", "client", "agent", "192.0.2.44")
	select {
	case payload := <-received:
		if payload["client_ip"] == "192.0.2.44" || !strings.HasPrefix(payload["client_ip"], "IP[MASKED:") {
			t.Fatalf("webhook leaked client IP: %v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not delivered")
	}
	arguments := splitCommand(`echo "a b" ; touch /tmp/never-created-by-shadow6`)
	if len(arguments) < 3 || arguments[1] != "a b" || arguments[2] != ";" {
		t.Fatalf("unexpected command split: %#v", arguments)
	}
	if splitCommand(`echo "unterminated`) != nil {
		t.Fatal("unterminated quote was accepted")
	}
}

func TestStrictSchemasAndWriteProgress(t *testing.T) {
	data := []byte(`{"version":1,"type":"request","id":1,"method":"x","params":{},"unknown":true}`)
	var message controlMessage
	if err := decodeStrict(data, &message); err == nil {
		t.Fatal("unknown control-message field was accepted")
	}
	if _, err := parsePeerIP("ff02::1"); err == nil {
		t.Fatal("multicast peer address was accepted")
	}
	if ip, err := parsePeerIP("fe80::1%eth0"); err != nil || ip.String() != "fe80::1" {
		t.Fatalf("scoped IPv6 peer address was rejected: %v, %v", ip, err)
	}
	if _, err := parsePeerIP("192.0.2.1%eth0"); err == nil {
		t.Fatal("IPv4 scope zone was accepted")
	}
	if err := writeFull(zeroWriter{}, []byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress writer returned %v", err)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write(_ []byte) (int, error) { return 0, nil }
