package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/ipv6"
)

const (
	kcpDataShards   = 10
	kcpParityShards = 3
)

var activeTunnelSlots = make(chan struct{}, maxActiveTunnels)
var proxyBufferPool = sync.Pool{New: func() any {
	buffer := make([]byte, proxyCopyBufferBytes)
	return &buffer
}}

type aeadConn struct {
	net.Conn
	aead        cipher.AEAD
	decoded     []byte
	readMutex   sync.Mutex
	writeMutex  sync.Mutex
	noncePrefix [4]byte
	sendCounter uint64
}

func newAEADConn(connection net.Conn, key []byte) (*aeadConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var prefix [4]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, err
	}
	return &aeadConn{Conn: connection, aead: aead, noncePrefix: prefix}, nil
}

func (connection *aeadConn) Write(plaintext []byte) (int, error) {
	connection.writeMutex.Lock()
	defer connection.writeMutex.Unlock()
	if len(plaintext) > maxAEADPlaintext {
		return 0, errors.New("AEAD plaintext frame is too large")
	}
	if connection.sendCounter == ^uint64(0) {
		return 0, errors.New("AEAD nonce counter exhausted")
	}
	nonce := make([]byte, connection.aead.NonceSize())
	copy(nonce, connection.noncePrefix[:])
	connection.sendCounter++
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], connection.sendCounter)
	ciphertext := connection.aead.Seal(nonce, nonce, plaintext, nil)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(ciphertext)))
	if err := writeFull(connection.Conn, length[:]); err != nil {
		return 0, err
	}
	if err := writeFull(connection.Conn, ciphertext); err != nil {
		return 0, err
	}
	return len(plaintext), nil
}

func (connection *aeadConn) Read(destination []byte) (int, error) {
	connection.readMutex.Lock()
	defer connection.readMutex.Unlock()
	if len(destination) == 0 {
		return 0, nil
	}
	if len(connection.decoded) != 0 {
		count := copy(destination, connection.decoded)
		connection.decoded = connection.decoded[count:]
		return count, nil
	}
	var lengthBytes [4]byte
	if _, err := io.ReadFull(connection.Conn, lengthBytes[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint32(lengthBytes[:]))
	minimum := connection.aead.NonceSize() + connection.aead.Overhead()
	maximum := maxAEADPlaintext + minimum
	if length < minimum || length > maximum {
		return 0, errors.New("invalid AEAD frame length")
	}
	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(connection.Conn, ciphertext); err != nil {
		return 0, err
	}
	nonceSize := connection.aead.NonceSize()
	plaintext, err := connection.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return 0, fmt.Errorf("AEAD authentication failed: %w", err)
	}
	count := copy(destination, plaintext)
	connection.decoded = plaintext[count:]
	return count, nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func deriveSymmetricKey(sharedSecret, clientPublic, agentPublic []byte) ([]byte, error) {
	saltInput := append(append([]byte(nil), clientPublic...), agentPublic...)
	salt := sha256.Sum256(saltInput)
	reader := hkdf.New(sha256.New, sharedSecret, salt[:], []byte("shadow6-kcp-aead-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func configureKCP(session *kcp.UDPSession) {
	session.SetStreamMode(true)
	session.SetWindowSize(kcpSendWindow, kcpReceiveWindow)
	session.SetNoDelay(1, 20, 2, 1)
	session.SetACKNoDelay(true)
	_ = session.SetMtu(kcpMTU)
	_ = session.SetReadBuffer(dataSocketBufferBytes)
	_ = session.SetWriteBuffer(dataSocketBufferBytes)
}

func copyWithPooledBuffer(destination io.Writer, source io.Reader) (int64, error) {
	buffer := proxyBufferPool.Get().(*[]byte)
	defer proxyBufferPool.Put(buffer)
	return io.CopyBuffer(destination, source, *buffer)
}

func proxyConnection(client net.Conn, targetPort int, key []byte) {
	defer client.Close()
	target, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(targetPort)), 5*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	secure, err := newAEADConn(client, key)
	if err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = copyWithPooledBuffer(target, secure); done <- struct{}{} }()
	go func() { _, _ = copyWithPooledBuffer(secure, target); done <- struct{}{} }()
	<-done
}

type AgentService struct {
	config     *AgentConfig
	privateKey ed25519.PrivateKey
}

func newAgentService(config *AgentConfig) (*AgentService, error) {
	privateKey, err := parsePrivateKey(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &AgentService{config: config, privateKey: privateKey}, nil
}

func (service *AgentService) handleGrant(_ context.Context, raw json.RawMessage) (any, error) {
	var request AccessReq
	if err := decodeStrict(raw, &request); err != nil {
		return nil, errors.New("invalid GrantAccess parameters")
	}
	return service.grantAccess(&request)
}

func (service *AgentService) grantAccess(request *AccessReq) (*AccessResp, error) {
	if request.TargetAgent != service.config.ID {
		return nil, errors.New("access request targets a different agent")
	}
	encodedClientKey, exists := service.config.ClientPubKeys[request.ClientID]
	if !exists {
		return nil, errors.New("client is not authorized by the agent")
	}
	clientKey, err := parsePublicKey(encodedClientKey)
	if err != nil || !ed25519.Verify(clientKey, clientSignaturePayload(request), request.ClientSig) {
		return nil, errors.New("invalid end-to-end client access signature")
	}
	return service.provisionAccess(request)
}

func (service *AgentService) provisionAccess(request *AccessReq) (*AccessResp, error) {
	authorizedIP, err := parsePeerIP(request.ClientIP)
	if err != nil {
		return nil, err
	}
	if len(request.E2EEPubKey) != 32 || !validIdentity(request.ClientID) || !validIdentity(request.TargetAgent) {
		return nil, errors.New("invalid access request identity or ephemeral key")
	}
	select {
	case activeTunnelSlots <- struct{}{}:
	default:
		return nil, errors.New("maximum active tunnel count reached")
	}
	releaseSlot := true
	defer func() {
		if releaseSlot {
			<-activeTunnelSlots
		}
	}()

	agentPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	clientPublic, err := ecdh.X25519().NewPublicKey(request.E2EEPubKey)
	if err != nil {
		return nil, errors.New("invalid client X25519 key")
	}
	sharedSecret, err := agentPrivate.ECDH(clientPublic)
	if err != nil {
		return nil, err
	}
	agentPublic := agentPrivate.PublicKey().Bytes()
	symmetricKey, err := deriveSymmetricKey(sharedSecret, request.E2EEPubKey, agentPublic)
	if err != nil {
		return nil, err
	}
	block, err := kcp.NewAESBlockCrypt(symmetricKey)
	if err != nil {
		return nil, err
	}
	listenAddress := "[::]:0"
	if authorizedIP.To4() != nil {
		listenAddress = "0.0.0.0:0"
	}
	listener, err := kcp.ListenWithOptions(listenAddress, block, kcpDataShards, kcpParityShards)
	if err != nil {
		return nil, err
	}
	_ = listener.SetReadBuffer(dataSocketBufferBytes)
	_ = listener.SetWriteBuffer(dataSocketBufferBytes)
	port := listener.Addr().(*net.UDPAddr).Port
	response := &AccessResp{
		Success: true, DynamicPort: 0, KCPPort: port, E2EEPubKey: agentPublic, Transport: "kcp",
	}
	response.AgentSig = ed25519.Sign(service.privateKey, agentSignaturePayload(request, response))

	releaseSlot = false
	go func() {
		defer func() { <-activeTunnelSlots }()
		defer listener.Close()
		sessions := make(chan struct{}, maxSessionsPerGrant)
		var active atomic.Int32
		var idleSince atomic.Int64
		idleSince.Store(time.Now().UnixNano())
		done := make(chan struct{})
		defer close(done)
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if active.Load() == 0 && time.Since(time.Unix(0, idleSince.Load())) >= time.Duration(service.config.AutoCloseAfter)*time.Second {
						_ = listener.Close()
						return
					}
				}
			}
		}()
		for {
			session, acceptErr := listener.AcceptKCP()
			if acceptErr != nil {
				return
			}
			remote := session.RemoteAddr().(*net.UDPAddr).IP
			if !remote.Equal(authorizedIP) {
				_ = session.Close()
				continue
			}
			select {
			case sessions <- struct{}{}:
				active.Add(1)
				idleSince.Store(time.Now().UnixNano())
				configureKCP(session)
				go func() {
					defer func() { <-sessions }()
					defer active.Add(-1)
					defer func() {
						if active.Load() == 0 {
							idleSince.Store(time.Now().UnixNano())
						}
					}()
					proxyConnection(session, service.config.TargetPort, symmetricKey)
				}()
			default:
				_ = session.Close()
			}
		}
	}()
	return response, nil
}

type lpdRequest struct {
	Version    int    `json:"version"`
	AgentID    string `json:"agent_id"`
	ClientID   string `json:"client_id"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      []byte `json:"nonce"`
	E2EEPubKey []byte `json:"e2ee_pubkey"`
	Signature  []byte `json:"signature"`
}

type lpdOffer struct {
	Version      int         `json:"version"`
	AgentID      string      `json:"agent_id"`
	RequestNonce []byte      `json:"request_nonce"`
	Access       *AccessResp `json:"access"`
	Signature    []byte      `json:"signature"`
}

func lpdRequestPayload(request *lpdRequest) []byte {
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(request.Timestamp))
	return signedFields("shadow6-lpd-request-v1", []byte(request.AgentID), []byte(request.ClientID), timestamp[:], request.Nonce, request.E2EEPubKey)
}

func lpdOfferPayload(offer *lpdOffer, clientPublic []byte) []byte {
	var port [4]byte
	binary.BigEndian.PutUint32(port[:], uint32(offer.Access.KCPPort))
	return signedFields("shadow6-lpd-offer-v1", []byte(offer.AgentID), offer.RequestNonce, clientPublic, offer.Access.E2EEPubKey, port[:])
}

type lpdReplayCache struct {
	mu   sync.Mutex
	seen map[string]int64
}

func newLPDReplayCache() *lpdReplayCache {
	return &lpdReplayCache{seen: make(map[string]int64)}
}

func (cache *lpdReplayCache) reserve(nonce []byte, now int64) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for key, timestamp := range cache.seen {
		if timestamp < now-60 {
			delete(cache.seen, key)
		}
	}
	key := string(nonce)
	if _, exists := cache.seen[key]; exists || len(cache.seen) >= 50_000 {
		return false
	}
	cache.seen[key] = now
	return true
}

func serveAgentLPDWithReplay(ctx context.Context, connection *net.UDPConn, service *AgentService, replay *lpdReplayCache) error {
	allowedClients := make(map[string]ed25519.PublicKey)
	for id, encoded := range service.config.ClientPubKeys {
		key, err := parsePublicKey(encoded)
		if err != nil {
			return err
		}
		allowedClients[id] = key
	}
	buffer := make([]byte, 4096)
	for {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		count, remote, err := connection.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			return err
		}
		var request lpdRequest
		if decodeStrict(buffer[:count], &request) != nil || request.Version != 1 ||
			request.AgentID != service.config.ID || len(request.Nonce) != 32 || len(request.E2EEPubKey) != 32 {
			continue
		}
		now := time.Now().Unix()
		if request.Timestamp < now-30 || request.Timestamp > now+30 {
			continue
		}
		clientKey := allowedClients[request.ClientID]
		if len(clientKey) == 0 || !ed25519.Verify(clientKey, lpdRequestPayload(&request), request.Signature) {
			continue
		}
		if !replay.reserve(request.Nonce, now) {
			continue
		}
		accessRequest := &AccessReq{
			ClientID: request.ClientID, TargetAgent: request.AgentID, ClientIP: remote.IP.String(), E2EEPubKey: request.E2EEPubKey,
		}
		access, err := service.provisionAccess(accessRequest)
		if err != nil {
			continue
		}
		offer := &lpdOffer{Version: 1, AgentID: service.config.ID, RequestNonce: request.Nonce, Access: access}
		offer.Signature = ed25519.Sign(service.privateKey, lpdOfferPayload(offer, request.E2EEPubKey))
		encoded, err := json.Marshal(offer)
		if err == nil && len(encoded) <= len(buffer) {
			_, _ = connection.WriteToUDP(encoded, remote)
		}
	}
}

func serveAgentLPD(ctx context.Context, connection *net.UDPConn, service *AgentService) error {
	return serveAgentLPDWithReplay(ctx, connection, service, newLPDReplayCache())
}

func startAgentLPD(ctx context.Context, service *AgentService) {
	listeners := make([]*net.UDPConn, 0, 2)
	if connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 44333}); err == nil {
		listeners = append(listeners, connection)
	} else {
		log.Printf("[Agent] IPv4 local discovery unavailable: %v", err)
	}
	if connection, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 44333}); err == nil {
		group := &net.UDPAddr{IP: net.ParseIP("ff02::1")}
		packetConnection := ipv6.NewPacketConn(connection)
		joined := 0
		if interfaces, listErr := net.Interfaces(); listErr == nil {
			for index := range interfaces {
				iface := &interfaces[index]
				if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
					continue
				}
				if packetConnection.JoinGroup(iface, group) == nil {
					joined++
				}
			}
		}
		log.Printf("[Agent] IPv6 LPD joined ff02::1 on %d interface(s)", joined)
		listeners = append(listeners, connection)
	} else {
		log.Printf("[Agent] IPv6 local discovery unavailable: %v", err)
	}
	if len(listeners) == 0 {
		log.Printf("[Agent] Local discovery disabled: no UDP listener could be created")
		return
	}
	replay := newLPDReplayCache()
	for _, connection := range listeners {
		connection := connection
		go func() {
			defer connection.Close()
			if err := serveAgentLPDWithReplay(ctx, connection, service, replay); err != nil {
				log.Printf("[Agent] Local discovery listener stopped: %v", err)
			}
		}()
	}
	log.Printf("[Agent] Authenticated IPv4/IPv6 local discovery listening on UDP 44333")
	<-ctx.Done()
}

func newLPDRequest(config *ClientConfig, clientPublic []byte, identityKey ed25519.PrivateKey) (*lpdRequest, ed25519.PublicKey, error) {
	agentKey, err := parsePublicKey(config.AgentPubKey)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	request := &lpdRequest{
		Version: 1, AgentID: config.TargetAgent, ClientID: config.ID,
		Timestamp: time.Now().Unix(), Nonce: nonce, E2EEPubKey: clientPublic,
	}
	request.Signature = ed25519.Sign(identityKey, lpdRequestPayload(request))
	return request, agentKey, nil
}

func performLocalDiscoveryRequestTo(config *ClientConfig, clientPublic []byte, request *lpdRequest, agentKey ed25519.PublicKey, destination *net.UDPAddr) (*AccessResp, string) {
	network := "udp4"
	localAddress := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if destination.IP.To4() == nil {
		network = "udp6"
		localAddress.IP = net.IPv6unspecified
	}
	connection, err := net.ListenUDP(network, localAddress)
	if err != nil {
		return nil, ""
	}
	defer connection.Close()
	_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, ""
	}
	if _, err := connection.WriteToUDP(encoded, destination); err != nil {
		return nil, ""
	}
	_ = connection.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buffer := make([]byte, 4096)
	for {
		count, remote, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return nil, ""
		}
		var offer lpdOffer
		if decodeStrict(buffer[:count], &offer) != nil || offer.Version != 1 || offer.AgentID != config.TargetAgent ||
			offer.Access == nil || !offer.Access.Success || offer.Access.KCPPort == 0 ||
			!bytesEqual(offer.RequestNonce, request.Nonce) || !ed25519.Verify(agentKey, lpdOfferPayload(&offer, clientPublic), offer.Signature) {
			continue
		}
		remoteIP := remote.IP.String()
		if remote.Zone != "" {
			remoteIP += "%" + remote.Zone
		}
		return offer.Access, remoteIP
	}
}

func performLocalDiscoveryTo(config *ClientConfig, clientPublic []byte, identityKey ed25519.PrivateKey, destination *net.UDPAddr) (*AccessResp, string) {
	request, agentKey, err := newLPDRequest(config, clientPublic, identityKey)
	if err != nil {
		return nil, ""
	}
	return performLocalDiscoveryRequestTo(config, clientPublic, request, agentKey, destination)
}

func bytesEqual(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	var difference byte
	for index := range first {
		difference |= first[index] ^ second[index]
	}
	return difference == 0
}

func performLocalDiscovery(config *ClientConfig, clientPublic []byte, identityKey ed25519.PrivateKey) (*AccessResp, string) {
	request, agentKey, err := newLPDRequest(config, clientPublic, identityKey)
	if err != nil {
		return nil, ""
	}
	destinations := []*net.UDPAddr{{IP: net.IPv4bcast, Port: 44333}}
	if interfaces, listErr := net.Interfaces(); listErr == nil {
		for index := range interfaces {
			iface := &interfaces[index]
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagMulticast != 0 {
				destinations = append(destinations, &net.UDPAddr{IP: net.ParseIP("ff02::1"), Port: 44333, Zone: iface.Name})
			}
		}
	}
	type discoveryResult struct {
		access *AccessResp
		ip     string
	}
	results := make(chan discoveryResult, len(destinations))
	for _, destination := range destinations {
		destination := destination
		go func() {
			access, ip := performLocalDiscoveryRequestTo(config, clientPublic, request, agentKey, destination)
			results <- discoveryResult{access: access, ip: ip}
		}()
	}
	timer := time.NewTimer(1700 * time.Millisecond)
	defer timer.Stop()
	for range destinations {
		select {
		case result := <-results:
			if result.access != nil {
				return result.access, result.ip
			}
		case <-timer.C:
			return nil, ""
		}
	}
	return nil, ""
}

func startAgent(config *Config) error {
	service, err := newAgentService(config.Agent)
	if err != nil {
		return err
	}
	brokerKey, _ := parsePublicKey(config.Agent.BrokerPubKey)
	rootContext, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	if config.Agent.AllowLocalDisc {
		go startAgentLPD(rootContext, service)
	}
	for {
		connection, writeMutex, err := dialBroker(config.Agent.BrokerAddrs, config.Agent.ID, service.privateKey, brokerKey)
		if err != nil {
			log.Printf("[Agent] Broker connection failed: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		peer := newRPCPeer(connection, writeMutex, map[string]rpcHandler{"Agent.GrantAccess": service.handleGrant})
		serveDone := make(chan error, 1)
		go func() { serveDone <- peer.serve() }()
		ticker := time.NewTicker(10 * time.Second)
		lastIP := ""
		update := func() {
			currentIP := routeIP()
			if currentIP == "" || currentIP == lastIP {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var response map[string]bool
			if peer.call(ctx, "Broker.UpdateIP", UpdateIPReq{AgentID: config.Agent.ID, IP: currentIP}, &response) == nil && response["success"] {
				lastIP = currentIP
			}
		}
		update()
		connected := true
		for connected {
			select {
			case <-ticker.C:
				update()
			case err := <-serveDone:
				log.Printf("[Agent] Broker connection closed: %v", err)
				connected = false
			}
		}
		ticker.Stop()
		peer.close()
		time.Sleep(time.Second)
	}
}

func verifyAgentAccess(config *ClientConfig, request *AccessReq, response *AccessResp) error {
	agentKey, err := parsePublicKey(config.AgentPubKey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(agentKey, agentSignaturePayload(request, response), response.AgentSig) {
		return errors.New("invalid agent access signature")
	}
	return nil
}

func dialSecureKCP(target string, key []byte) (*aeadConn, error) {
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, err
	}
	session, err := kcp.DialWithOptions(target, block, kcpDataShards, kcpParityShards)
	if err != nil {
		return nil, err
	}
	configureKCP(session)
	secure, err := newAEADConn(session, key)
	if err != nil {
		session.Close()
		return nil, err
	}
	return secure, nil
}

func startClient(config *Config) error {
	client := config.Client
	identityKey, err := parsePrivateKey(client.PrivateKey)
	if err != nil {
		return err
	}
	clientECDH, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	clientPublic := clientECDH.PublicKey().Bytes()
	var access *AccessResp
	var targetIP string
	var brokerRequest *AccessReq

	if client.AllowLocalDisc {
		access, targetIP = performLocalDiscovery(client, clientPublic, identityKey)
	}
	if access == nil {
		brokerKey, _ := parsePublicKey(client.BrokerPubKey)
		connection, writeMutex, dialErr := dialBroker(client.BrokerAddrs, client.ID, identityKey, brokerKey)
		if dialErr != nil {
			return dialErr
		}
		peer := newRPCPeer(connection, writeMutex, nil)
		serveDone := make(chan error, 1)
		go func() { serveDone <- peer.serve() }()
		clientIP := routeIP()
		if clientIP == "" {
			peer.close()
			return errors.New("cannot determine a routable client address")
		}
		request := &AccessReq{ClientID: client.ID, TargetAgent: client.TargetAgent, ClientIP: clientIP, E2EEPubKey: clientPublic}
		request.ClientSig = ed25519.Sign(identityKey, clientSignaturePayload(request))
		var response AccessResp
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = peer.call(ctx, "Broker.RequestAccess", request, &response)
		cancel()
		peer.close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
		}
		if err != nil {
			return err
		}
		if err := verifyAgentAccess(client, request, &response); err != nil {
			return err
		}
		access, targetIP, brokerRequest = &response, response.TargetIP, request
	}
	if access == nil || !access.Success || access.KCPPort < 1 || len(access.E2EEPubKey) != 32 {
		return errors.New("invalid access response")
	}
	if _, err := parsePeerIP(targetIP); err != nil {
		return err
	}
	agentPublic, err := ecdh.X25519().NewPublicKey(access.E2EEPubKey)
	if err != nil {
		return err
	}
	sharedSecret, err := clientECDH.ECDH(agentPublic)
	if err != nil {
		return err
	}
	key, err := deriveSymmetricKey(sharedSecret, clientPublic, access.E2EEPubKey)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	localPort := listener.Addr().(*net.TCPAddr).Port
	log.Printf("[Client] Secure local proxy listening on 127.0.0.1:%d", localPort)
	if client.OnSuccess != "" {
		if len(client.OnSuccess) > 4096 {
			return errors.New("on_success command is too long")
		}
		commandText := replaceHookVariables(client.OnSuccess, localPort, targetIP)
		arguments := splitCommand(commandText)
		if len(arguments) == 0 {
			return errors.New("on_success command is empty")
		}
		command := exec.Command(arguments[0], arguments[1:]...)
		command.Stdout, command.Stderr, command.Stdin = os.Stdout, os.Stderr, os.Stdin
		if err := command.Start(); err != nil {
			return fmt.Errorf("on_success failed: %w", err)
		}
		go func() { _ = command.Wait() }()
	}
	_ = brokerRequest
	target := net.JoinHostPort(targetIP, fmt.Sprint(access.KCPPort))
	localSlots := make(chan struct{}, 64)
	for {
		localConnection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return acceptErr
		}
		select {
		case localSlots <- struct{}{}:
			go func() {
				defer func() { <-localSlots }()
				defer localConnection.Close()
				secure, dialErr := dialSecureKCP(target, key)
				if dialErr != nil {
					return
				}
				defer secure.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(secure, localConnection); done <- struct{}{} }()
				go func() { _, _ = io.Copy(localConnection, secure); done <- struct{}{} }()
				<-done
			}()
		default:
			localConnection.Close()
		}
	}
}

func replaceHookVariables(command string, localPort int, targetIP string) string {
	result := command
	result = stringReplaceAll(result, "$LOCAL_TCP_PORT", fmt.Sprint(localPort))
	result = stringReplaceAll(result, "$TARGET_IP", targetIP)
	return result
}

func stringReplaceAll(value, old, replacement string) string {
	for {
		index := indexString(value, old)
		if index < 0 {
			return value
		}
		value = value[:index] + replacement + value[index+len(old):]
	}
}

func indexString(value, search string) int {
	if search == "" {
		return 0
	}
	for index := 0; index+len(search) <= len(value); index++ {
		if value[index:index+len(search)] == search {
			return index
		}
	}
	return -1
}

func splitCommand(value string) []string {
	var result []string
	var current []rune
	var quote rune
	escaped := false
	for _, character := range value {
		if escaped {
			current = append(current, character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current = append(current, character)
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character == ' ' || character == '\t' || character == '\n' {
			if len(current) != 0 {
				result = append(result, string(current))
				current = nil
			}
			continue
		}
		current = append(current, character)
	}
	if escaped || quote != 0 {
		return nil
	}
	if len(current) != 0 {
		result = append(result, string(current))
	}
	return result
}
