package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	controlVersion    = 1
	maxControlMessage = 64 * 1024
	maxRPCInFlight    = 32
)

type controlMessage struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	ID        uint64          `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	PeerID    string          `json:"peer_id,omitempty"`
	Nonce     []byte          `json:"nonce,omitempty"`
	Signature []byte          `json:"signature,omitempty"`
}

func signedFields(domain string, fields ...[]byte) []byte {
	result := make([]byte, 0, 128)
	result = append(result, domain...)
	var size [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		result = append(result, size[:]...)
		result = append(result, field...)
	}
	return result
}

func authPayload(peerID string, nonce []byte) []byte {
	return signedFields("shadow6-control-auth-v1", []byte(peerID), nonce)
}

func readControl(conn *websocket.Conn) (controlMessage, error) {
	messageType, data, err := conn.ReadMessage()
	if err != nil {
		return controlMessage{}, err
	}
	if messageType != websocket.TextMessage || len(data) > maxControlMessage {
		return controlMessage{}, errors.New("invalid control frame type or size")
	}
	var message controlMessage
	if err := decodeStrict(data, &message); err != nil {
		return controlMessage{}, err
	}
	if message.Version != controlVersion {
		return controlMessage{}, errors.New("unsupported control protocol version")
	}
	return message, nil
}

func writeControl(conn *websocket.Conn, mutex *sync.Mutex, message controlMessage) error {
	message.Version = controlVersion
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) > maxControlMessage {
		return errors.New("outgoing control message is too large")
	}
	mutex.Lock()
	defer mutex.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

func authenticatePeer(conn *websocket.Conn, writeMutex *sync.Mutex, expected map[string]ed25519.PublicKey, brokerKey ed25519.PrivateKey) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	if err := writeControl(conn, writeMutex, controlMessage{Type: "challenge", Nonce: nonce}); err != nil {
		return "", err
	}
	response, err := readControl(conn)
	if err != nil || response.Type != "auth" {
		return "", errors.New("invalid peer authentication response")
	}
	publicKey, exists := expected[response.PeerID]
	if !exists || !ed25519.Verify(publicKey, authPayload(response.PeerID, nonce), response.Signature) {
		return "", errors.New("peer signature verification failed")
	}
	challenge, err := readControl(conn)
	if err != nil || challenge.Type != "challenge" || len(challenge.Nonce) != 32 {
		return "", errors.New("invalid peer challenge")
	}
	brokerID := "broker"
	if err := writeControl(conn, writeMutex, controlMessage{
		Type:      "auth",
		PeerID:    brokerID,
		Signature: ed25519.Sign(brokerKey, authPayload(brokerID, challenge.Nonce)),
	}); err != nil {
		return "", err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return "", err
	}
	return response.PeerID, nil
}

func authenticateBroker(conn *websocket.Conn, writeMutex *sync.Mutex, peerID string, peerKey ed25519.PrivateKey, brokerKey ed25519.PublicKey) error {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	challenge, err := readControl(conn)
	if err != nil || challenge.Type != "challenge" || len(challenge.Nonce) != 32 {
		return errors.New("invalid broker challenge")
	}
	if err := writeControl(conn, writeMutex, controlMessage{
		Type:      "auth",
		PeerID:    peerID,
		Signature: ed25519.Sign(peerKey, authPayload(peerID, challenge.Nonce)),
	}); err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if err := writeControl(conn, writeMutex, controlMessage{Type: "challenge", Nonce: nonce}); err != nil {
		return err
	}
	response, err := readControl(conn)
	if err != nil || response.Type != "auth" || response.PeerID != "broker" ||
		!ed25519.Verify(brokerKey, authPayload("broker", nonce), response.Signature) {
		return errors.New("broker signature verification failed")
	}
	return conn.SetReadDeadline(time.Time{})
}

type rpcResult struct {
	data  json.RawMessage
	error string
}

type rpcHandler func(context.Context, json.RawMessage) (any, error)

type rpcPeer struct {
	conn       *websocket.Conn
	writeMutex *sync.Mutex
	handlers   map[string]rpcHandler
	nextID     atomic.Uint64
	pendingMu  sync.Mutex
	pending    map[uint64]chan rpcResult
	inFlight   chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
}

func newRPCPeer(conn *websocket.Conn, writeMutex *sync.Mutex, handlers map[string]rpcHandler) *rpcPeer {
	return &rpcPeer{
		conn: conn, writeMutex: writeMutex, handlers: handlers,
		pending: make(map[uint64]chan rpcResult), inFlight: make(chan struct{}, maxRPCInFlight), done: make(chan struct{}),
	}
}

func (peer *rpcPeer) close() {
	peer.closeOnce.Do(func() {
		close(peer.done)
		_ = peer.conn.Close()
		peer.pendingMu.Lock()
		for id, result := range peer.pending {
			delete(peer.pending, id)
			result <- rpcResult{error: "control connection closed"}
		}
		peer.pendingMu.Unlock()
	})
}

func (peer *rpcPeer) call(ctx context.Context, method string, params any, response any) error {
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return err
	}
	id := peer.nextID.Add(1)
	resultChannel := make(chan rpcResult, 1)
	peer.pendingMu.Lock()
	peer.pending[id] = resultChannel
	peer.pendingMu.Unlock()
	if err := writeControl(peer.conn, peer.writeMutex, controlMessage{Type: "request", ID: id, Method: method, Params: paramsJSON}); err != nil {
		peer.pendingMu.Lock()
		delete(peer.pending, id)
		peer.pendingMu.Unlock()
		return err
	}
	select {
	case result := <-resultChannel:
		if result.error != "" {
			return errors.New(result.error)
		}
		if response == nil {
			return nil
		}
		return decodeStrict(result.data, response)
	case <-ctx.Done():
		peer.pendingMu.Lock()
		delete(peer.pending, id)
		peer.pendingMu.Unlock()
		return ctx.Err()
	case <-peer.done:
		return errors.New("control connection closed")
	}
}

func (peer *rpcPeer) serve() error {
	defer peer.close()
	peer.conn.SetReadLimit(maxControlMessage)
	for {
		message, err := readControl(peer.conn)
		if err != nil {
			return err
		}
		switch message.Type {
		case "response":
			peer.pendingMu.Lock()
			resultChannel := peer.pending[message.ID]
			delete(peer.pending, message.ID)
			peer.pendingMu.Unlock()
			if resultChannel != nil {
				resultChannel <- rpcResult{data: message.Result, error: message.Error}
			}
		case "request":
			handler := peer.handlers[message.Method]
			if handler == nil || message.ID == 0 {
				_ = writeControl(peer.conn, peer.writeMutex, controlMessage{Type: "response", ID: message.ID, Error: "method not found"})
				continue
			}
			select {
			case peer.inFlight <- struct{}{}:
				go func(request controlMessage) {
					defer func() { <-peer.inFlight }()
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					result, callErr := handler(ctx, request.Params)
					reply := controlMessage{Type: "response", ID: request.ID}
					if callErr != nil {
						reply.Error = callErr.Error()
					} else {
						reply.Result, callErr = json.Marshal(result)
						if callErr != nil {
							reply.Error = "failed to serialize RPC response"
						}
					}
					_ = writeControl(peer.conn, peer.writeMutex, reply)
				}(message)
			default:
				_ = writeControl(peer.conn, peer.writeMutex, controlMessage{Type: "response", ID: message.ID, Error: "too many concurrent requests"})
			}
		default:
			return errors.New("unexpected post-authentication control message")
		}
	}
}

type Broker struct {
	config       *BrokerConfig
	agentIPs     map[string]string
	agentClients map[string]*rpcPeer
	mutex        sync.RWMutex
	connections  chan struct{}
	privateKey   ed25519.PrivateKey
	publicKeys   map[string]ed25519.PublicKey
}

func newBroker(config *BrokerConfig) (*Broker, error) {
	privateKey, err := parsePrivateKey(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	publicKeys := make(map[string]ed25519.PublicKey)
	for _, agent := range config.Agents {
		key, err := parsePublicKey(agent.PubKey)
		if err != nil {
			return nil, err
		}
		publicKeys[agent.ID] = key
	}
	for _, client := range config.Clients {
		key, err := parsePublicKey(client.PubKey)
		if err != nil {
			return nil, err
		}
		publicKeys[client.ID] = key
	}
	return &Broker{
		config: config, agentIPs: make(map[string]string), agentClients: make(map[string]*rpcPeer),
		connections: make(chan struct{}, maxControlConnections), privateKey: privateKey, publicKeys: publicKeys,
	}, nil
}

func (broker *Broker) isAgent(id string) bool {
	for _, agent := range broker.config.Agents {
		if agent.ID == id {
			return true
		}
	}
	return false
}

func (broker *Broker) handleUpdateIP(peerID string, isAgent bool, raw json.RawMessage) (any, error) {
	if !isAgent {
		return nil, errors.New("only authenticated agents may update an address")
	}
	var request UpdateIPReq
	if err := decodeStrict(raw, &request); err != nil {
		return nil, errors.New("invalid UpdateIP parameters")
	}
	ip, err := parsePeerIP(request.IP)
	if err != nil {
		return nil, err
	}
	broker.mutex.Lock()
	broker.agentIPs[peerID] = ip.String()
	broker.mutex.Unlock()
	log.Printf("[Broker] Agent %s updated IP: %s", peerID, maskIP(ip.String(), broker.config.StealthMode))
	return map[string]bool{"success": true}, nil
}

func clientSignaturePayload(request *AccessReq) []byte {
	return signedFields("shadow6-client-access-v1", []byte(request.ClientID), []byte(request.TargetAgent), []byte(request.ClientIP), request.E2EEPubKey)
}

func agentSignaturePayload(request *AccessReq, response *AccessResp) []byte {
	var port [4]byte
	binary.BigEndian.PutUint32(port[:], uint32(response.KCPPort))
	return signedFields("shadow6-agent-access-v1", []byte(request.ClientID), []byte(request.TargetAgent), request.E2EEPubKey, response.E2EEPubKey, port[:])
}

func (broker *Broker) handleRequestAccess(ctx context.Context, peerID string, isAgent bool, raw json.RawMessage) (any, error) {
	if isAgent {
		return nil, errors.New("only authenticated clients may request access")
	}
	var request AccessReq
	if err := decodeStrict(raw, &request); err != nil {
		return nil, errors.New("invalid RequestAccess parameters")
	}
	request.ClientID = peerID
	if _, err := parsePeerIP(request.ClientIP); err != nil {
		return nil, err
	}
	if len(request.E2EEPubKey) != 32 {
		return nil, errors.New("invalid client ephemeral key")
	}
	var clientConfig *ClientRBAC
	for index := range broker.config.Clients {
		if broker.config.Clients[index].ID == peerID {
			clientConfig = &broker.config.Clients[index]
			break
		}
	}
	if clientConfig == nil {
		return nil, errors.New("client is not registered")
	}
	clientKey, _ := parsePublicKey(clientConfig.PubKey)
	if !ed25519.Verify(clientKey, clientSignaturePayload(&request), request.ClientSig) {
		broker.sendWebhook("Invalid client access signature", peerID, request.TargetAgent, request.ClientIP)
		return nil, errors.New("invalid client access signature")
	}
	allowed := false
	for _, agentID := range clientConfig.AllowedAgents {
		if agentID == request.TargetAgent {
			allowed = true
			break
		}
	}
	if !allowed {
		broker.sendWebhook("Unauthorized access attempt", peerID, request.TargetAgent, request.ClientIP)
		return nil, errors.New("RBAC: access denied")
	}
	broker.mutex.RLock()
	targetIP := broker.agentIPs[request.TargetAgent]
	agentClient := broker.agentClients[request.TargetAgent]
	broker.mutex.RUnlock()
	if targetIP == "" || agentClient == nil {
		return nil, errors.New("agent is offline")
	}
	var response AccessResp
	if err := agentClient.call(ctx, "Agent.GrantAccess", request, &response); err != nil {
		return nil, fmt.Errorf("agent provisioning failed: %w", err)
	}
	if !response.Success || response.KCPPort < 1 || response.KCPPort > 65535 || len(response.E2EEPubKey) != 32 {
		return nil, errors.New("agent returned an invalid access response")
	}
	var agentKey ed25519.PublicKey
	for _, agent := range broker.config.Agents {
		if agent.ID == request.TargetAgent {
			agentKey, _ = parsePublicKey(agent.PubKey)
			break
		}
	}
	if !ed25519.Verify(agentKey, agentSignaturePayload(&request, &response), response.AgentSig) {
		return nil, errors.New("invalid agent access signature")
	}
	response.TargetIP = targetIP
	response.DynamicPort = 0
	response.Transport = "kcp"
	broker.sendWebhook("Access Granted", peerID, request.TargetAgent, request.ClientIP)
	return response, nil
}

func (broker *Broker) websocketHandler() http.Handler {
	upgrader := websocket.Upgrader{
		ReadBufferSize: 16 * 1024, WriteBufferSize: 16 * 1024, EnableCompression: false,
		CheckOrigin: func(request *http.Request) bool { return request.Header.Get("Origin") == "" },
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/ws" {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		select {
		case broker.connections <- struct{}{}:
			defer func() { <-broker.connections }()
		default:
			http.Error(writer, "connection limit reached", http.StatusServiceUnavailable)
			return
		}
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		writeMutex := &sync.Mutex{}
		peerID, err := authenticatePeer(connection, writeMutex, broker.publicKeys, broker.privateKey)
		if err != nil {
			log.Printf("[Broker] Authentication failed: %v", err)
			connection.Close()
			return
		}
		isAgent := broker.isAgent(peerID)
		handlers := map[string]rpcHandler{
			"Broker.UpdateIP": func(_ context.Context, raw json.RawMessage) (any, error) {
				return broker.handleUpdateIP(peerID, isAgent, raw)
			},
			"Broker.RequestAccess": func(ctx context.Context, raw json.RawMessage) (any, error) {
				return broker.handleRequestAccess(ctx, peerID, isAgent, raw)
			},
		}
		peer := newRPCPeer(connection, writeMutex, handlers)
		if isAgent {
			broker.mutex.Lock()
			if previous := broker.agentClients[peerID]; previous != nil {
				previous.close()
			}
			broker.agentClients[peerID] = peer
			broker.mutex.Unlock()
			defer func() {
				broker.mutex.Lock()
				if broker.agentClients[peerID] == peer {
					delete(broker.agentClients, peerID)
				}
				broker.mutex.Unlock()
			}()
		}
		log.Printf("[Broker] Authenticated %s connected", peerID)
		_ = peer.serve()
	})
}

var webhookSlots = make(chan struct{}, 50)
var webhookClient = &http.Client{Timeout: 5 * time.Second}

func (broker *Broker) sendWebhook(status, clientID, targetAgent, clientIP string) {
	if broker.config.WebhookURL == "" {
		return
	}
	select {
	case webhookSlots <- struct{}{}:
	default:
		log.Printf("[Broker] Webhook queue full; dropping alert")
		return
	}
	payload, err := json.Marshal(map[string]string{
		"event": "AccessRequest", "status": status, "client_id": clientID,
		"target_agent": targetAgent, "client_ip": maskIP(clientIP, broker.config.StealthMode),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		<-webhookSlots
		return
	}
	go func() {
		defer func() { <-webhookSlots }()
		request, err := http.NewRequest(http.MethodPost, broker.config.WebhookURL, bytes.NewReader(payload))
		if err != nil {
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := webhookClient.Do(request)
		if err == nil {
			response.Body.Close()
		}
	}()
}

func dialBroker(addresses []string, peerID string, peerKey ed25519.PrivateKey, brokerKey ed25519.PublicKey) (*websocket.Conn, *sync.Mutex, error) {
	dialer := websocket.Dialer{
		Proxy: http.ProxyFromEnvironment, HandshakeTimeout: 10 * time.Second,
		ReadBufferSize: 16 * 1024, WriteBufferSize: 16 * 1024,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	var lastError error
	for _, address := range addresses {
		normalized, err := normalizeBrokerURL(address)
		if err != nil {
			lastError = err
			continue
		}
		connection, response, err := dialer.Dial(normalized, nil)
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if err != nil {
			lastError = err
			continue
		}
		connection.SetReadLimit(maxControlMessage)
		writeMutex := &sync.Mutex{}
		if err := authenticateBroker(connection, writeMutex, peerID, peerKey, brokerKey); err != nil {
			connection.Close()
			lastError = err
			continue
		}
		return connection, writeMutex, nil
	}
	if lastError == nil {
		lastError = errors.New("no broker addresses configured")
	}
	return nil, nil, fmt.Errorf("all broker connections failed: %w", lastError)
}

var maskingSalt = func() []byte {
	result := make([]byte, 16)
	if _, err := rand.Read(result); err != nil {
		panic(err)
	}
	return result
}()

func maskIP(ip string, stealth bool) string {
	if !stealth || ip == "" {
		return ip
	}
	hash := sha256.Sum256(append(append([]byte(nil), maskingSalt...), []byte(ip)...))
	return fmt.Sprintf("IP[MASKED:%s]", hex.EncodeToString(hash[:4]))
}

func startBroker(config *Config) error {
	broker, err := newBroker(config.Broker)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/ws", broker.websocketHandler())
	server := &http.Server{
		Addr: config.Broker.ListenAddr, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	log.Printf("[Broker] Listening on %s; terminate TLS at a trusted reverse proxy", config.Broker.ListenAddr)
	return server.ListenAndServe()
}

func routeIP() string {
	for _, destination := range []string{"[2606:4700:4700::1111]:53", "1.1.1.1:53"} {
		connection, err := net.DialTimeout("udp", destination, time.Second)
		if err == nil {
			address := connection.LocalAddr().(*net.UDPAddr).IP
			connection.Close()
			if !address.IsUnspecified() {
				return address.String()
			}
		}
	}
	return ""
}
