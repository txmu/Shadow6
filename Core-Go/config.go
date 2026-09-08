package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type Config struct {
	Role   string        `json:"role"`
	Broker *BrokerConfig `json:"broker,omitempty"`
	Agent  *AgentConfig  `json:"agent,omitempty"`
	Client *ClientConfig `json:"client,omitempty"`
}

type BrokerConfig struct {
	ListenAddr  string       `json:"listen_addr"`
	PrivateKey  string       `json:"private_key"`
	Agents      []AgentRBAC  `json:"agents"`
	Clients     []ClientRBAC `json:"clients"`
	WebhookURL  string       `json:"webhook_url"`
	StealthMode bool         `json:"stealth_mode"`
}

type AgentRBAC struct {
	ID     string `json:"id"`
	PubKey string `json:"pubkey"`
}

type ClientRBAC struct {
	ID            string   `json:"id"`
	PubKey        string   `json:"pubkey"`
	AllowedAgents []string `json:"allowed_agents"`
}

type AgentConfig struct {
	ID             string            `json:"id"`
	BrokerAddrs    []string          `json:"broker_addrs"`
	BrokerPubKey   string            `json:"broker_pubkey"`
	PrivateKey     string            `json:"private_key"`
	TargetPort     int               `json:"target_port"`
	AutoCloseAfter int               `json:"auto_close_after"`
	AllowLocalDisc bool              `json:"allow_local_discovery"`
	ClientPubKeys  map[string]string `json:"client_pubkeys,omitempty"`
	Transport      string            `json:"transport,omitempty"`
}

type ClientConfig struct {
	ID             string   `json:"id"`
	BrokerAddrs    []string `json:"broker_addrs"`
	BrokerPubKey   string   `json:"broker_pubkey"`
	PrivateKey     string   `json:"private_key"`
	TargetAgent    string   `json:"target_agent"`
	AgentPubKey    string   `json:"agent_pubkey,omitempty"`
	OnSuccess      string   `json:"on_success"`
	AllowLocalDisc bool     `json:"allow_local_discovery"`
	Transport      string   `json:"transport,omitempty"`
}

type AccessReq struct {
	ClientID    string `json:"client_id"`
	TargetAgent string `json:"target_agent"`
	ClientIP    string `json:"client_ip"`
	E2EEPubKey  []byte `json:"e2ee_pubkey"`
	ClientSig   []byte `json:"client_sig"`
}

type AccessResp struct {
	Success     bool   `json:"success"`
	TargetIP    string `json:"target_ip"`
	DynamicPort int    `json:"dynamic_port"`
	KCPPort     int    `json:"kcp_port"`
	E2EEPubKey  []byte `json:"e2ee_pubkey"`
	ErrorMsg    string `json:"error_msg"`
	AgentSig    []byte `json:"agent_sig"`
	Transport   string `json:"transport"`
}

type UpdateIPReq struct {
	AgentID string `json:"agent_id"`
	IP      string `json:"ip"`
}

func decodeStrict(data []byte, destination any) error {
	if err := validateStrictJSON(data, reflect.TypeOf(destination)); err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func parsePrivateKey(value string) (ed25519.PrivateKey, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid private-key hex: %w", err)
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		key := ed25519.PrivateKey(append([]byte(nil), decoded...))
		if !key.Public().(ed25519.PublicKey).Equal(ed25519.NewKeyFromSeed(decoded[:32]).Public()) {
			return nil, errors.New("expanded private key has an inconsistent public half")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("private key must be 32 or 64 bytes, got %d", len(decoded))
	}
}

func parsePublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid public-key hex: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
}

func validIdentity(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-_.", character) {
			continue
		}
		return false
	}
	return true
}

func parsePeerIP(value string) (net.IP, error) {
	address := value
	if separator := strings.LastIndexByte(address, '%'); separator >= 0 {
		zone := address[separator+1:]
		address = address[:separator]
		if zone == "" || len(zone) > 64 {
			return nil, errors.New("invalid IPv6 scope zone")
		}
		for _, character := range zone {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || strings.ContainsRune("-_.", character) {
				continue
			}
			return nil, errors.New("invalid IPv6 scope zone")
		}
	}
	ip := net.ParseIP(address)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, errors.New("invalid, unspecified, or multicast peer IP")
	}
	if strings.Contains(value, "%") && ip.To4() != nil {
		return nil, errors.New("scope zones are valid only for IPv6 addresses")
	}
	return ip, nil
}

func normalizeBrokerURL(value string) (string, error) {
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid broker URL")
	}
	candidate := value
	if !strings.HasPrefix(candidate, "ws://") && !strings.HasPrefix(candidate, "wss://") {
		candidate = "wss://" + candidate + "/ws"
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("invalid broker URL")
	}
	hostIP := net.ParseIP(parsed.Hostname())
	loopback := parsed.Hostname() == "localhost" || (hostIP != nil && hostIP.IsLoopback())
	if parsed.Scheme != "wss" && !(parsed.Scheme == "ws" && loopback) {
		return "", errors.New("broker URLs must use wss://; ws:// is loopback-only")
	}
	return candidate, nil
}

func validateHTTPSURL(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("webhook_url is invalid")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("webhook_url must be an absolute HTTPS URL without credentials or a fragment")
	}
	return nil
}

func validateConfig(config *Config) error {
	switch config.Role {
	case "broker":
		if config.Broker == nil || config.Agent != nil || config.Client != nil {
			return errors.New("broker role requires only the broker section")
		}
		broker := config.Broker
		if _, err := net.ResolveTCPAddr("tcp", broker.ListenAddr); err != nil {
			return fmt.Errorf("invalid broker listen_addr: %w", err)
		}
		if _, err := parsePrivateKey(broker.PrivateKey); err != nil {
			return err
		}
		if err := validateHTTPSURL(broker.WebhookURL); err != nil {
			return err
		}
		identities := make(map[string]struct{})
		agentIDs := make(map[string]struct{})
		for _, agent := range broker.Agents {
			if !validIdentity(agent.ID) {
				return fmt.Errorf("invalid agent identity %q", agent.ID)
			}
			if _, exists := identities[agent.ID]; exists {
				return fmt.Errorf("duplicate identity %q", agent.ID)
			}
			identities[agent.ID] = struct{}{}
			agentIDs[agent.ID] = struct{}{}
			if _, err := parsePublicKey(agent.PubKey); err != nil {
				return fmt.Errorf("agent %s: %w", agent.ID, err)
			}
		}
		for _, client := range broker.Clients {
			if !validIdentity(client.ID) {
				return fmt.Errorf("invalid client identity %q", client.ID)
			}
			if _, exists := identities[client.ID]; exists {
				return fmt.Errorf("duplicate identity %q", client.ID)
			}
			identities[client.ID] = struct{}{}
			if _, err := parsePublicKey(client.PubKey); err != nil {
				return fmt.Errorf("client %s: %w", client.ID, err)
			}
			for _, allowed := range client.AllowedAgents {
				if _, exists := agentIDs[allowed]; !exists {
					return fmt.Errorf("client %s references unknown agent %s", client.ID, allowed)
				}
			}
		}
	case "agent":
		if config.Agent == nil || config.Broker != nil || config.Client != nil {
			return errors.New("agent role requires only the agent section")
		}
		agent := config.Agent
		if !validIdentity(agent.ID) || agent.TargetPort < 1 || agent.TargetPort > 65535 {
			return errors.New("invalid agent identity or target_port")
		}
		if agent.AutoCloseAfter < 1 || agent.AutoCloseAfter > 86400 {
			return errors.New("auto_close_after must be between 1 and 86400 seconds")
		}
		if len(agent.BrokerAddrs) == 0 {
			return errors.New("at least one broker address is required")
		}
		for _, address := range agent.BrokerAddrs {
			if _, err := normalizeBrokerURL(address); err != nil {
				return err
			}
		}
		if _, err := parsePrivateKey(agent.PrivateKey); err != nil {
			return err
		}
		if _, err := parsePublicKey(agent.BrokerPubKey); err != nil {
			return err
		}
		if agent.Transport != "" && agent.Transport != "kcp" {
			return errors.New("Go data plane requires transport=kcp")
		}
		if len(agent.ClientPubKeys) == 0 {
			return errors.New("agent requires client_pubkeys for end-to-end access authorization")
		}
		for id, key := range agent.ClientPubKeys {
			if !validIdentity(id) {
				return fmt.Errorf("invalid authorized client identity %q", id)
			}
			if _, err := parsePublicKey(key); err != nil {
				return fmt.Errorf("authorized client %s: %w", id, err)
			}
		}
	case "client":
		if config.Client == nil || config.Broker != nil || config.Agent != nil {
			return errors.New("client role requires only the client section")
		}
		client := config.Client
		if !validIdentity(client.ID) || !validIdentity(client.TargetAgent) {
			return errors.New("invalid client or target-agent identity")
		}
		if len(client.BrokerAddrs) == 0 {
			return errors.New("at least one broker address is required")
		}
		for _, address := range client.BrokerAddrs {
			if _, err := normalizeBrokerURL(address); err != nil {
				return err
			}
		}
		if _, err := parsePrivateKey(client.PrivateKey); err != nil {
			return err
		}
		if _, err := parsePublicKey(client.BrokerPubKey); err != nil {
			return err
		}
		if _, err := parsePublicKey(client.AgentPubKey); err != nil {
			return fmt.Errorf("agent public key: %w", err)
		}
		if client.Transport != "" && client.Transport != "kcp" {
			return errors.New("Go data plane requires transport=kcp")
		}
	default:
		return errors.New("role must be broker, agent, or client")
	}
	return nil
}

func readConfig(path string) (*Config, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular, non-symlink file")
	}
	if !secureConfigFile(info) || !secureConfigPath(path) {
		return nil, errors.New("configuration has unsafe ownership or permissions; Unix files must have mode 0600")
	}
	file, err := openConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot inspect opened config: %w", err)
	}
	if !secureConfigFile(openedInfo) || !secureConfigPath(path) || !os.SameFile(info, openedInfo) {
		return nil, errors.New("configuration changed during validation or has unsafe permissions")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read config: %w", err)
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("configuration exceeds the 1 MiB size limit")
	}
	var config Config
	if err := decodeStrict(data, &config); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %w", err)
	}
	if err := validateConfig(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func writeOwnerOnly(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".shadow6-config-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
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
	return os.Rename(temporaryPath, path)
}
