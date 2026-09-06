package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxConfig = 1 << 20

type Window struct {
	Start string `json:"start"`
	End   string `json:"end"`
}
type Config struct {
	Version        int       `json:"version"`
	Enabled        bool      `json:"enabled"`
	Role           string    `json:"role"`
	ListenHost     string    `json:"listen_host"`
	ListenPort     int       `json:"listen_port"`
	Upstream       string    `json:"upstream"`
	Upstreams      []string  `json:"upstreams"`
	RemoteHost     string    `json:"remote_host"`
	RemoteHosts    []string  `json:"remote_hosts"`
	LoadBalance    string    `json:"load_balance"`
	PrivateKey     string    `json:"private_key"`
	PeerPublicKeys []string  `json:"peer_public_keys"`
	Protocol       []string  `json:"protocol"`
	OpenMode       string    `json:"open_mode"`
	AllowedCIDRs   []string  `json:"allowed_cidrs"`
	Windows        []Window  `json:"windows"`
	MTD            MTDConfig `json:"mtd"`
	Limits         Limits    `json:"limits"`
}
type MTDConfig struct {
	Enabled       bool `json:"enabled"`
	PeriodSeconds int  `json:"period_seconds"`
	MinPort       int  `json:"min_port"`
	MaxPort       int  `json:"max_port"`
	GraceSeconds  int  `json:"grace_seconds"`
}
type Limits struct {
	MaxConnections int `json:"max_connections"`
	MaxFrameBytes  int `json:"max_frame_bytes"`
	IdleSeconds    int `json:"idle_seconds"`
}

func defaultConfig() Config {
	return Config{Version: 1, Enabled: false, Role: "server", ListenHost: "0.0.0.0", ListenPort: 1086, Upstream: "127.0.0.1:4433", LoadBalance: "round_robin", Protocol: []string{"tcp", "udp"}, OpenMode: "conditional", AllowedCIDRs: []string{"127.0.0.0/8", "::1/128"}, MTD: MTDConfig{true, 300, 49152, 65535, 15}, Limits: Limits{128, 65507, 120}}
}

func loadConfig(path string) (Config, error) {
	data, err := readSecretFile(path, maxConfig)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err = strictConfigJSON(data, &c); err != nil {
		return c, err
	}
	return c, validateConfig(c)
}
func validateConfig(c Config) error {
	if c.Version != 1 {
		return errors.New("version must be 1")
	}
	if c.Role != "server" && c.Role != "client" && c.Role != "relay" {
		return errors.New("role must be server, client, or relay")
	}
	if net.ParseIP(c.ListenHost) == nil {
		return errors.New("listen_host must be an IP address")
	}
	if c.ListenPort < 1024 || c.ListenPort > 65535 {
		return errors.New("listen_port must be 1024-65535")
	}
	if _, _, e := net.SplitHostPort(c.Upstream); e != nil {
		return fmt.Errorf("invalid upstream: %w", e)
	}
	if len(c.Upstreams) > 16 || len(c.RemoteHosts) > 16 {
		return errors.New("at most 16 upstreams or remote hosts are allowed")
	}
	for _, v := range c.Upstreams {
		if _, _, e := net.SplitHostPort(v); e != nil {
			return errors.New("invalid upstream list")
		}
	}
	for _, v := range c.RemoteHosts {
		if net.ParseIP(v) == nil {
			return errors.New("remote_hosts must contain IP addresses")
		}
	}
	if c.LoadBalance != "round_robin" && c.LoadBalance != "random" {
		return errors.New("load_balance must be round_robin or random")
	}
	if c.Role == "client" || c.Role == "relay" {
		if net.ParseIP(c.RemoteHost) == nil {
			return errors.New("remote_host must be an IP address")
		}
	}
	key, e := hex.DecodeString(c.PrivateKey)
	if e != nil || len(key) != ed25519.SeedSize && len(key) != ed25519.PrivateKeySize {
		return errors.New("private_key must be a 32- or 64-byte Ed25519 hex key")
	}
	if len(c.PeerPublicKeys) < 1 || len(c.PeerPublicKeys) > 256 {
		return errors.New("peer_public_keys must contain 1-256 keys")
	}
	for _, v := range c.PeerPublicKeys {
		b, e := hex.DecodeString(v)
		if e != nil || len(b) != ed25519.PublicKeySize {
			return errors.New("invalid peer public key")
		}
	}
	if len(c.Protocol) < 1 || len(c.Protocol) > 2 {
		return errors.New("protocol must select tcp and/or udp")
	}
	seen := map[string]bool{}
	for _, p := range c.Protocol {
		if p != "tcp" && p != "udp" || seen[p] {
			return errors.New("invalid or duplicate protocol")
		}
		seen[p] = true
	}
	if c.OpenMode != "unconditional" && c.OpenMode != "timed" && c.OpenMode != "conditional" {
		return errors.New("invalid open_mode")
	}
	if len(c.AllowedCIDRs) > 256 {
		return errors.New("too many allowed CIDRs")
	}
	for _, v := range c.AllowedCIDRs {
		if _, _, e := net.ParseCIDR(v); e != nil {
			return errors.New("invalid allowed CIDR")
		}
	}
	if len(c.Windows) > 32 {
		return errors.New("too many time windows")
	}
	for _, w := range c.Windows {
		if _, e := time.Parse("15:04", w.Start); e != nil {
			return errors.New("invalid window start")
		}
		if _, e := time.Parse("15:04", w.End); e != nil {
			return errors.New("invalid window end")
		}
	}
	if c.MTD.PeriodSeconds < 30 || c.MTD.PeriodSeconds > 86400 || c.MTD.MinPort < 1024 || c.MTD.MaxPort > 65535 || c.MTD.MinPort >= c.MTD.MaxPort || c.MTD.GraceSeconds < 0 || c.MTD.GraceSeconds > c.MTD.PeriodSeconds/2 {
		return errors.New("invalid MTD bounds")
	}
	if c.Limits.MaxConnections < 1 || c.Limits.MaxConnections > 4096 || c.Limits.MaxFrameBytes < 1024 || c.Limits.MaxFrameBytes > 65507 || c.Limits.IdleSeconds < 5 || c.Limits.IdleSeconds > 86400 {
		return errors.New("invalid limits")
	}
	return nil
}
func privateKey(c Config) ed25519.PrivateKey {
	b, _ := hex.DecodeString(c.PrivateKey)
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b)
	}
	return ed25519.PrivateKey(b)
}
func peerKeys(c Config) []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, 0, len(c.PeerPublicKeys))
	for _, v := range c.PeerPublicKeys {
		b, _ := hex.DecodeString(v)
		out = append(out, b)
	}
	return out
}
func example(path, role string) error {
	c := defaultConfig()
	c.Role = role
	if role == "client" {
		c.ListenHost = "127.0.0.1"
		c.RemoteHost = "203.0.113.10"
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if !filepath.IsAbs(path) {
		return errors.New("output must be absolute")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
func protocols(c Config, p string) bool {
	return strings.Contains(" "+strings.Join(c.Protocol, " ")+" ", " "+p+" ")
}
