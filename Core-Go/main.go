package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func generateKeys() error {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	fmt.Println("--- Ed25519 Key Pair Generated ---")
	fmt.Printf("Private Key (Hex): %s\n", hex.EncodeToString(privateKey))
	fmt.Printf("Public Key (Hex):  %s\n", hex.EncodeToString(publicKey))
	return nil
}

func initConfig(role string) error {
	config := Config{Role: role}
	switch role {
	case "broker":
		config.Broker = &BrokerConfig{
			ListenAddr: "127.0.0.1:4433", PrivateKey: "<HEX_PRIVATE_KEY>", StealthMode: true,
			Agents:  []AgentRBAC{{ID: "nas-1", PubKey: "<AGENT_PUB_KEY>"}},
			Clients: []ClientRBAC{{ID: "laptop-1", PubKey: "<CLIENT_PUB_KEY>", AllowedAgents: []string{"nas-1"}}},
		}
	case "agent":
		config.Agent = &AgentConfig{
			ID: "nas-1", BrokerAddrs: []string{"wss://broker.example/ws"},
			BrokerPubKey: "<BROKER_PUB_KEY>", PrivateKey: "<HEX_PRIVATE_KEY>", TargetPort: 22,
			AutoCloseAfter: 7200, AllowLocalDisc: false, Transport: "kcp",
			ClientPubKeys: map[string]string{"laptop-1": "<CLIENT_PUB_KEY>"},
		}
	case "client":
		config.Client = &ClientConfig{
			ID: "laptop-1", BrokerAddrs: []string{"wss://broker.example/ws"},
			BrokerPubKey: "<BROKER_PUB_KEY>", PrivateKey: "<HEX_PRIVATE_KEY>",
			TargetAgent: "nas-1", AgentPubKey: "<AGENT_PUB_KEY>",
			OnSuccess: "ssh root@127.0.0.1 -p $LOCAL_TCP_PORT", AllowLocalDisc: false, Transport: "kcp",
		}
	default:
		return errors.New("role must be broker, agent, or client")
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := writeOwnerOnly("config.json.example", data); err != nil {
		return err
	}
	fmt.Printf("Template config for role %q written to config.json.example\n", role)
	return nil
}

func systemdQuote(path string) (string, error) {
	if strings.ContainsAny(path, "\r\n\"") {
		return "", errors.New("systemd paths may not contain quotes or newlines")
	}
	return `"` + strings.ReplaceAll(path, `\`, `\\`) + `"`, nil
}

func installService(configPath string) error {
	if configPath == "" {
		return errors.New("--install-service requires --config")
	}
	absoluteConfig, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	absoluteConfig, err = filepath.EvalSymlinks(absoluteConfig)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	quotedExecutable, err := systemdQuote(executable)
	if err != nil {
		return err
	}
	quotedConfig, err := systemdQuote(absoluteConfig)
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=Shadow6 Go Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --config %s
Restart=on-failure
RestartSec=5
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
`, quotedExecutable, quotedConfig)
	return os.WriteFile("/etc/systemd/system/shadow6-go.service", []byte(unit), 0o644)
}

func daemonize(logPath string) error {
	arguments := make([]string, 0, len(os.Args))
	for _, argument := range os.Args[1:] {
		if argument != "--daemon" {
			arguments = append(arguments, argument)
		}
	}
	command := exec.Command(os.Args[0], arguments...)
	if logPath != "" {
		logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		command.Stdout, command.Stderr = logFile, logFile
	}
	if err := command.Start(); err != nil {
		return err
	}
	fmt.Printf("[Shadow6 Go] Running in background (PID: %d)\n", command.Process.Pid)
	return nil
}

func run() error {
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	configPath := flags.String("config", "", "Path to config.json")
	generateKey := flags.Bool("gen-key", false, "Generate an Ed25519 key pair")
	initialRole := flags.String("init-config", "", "Generate a role template")
	install := flags.Bool("install-service", false, "Install a hardened systemd unit")
	checkConfig := flags.Bool("check-config", false, "Validate configuration and exit")
	featureReport := flags.Bool("feature-report", false, "Print compiled Core/Crosed feature levels as JSON")
	crosedRequest := flags.String("crosed-request", "", "Process a signed local Crosed request")
	crosedTrust := flags.String("crosed-trust", "", "Owner-only Crosed trust store")
	daemon := flags.Bool("daemon", false, "Run in the background")
	logPath := flags.String("log", "", "Daemon log path")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if *generateKey {
		return generateKeys()
	}
	if *featureReport {
		encoded, err := marshalFeatureReport()
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		return nil
	}
	if *crosedRequest != "" {
		if *crosedTrust == "" {
			return errors.New("--crosed-request requires --crosed-trust")
		}
		response, err := handleCrosedRequest(*crosedRequest, *crosedTrust, time.Now())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(response)
	}
	if *initialRole != "" {
		return initConfig(*initialRole)
	}
	if *install {
		return installService(*configPath)
	}
	if *configPath == "" {
		return errors.New("usage: shadow6-go --config config.json")
	}
	if *daemon {
		return daemonize(*logPath)
	}
	config, err := readConfig(*configPath)
	if err != nil {
		return err
	}
	if *checkConfig {
		fmt.Printf("Configuration %s is valid for role %s\n", *configPath, config.Role)
		return nil
	}
	switch config.Role {
	case "broker":
		return startBroker(config)
	case "agent":
		return startAgent(config)
	case "client":
		return startClient(config)
	default:
		return errors.New("invalid role")
	}
}

func main() {
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		log.Printf("shadow6-go: %v", err)
		os.Exit(2)
	}
}
