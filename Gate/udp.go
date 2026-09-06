package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const udpHeaderBytes = 77
const udpEnvelopeBytes = udpHeaderBytes + ed25519.SignatureSize
const maxUDPReplays = 65536

type gateState struct {
	slots     chan struct{}
	mu        sync.Mutex
	replays   map[[48]byte]int64
	nextSweep int64
}

func newGateState(limit int) *gateState {
	return &gateState{slots: make(chan struct{}, limit), replays: make(map[[48]byte]int64)}
}

func udpPayloadLimit(c Config) int {
	limit := c.Limits.MaxFrameBytes
	if limit > 65507-udpEnvelopeBytes {
		limit = 65507 - udpEnvelopeBytes
	}
	return limit
}

// The cache is shared by listeners and rotations. Entries survive the entire
// timestamp window, including future-dated packets; a full cache evicts the
// soonest-expiring entry to preserve service for authenticated peers.
func (state *gateState) acceptNonce(pub, nonce []byte, timestamp, now int64) bool {
	var key [48]byte
	copy(key[:32], pub)
	copy(key[32:], nonce)
	state.mu.Lock()
	defer state.mu.Unlock()
	if now >= state.nextSweep {
		for k, expiry := range state.replays {
			if now > expiry {
				delete(state.replays, k)
			}
		}
		state.nextSweep = now + 1
	}
	if _, exists := state.replays[key]; exists {
		return false
	}
	if len(state.replays) >= maxUDPReplays {
		// Evict the soonest-expiring entry so a bounded replay cache cannot
		// permanently deny service to legitimate authenticated peers.
		var oldest [48]byte
		var expiry int64
		for k, value := range state.replays {
			if expiry == 0 || value < expiry {
				oldest, expiry = k, value
			}
		}
		if expiry != 0 {
			delete(state.replays, oldest)
		}
	}
	state.replays[key] = timestamp + 30
	return true
}

func validEnvelope(c Config, state *gateState, msg, responseTo []byte, now time.Time) ([]byte, bool) {
	if len(msg) < udpEnvelopeBytes || len(msg) > udpPayloadLimit(c)+udpEnvelopeBytes || string(msg[:4]) != "S6U2" {
		return nil, false
	}
	expectedKind := byte(0)
	if responseTo != nil {
		if len(responseTo) != 16 {
			return nil, false
		}
		expectedKind = 1
	}
	if msg[4] != expectedKind {
		return nil, false
	}
	var binding [16]byte
	copy(binding[:], responseTo)
	if string(msg[29:45]) != string(binding[:]) {
		return nil, false
	}
	timestamp := int64(binary.BigEndian.Uint64(msg[5:13]))
	if timestamp < now.Unix()-30 || timestamp > now.Unix()+30 {
		return nil, false
	}
	pub := ed25519.PublicKey(msg[45:77])
	trusted := false
	for _, peer := range peerKeys(c) {
		if pub.Equal(peer) {
			trusted = true
			break
		}
	}
	if !trusted || !ed25519.Verify(pub, msg[:len(msg)-64], msg[len(msg)-64:]) {
		return nil, false
	}
	if !state.acceptNonce(pub, msg[13:29], timestamp, now.Unix()) {
		return nil, false
	}
	return msg[udpHeaderBytes : len(msg)-64], true
}

func udpEnvelope(k ed25519.PrivateKey, payload, responseTo []byte) ([]byte, error) {
	if len(payload) > 65507-udpEnvelopeBytes || responseTo != nil && len(responseTo) != 16 {
		return nil, errors.New("invalid UDP envelope bounds")
	}
	out := make([]byte, udpHeaderBytes+len(payload))
	copy(out, "S6U2")
	if responseTo != nil {
		out[4] = 1
		copy(out[29:45], responseTo)
	}
	binary.BigEndian.PutUint64(out[5:13], uint64(time.Now().Unix()))
	if _, err := rand.Read(out[13:29]); err != nil {
		return nil, err
	}
	copy(out[45:77], k.Public().(ed25519.PublicKey))
	copy(out[udpHeaderBytes:], payload)
	return append(out, ed25519.Sign(k, out)...), nil
}

// Every transaction owns its buffer and has a bounded lifetime and worker slot.
// One silent upstream cannot block every client on the public UDP listener.
func runUDP(ctx context.Context, c Config, localPort int, until time.Time, state *gateState) error {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(c.ListenHost, fmt.Sprint(localPort)))
	if err != nil {
		return err
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	_ = pc.SetReadDeadline(until)
	limit := udpPayloadLimit(c)
	wireLimit := limit + udpEnvelopeBytes
	if c.Role == "client" {
		wireLimit = limit
	}
	buffer := make([]byte, wireLimit+1) // Oversize/truncated datagrams must not become valid prefixes.
	for {
		n, src, err := pc.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if n > wireLimit || !allowed(c, src, time.Now()) {
			continue
		}
		packet := buffer[:n]
		var nonce []byte
		if c.Role != "client" {
			payload, ok := validEnvelope(c, state, packet, nil, time.Now())
			if !ok {
				continue
			}
			nonce = append([]byte(nil), packet[13:29]...)
			packet = payload
		}
		select {
		case state.slots <- struct{}{}:
			payload := append([]byte(nil), packet...)
			go func() {
				defer func() { <-state.slots }()
				handleUDP(ctx, c, state, pc, src, payload, nonce)
			}()
		default:
		}
	}
}

func handleUDP(ctx context.Context, c Config, state *gateState, pc net.PacketConn, src net.Addr, payload, incomingNonce []byte) {
	target := pick(c.Upstreams, c.Upstream, c.LoadBalance == "random")
	outbound := payload
	var requestNonce []byte
	if c.Role != "server" {
		host := pick(c.RemoteHosts, c.RemoteHost, c.LoadBalance == "random")
		target = net.JoinHostPort(host, fmt.Sprint(activePort(c, time.Now())))
		var err error
		outbound, err = udpEnvelope(privateKey(c), payload, nil)
		if err != nil {
			return
		}
		requestNonce = outbound[13:29]
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", target)
	if err != nil {
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(c.Limits.IdleSeconds) * time.Second))
	if _, err = conn.Write(outbound); err != nil {
		return
	}
	limit := udpPayloadLimit(c)
	if c.Role != "server" {
		limit += udpEnvelopeBytes
	}
	buffer := make([]byte, limit+1)
	n, err := conn.Read(buffer)
	if err != nil || n > limit {
		return
	}
	reply := buffer[:n]
	if c.Role != "server" {
		var ok bool
		reply, ok = validEnvelope(c, state, reply, requestNonce, time.Now())
		if !ok {
			return
		}
	}
	if c.Role != "client" {
		reply, err = udpEnvelope(privateKey(c), reply, incomingNonce)
		if err != nil {
			return
		}
	}
	_, _ = pc.WriteTo(reply, src)
}
