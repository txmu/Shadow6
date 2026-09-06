package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func securePair(t *testing.T, limit int) (*secureConn, *secureConn) {
	t.Helper()
	apub, apriv, _ := ed25519.GenerateKey(nil)
	bpub, bpriv, _ := ed25519.GenerateKey(nil)
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	type result struct {
		c   *secureConn
		err error
	}
	done := make(chan result, 1)
	go func() { c, err := handshake(a, apriv, []ed25519.PublicKey{bpub}, true, limit); done <- result{c, err} }()
	s, err := handshake(b, bpriv, []ed25519.PublicKey{apub}, false, limit)
	if err != nil {
		t.Fatal(err)
	}
	other := <-done
	if other.err != nil {
		t.Fatal(other.err)
	}
	return other.c, s
}

func TestTrafficDirectionsAndStreamFraming(t *testing.T) {
	a, b := securePair(t, 1024)
	nonce := make([]byte, a.aead.NonceSize())
	plain := []byte("known plaintext")
	if bytes.Equal(a.aead.Seal(nil, nonce, plain, nil), a.recvAEAD.Seal(nil, nonce, plain, nil)) {
		t.Fatal("directions reuse the same traffic key and nonce")
	}
	data := bytes.Repeat([]byte("stream"), 2000)
	done := make(chan error, 1)
	go func() { _, err := a.Write(data); done <- err }()
	got := make([]byte, 0, len(data))
	for len(got) < len(data) {
		var small [17]byte
		n, err := b.Read(small[:])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, small[:n]...)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("small reads lost frame data")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := b.Write([]byte("reply")); done <- err }()
	var reply [5]byte
	if _, err := io.ReadFull(a, reply[:]); err != nil || string(reply[:]) != "reply" {
		t.Fatalf("reply: %q %v", reply, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeReplayRequiresFreshKeyConfirmation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, serverKey, _ := ed25519.GenerateKey(nil)
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte("S6I2"), pub...)
	body = append(body, eph.PublicKey().Bytes()...)
	body = append(body, make([]byte, 32)...)
	hello := append(body, ed25519.Sign(priv, body)...)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan error, 1)
	go func() { _, err := handshake(b, serverKey, []ed25519.PublicKey{pub}, false, 1024); done <- err }()
	if err := writeAll(a, hello); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(a, make([]byte, len(hello))); err != nil {
		t.Fatal(err)
	}
	a.Close() // A recorded signed hello supplies no proof of this session's key.
	if err := <-done; err == nil {
		t.Fatal("replayed hello completed authentication")
	}
}

type memoryConn struct {
	bytes.Buffer
	closed bool
}

func (c *memoryConn) Close() error                     { c.closed = true; return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestFrameReplayLengthAndSequenceExhaustion(t *testing.T) {
	a, b := securePair(t, 1024)
	for _, length := range []uint32{0, 16, 1041, 0xffffffff} {
		wire := &memoryConn{}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], length)
		wire.Write(header[:])
		receiver := &secureConn{Conn: wire, recvAEAD: b.recvAEAD, max: 1024}
		if _, err := receiver.Read(make([]byte, 1024)); err == nil || !wire.closed {
			t.Fatalf("invalid frame %d accepted", length)
		}
	}
	wire := &memoryConn{}
	sender := &secureConn{Conn: wire, aead: a.aead, max: 1024}
	if _, err := sender.Write([]byte("once")); err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(nil), wire.Bytes()...)
	wire.Write(frame)
	receiver := &secureConn{Conn: wire, recvAEAD: b.recvAEAD, max: 1024}
	if _, err := receiver.Read(make([]byte, 20)); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Read(make([]byte, 20)); err == nil {
		t.Fatal("replayed encrypted frame accepted")
	}
	wire = &memoryConn{}
	sender = &secureConn{Conn: wire, aead: a.aead, max: 1024, send: ^uint64(0)}
	if _, err := sender.Write([]byte("overflow")); err == nil || wire.Len() != 0 {
		t.Fatal("send counter wrapped")
	}
}

func TestUDPReplayBindingAndBounds(t *testing.T) {
	c := testConfig(t)
	state := newGateState(2)
	packet, err := udpEnvelope(privateKey(c), []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if p, ok := validEnvelope(c, state, packet, nil, now); !ok || string(p) != "hello" {
		t.Fatal("valid packet rejected")
	}
	if _, ok := validEnvelope(c, state, packet, nil, now); ok {
		t.Fatal("UDP replay accepted")
	}
	reply, _ := udpEnvelope(privateKey(c), []byte("reply"), packet[13:29])
	if _, ok := validEnvelope(c, state, reply, nil, now); ok {
		t.Fatal("reply reflected as request")
	}
	if _, ok := validEnvelope(c, state, reply, make([]byte, 16), now); ok {
		t.Fatal("wrong request binding accepted")
	}
	if _, ok := validEnvelope(c, state, reply, packet[13:29], now); !ok {
		t.Fatal("bound reply rejected")
	}
	if _, ok := validEnvelope(c, newGateState(2), packet, nil, now.Add(61*time.Second)); ok {
		t.Fatal("expired envelope accepted")
	}
	oversize, _ := udpEnvelope(privateKey(c), make([]byte, 1025), nil)
	c.Limits.MaxFrameBytes = 1024
	if _, ok := validEnvelope(c, state, oversize, nil, now); ok {
		t.Fatal("oversize signed payload accepted")
	}
	if _, err := udpEnvelope(privateKey(c), make([]byte, 65507), nil); err == nil {
		t.Fatal("UDP wire size overflow accepted")
	}
}

func TestReplayCacheFullAndWindowBoundary(t *testing.T) {
	state := newGateState(1)
	pub := make([]byte, 32)
	nonce := make([]byte, 16)
	for i := 0; i < maxUDPReplays; i++ {
		binary.BigEndian.PutUint64(nonce, uint64(i))
		if !state.acceptNonce(pub, nonce, 100, 100) {
			t.Fatal(i)
		}
	}
	binary.BigEndian.PutUint64(nonce, maxUDPReplays)
	if !state.acceptNonce(pub, nonce, 100, 100) {
		t.Fatal("full replay cache rejected a fresh authenticated entry")
	}
	binary.BigEndian.PutUint64(nonce, 0)
	if state.acceptNonce(pub, nonce, 100, 130) {
		t.Fatal("replay evicted at inclusive timestamp boundary")
	}
	if !state.acceptNonce(pub, nonce, 131, 131) {
		t.Fatal("expired replay entries not reclaimed")
	}
}

func TestGateConfigStrictJSONAndSecretFile(t *testing.T) {
	c := testConfig(t)
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gate.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{string(data) + "garbage", string(data) + " {}", strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1), strings.Replace(string(data), `"version":1`, `"Version":1`, 1), strings.Replace(string(data), `"enabled":true`, `"enabled":null`, 1)} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("ambiguous configuration accepted")
		}
	}
	os.WriteFile(path, data, 0600)
	if runtime.GOOS != "windows" {
		for _, mode := range []os.FileMode{0644, 0400, 0700} {
			os.Chmod(path, mode)
			if _, err := loadConfig(path); err == nil {
				t.Fatalf("mode %o accepted", mode)
			}
		}
	}
	os.Chmod(path, 0600)
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(link); err == nil {
		t.Fatal("symlink secret file accepted")
	}
	if err := example(path, "server"); err == nil {
		t.Fatal("example overwrote an existing file")
	}
	if err := example(link, "server"); err == nil {
		t.Fatal("example followed a symlink")
	}
}

func TestMTDCanonicalKeySetAndIPv6Scope(t *testing.T) {
	c := testConfig(t)
	pub, _ := hex.DecodeString(c.PeerPublicKeys[0])
	key := hex.EncodeToString(pub)
	want := derivedPort(c, 123)
	c.PeerPublicKeys = []string{strings.ToUpper(key), key, key}
	if got := derivedPort(c, 123); got != want {
		t.Fatal("case/duplicates changed the MTD identity set")
	}
	c.AllowedCIDRs = []string{"fe80::/10"}
	if !allowed(c, &net.TCPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0", Port: 1234}, time.Now()) {
		t.Fatal("scoped IPv6 denied despite matching CIDR")
	}
	c.AllowedCIDRs = []string{"127.0.0.0/8"}
	if !allowed(c, &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 1234}, time.Now()) {
		t.Fatal("mapped loopback denied")
	}
}
