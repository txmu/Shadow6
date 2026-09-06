package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Version 2 binds both identities and roles into separate traffic keys and
// confirms possession of the fresh session key before opening an upstream.
var gateMagic = []byte("S6I2")

type secureConn struct {
	net.Conn
	aead     cipher.AEAD
	recvAEAD cipher.AEAD
	writeMu  sync.Mutex
	readMu   sync.Mutex
	pending  []byte
	send     uint64
	recv     uint64
	max      int
}

func handshake(conn net.Conn, own ed25519.PrivateKey, peers []ed25519.PublicKey, initiator bool, max int) (*secureConn, error) {
	if len(own) != ed25519.PrivateKeySize || max < 20 || max > 65507 {
		return nil, errors.New("invalid handshake parameters")
	}
	if e := conn.SetDeadline(time.Now().Add(10 * time.Second)); e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	curve := ecdh.X25519()
	eph, e := curve.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	pub := own.Public().(ed25519.PublicKey)
	magic, expected := string(gateMagic), "S6R2"
	if !initiator {
		magic, expected = expected, magic
	}
	body := append(append(append([]byte{}, magic...), pub...), eph.PublicKey().Bytes()...)
	body = append(body, nonce...)
	sig := ed25519.Sign(own, body)
	hello := append(body, sig...)
	other := make([]byte, len(hello))
	if initiator {
		if e = writeAll(conn, hello); e == nil {
			_, e = io.ReadFull(conn, other)
		}
	} else {
		if _, e = io.ReadFull(conn, other); e == nil {
			e = writeAll(conn, hello)
		}
	}
	if e != nil {
		return nil, e
	}
	if string(other[:4]) != expected {
		return nil, errors.New("invalid Gate hello")
	}
	opub := ed25519.PublicKey(other[4:36])
	ok := false
	for _, p := range peers {
		if ed25519.PublicKey.Equal(p, opub) {
			ok = true
			break
		}
	}
	if !ok || !ed25519.Verify(opub, other[:100], other[100:]) {
		return nil, errors.New("peer authentication failed")
	}
	oe, e := curve.NewPublicKey(other[36:68])
	if e != nil {
		return nil, e
	}
	shared, e := eph.ECDH(oe)
	if e != nil {
		return nil, e
	}
	transcript := sha256.New()
	if initiator {
		transcript.Write(hello)
		transcript.Write(other)
	} else {
		transcript.Write(other)
		transcript.Write(hello)
	}
	// HKDF-SHA256 extract, then one expand block for each direction.
	extract := hmac.New(sha256.New, transcript.Sum(nil))
	extract.Write(shared)
	traffic := func(label string) cipher.AEAD {
		expand := hmac.New(sha256.New, extract.Sum(nil))
		expand.Write([]byte("shadow6-gate-v2/" + label + "\x01"))
		block, _ := aes.NewCipher(expand.Sum(nil))
		aead, _ := cipher.NewGCM(block)
		return aead
	}
	send, recv := traffic("initiator"), traffic("responder")
	if !initiator {
		send, recv = recv, send
	}
	s := &secureConn{Conn: conn, aead: send, recvAEAD: recv, max: max}
	finished := []byte("S6F2")
	readFinished := func() error {
		b := make([]byte, 20)
		n, err := s.Read(b)
		if err != nil {
			return err
		}
		if n != len(finished) || string(b[:n]) != string(finished) || len(s.pending) != 0 {
			return errors.New("invalid key confirmation")
		}
		return nil
	}
	if initiator {
		if _, e = s.Write(finished); e == nil {
			e = readFinished()
		}
	} else {
		if e = readFinished(); e == nil {
			_, e = s.Write(finished)
		}
	}
	if e != nil {
		return nil, e
	}
	if e = conn.SetDeadline(time.Time{}); e != nil {
		return nil, e
	}
	success = true
	return s, nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func (s *secureConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		if s.send == ^uint64(0) {
			s.Close()
			return written, errors.New("send sequence exhausted")
		}
		chunk := p
		if len(chunk) > s.max {
			chunk = chunk[:s.max]
		}
		n := make([]byte, s.aead.NonceSize())
		binary.BigEndian.PutUint64(n[len(n)-8:], s.send)
		s.send++
		sealed := s.aead.Seal(nil, n, chunk, nil)
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], uint32(len(sealed)))
		if e := writeAll(s.Conn, h[:]); e != nil {
			s.Close()
			return written, e
		}
		if e := writeAll(s.Conn, sealed); e != nil {
			s.Close()
			return written, e
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}
func (s *secureConn) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	if s.recv == ^uint64(0) {
		s.Close()
		return 0, errors.New("receive sequence exhausted")
	}
	var h [4]byte
	if _, e := io.ReadFull(s.Conn, h[:]); e != nil {
		s.Close()
		return 0, e
	}
	l := binary.BigEndian.Uint32(h[:])
	if l <= uint32(s.recvAEAD.Overhead()) || l > uint32(s.max+s.recvAEAD.Overhead()) {
		s.Close()
		return 0, errors.New("invalid frame length")
	}
	b := make([]byte, l)
	if _, e := io.ReadFull(s.Conn, b); e != nil {
		s.Close()
		return 0, e
	}
	n := make([]byte, s.recvAEAD.NonceSize())
	binary.BigEndian.PutUint64(n[len(n)-8:], s.recv)
	s.recv++
	plain, e := s.recvAEAD.Open(nil, n, b, nil)
	if e != nil {
		s.Close()
		return 0, e
	}
	count := copy(p, plain)
	s.pending = plain[count:]
	return count, nil
}
