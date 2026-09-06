package main

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}
func (c *idleConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

// Keep the slot until the underlying connection closes, including WebSockets
// hijacked out of net/http. Limiting only HTTP handlers misses slow headers.
type boundedListener struct {
	net.Listener
	mu          sync.Mutex
	limit       int
	connections map[*countedConn]struct{}
}
type countedConn struct {
	net.Conn
	owner *boundedListener
	once  sync.Once
}

func newBoundedListener(listener net.Listener, limit int) *boundedListener {
	return &boundedListener{Listener: listener, limit: limit, connections: make(map[*countedConn]struct{})}
}
func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		if len(l.connections) >= l.limit {
			l.mu.Unlock()
			c.Close()
			continue
		}
		wrapped := &countedConn{Conn: c, owner: l}
		l.connections[wrapped] = struct{}{}
		l.mu.Unlock()
		return wrapped, nil
	}
}
func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.connections, c); c.owner.mu.Unlock() })
	return err
}
func (l *boundedListener) closeConnections() {
	l.mu.Lock()
	connections := make([]*countedConn, 0, len(l.connections))
	for c := range l.connections {
		connections = append(connections, c)
	}
	l.mu.Unlock()
	for _, c := range connections {
		c.Close()
	}
}

func readCertificate(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return nil, errors.New("TLS certificate must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, errors.New("TLS certificate exceeds size limit")
	}
	return data, nil
}
