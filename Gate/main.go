package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const version = "2.0.0"

var balanceCounter atomic.Uint64

func pick(values []string, fallback string, randomized bool) string {
	if len(values) == 0 {
		return fallback
	}
	if randomized {
		var b [8]byte
		_, _ = rand.Read(b[:])
		return values[binary.BigEndian.Uint64(b[:])%uint64(len(values))]
	}
	return values[(balanceCounter.Add(1)-1)%uint64(len(values))]
}

func relay(a, b net.Conn, idle time.Duration) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		defer a.Close()
		defer b.Close()
		buf := make([]byte, 32768)
		for {
			src.SetReadDeadline(time.Now().Add(idle))
			n, e := src.Read(buf)
			if n > 0 {
				dst.SetWriteDeadline(time.Now().Add(idle))
				if _, w := dst.Write(buf[:n]); w != nil {
					return
				}
			}
			if e != nil {
				return
			}
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
func runTCP(ctx context.Context, c Config, localPort int, until time.Time, state *gateState) error {
	ln, e := net.Listen("tcp", net.JoinHostPort(c.ListenHost, fmt.Sprint(localPort)))
	if e != nil {
		return e
	}
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	_ = ln.(*net.TCPListener).SetDeadline(until)
	log.Printf("Gate TCP %s role=%s", ln.Addr(), c.Role)
	for {
		raw, e := ln.Accept()
		if e != nil {
			return e
		}
		if !allowed(c, raw.RemoteAddr(), time.Now()) {
			raw.Close()
			continue
		}
		select {
		case state.slots <- struct{}{}:
			go func() {
				defer func() { <-state.slots }()
				defer raw.Close()
				var e error // Per-connection errors must never share the accept loop's variable.
				var remote net.Conn
				var secure *secureConn
				if c.Role == "server" || c.Role == "relay" {
					secure, e = handshake(raw, privateKey(c), peerKeys(c), false, c.Limits.MaxFrameBytes)
					if e == nil {
						if c.Role == "server" {
							remote, e = net.DialTimeout("tcp", pick(c.Upstreams, c.Upstream, c.LoadBalance == "random"), 10*time.Second)
						} else {
							host := pick(c.RemoteHosts, c.RemoteHost, c.LoadBalance == "random")
							remote, e = net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(activePort(c, time.Now()))), 10*time.Second)
							if e == nil {
								var outbound *secureConn
								outbound, e = handshake(remote, privateKey(c), peerKeys(c), true, c.Limits.MaxFrameBytes)
								if e == nil {
									e = exchangeRotation(outbound, c, false)
									remote = outbound
								}
							}
						}
					}
				} else {
					host := pick(c.RemoteHosts, c.RemoteHost, c.LoadBalance == "random")
					remote, e = net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(activePort(c, time.Now()))), 10*time.Second)
					if e == nil {
						secure, e = handshake(remote, privateKey(c), peerKeys(c), true, c.Limits.MaxFrameBytes)
					}
				}
				if e != nil {
					log.Printf("Gate TCP rejected: %v", e)
					if remote != nil {
						remote.Close()
					}
					return
				}
				if e = exchangeRotation(secure, c, c.Role != "client"); e != nil {
					remote.Close()
					return
				}
				if c.Role == "server" || c.Role == "relay" {
					relay(secure, remote, time.Duration(c.Limits.IdleSeconds)*time.Second)
				} else {
					relay(raw, secure, time.Duration(c.Limits.IdleSeconds)*time.Second)
				}
			}()
		default:
			raw.Close()
		}
	}
}

func exchangeRotation(conn *secureConn, c Config, server bool) error {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	record := make([]byte, 20)
	copy(record, []byte("S6R1"))
	slot := rotationSlot(c, time.Now())
	binary.BigEndian.PutUint64(record[4:12], uint64(slot))
	binary.BigEndian.PutUint32(record[12:16], uint32(portForSlot(c, slot)))
	binary.BigEndian.PutUint32(record[16:20], uint32(portForSlot(c, slot+1)))
	if server {
		_, e := conn.Write(record)
		return e
	}
	got := make([]byte, 20)
	n, e := conn.Read(got)
	if e != nil {
		return e
	}
	if n != 20 || string(got[:4]) != "S6R1" {
		return fmt.Errorf("invalid rotation notice")
	}
	peerSlot := int64(binary.BigEndian.Uint64(got[4:12]))
	if peerSlot < slot-1 || peerSlot > slot+1 ||
		binary.BigEndian.Uint32(got[12:16]) != uint32(portForSlot(c, peerSlot)) ||
		binary.BigEndian.Uint32(got[16:20]) != uint32(portForSlot(c, peerSlot+1)) {
		return fmt.Errorf("rotation notice does not match configured peer set and slot")
	}
	return nil
}

func main() {
	cfgPath := flag.String("config", "gate.json", "configuration")
	check := flag.Bool("check-config", false, "validate configuration")
	features := flag.Bool("feature-report", false, "print feature contract")
	portOnly := flag.Bool("current-port", false, "print current deterministic port")
	gen := flag.Bool("gen-key", false, "generate Ed25519 identity")
	exampleOut := flag.String("init-config", "", "write disabled example to absolute path")
	role := flag.String("role", "server", "example role")
	flag.Parse()
	if *features {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"component": "shadow6-gate", "version": version, "compiled": true, "enabled_by_default": false, "tcp": true, "udp": true, "mtd": true, "client_front_proxy": true, "agent_rear_proxy": true, "authenticated_relays": true, "multi_broker_load_balance": true})
		return
	}
	if *gen {
		pub, priv, _ := ed25519.GenerateKey(nil)
		fmt.Printf("Private Key (Hex): %s\nPublic Key (Hex): %s\n", hex.EncodeToString(priv.Seed()), hex.EncodeToString(pub))
		return
	}
	if *exampleOut != "" {
		if e := example(*exampleOut, *role); e != nil {
			log.Fatal(e)
		}
		return
	}
	c, e := loadConfig(*cfgPath)
	if e != nil {
		log.Fatal(e)
	}
	if *check {
		fmt.Println("Gate configuration is valid")
		return
	}
	if *portOnly {
		fmt.Println(activePort(c, time.Now()))
		return
	}
	if !c.Enabled {
		log.Fatal("Gate is compiled but disabled; set enabled=true explicitly")
	}
	state := newGateState(c.Limits.MaxConnections)
	for {
		now := time.Now()
		port := activePort(c, now)
		localPort := port
		until := time.Time{}
		if c.Role == "client" {
			localPort = c.ListenPort
		} else if c.MTD.Enabled {
			until = time.Unix((rotationSlot(c, now)+1)*int64(c.MTD.PeriodSeconds), 0)
		}
		ctx, cancel := context.WithCancel(context.Background())
		errs := make(chan error, 2)
		if protocols(c, "tcp") {
			go func() { errs <- runTCP(ctx, c, localPort, until, state) }()
		}
		if protocols(c, "udp") {
			go func() { errs <- runUDP(ctx, c, localPort, until, state) }()
		}
		e := <-errs
		cancel()
		// Rebind only after both old listeners have closed. Live TCP sessions
		// retain their shared worker slots across rotations.
		for remaining := len(c.Protocol) - 1; remaining > 0; remaining-- {
			<-errs
		}
		if nerr, ok := e.(net.Error); c.Role != "client" && c.MTD.Enabled && ok && nerr.Timeout() {
			log.Printf("Gate MTD rotating from port %d", port)
			continue
		}
		log.Fatal(e)
	}
}
