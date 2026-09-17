package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// A host may publish both A and AAAA records while routing only one family, so
// binding or dialing a single family turns an ordinary environment difference
// into a hard failure. Every socket here tries the preferred family first and
// then the other one.
func otherFamily(network string) string {
	if len(network) >= 4 && network[len(network)-1] == '4' {
		return network[:len(network)-1] + "6"
	}
	if len(network) >= 4 && network[len(network)-1] == '6' {
		return network[:len(network)-1] + "4"
	}
	return network
}

func familyOf(ip net.IP) string {
	if ip == nil || ip.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

func udpFamilyOf(ip net.IP) string {
	if ip == nil || ip.To4() != nil {
		return "udp4"
	}
	return "udp6"
}

func firstSuccessful[T any](preferred string, attempt func(network string) (T, error)) (T, error) {
	var zero T
	value, err := attempt(preferred)
	if err == nil {
		return value, nil
	}
	fallback, fallbackErr := attempt(otherFamily(preferred))
	if fallbackErr == nil {
		return fallback, nil
	}
	return zero, errors.Join(
		fmt.Errorf("%s: %w", preferred, err),
		fmt.Errorf("%s: %w", otherFamily(preferred), fallbackErr),
	)
}

// alternateHost maps a bind host to its counterpart in the other address family.
// Only wildcard and loopback hosts are translated: a host that names a specific
// address must never be widened into a wildcard, because that would change which
// interfaces the service is exposed on.
func alternateHost(host string) string {
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		if host == "" || host == "0.0.0.0" {
			return "::"
		}
		return "0.0.0.0"
	case "127.0.0.1":
		return "::1"
	case "::1", "[::1]":
		return "127.0.0.1"
	default:
		return ""
	}
}

// listenTCPAnyFamily binds a TCP listener on whichever family accepts it.
func listenTCPAnyFamily(host string, port int) (net.Listener, error) {
	preferred := familyOf(net.ParseIP(host))
	return firstSuccessful(preferred, func(network string) (net.Listener, error) {
		candidate := host
		if network != preferred {
			if translated := alternateHost(host); translated != "" {
				candidate = translated
			} else {
				return nil, errors.New("no equivalent host in the other address family")
			}
		}
		return net.Listen(network, net.JoinHostPort(candidate, fmt.Sprint(port)))
	})
}

// listenUDPAnyFamily binds a UDP packet connection on whichever family accepts it.
func listenUDPAnyFamily(host string, port int) (net.PacketConn, error) {
	preferred := udpFamilyOf(net.ParseIP(host))
	return firstSuccessful(preferred, func(network string) (net.PacketConn, error) {
		candidate := host
		if network != preferred {
			if translated := alternateHost(host); translated != "" {
				candidate = translated
			} else {
				return nil, errors.New("no equivalent host in the other address family")
			}
		}
		return net.ListenPacket(network, net.JoinHostPort(candidate, fmt.Sprint(port)))
	})
}

// dialUDPAnyFamily resolves the upstream and dials whichever family answers.
func dialUDPAnyFamily(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp4", target)
	if err == nil {
		return conn, nil
	}
	fallback, fallbackErr := dialer.DialContext(ctx, "udp6", target)
	if fallbackErr == nil {
		return fallback, nil
	}
	return nil, errors.Join(fmt.Errorf("udp4: %w", err), fmt.Errorf("udp6: %w", fallbackErr))
}
