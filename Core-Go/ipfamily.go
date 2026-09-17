package main

import (
	"errors"
	"fmt"
	"net"
)

// A host may publish both A and AAAA records while routing only one family, and
// a wildcard bind can succeed on one family but not the other. Choosing a single
// family up front turns an ordinary environment difference into a hard failure,
// so binds try the preferred family first and then the other one.
//
// This only covers binds whose address the operator configured. Sockets bound to
// a specific peer family (the KCP data plane and local discovery) must stay on
// that peer's family, because the peer decides which family is reachable.
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

// firstSuccessful runs attempt for the preferred family and then its complement,
// returning the first success or every failure joined together.
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

// listenTCPAnyFamily binds a TCP listener on whichever family accepts it.
func listenTCPAnyFamily(host string, port int) (net.Listener, error) {
	preferred := familyOf(net.ParseIP(host))
	return firstSuccessful(preferred, func(network string) (net.Listener, error) {
		candidate := host
		if network != preferred {
			translated := alternateHost(host)
			if translated == "" {
				return nil, errors.New("no equivalent host in the other address family")
			}
			candidate = translated
		}
		return net.Listen(network, net.JoinHostPort(candidate, fmt.Sprint(port)))
	})
}
