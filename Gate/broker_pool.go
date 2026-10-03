package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// poolTargets preserves the requested selection policy for the first attempt,
// then tries each remaining explicit member once. It never adds destinations.
func poolTargets(values []string, fallback string, randomized bool) []string {
	first := pick(values, fallback, randomized)
	if len(values) == 0 {
		return []string{first}
	}
	result := []string{first}
	for _, value := range values {
		if value != first {
			result = append(result, value)
		}
	}
	return result
}

func dialTCPPool(ctx context.Context, values []string, fallback string, randomized bool) (net.Conn, error) {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	targets := poolTargets(values, fallback, randomized)
	var last error
	for _, target := range targets {
		if err := deadline.Err(); err != nil {
			return nil, err
		}
		timeout := 10 * time.Second
		if len(targets) > 1 {
			timeout = 2 * time.Second
		}
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(deadline, "tcp", target)
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, fmt.Errorf("explicit TCP broker pool unavailable: %w", last)
}

func dialRemotePool(ctx context.Context, c Config) (net.Conn, error) {
	port := activePort(c, time.Now())
	targets := make([]string, 0, len(c.RemoteHosts))
	for _, host := range c.RemoteHosts {
		targets = append(targets, net.JoinHostPort(host, fmt.Sprint(port)))
	}
	return dialTCPPool(ctx, targets, net.JoinHostPort(c.RemoteHost, fmt.Sprint(port)), c.LoadBalance == "random")
}
