package main

import (
	"net"
	"net/netip"
	"time"
)

func allowed(c Config, addr net.Addr, now time.Time) bool {
	if !c.Enabled {
		return false
	}
	timed := func() bool {
		minute := now.Hour()*60 + now.Minute()
		for _, w := range c.Windows {
			s, _ := time.Parse("15:04", w.Start)
			e, _ := time.Parse("15:04", w.End)
			a, b := s.Hour()*60+s.Minute(), e.Hour()*60+e.Minute()
			if a <= b && minute >= a && minute <= b || a > b && (minute >= a || minute <= b) {
				return true
			}
		}
		return false
	}
	if c.OpenMode == "unconditional" {
		return true
	}
	if c.OpenMode == "timed" {
		return timed()
	}
	host, _, e := net.SplitHostPort(addr.String())
	if e != nil {
		return false
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip := net.IP(parsed.WithZone("").Unmap().AsSlice())
	for _, v := range c.AllowedCIDRs {
		_, n, err := net.ParseCIDR(v)
		if err == nil && n.Contains(ip) {
			return len(c.Windows) == 0 || timed()
		}
	}
	return false
}
