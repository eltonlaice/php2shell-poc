// Package guard keeps the verification commands pointed at lab targets.
//
// The verifiers send traffic that is indistinguishable from an attack. They
// therefore refuse public addresses unless the operator explicitly opts in
// with --allow-public, and even then they never fan out across targets.
package guard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Check validates that target is an http(s) URL and, unless allowPublic is
// set, that it resolves only to loopback, private, or link-local addresses.
func Check(target string, allowPublic bool) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("guard: parse target: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("guard: unsupported scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("guard: target %q has no host", target)
	}
	if allowPublic {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return checkAddr(host, addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("guard: cannot resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("guard: %q resolved to no addresses", host)
	}
	for _, addr := range addrs {
		if err := checkAddr(host, addr); err != nil {
			return err
		}
	}
	return nil
}

func checkAddr(host string, addr netip.Addr) error {
	if isLocal(addr) {
		return nil
	}
	return fmt.Errorf("guard: refusing non-local target %q (%s); use --allow-public only for systems you own", host, addr)
}

func isLocal(addr netip.Addr) bool {
	return addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified() ||
		addr.IsMulticast()
}
