// Package enrich applies post-discovery lookups to merged scan results.
package enrich

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/local/network-scanner/internal/device"
)

const defaultDNSTimeout = 300 * time.Millisecond

// Hostnames fills Hostname via concurrent reverse DNS (best-effort).
// Failures are silent: a host with no PTR record keeps Hostname empty
// and is printed as "-" in the table. Bounded to 32 in-flight lookups.
func Hostnames(ctx context.Context, devices []device.Device, timeout time.Duration) {
	if timeout <= 0 {
		timeout = defaultDNSTimeout
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i := range devices {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			rctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			names, err := net.DefaultResolver.LookupAddr(rctx, devices[i].IP.String())
			if err != nil || len(names) == 0 {
				return
			}
			name := names[0]
			if len(name) > 0 && name[len(name)-1] == '.' {
				name = name[:len(name)-1]
			}
			devices[i].Hostname = name
		}(i)
	}
	wg.Wait()
}

// TCPProbe tries a quick TCP connect to common ports. Discovery still comes
// from ICMP/ARP; this is a lightweight secondary reachability check.
func TCPProbe(ctx context.Context, devices []device.Device, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	ports := []string{"80", "443", "22", "445", "3389"}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)

	for i := range devices {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			ip := devices[i].IP.String()
			for _, p := range ports {
				if ctx.Err() != nil {
					return
				}
				d := net.Dialer{Timeout: timeout}
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, p))
				if err == nil {
					_ = conn.Close()
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
