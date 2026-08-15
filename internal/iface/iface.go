// Package iface detects the local network interface and its IPv4 subnet.
package iface

import (
	"fmt"
	"net"
	"strings"
)

// LocalNet describes the interface and IPv4 CIDR used for scanning.
type LocalNet struct {
	Interface *net.Interface
	IP        net.IP     // host IPv4 address on this interface
	Network   *net.IPNet // subnet (IP & mask)
}

// Detect finds a suitable local interface with a non-loopback IPv4 address.
// Prefer private (RFC1918) addresses; skip link-local (169.254/16).
// If ifaceName is non-empty, only that interface is considered.
func Detect(ifaceName string) (*LocalNet, error) {
	var ifaces []net.Interface
	var err error

	if ifaceName != "" {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", ifaceName, err)
		}
		ifaces = []net.Interface{*ifi}
	} else {
		ifaces, err = net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("list interfaces: %w", err)
		}
	}

	var fallback *LocalNet

	for i := range ifaces {
		ifi := &ifaces[i]

		// Skip down or loopback interfaces.
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		// ARP needs a hardware address.
		if len(ifi.HardwareAddr) == 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			// Skip link-local (APIPA).
			if ip4[0] == 169 && ip4[1] == 254 {
				continue
			}

			// Copy mask-bounded network for clean CIDR display / host iteration.
			mask := ipNet.Mask
			network := &net.IPNet{
				IP:   ip4.Mask(mask),
				Mask: mask,
			}
			ln := &LocalNet{
				Interface: ifi,
				IP:        append(net.IP(nil), ip4...),
				Network:   network,
			}

			if isPrivate(ip4) {
				return ln, nil
			}
			// Keep first public IPv4 as fallback (e.g. some VPS setups).
			if fallback == nil {
				fallback = ln
			}
		}
	}

	if fallback != nil {
		return fallback, nil
	}
	if ifaceName != "" {
		return nil, fmt.Errorf("interface %q has no usable IPv4 address", ifaceName)
	}
	return nil, fmt.Errorf("no suitable local IPv4 interface found")
}

// Hosts returns every usable host address in the subnet (excludes network & broadcast
// for masks shorter than /31). Caps at maxHosts to avoid huge ranges (e.g. /8).
func (ln *LocalNet) Hosts(maxHosts int) ([]net.IP, error) {
	ones, bits := ln.Network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 is supported")
	}

	hostBits := bits - ones
	total := 1 << hostBits
	// /31 and /32 are special; still try the address(es) present.
	var start, end int
	switch {
	case ones >= 31:
		start, end = 0, total
	default:
		start, end = 1, total-1 // skip network & broadcast
	}

	count := end - start
	if count <= 0 {
		return nil, fmt.Errorf("subnet %s has no host addresses", ln.Network)
	}
	if maxHosts > 0 && count > maxHosts {
		return nil, fmt.Errorf(
			"subnet %s has %d hosts (max %d); use a narrower interface/subnet or raise the host limit",
			ln.CIDR(), count, maxHosts,
		)
	}

	base := binaryIP(ln.Network.IP.To4())
	out := make([]net.IP, 0, count)
	for i := start; i < end; i++ {
		out = append(out, intToIP(base+uint32(i)))
	}
	return out, nil
}

// CIDR returns the subnet string, e.g. "192.168.1.0/24".
func (ln *LocalNet) CIDR() string {
	ones, _ := ln.Network.Mask.Size()
	return fmt.Sprintf("%s/%d", ln.Network.IP.String(), ones)
}

func (ln *LocalNet) String() string {
	return fmt.Sprintf("%s on %s (%s)", ln.IP, ln.Interface.Name, ln.CIDR())
}

func isPrivate(ip net.IP) bool {
	private := []net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
	}
	for _, n := range private {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func binaryIP(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func intToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).To4()
}

// IsPermissionError reports whether err looks like a privileges failure.
func IsPermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "are you root")
}
