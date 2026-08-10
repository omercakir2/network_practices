// Package device defines discovered host records and simple type heuristics.
package device

import (
	"net"
	"strings"
)

// Status values for a discovered host.
const (
	StatusUp   = "up"
	StatusDown = "down"
)

// Type is a coarse inferred role for the host.
const (
	TypeNetwork = "Network device"
	TypeEnd     = "End device"
	TypeUnknown = "Unknown"
)

// Device is one host found on the local subnet.
type Device struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Vendor   string
	Hostname string
	Status   string
	Type     string
}

// InferType applies a basic vendor-name heuristic.
func InferType(vendor string) string {
	v := strings.ToLower(vendor)
	if v == "" || v == "unknown" {
		return TypeUnknown
	}

	if strings.Contains(v, "randomized") {
		return TypeEnd
	}

	// Network infrastructure vendors / product lines.
	networkHints := []string{
		"cisco", "ubiquiti", "tp-link", "tplink", "netgear", "asus",
		"mikrotik", "aruba", "juniper", "hpe", "fortinet",
		"palo alto", "meraki", "ruckus", "extreme", "d-link", "dlink",
		"linksys", "zyxel", "engenius", "openwrt", "pfsense",
	}
	for _, h := range networkHints {
		if strings.Contains(v, h) {
			return TypeNetwork
		}
	}

	// Known end-station / consumer / virtual vendors.
	endHints := []string{
		"apple", "samsung", "google", "microsoft", "intel", "dell",
		"lenovo", "sony", "lg", "amazon", "xiaomi", "hp",
		"raspberry", "espressif", "sonos", "roku", "philips",
		"vmware", "virtualbox", "qemu", "parallels", "nest",
	}
	for _, h := range endHints {
		if strings.Contains(v, h) {
			return TypeEnd
		}
	}

	// Generic NIC chipsets are usually end devices.
	if strings.Contains(v, "realtek") || strings.Contains(v, "broadcom") {
		return TypeEnd
	}

	return TypeUnknown
}
