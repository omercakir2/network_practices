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

// Neighbor is one LLDP (or similar) adjacency learned after SSH login.
type Neighbor struct {
	LocalPort  string
	RemoteName string
	RemotePort string
	RemoteID   string // chassis ID / MAC when present
}

// SysInfo is inventory collected after a successful SSH login.
// Zero value means the host was not reached over SSH. The password is never stored.
type SysInfo struct {
	User      string
	Hostname  string
	Model     string
	Version   string
	Uptime    string
	Family    string // e.g. Junos "junos-ex"
	CPU       string // e.g. "5s 8% / 1m 9% / 5m 10%" or "user 3% idle 95%"
	Memory    string // e.g. "28%"
	Temp      string // e.g. "42C"
	Neighbors []Neighbor
}

// Empty reports whether no SSH fields were collected.
func (s SysInfo) Empty() bool {
	return s.User == "" && s.Hostname == "" && s.Model == "" && s.Version == "" && s.Uptime == "" && s.Family == "" &&
		s.CPU == "" && s.Memory == "" && s.Temp == "" && len(s.Neighbors) == 0
}

// VendorUnset reports whether Vendor is empty or a placeholder from OUI lookup.
func VendorUnset(v string) bool {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "", "unknown", "randomized mac":
		return true
	}
	return false
}

// InferVendor guesses a vendor from SSH model / version / family.
// Returns "" when nothing matches.
func InferVendor(s SysInfo) string {
	blob := strings.ToLower(s.Model + " " + s.Version + " " + s.Family)
	for _, h := range []struct{ sub, vendor string }{
		{"junos", "Juniper"},
		{"juniper", "Juniper"},
		{"cisco", "Cisco"},
		{"ios-xe", "Cisco"},
		{"nx-os", "Cisco"},
		{"catalyst", "Cisco"},
		{"huawei", "Huawei"},
		{"vrp", "Huawei"},
		{"aruba", "Aruba"},
		{"procurve", "Aruba"},
		{"mikrotik", "MikroTik"},
		{"routeros", "MikroTik"},
		{"openwrt", "OpenWrt"},
	} {
		if strings.Contains(blob, h.sub) {
			return h.vendor
		}
	}
	m := strings.ToLower(strings.TrimSpace(s.Model))
	switch {
	case strings.HasPrefix(m, "ex") && strings.Contains(m, "-"):
		return "Juniper"
	case strings.HasPrefix(m, "qfx"), strings.HasPrefix(m, "srx"), strings.HasPrefix(m, "mx"):
		return "Juniper"
	case strings.HasPrefix(m, "ws-"), strings.HasPrefix(m, "c29"),
		strings.HasPrefix(m, "isr"), strings.HasPrefix(m, "asr"):
		return "Cisco"
	case strings.HasPrefix(m, "s57"), strings.HasPrefix(m, "s67"):
		return "Huawei"
	}
	// Junos train: 24.4R1-S2.15
	v := strings.ToLower(s.Version)
	if strings.Contains(v, "r") && strings.Contains(v, ".") &&
		(strings.Contains(v, "s") || strings.HasPrefix(m, "ex")) {
		if len(v) > 0 && v[0] >= '0' && v[0] <= '9' && strings.ContainsAny(v, "rR") {
			return "Juniper"
		}
	}
	return ""
}

// Device is one host found on the local subnet.
type Device struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Vendor   string
	Hostname string
	Status   string
	Type     string
	SysInfo  SysInfo
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
