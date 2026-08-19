package sshprobe

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/local/network-scanner/internal/device"
)

const cmdTimeout = 5 * time.Second

var execCommands = []string{
	"show system information",     // Junos CLI (EX/QFX)
	"cli show system information", // Junos root shell → CLI
	"show version",
	"display version",
	"uname -a",
	"cat /etc/os-release",
	"hostname",
	"uptime",
}

var shellCommands = []string{
	"terminal length 0",
	"terminal pager 0",
	"screen-length 0 temporary",
	"show system information",
	"show version",
	"display version",
}

// Tried only when the version dump did not already contain a MAC.
var macCommands = []string{
	"show chassis mac-addresses",
	"cli show chassis mac-addresses",
}

var (
	reCiscoVersion = regexp.MustCompile(`(?i)Version\s+([0-9][0-9A-Za-z.():/-]+)`)
	reCiscoModel   = regexp.MustCompile(`(?i)(?:cisco\s+)(WS-\S+|C\d+\S+|ISR\S+|ASR\S+|N\d+\S+|Catalyst\s+\S+)`)
	reModelNumber  = regexp.MustCompile(`(?i)Model number\s*:\s*(\S+)`)
	reUptimeIOS    = regexp.MustCompile(`(?im)^(\S+)?\s*uptime is ([^\r\n]+)`)
	reHuaweiVer    = regexp.MustCompile(`(?i)VRP[^\n]*Version\s+(\S+(?:\s+\([^)]+\))?)`)
	reHuaweiModel  = regexp.MustCompile(`(?i)HUAWEI\s+(S\d\S+)`)
	reUname        = regexp.MustCompile(`(?i)\bLinux\s+(\S+)\s+(\S+)`)
	rePrettyName   = regexp.MustCompile(`(?m)^PRETTY_NAME=(.+)$`)
	reLinuxUptime  = regexp.MustCompile(`\bup\s+(.+?)(?:,\s+\d+\s+users?)`)
	reJunosModel   = regexp.MustCompile(`(?im)^Model:\s*(\S+)`)
	reJunosVer     = regexp.MustCompile(`(?im)^Junos:\s*(\S+)`)
	reJunosHost    = regexp.MustCompile(`(?im)^Hostname:\s*(\S+)`)
	reJunosFamily  = regexp.MustCompile(`(?im)^Family:\s*(\S+)`)
	reLabeledMAC   = regexp.MustCompile(`(?i)(?:base ethernet mac address|public base address|hardware address|mac address)\s*:?\s*((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})`)
	reAnyMAC       = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}`)
)

func collect(ctx context.Context, r runner) (device.SysInfo, bool, net.HardwareAddr) {
	raw := gatherOutput(ctx, r, execCommands, shellCommands)
	info := parseSysInfo(raw)
	mac := parseMAC(raw)
	if mac == nil {
		extra := gatherOutput(ctx, r, macCommands, nil)
		if extra != "" {
			raw = raw + "\n" + extra
			if info.Model == "" && info.Version == "" {
				info = parseSysInfo(raw)
			}
			mac = parseMAC(raw)
		}
	}
	netDev := isNetworkDevice(info, raw)
	if netDev {
		applyHealth(&info, gatherHealth(ctx, r))
		info.Neighbors = parseLLDP(gatherLLDP(ctx, r))
		info.Interfaces = parseIfaces(gatherIfaces(ctx, r))
	}
	return info, netDev, mac
}

func gatherOutput(ctx context.Context, r runner, exec []string, shell []string) string {
	var b strings.Builder
	execOK := false
	for _, cmd := range exec {
		if ctx.Err() != nil {
			break
		}
		cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
		out, _ := r.CombinedOutput(cctx, cmd)
		cancel()
		out = strings.TrimSpace(out)
		if out == "" {
			continue
		}
		execOK = true
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(out)
		if looksLikeNetworkOS(out) {
			break
		}
	}
	if !execOK && len(shell) > 0 {
		cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
		out, _ := r.ShellOutput(cctx, shell)
		cancel()
		out = strings.TrimSpace(out)
		if out != "" {
			b.WriteString(out)
		}
	}
	return b.String()
}

func parseSysInfo(s string) device.SysInfo {
	var info device.SysInfo

	if m := reUptimeIOS.FindStringSubmatch(s); len(m) == 3 {
		name := strings.TrimSpace(m[1])
		if hostnameOK(name) {
			info.Hostname = name
		}
		info.Uptime = strings.TrimSpace(m[2])
	}

	if find(&info.Hostname, reJunosHost, s) {
		// labeled Junos hostname wins over uptime-line guesses
	}
	_ = find(&info.Family, reJunosFamily, s)

	switch {
	case find(&info.Model, reJunosModel, s):
	case find(&info.Model, reModelNumber, s):
	case find(&info.Model, reCiscoModel, s):
	case find(&info.Model, reHuaweiModel, s):
	}

	if find(&info.Version, reJunosVer, s) {
		// Junos: 24.4R1-S2.15
	} else if !find(&info.Version, reCiscoVersion, s) {
		_ = find(&info.Version, reHuaweiVer, s)
	}
	if info.Version != "" {
		info.Version = strings.TrimRight(info.Version, ",")
	}

	if m := reUname.FindStringSubmatch(s); len(m) == 3 {
		if info.Hostname == "" {
			info.Hostname = m[1]
		}
		if info.Version == "" {
			info.Version = "Linux " + m[2]
		}
	}
	if m := rePrettyName.FindStringSubmatch(s); len(m) == 2 {
		pretty := strings.Trim(strings.TrimSpace(m[1]), `"'`)
		if info.Version == "" {
			info.Version = pretty
		}
		if info.Model == "" {
			info.Model = pretty
		}
	}

	if info.Uptime == "" {
		if m := reLinuxUptime.FindStringSubmatch(s); len(m) == 2 {
			info.Uptime = strings.TrimSpace(m[1])
		}
	}

	if info.Hostname == "" {
		info.Hostname = standaloneHostname(s)
	}

	if info.Version == "" {
		info.Version = firstUsefulLine(s)
	}
	return info
}

func find(dst *string, re *regexp.Regexp, s string) bool {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return false
	}
	*dst = strings.TrimSpace(m[1])
	return *dst != ""
}

func hostnameOK(name string) bool {
	if name == "" {
		return false
	}
	switch strings.ToLower(name) {
	case "switch", "system", "router", "uptime":
		return false
	}
	return true
}

func standaloneHostname(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.ContainsAny(line, " \t") {
			continue
		}
		if skipLine(line) {
			continue
		}
		// A single token line from `hostname` — reject paths and prompts.
		if strings.ContainsAny(line, "/#$") {
			continue
		}
		if hostnameOK(line) && !strings.Contains(line, "=") {
			return line
		}
	}
	return ""
}

func firstUsefulLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if skipLine(line) {
			continue
		}
		if len(line) > 80 {
			line = line[:80]
		}
		return line
	}
	return ""
}

func skipLine(line string) bool {
	if line == "" {
		return true
	}
	if strings.HasPrefix(line, "%") {
		return true
	}
	l := strings.ToLower(line)
	for _, p := range []string{
		"not found", "invalid", "unknown command", "syntax error",
		"permission denied", "command not",
	} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func looksLikeNetworkOS(s string) bool {
	l := strings.ToLower(s)
	for _, h := range []string{
		"cisco ios", "cisco nexus", "nx-os", "ios-xe", "ios xr",
		"huawei versatile", "vrp (r)",
		"aruba", "procurve", "comware",
		"mikrotik", "routeros",
		"junos", "juniper",
	} {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

func isNetworkDevice(info device.SysInfo, raw string) bool {
	if looksLikeNetworkOS(raw) {
		return true
	}
	m := strings.ToLower(info.Model)
	return strings.HasPrefix(m, "ws-") ||
		strings.HasPrefix(m, "c29") ||
		strings.HasPrefix(m, "ex") ||
		strings.Contains(m, "catalyst")
}

func parseMAC(s string) net.HardwareAddr {
	if m := reLabeledMAC.FindStringSubmatch(s); len(m) == 2 {
		if hw := parseHW(m[1]); hw != nil {
			return hw
		}
	}
	for _, raw := range reAnyMAC.FindAllString(s, -1) {
		if hw := parseHW(raw); hw != nil {
			return hw
		}
	}
	return nil
}

func parseHW(s string) net.HardwareAddr {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) < 6 {
		return nil
	}
	var z byte
	for _, b := range hw[:6] {
		z |= b
	}
	if z == 0 {
		return nil
	}
	out := make(net.HardwareAddr, 6)
	copy(out, hw)
	return out
}
