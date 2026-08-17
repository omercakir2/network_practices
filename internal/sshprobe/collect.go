package sshprobe

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/local/network-scanner/internal/device"
)

const cmdTimeout = 5 * time.Second

var execCommands = []string{
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
	"show version",
	"display version",
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
)

func collect(ctx context.Context, r runner) (device.SysInfo, bool) {
	var b strings.Builder
	execOK := false

	for _, cmd := range execCommands {
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

	if !execOK {
		cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
		out, _ := r.ShellOutput(cctx, shellCommands)
		cancel()
		out = strings.TrimSpace(out)
		if out != "" {
			b.WriteString(out)
		}
	}

	raw := b.String()
	info := parseSysInfo(raw)
	return info, isNetworkDevice(info, raw)
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

	switch {
	case find(&info.Model, reModelNumber, s):
	case find(&info.Model, reCiscoModel, s):
	case find(&info.Model, reHuaweiModel, s):
	}

	if !find(&info.Version, reCiscoVersion, s) {
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
		strings.Contains(m, "catalyst")
}
