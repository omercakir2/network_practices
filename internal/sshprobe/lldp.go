package sshprobe

import (
	"context"
	"strings"
	"unicode"

	"github.com/local/network-scanner/internal/device"
)

var lldpCommands = []string{
	"show lldp neighbors",
	"cli show lldp neighbors",
	"show lldp neighbor-information",
	"display lldp neighbor brief",
	"display lldp neighbor",
}

func gatherLLDP(ctx context.Context, r runner) string {
	execWorked := false
	for _, cmd := range lldpCommands {
		if ctx.Err() != nil {
			return ""
		}
		cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
		out, err := r.CombinedOutput(cctx, cmd)
		cancel()
		out = strings.TrimSpace(out)
		if err == nil || out != "" {
			execWorked = true
		}
		if len(parseLLDP(out)) > 0 {
			return out
		}
	}
	if execWorked {
		return ""
	}
	cmds := append([]string{"terminal length 0"}, lldpCommands[:2]...)
	cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	out, _ := r.ShellOutput(cctx, cmds)
	cancel()
	return strings.TrimSpace(out)
}

func parseLLDP(s string) []device.Neighbor {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "device id") && strings.Contains(l, "local intf"):
		return parseCiscoLLDPTable(s)
	case strings.Contains(l, "local intf:") && strings.Contains(l, "system name:"):
		return parseCiscoLLDPDetail(s)
	case strings.Contains(l, "neighbor dev"):
		return parseHuaweiLLDPTable(s)
	case strings.Contains(l, "chassis id") &&
		(strings.Contains(l, "local interface") || strings.Contains(l, "system name")):
		return parseJunosLLDPTable(s)
	default:
		return nil
	}
}

func parseCiscoLLDPTable(s string) []device.Neighbor {
	lines := strings.Split(s, "\n")
	start := -1
	for i, line := range lines {
		l := strings.ToLower(line)
		if strings.Contains(l, "device id") && strings.Contains(l, "local intf") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var out []device.Neighbor
	for _, line := range lines[start:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "total") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		hold := -1
		for i, f := range fields {
			if isHoldTime(f) {
				hold = i
				break
			}
		}
		if hold < 2 || hold+1 >= len(fields) {
			continue
		}
		n := device.Neighbor{
			RemoteName: strings.Join(fields[:hold-1], " "),
			LocalPort:  fields[hold-1],
			RemotePort: fields[len(fields)-1],
		}
		if n.RemoteName == "" || n.LocalPort == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}

func parseCiscoLLDPDetail(s string) []device.Neighbor {
	blocks := splitLLDPBlocks(s)
	var out []device.Neighbor
	for _, b := range blocks {
		n := device.Neighbor{
			LocalPort:  labeledField(b, "local intf"),
			RemoteName: labeledField(b, "system name"),
			RemotePort: labeledField(b, "port id"),
			RemoteID:   labeledField(b, "chassis id"),
		}
		if n.LocalPort == "" && n.RemoteName == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}

func parseJunosLLDPTable(s string) []device.Neighbor {
	lines := strings.Split(s, "\n")
	start := -1
	for i, line := range lines {
		l := strings.ToLower(line)
		if strings.Contains(l, "local interface") ||
			(strings.Contains(l, "interface") && strings.Contains(l, "chassis id")) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var out []device.Neighbor
	for _, line := range lines[start:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "{") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		n := device.Neighbor{LocalPort: fields[0]}
		idAt := -1
		for i, f := range fields[1:] {
			if parseHW(f) != nil {
				idAt = i + 1
				n.RemoteID = f
				break
			}
		}
		if idAt >= 0 && idAt+1 < len(fields) {
			rest := fields[idAt+1:]
			if len(rest) >= 2 {
				n.RemotePort = rest[0]
				n.RemoteName = strings.Join(rest[1:], " ")
			} else if len(rest) == 1 {
				n.RemoteName = rest[0]
			}
		} else if len(fields) >= 3 {
			n.RemotePort = fields[len(fields)-2]
			n.RemoteName = fields[len(fields)-1]
		}
		if n.RemoteName == "" && n.RemoteID == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}

func parseHuaweiLLDPTable(s string) []device.Neighbor {
	lines := strings.Split(s, "\n")
	start := -1
	for i, line := range lines {
		l := strings.ToLower(line)
		if strings.Contains(l, "neighbor dev") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var out []device.Neighbor
	for _, line := range lines[start:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		n := device.Neighbor{
			LocalPort:  fields[0],
			RemoteName: fields[1],
			RemotePort: fields[2],
		}
		out = append(out, n)
	}
	return out
}

func isHoldTime(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func labeledField(s, key string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:i]), key) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

func splitLLDPBlocks(s string) []string {
	var blocks []string
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		blocks = append(blocks, strings.Join(cur, "\n"))
		cur = nil
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.Trim(line, "-") == "" && strings.Contains(line, "-") {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return blocks
}
