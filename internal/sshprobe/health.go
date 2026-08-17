package sshprobe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/local/network-scanner/internal/device"
)

// Health snapshot: CPU / memory / temperature. First command that fills
// the interesting fields wins; later commands only fill blanks.
var healthCommands = []string{
	"show chassis routing-engine", // Junos: CPU, memory, temp
	"cli show chassis routing-engine",
	"show processes cpu",     // Cisco IOS
	"show memory statistics", // Cisco memory
	"show system resources",  // NX-OS
	"display cpu-usage",      // Huawei
	"display memory-usage",
}

var (
	reCiscoCPU    = regexp.MustCompile(`(?i)CPU utilization for five seconds:\s*([0-9.]+)\s*%(?:\s*/\s*([0-9.]+)%)?;\s*one minute:\s*([0-9.]+)\s*%;\s*five minutes:\s*([0-9.]+)\s*%`)
	reHuaweiCPU   = regexp.MustCompile(`(?i)CPU utilization(?: for five seconds)?:\s*([0-9.]+)\s*%(?:;\s*one minute:\s*([0-9.]+)\s*%)?(?:;\s*five minutes:\s*([0-9.]+)\s*%)?`)
	reJunosIdle   = regexp.MustCompile(`(?im)^\s*Idle\s+(\d+)\s+percent`)
	reJunosUser   = regexp.MustCompile(`(?im)^\s*User\s+(\d+)\s+percent`)
	reJunosKern   = regexp.MustCompile(`(?im)^\s*Kernel\s+(\d+)\s+percent`)
	reJunosMem    = regexp.MustCompile(`(?i)Memory utilization\s+(\d+)\s+percent`)
	reJunosTemp   = regexp.MustCompile(`(?im)^\s*Temperature\s+(\d+)\s+degrees C`)
	reNXOSCPU     = regexp.MustCompile(`(?i)CPU states\s*:\s*([0-9.]+)%\s*user,\s*([0-9.]+)%\s*kernel,\s*([0-9.]+)%\s*idle`)
	reNXOSMem     = regexp.MustCompile(`(?i)Memory usage:\s*(\d+)K total,\s*(\d+)K used`)
	reHuaweiMem   = regexp.MustCompile(`(?i)Memory utilization:\s*([0-9.]+)\s*%`)
	reCiscoMem    = regexp.MustCompile(`(?i)Processor(?:\s+Pool)?\s+Total:\s*(\d+)\s+Used:\s*(\d+)`)
	reCiscoMemRow = regexp.MustCompile(`(?im)^Processor\s+\S+\s+(\d+)\s+(\d+)`)
)

func gatherHealth(ctx context.Context, r runner) string {
	var b strings.Builder
	execWorked := false
	for _, cmd := range healthCommands {
		if ctx.Err() != nil {
			break
		}
		cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
		out, err := r.CombinedOutput(cctx, cmd)
		cancel()
		out = strings.TrimSpace(out)
		if err == nil || out != "" {
			execWorked = true
		}
		if out == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(out)
		var tmp device.SysInfo
		applyHealth(&tmp, b.String())
		if tmp.CPU != "" && tmp.Memory != "" {
			return b.String()
		}
	}
	if !execWorked {
		cmds := []string{"terminal length 0", "show chassis routing-engine", "show processes cpu"}
		cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
		out, _ := r.ShellOutput(cctx, cmds)
		cancel()
		return strings.TrimSpace(out)
	}
	return b.String()
}

func applyHealth(info *device.SysInfo, s string) {
	if info.CPU == "" {
		info.CPU = parseCPU(s)
	}
	if info.Memory == "" {
		info.Memory = parseMemory(s)
	}
	if info.Temp == "" {
		info.Temp = parseTemp(s)
	}
}

func parseCPU(s string) string {
	if m := reCiscoCPU.FindStringSubmatch(s); len(m) >= 5 {
		return fmt.Sprintf("5s %s%% / 1m %s%% / 5m %s%%", trimPct(m[1]), trimPct(m[3]), trimPct(m[4]))
	}
	if m := reNXOSCPU.FindStringSubmatch(s); len(m) == 4 {
		return fmt.Sprintf("user %s%% idle %s%%", trimPct(m[1]), trimPct(m[3]))
	}
	if m := reJunosIdle.FindStringSubmatch(s); len(m) == 2 {
		idle, _ := strconv.Atoi(m[1])
		user := labeledPct(reJunosUser, s)
		kern := labeledPct(reJunosKern, s)
		switch {
		case user != "" && kern != "":
			return fmt.Sprintf("user %s%% kernel %s%% idle %d%%", user, kern, idle)
		case user != "":
			return fmt.Sprintf("user %s%% idle %d%%", user, idle)
		default:
			busy := 100 - idle
			if busy < 0 {
				busy = 0
			}
			return fmt.Sprintf("%d%% busy (idle %d%%)", busy, idle)
		}
	}
	if m := reHuaweiCPU.FindStringSubmatch(s); len(m) >= 2 && m[1] != "" {
		if m[2] != "" && m[3] != "" {
			return fmt.Sprintf("5s %s%% / 1m %s%% / 5m %s%%", trimPct(m[1]), trimPct(m[2]), trimPct(m[3]))
		}
		return trimPct(m[1]) + "%"
	}
	return ""
}

func parseMemory(s string) string {
	if m := reJunosMem.FindStringSubmatch(s); len(m) == 2 {
		return m[1] + "%"
	}
	if m := reHuaweiMem.FindStringSubmatch(s); len(m) == 2 {
		return trimPct(m[1]) + "%"
	}
	if m := reNXOSMem.FindStringSubmatch(s); len(m) == 3 {
		if p := pctOf(m[1], m[2]); p != "" {
			return p
		}
	}
	if m := reCiscoMem.FindStringSubmatch(s); len(m) == 3 {
		if p := pctOf(m[1], m[2]); p != "" {
			return p
		}
	}
	if m := reCiscoMemRow.FindStringSubmatch(s); len(m) == 3 {
		if p := pctOf(m[1], m[2]); p != "" {
			return p
		}
	}
	return ""
}

func pctOf(totalS, usedS string) string {
	total, err1 := strconv.ParseFloat(totalS, 64)
	used, err2 := strconv.ParseFloat(usedS, 64)
	if err1 != nil || err2 != nil || total <= 0 {
		return ""
	}
	return fmt.Sprintf("%.0f%%", used*100/total)
}

func parseTemp(s string) string {
	if m := reJunosTemp.FindStringSubmatch(s); len(m) == 2 {
		return m[1] + "C"
	}
	return ""
}

func labeledPct(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func trimPct(s string) string {
	return strings.TrimSpace(s)
}
