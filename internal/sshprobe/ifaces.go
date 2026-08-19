package sshprobe

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/local/network-scanner/internal/device"
)

var ifaceCommands = []string{
	"show interfaces statistics",
	"cli show interfaces statistics",
	"show interfaces counters",
	"display interface",
}

var (
	reJunosPhys     = regexp.MustCompile(`(?im)^Physical interface:\s*([^,]+),\s*(.+)$`)
	reInPackets     = regexp.MustCompile(`(?im)^\s*Input\s+packets\s*:\s*(\d+)`)
	reOutPackets    = regexp.MustCompile(`(?im)^\s*Output\s+packets\s*:\s*(\d+)`)
	reInBytes       = regexp.MustCompile(`(?im)^\s*Input\s+bytes\s*:\s*(\d+)`)
	reOutBytes      = regexp.MustCompile(`(?im)^\s*Output\s+bytes\s*:\s*(\d+)`)
	reBareErrors    = regexp.MustCompile(`(?im)(?:^|,)\s*Errors:\s*(\d+)`)
	reBareDrops     = regexp.MustCompile(`(?im)(?:^|,)\s*Drops:\s*(\d+)`)
	reCompactInErr  = regexp.MustCompile(`(?i)Input errors:\s*(\d+)`)
	reCompactOutErr = regexp.MustCompile(`(?i)Output errors:\s*(\d+)`)
	reHuaweiHeader  = regexp.MustCompile(`(?im)^(\S+)\s+current state\s*:\s*(.+)$`)
	reHuaweiInput   = regexp.MustCompile(`(?i)Input:\s+(\d+)\s+packets,\s+(\d+)\s+bytes`)
	reHuaweiOutput  = regexp.MustCompile(`(?i)Output:\s+(\d+)\s+packets,\s+(\d+)\s+bytes`)
	reHuaweiErrors  = regexp.MustCompile(`(?i)(\d+)\s+errors`)
	reHuaweiDrops   = regexp.MustCompile(`(?i)(\d+)\s+drops?(?:ped)?`)
)

func gatherIfaces(ctx context.Context, r runner) string {
	execWorked := false
	for _, cmd := range ifaceCommands {
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
		if len(parseIfaces(out)) > 0 {
			return out
		}
	}
	if execWorked {
		return ""
	}
	cmds := append([]string{"terminal length 0"}, ifaceCommands[:2]...)
	cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	out, _ := r.ShellOutput(cctx, cmds)
	cancel()
	return strings.TrimSpace(out)
}

func parseIfaces(s string) []device.IfaceCounters {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "physical interface:"):
		return parseJunosIfaces(s)
	case strings.Contains(l, "inucastpkts") || strings.Contains(l, "inoctets"):
		return parseCiscoIfaces(s)
	case strings.Contains(l, "current state") && strings.Contains(l, "input:"):
		return parseHuaweiIfaces(s)
	default:
		return nil
	}
}

func parseJunosIfaces(s string) []device.IfaceCounters {
	var out []device.IfaceCounters
	for _, block := range splitMarkedBlocks(s, "physical interface:") {
		if c, ok := parseJunosIfaceBlock(block); ok {
			out = append(out, c)
		}
	}
	return out
}

func parseJunosIfaceBlock(block string) (device.IfaceCounters, bool) {
	phys := cutAtFold(block, "logical interface")
	m := reJunosPhys.FindStringSubmatch(phys)
	if len(m) < 3 {
		return device.IfaceCounters{}, false
	}
	name := physicalIfd(m[1])
	if name == "" {
		return device.IfaceCounters{}, false
	}
	c := device.IfaceCounters{
		Name:  name,
		Admin: junosAdmin(m[2]),
		Oper:  junosOper(m[2]),
	}
	traffic := sectionBetween(phys, "traffic statistics:", "ipv6", "input errors:", "output errors:")
	if traffic == "" {
		traffic = phys
	}
	c.InPackets = firstUint(reInPackets, traffic)
	c.OutPackets = firstUint(reOutPackets, traffic)
	c.InBytes = firstUint(reInBytes, traffic)
	c.OutBytes = firstUint(reOutBytes, traffic)

	inErr := sectionBetween(phys, "input errors:", "output errors:")
	outErr := sectionBetween(phys, "output errors:")
	if reBareErrors.MatchString(inErr) || reBareDrops.MatchString(inErr) {
		c.InErrors = firstUint(reBareErrors, inErr)
		c.InDrops = firstUint(reBareDrops, inErr)
	} else {
		c.InErrors = firstUint(reCompactInErr, phys)
	}
	if reBareErrors.MatchString(outErr) || reBareDrops.MatchString(outErr) {
		c.OutErrors = firstUint(reBareErrors, outErr)
		c.OutDrops = firstUint(reBareDrops, outErr)
	} else {
		c.OutErrors = firstUint(reCompactOutErr, phys)
	}
	return c, true
}

func junosAdmin(rest string) string {
	l := strings.ToLower(rest)
	switch {
	case strings.Contains(l, "administratively down"), strings.Contains(l, "disabled"):
		return "down"
	case strings.Contains(l, "enabled"):
		return "up"
	}
	return ""
}

func junosOper(rest string) string {
	l := strings.ToLower(rest)
	switch {
	case strings.Contains(l, "physical link is up"):
		return "up"
	case strings.Contains(l, "physical link is down"):
		return "down"
	}
	return ""
}

func parseCiscoIfaces(s string) []device.IfaceCounters {
	byName := map[string]*device.IfaceCounters{}
	var order []string
	var cols []string
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			cols = nil
			continue
		}
		if ciscoHeader(fields) {
			cols = normalizeCiscoCols(fields)
			continue
		}
		if cols == nil || !ciscoPort(fields[0]) {
			continue
		}
		name := physicalIfd(fields[0])
		if name == "" {
			continue
		}
		c, ok := byName[name]
		if !ok {
			c = &device.IfaceCounters{Name: name}
			byName[name] = c
			order = append(order, name)
		}
		applyCiscoRow(c, cols, fields)
	}
	if len(order) == 0 {
		return nil
	}
	out := make([]device.IfaceCounters, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

func ciscoHeader(fields []string) bool {
	for _, f := range fields {
		switch strings.ToLower(f) {
		case "inoctets", "inucastpkts", "outoctets", "outucastpkts",
			"fcs-err", "align-err", "xmit-err", "rcv-err", "outdiscards":
			return true
		}
	}
	return false
}

func normalizeCiscoCols(fields []string) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = strings.ToLower(f)
	}
	return out
}

func ciscoPort(s string) bool {
	if s == "" {
		return false
	}
	switch strings.ToLower(s) {
	case "port", "interface", "port-id":
		return false
	}
	r := rune(s[0])
	return unicode.IsLetter(r)
}

func applyCiscoRow(c *device.IfaceCounters, cols, fields []string) {
	n := len(cols)
	if len(fields) < n {
		n = len(fields)
	}
	var inPkts, outPkts uint64
	for i := 1; i < n; i++ {
		v, ok := parseUint(fields[i])
		if !ok {
			continue
		}
		switch cols[i] {
		case "inoctets":
			c.InBytes = v
		case "outoctets":
			c.OutBytes = v
		case "inucastpkts", "inmcastpkts", "inbcastpkts":
			inPkts += v
		case "outucastpkts", "outmcastpkts", "outbcastpkts":
			outPkts += v
		case "outdiscards":
			c.OutDrops = v
		case "fcs-err", "align-err", "rcv-err":
			c.InErrors += v
		case "xmit-err":
			c.OutErrors += v
		}
	}
	if inPkts > 0 {
		c.InPackets = inPkts
	}
	if outPkts > 0 {
		c.OutPackets = outPkts
	}
}

func parseHuaweiIfaces(s string) []device.IfaceCounters {
	var out []device.IfaceCounters
	for _, block := range splitHuaweiIfaceBlocks(s) {
		if c, ok := parseHuaweiIfaceBlock(block); ok {
			out = append(out, c)
		}
	}
	return out
}

func splitHuaweiIfaceBlocks(s string) []string {
	var starts []int
	for _, loc := range reHuaweiHeader.FindAllStringIndex(s, -1) {
		starts = append(starts, loc[0])
	}
	if len(starts) == 0 {
		return nil
	}
	var blocks []string
	for i, start := range starts {
		end := len(s)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		blocks = append(blocks, s[start:end])
	}
	return blocks
}

func parseHuaweiIfaceBlock(block string) (device.IfaceCounters, bool) {
	m := reHuaweiHeader.FindStringSubmatch(block)
	if len(m) < 3 {
		return device.IfaceCounters{}, false
	}
	name := physicalIfd(m[1])
	if name == "" {
		return device.IfaceCounters{}, false
	}
	c := device.IfaceCounters{Name: name}
	c.Admin, c.Oper = huaweiState(m[2])
	if in := reHuaweiInput.FindStringSubmatch(block); len(in) == 3 {
		c.InPackets = mustUint(in[1])
		c.InBytes = mustUint(in[2])
	}
	if outm := reHuaweiOutput.FindStringSubmatch(block); len(outm) == 3 {
		c.OutPackets = mustUint(outm[1])
		c.OutBytes = mustUint(outm[2])
	}
	applyHuaweiErrDrops(&c, block)
	return c, true
}

func huaweiState(s string) (admin, oper string) {
	l := strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(l, "administratively"):
		return "down", "down"
	case strings.HasPrefix(l, "up"):
		return "up", "up"
	case strings.HasPrefix(l, "down"):
		return "up", "down"
	}
	return "", ""
}

func applyHuaweiErrDrops(c *device.IfaceCounters, block string) {
	// Associate errors/drops with the preceding Input:/Output: section.
	last := ""
	for _, line := range strings.Split(block, "\n") {
		ll := strings.ToLower(line)
		switch {
		case strings.Contains(ll, "input:"):
			last = "in"
		case strings.Contains(ll, "output:"):
			last = "out"
		}
		if last == "" {
			continue
		}
		if em := reHuaweiErrors.FindStringSubmatch(line); len(em) == 2 {
			if last == "in" {
				c.InErrors = mustUint(em[1])
			} else {
				c.OutErrors = mustUint(em[1])
			}
		}
		if dm := reHuaweiDrops.FindStringSubmatch(line); len(dm) == 2 {
			if last == "in" {
				c.InDrops = mustUint(dm[1])
			} else {
				c.OutDrops = mustUint(dm[1])
			}
		}
	}
}

func physicalIfd(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	i := strings.LastIndex(name, ".")
	if i <= 0 || i == len(name)-1 {
		return name
	}
	if !allDigits(name[i+1:]) {
		return name
	}
	return name[:i]
}

func splitMarkedBlocks(s, mark string) []string {
	ls := strings.ToLower(s)
	mark = strings.ToLower(mark)
	var starts []int
	for idx := 0; ; {
		i := strings.Index(ls[idx:], mark)
		if i < 0 {
			break
		}
		starts = append(starts, idx+i)
		idx += i + len(mark)
	}
	if len(starts) == 0 {
		return nil
	}
	var blocks []string
	for i, start := range starts {
		end := len(s)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		blocks = append(blocks, s[start:end])
	}
	return blocks
}

func cutAtFold(s, mark string) string {
	l := strings.ToLower(s)
	if i := strings.Index(l, strings.ToLower(mark)); i >= 0 {
		return s[:i]
	}
	return s
}

func sectionBetween(s, start string, ends ...string) string {
	ls := strings.ToLower(s)
	start = strings.ToLower(start)
	i := strings.Index(ls, start)
	if i < 0 {
		return ""
	}
	body := s[i+len(start):]
	lb := strings.ToLower(body)
	endAt := len(body)
	for _, e := range ends {
		if e == "" {
			continue
		}
		if j := strings.Index(lb, strings.ToLower(e)); j >= 0 && j < endAt {
			endAt = j
		}
	}
	return body[:endAt]
}

func firstUint(re *regexp.Regexp, s string) uint64 {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return 0
	}
	return mustUint(m[1])
}

func mustUint(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

func parseUint(s string) (uint64, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n, err == nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
