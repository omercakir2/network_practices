package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/local/network-scanner/internal/device"
	"github.com/local/network-scanner/internal/oui"
)

// enrichSelf fills vendor/type for the local host entry.
func enrichSelf(d device.Device) device.Device {
	d.Vendor = oui.Lookup(d.MAC)
	d.Type = device.InferType(d.Vendor)
	if d.Status == "" {
		d.Status = device.StatusUp
	}
	return d
}

// printTable writes a readable aligned table to stdout.
func printTable(devices []device.Device) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "IP\tMAC\tVENDOR\tHOSTNAME\tSTATUS\tTYPE\tMODEL\tVERSION")
	fmt.Fprintln(w, strings.Repeat("─", 15)+"\t"+
		strings.Repeat("─", 17)+"\t"+
		strings.Repeat("─", 14)+"\t"+
		strings.Repeat("─", 16)+"\t"+
		strings.Repeat("─", 6)+"\t"+
		strings.Repeat("─", 14)+"\t"+
		strings.Repeat("─", 12)+"\t"+
		strings.Repeat("─", 12))

	if len(devices) == 0 {
		fmt.Fprintln(w, "(none)\t\t\t\t\t\t\t")
		_ = w.Flush()
		return
	}

	for _, d := range devices {
		mac := formatMAC(d.MAC)
		host := d.Hostname
		if host == "" {
			host = "-"
		}
		vendor := d.Vendor
		if vendor == "" {
			vendor = "Unknown"
		}
		model := d.SysInfo.Model
		if model == "" {
			model = "-"
		}
		version := d.SysInfo.Version
		if version == "" {
			version = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			d.IP.String(),
			mac,
			vendor,
			host,
			d.Status,
			d.Type,
			model,
			version,
		)
	}
	_ = w.Flush()
	printSysInfo(devices)
}

func printSysInfo(devices []device.Device) {
	var rows []device.Device
	for _, d := range devices {
		if !d.SysInfo.Empty() {
			rows = append(rows, d)
		}
	}
	if len(rows) == 0 {
		return
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SSH SYSTEM INFO")
	fmt.Fprintln(w, "IP\tUSER\tHOSTNAME\tMODEL\tVERSION\tUPTIME\tCPU\tMEM\tTEMP")
	for _, d := range rows {
		host := d.SysInfo.Hostname
		if host == "" {
			host = dash(d.Hostname)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			d.IP.String(),
			dash(d.SysInfo.User),
			dash(host),
			dash(d.SysInfo.Model),
			dash(d.SysInfo.Version),
			dash(d.SysInfo.Uptime),
			dash(d.SysInfo.CPU),
			dash(d.SysInfo.Memory),
			dash(d.SysInfo.Temp),
		)
	}
	_ = w.Flush()
	printNeighbors(rows)
	printIfaceCounters(rows)
}

func printNeighbors(devices []device.Device) {
	var any bool
	for _, d := range devices {
		if len(d.SysInfo.Neighbors) > 0 {
			any = true
			break
		}
	}
	if !any {
		return
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LLDP NEIGHBORS")
	fmt.Fprintln(w, "HOST\tLOCAL PORT\tREMOTE NAME\tREMOTE PORT\tREMOTE ID")
	for _, d := range devices {
		host := deviceHost(d)
		for _, n := range d.SysInfo.Neighbors {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				host,
				dash(n.LocalPort),
				dash(n.RemoteName),
				dash(n.RemotePort),
				dash(n.RemoteID),
			)
		}
	}
	_ = w.Flush()
}

// printIfaceCounters writes lifetime per-port packet/drop/error counters.
// Down ports with all-zero counters are omitted so a 48-port box stays readable.
func printIfaceCounters(devices []device.Device) {
	type row struct {
		host string
		c    device.IfaceCounters
	}
	var rows []row
	for _, d := range devices {
		host := deviceHost(d)
		for _, c := range d.SysInfo.Interfaces {
			if shouldShowIface(c) {
				rows = append(rows, row{host, c})
			}
		}
	}
	if len(rows) == 0 {
		return
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "INTERFACE COUNTERS (lifetime)")
	fmt.Fprintln(w, "HOST\tPORT\tADMIN\tLINK\tIN PKTS\tOUT PKTS\tIN DROP\tOUT DROP\tIN ERR\tOUT ERR")
	for _, r := range rows {
		c := r.c
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.host,
			dash(c.Name),
			dash(c.Admin),
			dash(c.Oper),
			strconv.FormatUint(c.InPackets, 10),
			strconv.FormatUint(c.OutPackets, 10),
			strconv.FormatUint(c.InDrops, 10),
			strconv.FormatUint(c.OutDrops, 10),
			strconv.FormatUint(c.InErrors, 10),
			strconv.FormatUint(c.OutErrors, 10),
		)
	}
	_ = w.Flush()
}

// shouldShowIface is true for an up link, or any port that already has traffic/errors.
func shouldShowIface(c device.IfaceCounters) bool {
	if strings.EqualFold(c.Oper, "up") {
		return true
	}
	return c.InPackets|c.OutPackets|c.InBytes|c.OutBytes|c.InDrops|c.OutDrops|c.InErrors|c.OutErrors != 0
}

func deviceHost(d device.Device) string {
	if d.SysInfo.Hostname != "" {
		return d.SysInfo.Hostname
	}
	if d.Hostname != "" {
		return d.Hostname
	}
	if d.IP != nil {
		return d.IP.String()
	}
	return "-"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatMAC(mac net.HardwareAddr) string {
	if len(mac) == 0 {
		return "-"
	}
	return strings.ToUpper(mac.String())
}

// ipLess compares two IPv4 addresses numerically.
func ipLess(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return a.String() < b.String()
	}
	for i := 0; i < 4; i++ {
		if a4[i] != b4[i] {
			return a4[i] < b4[i]
		}
	}
	return false
}
