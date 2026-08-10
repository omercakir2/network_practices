package main

import (
	"fmt"
	"net"
	"os"
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

	fmt.Fprintln(w, "IP\tMAC\tVENDOR\tHOSTNAME\tSTATUS\tTYPE")
	fmt.Fprintln(w, strings.Repeat("─", 15)+"\t"+
		strings.Repeat("─", 17)+"\t"+
		strings.Repeat("─", 14)+"\t"+
		strings.Repeat("─", 16)+"\t"+
		strings.Repeat("─", 6)+"\t"+
		strings.Repeat("─", 14))

	if len(devices) == 0 {
		fmt.Fprintln(w, "(none)\t\t\t\t\t")
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			d.IP.String(),
			mac,
			vendor,
			host,
			d.Status,
			d.Type,
		)
	}
	_ = w.Flush()
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
