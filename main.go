// network-scanner discovers active hosts on the local IPv4 subnet via ARP.
//
// Requires elevated privileges (root or CAP_NET_RAW) to open raw ARP sockets.
//
//	sudo go run .              # scan default local interface
//	sudo ./network-scanner -h  # help
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/local/network-scanner/internal/arpscan"
	"github.com/local/network-scanner/internal/device"
	"github.com/local/network-scanner/internal/iface"
)

const (
	appName    = "network-scanner"
	appVersion = "1.0.0"
	// Refuse to expand absurdly large subnets (e.g. a /8 picked by mistake).
	maxHosts = 4096
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		ifaceName   string
		workers     int
		timeout     time.Duration
		scanTimeout time.Duration
		noDNS       bool
		tcpProbe    bool
		quiet       bool
		showVersion bool
	)

	fs.StringVar(&ifaceName, "interface", "", "network interface to scan (default: auto-detect)")
	fs.StringVar(&ifaceName, "i", "", "short for -interface")
	fs.IntVar(&workers, "workers", 64, "number of concurrent ARP workers")
	fs.DurationVar(&timeout, "timeout", 750*time.Millisecond, "how long to wait for ARP replies after sending requests")
	fs.DurationVar(&scanTimeout, "scan-timeout", 2*time.Minute, "overall scan deadline")
	fs.BoolVar(&noDNS, "no-dns", false, "skip reverse DNS lookups")
	fs.BoolVar(&tcpProbe, "tcp-probe", false, "also run a lightweight TCP connect probe on discovered hosts")
	fs.BoolVar(&quiet, "quiet", false, "suppress progress output")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `%s — discover active devices on the local subnet (ARP scan)

USAGE:
  sudo %s [options]

DESCRIPTION:
  Automatically detects the local network interface and its IPv4 CIDR, then
  sends ARP requests to every host address on that subnet. Replies yield IP
  and MAC; vendor is looked up from an embedded OUI table; hostname is
  resolved via reverse DNS when possible.

  Only the local subnet is scanned — remote/arbitrary ranges are not supported.

  Raw ARP sockets require elevated privileges (root or CAP_NET_RAW).

OPTIONS:
`, appName, appName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
  sudo %s
  sudo %s -i en0
  sudo %s -workers 128 -timeout 300ms -no-dns
  sudo %s -tcp-probe

`, appName, appName, appName, appName)
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if showVersion {
		fmt.Printf("%s %s\n", appName, appVersion)
		return 0
	}

	// --- Detect local interface + IPv4 subnet ---------------------------------
	local, err := iface.Detect(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: interface detection failed: %v\n", err)
		return 1
	}

	hosts, err := local.Hosts(maxHosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "Interface : %s (%s)\n", local.Interface.Name, local.Interface.HardwareAddr)
	fmt.Fprintf(os.Stderr, "Local IP  : %s\n", local.IP)
	fmt.Fprintf(os.Stderr, "Subnet    : %s (%d hosts)\n", local.CIDR(), len(hosts))
	fmt.Fprintf(os.Stderr, "Workers   : %d  |  ARP timeout: %s\n", workers, timeout)
	fmt.Fprintln(os.Stderr, "Scanning… (Ctrl-C to abort)")

	// --- Context: overall deadline + signal handling -------------------------
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Progress line on stderr ---------------------------------------------
	var progressFn func(done, total int)
	if !quiet {
		var lastPct = -1
		progressFn = func(done, total int) {
			if total == 0 {
				return
			}
			pct := done * 100 / total
			// Throttle redraws to whole-percent steps.
			if pct == lastPct && done != total {
				return
			}
			lastPct = pct
			fmt.Fprintf(os.Stderr, "\r  progress: %d/%d (%d%%)   ", done, total, pct)
			if done == total {
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	// --- Run ARP scan --------------------------------------------------------
	start := time.Now()
	devices, err := arpscan.Scan(ctx, local.Interface, local.IP, hosts, arpscan.Options{
		Workers:       workers,
		Timeout:       timeout,
		ResolveDNS:    !noDNS,
		SecondaryPing: tcpProbe,
		Progress:      progressFn,
	})
	elapsed := time.Since(start)

	if err != nil {
		if iface.IsPermissionError(err) {
			printPrivilegeHelp(err)
			return 1
		}
		// pcap/libpcap often surfaces privilege problems with platform-specific text.
		errText := strings.ToLower(err.Error())
		if strings.Contains(errText, "permission") ||
			strings.Contains(errText, "not permitted") ||
			strings.Contains(errText, "bpf") ||
			strings.Contains(errText, "operation not supported") {
			printPrivilegeHelp(err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 1
	}

	// Include this machine itself if the ARP sweep missed it (common: some
	// stacks do not reply to ARP for their own address on the same host).
	devices = ensureSelf(devices, local)

	// Sort by IPv4 numeric order.
	sort.Slice(devices, func(i, j int) bool {
		return ipLess(devices[i].IP, devices[j].IP)
	})

	fmt.Fprintf(os.Stderr, "Found %d device(s) in %s\n\n", len(devices), elapsed.Round(time.Millisecond))

	printTable(devices)

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\nnote: scan ended early (timeout or interrupt); results may be incomplete")
	}
	return 0
}

func printPrivilegeHelp(err error) {
	fmt.Fprintf(os.Stderr, `error: insufficient privileges to open a capture device: %v

ARP scanning uses libpcap and requires elevated privileges.

  macOS / Linux:
    sudo %s [options]

  Linux (optional, avoid full root):
    sudo setcap cap_net_raw,cap_net_admin+ep ./network-scanner
    ./network-scanner [options]

  macOS (optional): install Wireshark ChmodBPF and join the access_bpf group
  so capture works without sudo after logout/login.
`, err, appName)
}

// ensureSelf adds the scanning host if it was not observed via ARP
// (some stacks do not answer ARP for their own address).
func ensureSelf(devices []device.Device, local *iface.LocalNet) []device.Device {
	self := local.IP.String()
	for _, d := range devices {
		if d.IP.Equal(local.IP) || d.IP.String() == self {
			return devices
		}
	}
	mac := local.Interface.HardwareAddr
	d := device.Device{
		IP:     append(local.IP.To4()[:0:0], local.IP.To4()...),
		MAC:    append(mac[:0:0], mac...),
		Status: device.StatusUp,
	}
	d = enrichSelf(d)
	if h, err := os.Hostname(); err == nil && h != "" {
		d.Hostname = h
	}
	return append(devices, d)
}
