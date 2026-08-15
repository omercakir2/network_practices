// network-scanner discovers active hosts on the local IPv4 subnet.
//
// After detecting the interface CIDR it runs a pipeline: ICMP echo (up to 3
// attempts per address) then an ARP sweep. Requires elevated privileges
// (root or CAP_NET_RAW) for raw ICMP and ARP sockets.
//
//	sudo go run .              # scan default local interface
//	sudo ./network-scanner -h  # help
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/local/network-scanner/internal/arpscan"
	"github.com/local/network-scanner/internal/device"
	"github.com/local/network-scanner/internal/enrich"
	"github.com/local/network-scanner/internal/icmpping"
	"github.com/local/network-scanner/internal/iface"
	"github.com/local/network-scanner/internal/pipeline"
)

const (
	appName    = "network-scanner"
	appVersion = "1.1.0"
	// defaultMaxHosts is the -max-hosts default. A /20 is 4094 usable
	// addresses; anything wider needs an explicit raise (or 0 for no cap).
	defaultMaxHosts = 4096
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
		noPing      bool
		pingCount   int
		tcpProbe    bool
		quiet       bool
		showVersion bool
		maxHosts    int
	)

	fs.StringVar(&ifaceName, "interface", "", "network interface to scan (default: auto-detect)")
	fs.StringVar(&ifaceName, "i", "", "short for -interface")
	fs.IntVar(&workers, "workers", 64, "number of concurrent workers per discovery method")
	fs.DurationVar(&timeout, "timeout", 750*time.Millisecond, "per-attempt ICMP wait and ARP reply settle window")
	fs.DurationVar(&scanTimeout, "scan-timeout", 2*time.Minute, "overall scan deadline")
	fs.BoolVar(&noDNS, "no-dns", false, "skip reverse DNS lookups")
	fs.BoolVar(&noPing, "no-ping", false, "skip the ICMP ping stage")
	fs.IntVar(&pingCount, "ping-count", icmpping.DefaultAttempts, "max ICMP echo attempts per IP")
	fs.BoolVar(&tcpProbe, "tcp-probe", false, "also run a lightweight TCP connect probe on discovered hosts")
	fs.BoolVar(&quiet, "quiet", false, "suppress progress output")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	fs.IntVar(&maxHosts, "max-hosts", defaultMaxHosts, "refuse subnets larger than this many hosts (0 = no limit)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `%s — discover active devices on the local subnet

USAGE:
  sudo %s [options]

DESCRIPTION:
  Automatically detects the local network interface and its IPv4 CIDR, then
  runs a discovery pipeline: ICMP echo to every host (max 3 attempts, stop
  on reply) followed by an ARP sweep of the same addresses. Replies yield
  IP and (from ARP) MAC; vendor is looked up from an embedded OUI table;
  hostname is resolved via reverse DNS when possible.

  Only the local subnet is scanned — remote/arbitrary ranges are not supported.

  Raw ICMP and ARP sockets require elevated privileges (root or CAP_NET_RAW).

OPTIONS:
`, appName, appName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
  sudo %s
  sudo %s -i en0
  sudo %s -workers 128 -timeout 300ms -no-dns
  sudo %s -no-ping
  sudo %s -tcp-probe
  sudo %s -max-hosts 65534 -scan-timeout 15m   # allow a /16

`, appName, appName, appName, appName, appName, appName)
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if showVersion {
		fmt.Printf("%s %s\n", appName, appVersion)
		return 0
	}
	if maxHosts < 0 {
		fmt.Fprintf(os.Stderr, "error: -max-hosts must be >= 0 (0 = no limit)\n")
		return 2
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
		if maxHosts > 0 && strings.Contains(err.Error(), "raise the host limit") {
			fmt.Fprintf(os.Stderr, "hint: %s -max-hosts 65534  (0 = no limit; also raise -scan-timeout on large subnets)\n", appName)
		}
		return 1
	}

	if pingCount < 1 {
		pingCount = icmpping.DefaultAttempts
	}

	fmt.Fprintf(os.Stderr, "Interface : %s (%s)\n", local.Interface.Name, local.Interface.HardwareAddr)
	fmt.Fprintf(os.Stderr, "Local IP  : %s\n", local.IP)
	fmt.Fprintf(os.Stderr, "Subnet    : %s (%d hosts)\n", local.CIDR(), len(hosts))
	if noPing {
		fmt.Fprintf(os.Stderr, "Workers   : %d  |  ping: off  |  ARP timeout: %s\n", workers, timeout)
	} else {
		fmt.Fprintf(os.Stderr, "Workers   : %d  |  ping: %d×%s  |  ARP timeout: %s\n", workers, pingCount, timeout, timeout)
	}
	fmt.Fprintln(os.Stderr, "Scanning… (Ctrl-C to abort)")

	// --- Context: overall deadline + signal handling -------------------------
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Progress line on stderr ---------------------------------------------
	var progressFn func(stage string, done, total int)
	if !quiet {
		var (
			lastPct   = -1
			lastStage string
			lastDraw  time.Time
		)
		progressFn = func(stage string, done, total int) {
			if total == 0 {
				return
			}
			if stage != lastStage {
				if lastStage != "" && lastPct != 100 {
					fmt.Fprintln(os.Stderr)
				}
				lastPct = -1
				lastStage = stage
				lastDraw = time.Time{}
			}
			pct := done * 100 / total
			// Whole-percent steps, or at least every 200ms so a /16 does not
			// look frozen between 10% and 11% (655 hosts).
			if pct == lastPct && done != total && time.Since(lastDraw) < 200*time.Millisecond {
				return
			}
			lastPct = pct
			lastDraw = time.Now()
			fmt.Fprintf(os.Stderr, "\r  %s: %d/%d (%d%%)   ", stage, done, total, pct)
			if done == total {
				fmt.Fprintln(os.Stderr)
			}
		}
	}

	// --- Discovery pipeline: ICMP then ARP -----------------------------------
	// Order matters: ping first (soft-fail), then ARP over the same host list.
	// ARP is never filtered to ICMP hits — hosts that drop ping still get probed.
	var methods []pipeline.Method
	if !noPing {
		methods = append(methods, icmpping.Method{Attempts: pingCount})
	}
	methods = append(methods, arpscan.Method{})

	start := time.Now()
	devices, err := pipeline.New(methods...).Run(ctx, pipeline.Request{
		Iface:    local.Interface,
		SrcIP:    local.IP,
		Targets:  hosts,
		Workers:  workers,
		Timeout:  timeout,
		Progress: progressFn,
		Warn: func(method string, err error) {
			fmt.Fprintf(os.Stderr, "warning: %s stage failed (%v); continuing\n", method, err)
		},
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

	// Enrichment runs on the merged list so ICMP-only hosts get DNS too.
	if !noDNS && len(devices) > 0 {
		enrich.Hostnames(ctx, devices, 300*time.Millisecond)
	}
	if tcpProbe && len(devices) > 0 {
		enrich.TCPProbe(ctx, devices, timeout)
	}

	// Include this machine itself if the sweep missed it (common: some
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

// ensureSelf adds the scanning host if it was not observed, or fills in
// MAC/hostname when ICMP found us but ARP did not.
func ensureSelf(devices []device.Device, local *iface.LocalNet) []device.Device {
	self := local.IP.String()
	mac := local.Interface.HardwareAddr
	hostname := ""
	if h, err := os.Hostname(); err == nil {
		hostname = h
	}
	for i, d := range devices {
		if d.IP.Equal(local.IP) || d.IP.String() == self {
			if len(d.MAC) == 0 && len(mac) > 0 {
				devices[i].MAC = append(net.HardwareAddr(nil), mac...)
				devices[i] = enrichSelf(devices[i])
			}
			if devices[i].Hostname == "" && hostname != "" {
				devices[i].Hostname = hostname
			}
			return devices
		}
	}
	d := device.Device{
		IP:     append(local.IP.To4()[:0:0], local.IP.To4()...),
		MAC:    append(mac[:0:0], mac...),
		Status: device.StatusUp,
	}
	d = enrichSelf(d)
	if hostname != "" {
		d.Hostname = hostname
	}
	return append(devices, d)
}
