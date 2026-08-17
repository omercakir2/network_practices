package pipeline

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/local/network-scanner/internal/device"
)

// stub is a fake discovery method. It records that it ran (via ran) and
// returns the canned devices/error — no sockets, no network.
type stub struct {
	name string
	devs []device.Device
	err  error
	ran  *[]string // append-only log of method names in the order they ran
}

func (s stub) Name() string { return s.name }

func (s stub) Run(ctx context.Context, req Request) ([]device.Device, error) {
	if s.ran != nil {
		*s.ran = append(*s.ran, s.name)
	}
	return s.devs, s.err
}

// softStub is a stub whose errors must not stop the rest of the pipeline
// (same contract as icmpping.Method).
type softStub struct{ stub }

func (s softStub) SoftFail() bool { return true }

// Methods must run in the order they were passed to New (ICMP then ARP).
func TestRunOrder(t *testing.T) {
	var ran []string
	p := New(
		stub{name: "icmp", ran: &ran},
		stub{name: "arp", ran: &ran},
	)
	_, err := p.Run(context.Background(), Request{
		Targets: []net.IP{net.IPv4(192, 168, 1, 1)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(ran) != 2 || ran[0] != "icmp" || ran[1] != "arp" {
		t.Fatalf("order = %v, want [icmp arp]", ran)
	}
}

// A host found by either method appears once. ARP fills MAC/vendor/type
// on the overlapping IP; ICMP-only rows stay without a MAC.
func TestMergeUnion(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	p := New(
		stub{name: "icmp", devs: []device.Device{
			{IP: net.IPv4(192, 168, 1, 10), Status: device.StatusUp},
			{IP: net.IPv4(192, 168, 1, 11), Status: device.StatusUp},
		}},
		stub{name: "arp", devs: []device.Device{
			{IP: net.IPv4(192, 168, 1, 11), MAC: mac, Vendor: "Acme", Type: device.TypeEnd, Status: device.StatusUp},
			{IP: net.IPv4(192, 168, 1, 12), MAC: mac, Vendor: "Acme", Type: device.TypeEnd, Status: device.StatusUp},
		}},
	)
	devs, err := p.Run(context.Background(), Request{
		Targets: []net.IP{net.IPv4(192, 168, 1, 1)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	byIP := map[string]device.Device{}
	for _, d := range devs {
		byIP[d.IP.String()] = d
	}
	if len(byIP) != 3 {
		t.Fatalf("got %d devices, want 3", len(byIP))
	}

	onlyICMP := byIP["192.168.1.10"]
	if len(onlyICMP.MAC) != 0 {
		t.Fatalf("icmp-only MAC = %v, want empty", onlyICMP.MAC)
	}
	if onlyICMP.Type != device.TypeUnknown {
		t.Fatalf("icmp-only Type = %q, want %q", onlyICMP.Type, device.TypeUnknown)
	}

	both := byIP["192.168.1.11"]
	if both.MAC.String() != mac.String() {
		t.Fatalf("both MAC = %v, want %v", both.MAC, mac)
	}
	if both.Vendor != "Acme" {
		t.Fatalf("both Vendor = %q, want Acme", both.Vendor)
	}
	if both.Type != device.TypeEnd {
		t.Fatalf("both Type = %q, want %q", both.Type, device.TypeEnd)
	}

	if _, ok := byIP["192.168.1.12"]; !ok {
		t.Fatal("missing arp-only host 192.168.1.12")
	}
}

// ICMP listen failure is a warning, not a hard stop: ARP still runs and
// its hits are returned.
func TestSoftFailContinues(t *testing.T) {
	var ran []string
	var warned []string
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	p := New(
		softStub{stub{name: "icmp", err: errors.New("listen failed"), ran: &ran}},
		stub{name: "arp", ran: &ran, devs: []device.Device{
			{IP: net.IPv4(10, 0, 0, 2), MAC: mac, Status: device.StatusUp},
		}},
	)
	devs, err := p.Run(context.Background(), Request{
		Targets: []net.IP{net.IPv4(10, 0, 0, 2)},
		Warn: func(method string, err error) {
			warned = append(warned, method)
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(ran) != 2 || ran[0] != "icmp" || ran[1] != "arp" {
		t.Fatalf("order = %v, want [icmp arp]", ran)
	}
	if len(warned) != 1 || warned[0] != "icmp" {
		t.Fatalf("warned = %v, want [icmp]", warned)
	}
	if len(devs) != 1 || devs[0].IP.String() != "10.0.0.2" {
		t.Fatalf("devices = %+v, want arp hit", devs)
	}
}

// A fatal method error (ARP/pcap) aborts the pipeline; later stages never run.
func TestFatalErrorStops(t *testing.T) {
	var ran []string
	want := errors.New("pcap failed")
	p := New(
		stub{name: "icmp", ran: &ran},
		stub{name: "arp", err: want, ran: &ran},
		stub{name: "later", ran: &ran},
	)
	_, err := p.Run(context.Background(), Request{
		Targets: []net.IP{net.IPv4(10, 0, 0, 1)},
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if len(ran) != 2 {
		t.Fatalf("ran = %v, want icmp then arp only", ran)
	}
}

// SSH SysInfo attaches to an ICMP/ARP row. A later empty SysInfo does not wipe it.
// TypeNetwork from SSH upgrades a previous TypeUnknown.
func TestMergeSysInfo(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	info := device.SysInfo{
		User:     "admin",
		Hostname: "core-sw",
		Model:    "WS-C2960",
		Version:  "15.2(7)E",
		Uptime:   "3 weeks",
	}
	p := New(
		stub{name: "arp", devs: []device.Device{
			{IP: net.IPv4(192, 168, 1, 1), MAC: mac, Status: device.StatusUp, Type: device.TypeUnknown},
		}},
		stub{name: "ssh", devs: []device.Device{
			{
				IP:       net.IPv4(192, 168, 1, 1),
				Hostname: "core-sw",
				Status:   device.StatusUp,
				Type:     device.TypeNetwork,
				SysInfo:  info,
			},
		}},
		stub{name: "later", devs: []device.Device{
			{IP: net.IPv4(192, 168, 1, 1), Status: device.StatusUp},
		}},
	)
	devs, err := p.Run(context.Background(), Request{
		Targets: []net.IP{net.IPv4(192, 168, 1, 1)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("got %d devices, want 1", len(devs))
	}
	d := devs[0]
	if d.MAC.String() != mac.String() {
		t.Fatalf("MAC = %v, want %v", d.MAC, mac)
	}
	if d.Hostname != "core-sw" {
		t.Fatalf("Hostname = %q, want core-sw", d.Hostname)
	}
	if d.Type != device.TypeNetwork {
		t.Fatalf("Type = %q, want %q", d.Type, device.TypeNetwork)
	}
	if d.SysInfo != info {
		t.Fatalf("SysInfo = %+v, want %+v", d.SysInfo, info)
	}
}

// New() with no methods is a no-op, not an error.
func TestEmptyPipeline(t *testing.T) {
	devs, err := New().Run(context.Background(), Request{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if devs != nil {
		t.Fatalf("devs = %v, want nil", devs)
	}
}
