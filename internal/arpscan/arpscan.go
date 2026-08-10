// Package arpscan performs a concurrent ARP sweep of a local IPv4 subnet.
//
// How it works:
//  1. Open a live pcap handle on the chosen interface (needs root / CAP_NET_RAW
//     or BPF group membership on macOS).
//  2. Start one reader goroutine that collects ARP replies.
//  3. A pool of workers serializes and writes ARP request frames for every
//     host address in the subnet (writes are mutex-protected on the handle).
//  4. After all requests are sent, wait a short settle period for stragglers,
//     then stop the reader and return deduplicated results.
//
// ARP is the source of truth for L2 presence on the local segment. Hosts that
// block ICMP still answer ARP if they are on-link.
//
// Built on github.com/google/gopacket (libpcap). Requires CGO.
package arpscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/local/network-scanner/internal/device"
	"github.com/local/network-scanner/internal/oui"
)

// Options controls scan behaviour.
type Options struct {
	// Workers is the number of concurrent ARP senders (default 64).
	Workers int
	// Timeout is how long to wait after the last request for late replies
	// (default 750ms). Per-write operations use a short pcap timeout.
	Timeout time.Duration
	// ResolveDNS enables best-effort reverse DNS for each hit.
	ResolveDNS bool
	// DNSTimeout bounds each reverse lookup (default 300ms).
	DNSTimeout time.Duration
	// SecondaryPing enables a lightweight concurrent TCP connect probe
	// against common ports. ARP remains the authority for discovery.
	SecondaryPing bool
	// Progress, if non-nil, is called with (done, total) as each request is sent.
	Progress func(done, total int)
}

// Scan ARP-probes every address in targets on the given interface.
// srcIP must be the IPv4 address of iface used as the ARP sender protocol address.
func Scan(ctx context.Context, iface *net.Interface, srcIP net.IP, targets []net.IP, opt Options) ([]device.Device, error) {
	opt = defaults(opt)
	srcIP = srcIP.To4()
	if srcIP == nil {
		return nil, errors.New("source IP must be IPv4")
	}
	if len(iface.HardwareAddr) == 0 {
		return nil, fmt.Errorf("interface %s has no MAC address", iface.Name)
	}
	if len(targets) == 0 {
		return nil, nil
	}

	// OpenLive snaplen, promiscuous, read timeout.
	// A non-zero read timeout lets the packet source unblock periodically so
	// we can notice context cancellation.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, 200*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open pcap on %s: %w", iface.Name, err)
	}
	// Closed explicitly after the settle window so the reader unblocks;
	// use a once-guard so we never double-close.
	var closeOnce sync.Once
	closeHandle := func() { closeOnce.Do(func() { handle.Close() }) }
	defer closeHandle()

	// Only Ethernet ARP traffic — keeps the reader cheap.
	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}

	// Shared result map guarded by mu.
	var (
		mu   sync.Mutex
		seen = make(map[string]net.HardwareAddr, 64)
	)

	// Reader: collect ARP replies until stop is closed and the packet loop ends.
	stop := make(chan struct{})
	var readerDone sync.WaitGroup
	readerDone.Add(1)
	go func() {
		defer readerDone.Done()
		readARP(handle, iface.HardwareAddr, stop, func(ip net.IP, mac net.HardwareAddr) {
			key := ip.String()
			mu.Lock()
			if _, exists := seen[key]; !exists {
				seen[key] = append(net.HardwareAddr(nil), mac...)
			}
			mu.Unlock()
		})
	}()

	// Pre-build the constant parts of the Ethernet + ARP request frames.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpReq := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// pcap handles are not safe for concurrent WritePacketData — serialize writes.
	var writeMu sync.Mutex
	writeARP := func(dst net.IP) error {
		ip4 := dst.To4()
		if ip4 == nil {
			return nil
		}
		// Copy template; mutate destination protocol address.
		req := arpReq
		req.DstProtAddress = []byte(ip4)

		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, serializeOpts, &eth, &req); err != nil {
			return err
		}
		writeMu.Lock()
		err := handle.WritePacketData(buf.Bytes())
		writeMu.Unlock()
		return err
	}

	// Worker pool sends requests concurrently (writes still serialized).
	jobs := make(chan net.IP, opt.Workers*2)
	var sendErr atomic.Value // error
	var sent atomic.Int64
	total := len(targets)

	workers := opt.Workers
	if workers > total {
		workers = total
	}
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := writeARP(ip); err != nil {
					sendErr.Store(err)
					return
				}
				n := int(sent.Add(1))
				if opt.Progress != nil {
					opt.Progress(n, total)
				}
			}
		}()
	}

	// Feed targets.
feed:
	for _, ip := range targets {
		if ctx.Err() != nil {
			break
		}
		if sendErr.Load() != nil {
			break
		}
		select {
		case <-ctx.Done():
			break feed
		case jobs <- ip:
		}
	}
	close(jobs)
	wg.Wait()

	// Allow late replies to arrive after the last request.
	settle := opt.Timeout
	timer := time.NewTimer(settle)
	select {
	case <-ctx.Done():
		timer.Stop()
	case <-timer.C:
	}

	// Stop the reader and wait for it to exit.
	close(stop)
	// Closing the handle unblocks any pending ReadPacketData.
	closeHandle()
	readerDone.Wait()

	if err, _ := sendErr.Load().(error); err != nil {
		return nil, fmt.Errorf("send ARP: %w", err)
	}

	mu.Lock()
	devices := make([]device.Device, 0, len(seen))
	for ipStr, mac := range seen {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			continue
		}
		d := device.Device{
			IP:     append(net.IP(nil), ip...),
			MAC:    append(net.HardwareAddr(nil), mac...),
			Vendor: oui.Lookup(mac),
			Status: device.StatusUp,
		}
		d.Type = device.InferType(d.Vendor)
		devices = append(devices, d)
	}
	mu.Unlock()

	if opt.ResolveDNS && len(devices) > 0 {
		resolveHostnames(ctx, devices, opt.DNSTimeout)
	}
	if opt.SecondaryPing && len(devices) > 0 {
		secondaryProbe(ctx, devices, opt.Timeout)
	}

	return devices, nil
}

// readARP consumes packets from handle until stop is closed.
// onReply is invoked for each ARP reply not sourced from our own MAC.
func readARP(handle *pcap.Handle, selfMAC net.HardwareAddr, stop <-chan struct{}, onReply func(net.IP, net.HardwareAddr)) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	// Disable NoCopy so packet data remains valid after the next read.
	src.DecodeOptions.Lazy = true
	packets := src.Packets()

	for {
		select {
		case <-stop:
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if packet == nil {
				continue
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			a := arpLayer.(*layers.ARP)
			// Accept replies; also accept requests from others (gratuitous/info).
			if a.Operation != layers.ARPReply {
				continue
			}
			// Ignore frames we originated.
			if bytes.Equal(selfMAC, a.SourceHwAddress) {
				continue
			}
			if len(a.SourceProtAddress) != 4 || len(a.SourceHwAddress) < 6 {
				continue
			}
			ip := net.IP(append([]byte(nil), a.SourceProtAddress...))
			mac := net.HardwareAddr(append([]byte(nil), a.SourceHwAddress...))
			onReply(ip, mac)
		}
	}
}

func defaults(o Options) Options {
	if o.Workers <= 0 {
		o.Workers = 64
	}
	if o.Timeout <= 0 {
		o.Timeout = 750 * time.Millisecond
	}
	if o.DNSTimeout <= 0 {
		o.DNSTimeout = 300 * time.Millisecond
	}
	return o
}

// resolveHostnames fills Hostname via concurrent reverse DNS (best-effort).
func resolveHostnames(ctx context.Context, devices []device.Device, timeout time.Duration) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i := range devices {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			rctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			names, err := net.DefaultResolver.LookupAddr(rctx, devices[i].IP.String())
			if err != nil || len(names) == 0 {
				return
			}
			name := names[0]
			if len(name) > 0 && name[len(name)-1] == '.' {
				name = name[:len(name)-1]
			}
			devices[i].Hostname = name
		}(i)
	}
	wg.Wait()
}

// secondaryProbe tries a quick TCP connect to common ports. Discovery still
// comes from ARP; this is a lightweight secondary reachability check.
func secondaryProbe(ctx context.Context, devices []device.Device, timeout time.Duration) {
	ports := []string{"80", "443", "22", "445", "3389"}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)

	for i := range devices {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			ip := devices[i].IP.String()
			for _, p := range ports {
				if ctx.Err() != nil {
					return
				}
				d := net.Dialer{Timeout: timeout}
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, p))
				if err == nil {
					_ = conn.Close()
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
