// Package arpscan performs a concurrent ARP sweep of a local IPv4 subnet.
//
// How it works:
//  1. Open two live pcap handles on the chosen interface (needs root /
//     CAP_NET_RAW or BPF group membership on macOS): one to read replies,
//     one to send requests. A single handle is a fallback only.
//     libpcap serializes Read+Write on the same pcap_t, so sharing one
//     handle with a 200ms read timeout makes a /16 look frozen (~5 pkt/s).
//  2. Start one reader goroutine that collects ARP replies.
//  3. Send ARP requests on the write handle. Sends are serialized (pcap
//     writes are not goroutine-safe); extra -workers do not speed this up.
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/local/network-scanner/internal/device"
	"github.com/local/network-scanner/internal/oui"
	"github.com/local/network-scanner/internal/pipeline"
)

// Options controls scan behaviour.
type Options struct {
	// Workers is the number of concurrent ARP senders (default 64).
	Workers int
	// Timeout is how long to wait after the last request for late replies
	// (default 750ms). Per-write operations use a short pcap timeout.
	Timeout time.Duration
	// Progress, if non-nil, is called with (done, total) as each request is sent.
	Progress func(done, total int)
}

// Method adapts Scan to the discovery pipeline. Unlike ICMP it does not
// implement SoftFailer: a pcap/privilege error is fatal.
type Method struct{}

// Name implements pipeline.Method. Progress lines use this label.
func (Method) Name() string { return "arp" }

// Run ARP-probes every address in req.Targets (the full subnet, not just
// ICMP hits). Translates the shared pipeline.Request into Scan options.
func (Method) Run(ctx context.Context, req pipeline.Request) ([]device.Device, error) {
	var progress func(done, total int)
	if req.Progress != nil {
		progress = func(done, total int) {
			req.Progress("arp", done, total)
		}
	}
	return Scan(ctx, req.Iface, req.SrcIP, req.Targets, Options{
		Workers:  req.Workers,
		Timeout:  req.Timeout,
		Progress: progress,
	})
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

	// Two handles: libpcap holds one mutex for Read and Write on a pcap_t.
	// Sharing a handle with a 200ms read timeout serializes every send behind
	// that wait (~5 pkt/s) — a /16 then sits on "arp: 10%" for minutes.
	rx, err := pcap.OpenLive(iface.Name, 65536, true, 50*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open pcap on %s: %w", iface.Name, err)
	}
	tx, txErr := pcap.OpenLive(iface.Name, 256, false, time.Millisecond)
	if txErr != nil {
		tx = rx
	}

	var closeOnce sync.Once
	closeHandles := func() {
		closeOnce.Do(func() {
			rx.Close()
			if tx != rx {
				tx.Close()
			}
		})
	}
	defer closeHandles()

	// Only Ethernet ARP traffic — keeps the reader cheap.
	if err := rx.SetBPFFilter("arp"); err != nil {
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
		readARP(rx, iface.HardwareAddr, stop, func(ip net.IP, mac net.HardwareAddr) {
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

	// One sender: WritePacketData is not concurrent-safe, so a worker pool
	// cannot go faster than this loop and only adds lock contention.
	//
	// Pace + retry: blasting 65k ARP frames on macOS/Wi-Fi fills the BPF/driver
	// TX ring (ENOBUFS / "No buffer space available") around ~8k packets.
	inj := newInjector(tx)
	buf := gopacket.NewSerializeBuffer()
	total := len(targets)
	var sendErr error
	for i, ip := range targets {
		if ctx.Err() != nil {
			break
		}
		ip4 := ip.To4()
		if ip4 == nil {
			if opt.Progress != nil {
				opt.Progress(i+1, total)
			}
			continue
		}
		req := arpReq
		req.DstProtAddress = []byte(ip4)
		if err := buf.Clear(); err != nil {
			sendErr = err
			break
		}
		if err := gopacket.SerializeLayers(buf, serializeOpts, &eth, &req); err != nil {
			sendErr = err
			break
		}
		if err := inj.write(ctx, buf.Bytes()); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				break
			}
			sendErr = err
			break
		}
		if opt.Progress != nil {
			opt.Progress(i+1, total)
		}
	}

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
	// Closing the read handle unblocks any pending ReadPacketData.
	closeHandles()
	readerDone.Wait()

	if sendErr != nil {
		return nil, fmt.Errorf("send ARP: %w", sendErr)
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
	return o
}

const (
	injectBurstMin   = 2
	injectBurstStart = 8
	injectBurstMax   = 32
	injectGap        = time.Millisecond
	injectRetryMax   = 64
	injectBackoffMax = 50 * time.Millisecond
)

// injector writes frames with a small burst/pause cadence and retries
// ENOBUFS so a /16 sweep does not abort when the kernel TX ring fills.
type injector struct {
	tx    *pcap.Handle
	burst int // successful writes since last pause
	limit int // pause after this many writes; shrinks on ENOBUFS
}

func newInjector(tx *pcap.Handle) *injector {
	return &injector{tx: tx, limit: injectBurstStart}
}

func (in *injector) write(ctx context.Context, frame []byte) error {
	for try := 0; try < injectRetryMax; try++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := in.tx.WritePacketData(frame)
		if err == nil {
			in.burst++
			if in.burst < in.limit {
				return nil
			}
			in.burst = 0
			if in.limit < injectBurstMax {
				in.limit++
			}
			return sleepCtx(ctx, injectGap)
		}
		if !isNoBuffer(err) {
			return err
		}
		// TX ring full: slow down and retry this same frame.
		in.burst = 0
		if in.limit > injectBurstMin {
			in.limit /= 2
		}
		backoff := time.Duration(4<<try) * time.Millisecond
		if backoff > injectBackoffMax {
			backoff = injectBackoffMax
		}
		if err := sleepCtx(ctx, backoff); err != nil {
			return err
		}
	}
	return errors.New("send: no buffer space available after retries")
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func isNoBuffer(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOBUFS) {
		return true
	}
	// pcap wraps the errno as "send: No buffer space available".
	s := err.Error()
	return strings.Contains(s, "No buffer space") ||
		strings.Contains(s, "no buffer space") ||
		strings.Contains(s, "ENOBUFS")
}
