// Package icmpping discovers live IPv4 hosts with ICMP echo (ping).
//
// One shared socket is used for the whole stage. A worker pool sends up to
// Attempts echo requests per target and stops retrying that IP on the first
// reply. Hosts that never answer are omitted from the result.
package icmpping

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/local/network-scanner/internal/device"
	"github.com/local/network-scanner/internal/pipeline"
)

const (
	// DefaultAttempts is the maximum echo requests sent to each IP.
	DefaultAttempts = 3
	// echoPayload is the ICMP data field; unused for matching, just identifiable
	// in a packet capture.
	echoPayload = "network-scanner"
	// readTick is how often the reply reader wakes to notice ctx cancellation.
	readTick = 200 * time.Millisecond
)

// packetConn is the subset of icmp.PacketConn the pinger needs.
// Tests swap in a fake so we never open a real raw socket.
type packetConn interface {
	WriteTo(b []byte, dst net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	Close() error
	SetReadDeadline(t time.Time) error
}

// Method is the ICMP stage of the discovery pipeline.
//
// listen and echoID are left zero in production (a real socket is opened and
// the process pid is used as the ICMP identifier). Tests set them to inject
// a fake connection and a known identifier.
type Method struct {
	// Attempts is the max echo requests per IP (default 3).
	Attempts int

	listen func(srcIP net.IP) (packetConn, error)
	echoID int
}

// Name implements pipeline.Method. Progress lines and warnings use this label.
func (Method) Name() string { return "icmp" }

// SoftFail implements pipeline.SoftFailer: a listen failure must not skip ARP.
func (Method) SoftFail() bool { return true }

// Run pings every IPv4 address in req.Targets concurrently.
//
// Layout:
//  1. Open one shared ICMP socket (or the test fake).
//  2. Start a single reader goroutine that demuxes echo replies by peer IP.
//  3. A worker pool calls pingOne for each target (max Attempts, stop on reply).
//  4. Return only the IPs that answered. No MAC — ARP fills that later.
func (m Method) Run(ctx context.Context, req pipeline.Request) ([]device.Device, error) {
	if len(req.Targets) == 0 {
		return nil, nil
	}
	attempts := m.Attempts
	if attempts <= 0 {
		attempts = DefaultAttempts
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 750 * time.Millisecond
	}
	workers := req.Workers
	if workers <= 0 {
		workers = 64
	}
	if workers > len(req.Targets) {
		workers = len(req.Targets)
	}

	// Production uses listenICMP; tests inject a fake via m.listen.
	listen := m.listen
	if listen == nil {
		listen = listenICMP
	}
	conn, err := listen(req.SrcIP)
	if err != nil {
		return nil, err
	}
	// Close once: defer for normal return, and again after workers so the
	// blocked reader unblocks promptly.
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	defer closeConn()

	// ICMP echo identifier (16-bit). Matching replies by ID + peer IP
	// keeps us from counting someone else's ping.
	echoID := m.echoID
	if echoID == 0 {
		echoID = os.Getpid() & 0xffff
		if echoID == 0 {
			echoID = 1
		}
	}

	// wanted is the set of IPs we actually probed. Replies from anywhere
	// else (unicast noise, wrong subnet) are ignored.
	wanted := make(map[string]struct{}, len(req.Targets))
	for _, ip := range req.Targets {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		wanted[ip4.String()] = struct{}{}
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	tr := newTracker()
	rctx, stopReader := context.WithCancel(ctx)
	defer stopReader()

	// One reader for the whole stage — ICMP sockets are not a good fit
	// for N concurrent ReadFrom loops.
	var readerDone sync.WaitGroup
	readerDone.Add(1)
	go func() {
		defer readerDone.Done()
		readReplies(rctx, conn, echoID, wanted, tr)
	}()

	var (
		writeMu sync.Mutex // icmp.PacketConn.WriteTo is not goroutine-safe
		seq     atomic.Int64
		done    atomic.Int64
		wg      sync.WaitGroup
	)
	jobs := make(chan net.IP, workers*2)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				pingOne(ctx, conn, &writeMu, &seq, echoID, ip, attempts, timeout, tr)
				n := int(done.Add(1))
				if req.Progress != nil {
					req.Progress(m.Name(), n, len(req.Targets))
				}
			}
		}()
	}

feed:
	for _, ip := range req.Targets {
		if ip.To4() == nil {
			n := int(done.Add(1))
			if req.Progress != nil {
				req.Progress(m.Name(), n, len(req.Targets))
			}
			continue
		}
		select {
		case <-ctx.Done():
			break feed
		case jobs <- ip:
		}
	}
	close(jobs)
	wg.Wait()
	stopReader()
	closeConn()
	readerDone.Wait()

	live := tr.liveIPs()
	devices := make([]device.Device, 0, len(live))
	for _, ipStr := range live {
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			continue
		}
		devices = append(devices, device.Device{
			IP:     append(net.IP(nil), ip...),
			Status: device.StatusUp,
		})
	}
	return devices, nil
}

// pingOne sends up to `attempts` echo requests to a single IP and returns
// as soon as a reply is recorded in tr, the context is cancelled, or the
// retry budget is spent. Each attempt waits `timeout` for a reply.
func pingOne(ctx context.Context, conn packetConn, writeMu *sync.Mutex, seq *atomic.Int64, echoID int, ip net.IP, attempts int, timeout time.Duration, tr *tracker) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	key := ip4.String()
	ch := tr.waiter(key)

	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil || tr.replied(key) {
			return
		}
		body, err := encodeEcho(echoID, int(seq.Add(1)))
		if err != nil {
			return
		}
		writeMu.Lock()
		_, _ = conn.WriteTo(body, &net.IPAddr{IP: ip4})
		writeMu.Unlock()

		timer := time.NewTimer(timeout)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-ch:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// readReplies is the single receive loop. It marks a target live when an
// echo-reply arrives from an address in wanted. Deadlines keep the loop
// cancellable; any non-timeout read error (usually Close) exits it.
func readReplies(ctx context.Context, conn packetConn, echoID int, wanted map[string]struct{}, tr *tracker) {
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(readTick))
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		ip := addrIP(peer)
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := wanted[key]; !ok {
			continue
		}
		if !isOurEchoReply(buf[:n], echoID) {
			continue
		}
		tr.gotReply(key)
	}
}

// isOurEchoReply reports whether b is an ICMP echo-reply that belongs to
// this process (matching echoID). Protocol number 1 is IPv4 ICMP.
func isOurEchoReply(b []byte, echoID int) bool {
	msg, err := icmp.ParseMessage(1, b) // iana.ProtocolICMP
	if err != nil {
		return false
	}
	if msg.Type != ipv4.ICMPTypeEchoReply {
		return false
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return false
	}
	// Some unprivileged stacks overwrite the identifier; accept any reply
	// from a target IP when the kernel has rewritten ID to 0.
	if echo.ID != echoID && echo.ID != 0 {
		return false
	}
	return true
}

// encodeEcho builds a raw ICMP echo-request (type 8) ready for WriteTo.
func encodeEcho(id, seq int) ([]byte, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte(echoPayload),
		},
	}
	return msg.Marshal(nil)
}

// listenICMP opens a raw IPv4 ICMP socket. If that fails (common without
// CAP_NET_RAW on some setups), it falls back to an unprivileged datagram
// socket ("udp4"), which works on Darwin and on Linux when the process
// is in ping_group_range.
func listenICMP(srcIP net.IP) (packetConn, error) {
	addr := "0.0.0.0"
	if ip4 := srcIP.To4(); ip4 != nil {
		addr = ip4.String()
	}
	c, err := icmp.ListenPacket("ip4:icmp", addr)
	if err == nil {
		return &addrConn{PacketConn: c, udp: false}, nil
	}
	c2, err2 := icmp.ListenPacket("udp4", "0.0.0.0")
	if err2 != nil {
		return nil, fmt.Errorf("icmp listen: %w", err)
	}
	return &addrConn{PacketConn: c2, udp: true}, nil
}

// addrConn normalizes WriteTo destinations for raw vs datagram ICMP sockets.
type addrConn struct {
	*icmp.PacketConn
	udp bool
}

func (c *addrConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	ip := addrIP(dst)
	if c.udp {
		return c.PacketConn.WriteTo(b, &net.UDPAddr{IP: ip})
	}
	return c.PacketConn.WriteTo(b, &net.IPAddr{IP: ip})
}

// addrIP pulls an IPv4 address out of the various net.Addr types ICMP
// sockets return (IPAddr for raw, UDPAddr for the datagram fallback).
func addrIP(a net.Addr) net.IP {
	if a == nil {
		return nil
	}
	switch v := a.(type) {
	case *net.IPAddr:
		return v.IP.To4()
	case *net.UDPAddr:
		return v.IP.To4()
	default:
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return net.ParseIP(a.String()).To4()
		}
		return net.ParseIP(host).To4()
	}
}

// tracker records which IPs have answered and lets pingOne wait for a
// specific IP without polling. gotReply closes that IP's wait channel
// so the sender's select wakes immediately.
type tracker struct {
	mu   sync.Mutex
	live map[string]struct{}      // IPs that sent us an echo-reply
	wait map[string]chan struct{} // per-IP signal; closed on first reply
}

func newTracker() *tracker {
	return &tracker{
		live: make(map[string]struct{}),
		wait: make(map[string]chan struct{}),
	}
}

// gotReply marks ip live and wakes any pingOne waiting on it.
func (t *tracker) gotReply(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.live[ip] = struct{}{}
	if ch, ok := t.wait[ip]; ok {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}

// waiter returns a channel that is closed when ip replies. If the reply
// already arrived, the returned channel is already closed.
func (t *tracker) waiter(ip string) <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.live[ip]; ok {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	if ch, ok := t.wait[ip]; ok {
		return ch
	}
	ch := make(chan struct{})
	t.wait[ip] = ch
	return ch
}

// replied is a non-blocking check used to skip further attempts.
func (t *tracker) replied(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.live[ip]
	return ok
}

// liveIPs is the set of addresses that answered at least once.
func (t *tracker) liveIPs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.live))
	for ip := range t.live {
		out = append(out, ip)
	}
	return out
}
