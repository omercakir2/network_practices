package icmpping

// These tests never open a real ICMP socket. A fakeConn stands in for the
// kernel: tests record every echo we "send" and can inject replies as if a
// host had answered. That lets us check retry/cancel behaviour without root.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/local/network-scanner/internal/pipeline"
)

// timeoutErr mimics a socket read deadline so the reader loop can poll
// for context cancellation the same way a real icmp.PacketConn does.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// reply is one fake ICMP echo-reply waiting for ReadFrom.
type reply struct {
	ip  net.IP // peer the reply is "from"
	raw []byte // marshalled ICMP echo-reply bytes
}

// fakeConn is an in-memory packetConn used by every test below.
//
// WriteTo records the destination IP (so tests can assert how many times
// we pinged a host) and optionally runs onWrite, which tests use to inject
// a reply at a chosen attempt.
//
// ReadFrom blocks until pushReply delivers a packet, the read deadline
// fires, or Close is called.
type fakeConn struct {
	mu       sync.Mutex
	writes   []net.IP          // destinations of every WriteTo, in order
	onWrite  func(n int, ip net.IP) // optional hook; n is 1-based write count
	replies  chan reply
	closed   chan struct{}
	deadline time.Time
	echoID   int // ICMP identifier our replies must carry
}

// newFakeConn builds a closed-until-used socket stand-in.
// echoID must match the Method.echoID the test will run with, otherwise
// isOurEchoReply will drop the injected packets.
func newFakeConn(echoID int) *fakeConn {
	return &fakeConn{
		replies: make(chan reply, 32),
		closed:  make(chan struct{}),
		echoID:  echoID,
	}
}

// WriteTo pretends to send an echo request. The payload is ignored; we
// only care which IP was targeted so retry tests can count attempts.
func (f *fakeConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	ip := addrIP(dst)
	f.mu.Lock()
	f.writes = append(f.writes, append(net.IP(nil), ip...))
	n := len(f.writes)
	hook := f.onWrite
	f.mu.Unlock()
	if hook != nil {
		hook(n, ip)
	}
	return len(b), nil
}

// ReadFrom returns the next injected reply, or a timeout if the deadline
// (set by the production reader loop every 200ms) has elapsed.
func (f *fakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	f.mu.Lock()
	dl := f.deadline
	f.mu.Unlock()

	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, timeoutErr{}
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		timeout = timer.C
	}

	select {
	case <-f.closed:
		return 0, nil, net.ErrClosed
	case r := <-f.replies:
		n := copy(b, r.raw)
		return n, &net.IPAddr{IP: r.ip}, nil
	case <-timeout:
		return 0, nil, timeoutErr{}
	}
}

// Close unblocks any ReadFrom and is safe to call more than once.
func (f *fakeConn) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

// SetReadDeadline is what the production reader uses to wake up and
// notice ctx cancellation instead of blocking forever on ReadFrom.
func (f *fakeConn) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	return nil
}

// pushReply queues a well-formed ICMP echo-reply from ip. Call this from
// onWrite (or another goroutine) to simulate the host answering.
func (f *fakeConn) pushReply(ip net.IP) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: f.echoID, Seq: 1, Data: []byte(echoPayload)},
	}
	raw, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	select {
	case <-f.closed:
	case f.replies <- reply{ip: append(net.IP(nil), ip...), raw: raw}:
	}
}

// writeCount is the total number of echo requests sent to any destination.
func (f *fakeConn) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

// writesFor is how many echo requests went to one IP (i.e. retry count).
func (f *fakeConn) writesFor(ip net.IP) int {
	want := ip.To4().String()
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, w := range f.writes {
		if w.To4().String() == want {
			n++
		}
	}
	return n
}

// deviceIPs is a tiny view of a discovered host so assertions stay readable.
type deviceIPs struct {
	ip, status string
}

// runPing executes the ICMP method against targets using the given fake
// socket. Passing ctx == nil uses context.Background(). Timeout is the
// per-attempt wait (keep it short so failing tests do not stall).
func runPing(t *testing.T, conn *fakeConn, targets []net.IP, attempts int, timeout time.Duration, ctx context.Context) []deviceIPs {
	t.Helper()
	if ctx == nil {
		ctx = context.Background()
	}
	// Inject the fake socket via listen so Run never calls icmp.ListenPacket.
	m := Method{
		Attempts: attempts,
		echoID:   conn.echoID,
		listen:   func(net.IP) (packetConn, error) { return conn, nil },
	}
	devs, err := m.Run(ctx, pipeline.Request{
		Targets: targets,
		Workers: 4,
		Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := make([]deviceIPs, 0, len(devs))
	for _, d := range devs {
		out = append(out, deviceIPs{ip: d.IP.String(), status: d.Status})
	}
	return out
}

// A host that answers the first ping must not be probed again.
func TestReplyOnFirstAttemptStopsRetries(t *testing.T) {
	const id = 42
	conn := newFakeConn(id)
	ip := net.IPv4(192, 168, 1, 10)
	// The moment we send to this IP, pretend it replied.
	conn.onWrite = func(n int, dst net.IP) {
		if dst.Equal(ip) {
			conn.pushReply(dst)
		}
	}
	devs := runPing(t, conn, []net.IP{ip}, 3, 40*time.Millisecond, nil)
	if len(devs) != 1 || devs[0].ip != "192.168.1.10" {
		t.Fatalf("devs = %v, want 192.168.1.10", devs)
	}
	if n := conn.writesFor(ip); n != 1 {
		t.Fatalf("writes = %d, want 1", n)
	}
}

// A host that is silent on attempt 1 and answers on attempt 2 must not
// receive a third echo.
func TestReplyOnSecondAttemptSkipsThird(t *testing.T) {
	const id = 43
	conn := newFakeConn(id)
	ip := net.IPv4(192, 168, 1, 20)
	var seen int
	conn.onWrite = func(n int, dst net.IP) {
		if !dst.Equal(ip) {
			return
		}
		seen++
		if seen >= 2 {
			conn.pushReply(dst)
		}
	}
	devs := runPing(t, conn, []net.IP{ip}, 3, 30*time.Millisecond, nil)
	if len(devs) != 1 || devs[0].ip != "192.168.1.20" {
		t.Fatalf("devs = %v, want 192.168.1.20", devs)
	}
	if n := conn.writesFor(ip); n != 2 {
		t.Fatalf("writes = %d, want 2", n)
	}
}

// A host that never answers is not a discovery hit, but we still spend
// the full retry budget (3 writes) on it.
func TestNoReplyOmittedAfterThreeAttempts(t *testing.T) {
	const id = 44
	conn := newFakeConn(id)
	ip := net.IPv4(192, 168, 1, 30)
	devs := runPing(t, conn, []net.IP{ip}, 3, 20*time.Millisecond, nil)
	if len(devs) != 0 {
		t.Fatalf("devs = %v, want none", devs)
	}
	if n := conn.writesFor(ip); n != 3 {
		t.Fatalf("writes = %d, want 3", n)
	}
}

// Replies from IPs we did not probe (noise, spoofed packets, etc.) must
// not show up in the result list.
func TestUnknownPeerIgnored(t *testing.T) {
	const id = 45
	conn := newFakeConn(id)
	target := net.IPv4(10, 0, 0, 5)
	conn.onWrite = func(n int, dst net.IP) {
		conn.pushReply(net.IPv4(1, 2, 3, 4))
	}
	devs := runPing(t, conn, []net.IP{target}, 2, 20*time.Millisecond, nil)
	if len(devs) != 0 {
		t.Fatalf("devs = %v, want none", devs)
	}
}

// Cancelling the context must unblock Run quickly instead of sitting out
// the remaining retry timers (here 3 × 2s).
func TestContextCancelReturns(t *testing.T) {
	const id = 46
	conn := newFakeConn(id)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel on the first send so we do not wait out every retry.
	conn.onWrite = func(n int, dst net.IP) {
		cancel()
	}
	start := time.Now()
	m := Method{
		Attempts: 3,
		echoID:   id,
		listen:   func(net.IP) (packetConn, error) { return conn, nil },
	}
	_, err := m.Run(ctx, pipeline.Request{
		Targets: []net.IP{net.IPv4(10, 0, 0, 9)},
		Workers: 1,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Run hung after cancel (%s)", time.Since(start))
	}
}

// If the socket cannot be opened, Run must surface that error so the
// pipeline can warn and continue to ARP (SoftFail).
func TestListenErrorPropagates(t *testing.T) {
	m := Method{
		listen: func(net.IP) (packetConn, error) {
			return nil, net.ErrClosed
		},
	}
	_, err := m.Run(context.Background(), pipeline.Request{
		Targets: []net.IP{net.IPv4(10, 0, 0, 1)},
	})
	if err == nil {
		t.Fatal("expected listen error")
	}
}
