// Package sshprobe is an opt-in pipeline method that tries SSH with
// alternative usernames and passwords, then reads system info.
//
// Passwords are never stored on the returned Device.
package sshprobe

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/local/network-scanner/internal/device"
	"github.com/local/network-scanner/internal/envload"
	"github.com/local/network-scanner/internal/oui"
	"github.com/local/network-scanner/internal/pipeline"
)

const (
	defaultPort        = 22
	defaultDialTimeout = 4 * time.Second
	maxSSHWorkers      = 8
)

// runner is the SSH session surface collect() needs.
// Tests swap in a fake so Run never opens a real connection.
type runner interface {
	CombinedOutput(ctx context.Context, cmd string) (string, error)
	ShellOutput(ctx context.Context, cmds []string) (string, error)
	Close() error
}

type dialFunc func(ctx context.Context, addr, user, password string, timeout time.Duration) (runner, error)
type tcpCheckFunc func(ctx context.Context, addr string, timeout time.Duration) bool

// Method is the SSH stage of the discovery pipeline.
type Method struct {
	Users       []string
	Passwords   []string
	Port        int
	DialTimeout time.Duration

	dial     dialFunc
	tcpCheck tcpCheckFunc
}

// Name implements pipeline.Method.
func (Method) Name() string { return "ssh" }

// SoftFail implements pipeline.SoftFailer: SSH must not abort ARP results.
func (Method) SoftFail() bool { return true }

// CredentialsFromEnv reads SSH_USERS, SSH_PASSWORDS, and optional SSH_PORT.
func CredentialsFromEnv() (users, passwords []string, port int) {
	users = envload.LookupCSV("SSH_USERS")
	passwords = envload.LookupCSV("SSH_PASSWORDS")
	port = defaultPort
	if s := os.Getenv("SSH_PORT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n < 65536 {
			port = n
		}
	}
	return users, passwords, port
}

// Run TCP-checks :22 on every target, then tries user×password until one works.
// Closed ports and failed logins are silent. Only a successful login is returned.
func (m Method) Run(ctx context.Context, req pipeline.Request) ([]device.Device, error) {
	if len(m.Users) == 0 || len(m.Passwords) == 0 || len(req.Targets) == 0 {
		return nil, nil
	}

	dial := m.dial
	if dial == nil {
		dial = dialSSH
	}
	tcpCheck := m.tcpCheck
	if tcpCheck == nil {
		tcpCheck = tcpOpen
	}

	tcpTimeout := req.Timeout
	if tcpTimeout <= 0 {
		tcpTimeout = 750 * time.Millisecond
	}
	workers := sshWorkers(req.Workers, len(req.Targets))

	var (
		mu   sync.Mutex
		out  []device.Device
		done atomic.Int64
		wg   sync.WaitGroup
	)
	jobs := make(chan net.IP, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if d, ok := m.probeOne(ctx, ip, tcpTimeout, tcpCheck, dial); ok {
					mu.Lock()
					out = append(out, d)
					mu.Unlock()
				}
				n := int(done.Add(1))
				if req.Progress != nil {
					req.Progress(m.Name(), n, len(req.Targets))
				}
			}
		}()
	}

feed:
	for _, ip := range req.Targets {
		ip4 := ip.To4()
		if ip4 == nil {
			n := int(done.Add(1))
			if req.Progress != nil {
				req.Progress(m.Name(), n, len(req.Targets))
			}
			continue
		}
		select {
		case <-ctx.Done():
			break feed
		case jobs <- append(net.IP(nil), ip4...):
		}
	}
	close(jobs)
	wg.Wait()
	return out, nil
}

func (m Method) probeOne(ctx context.Context, ip net.IP, tcpTimeout time.Duration, tcpCheck tcpCheckFunc, dial dialFunc) (device.Device, bool) {
	if ctx.Err() != nil {
		return device.Device{}, false
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(m.port()))
	if !tcpCheck(ctx, addr, tcpTimeout) {
		return device.Device{}, false
	}
	timeout := m.dialTimeout()
	for _, user := range m.Users {
		for _, pass := range m.Passwords {
			if ctx.Err() != nil {
				return device.Device{}, false
			}
			client, err := dial(ctx, addr, user, pass, timeout)
			if err != nil || client == nil {
				continue
			}
			info, netDev, mac := collect(ctx, client)
			_ = client.Close()
			info.User = user
			d := device.Device{
				IP:       append(net.IP(nil), ip.To4()...),
				Status:   device.StatusUp,
				Hostname: info.Hostname,
				SysInfo:  info,
			}
			if len(mac) > 0 {
				d.MAC = append(net.HardwareAddr(nil), mac...)
				d.Vendor = oui.Lookup(mac)
			}
			if v := device.InferVendor(info); v != "" && device.VendorUnset(d.Vendor) {
				d.Vendor = v
			}
			if netDev {
				d.Type = device.TypeNetwork
			}
			return d, true
		}
	}
	return device.Device{}, false
}

func (m Method) port() int {
	if m.Port <= 0 {
		return defaultPort
	}
	return m.Port
}

func (m Method) dialTimeout() time.Duration {
	if m.DialTimeout <= 0 {
		return defaultDialTimeout
	}
	return m.DialTimeout
}

func sshWorkers(reqWorkers, ntargets int) int {
	w := reqWorkers
	if w <= 0 || w > maxSSHWorkers {
		w = maxSSHWorkers
	}
	if ntargets > 0 && w > ntargets {
		w = ntargets
	}
	if w < 1 {
		w = 1
	}
	return w
}
