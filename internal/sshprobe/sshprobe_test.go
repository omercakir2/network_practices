package sshprobe

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/local/network-scanner/internal/device"
	"github.com/local/network-scanner/internal/pipeline"
)

type fakeClient struct {
	exec     map[string]string
	execErr  error
	shellOut string
	closed   bool
}

func (f *fakeClient) CombinedOutput(ctx context.Context, cmd string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if f.execErr != nil {
		return "", f.execErr
	}
	if out, ok := f.exec[cmd]; ok {
		return out, nil
	}
	return "", errors.New("unknown command")
}

func (f *fakeClient) ShellOutput(ctx context.Context, cmds []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return f.shellOut, nil
}

func (f *fakeClient) Close() error {
	f.closed = true
	return nil
}

func testReq(ips ...net.IP) pipeline.Request {
	return pipeline.Request{
		Targets: ips,
		Workers: 2,
		Timeout: 50 * time.Millisecond,
	}
}

func TestClosedPortSkipsDial(t *testing.T) {
	m := Method{
		Users:     []string{"admin"},
		Passwords: []string{"x"},
		tcpCheck:  func(context.Context, string, time.Duration) bool { return false },
		dial: func(context.Context, string, string, string, time.Duration) (runner, error) {
			t.Fatal("dial should not run when port is closed")
			return nil, nil
		},
	}
	devs, err := m.Run(context.Background(), testReq(net.IPv4(10, 0, 0, 1)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("devs = %+v, want none", devs)
	}
}

func TestAuthFailReturnsNothing(t *testing.T) {
	m := Method{
		Users:     []string{"admin"},
		Passwords: []string{"bad"},
		tcpCheck:  func(context.Context, string, time.Duration) bool { return true },
		dial: func(context.Context, string, string, string, time.Duration) (runner, error) {
			return nil, errors.New("auth failed")
		},
	}
	devs, err := m.Run(context.Background(), testReq(net.IPv4(10, 0, 0, 1)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("devs = %+v, want none", devs)
	}
}

func TestSecondPairWins(t *testing.T) {
	var tried []string
	m := Method{
		Users:     []string{"admin", "root"},
		Passwords: []string{"bad", "good"},
		tcpCheck:  func(context.Context, string, time.Duration) bool { return true },
		dial: func(ctx context.Context, addr, user, pass string, timeout time.Duration) (runner, error) {
			tried = append(tried, user+":"+pass)
			if user == "admin" && pass == "good" {
				return &fakeClient{exec: map[string]string{
					"show version": ciscoShowVersion,
				}}, nil
			}
			return nil, errors.New("denied")
		},
	}
	devs, err := m.Run(context.Background(), testReq(net.IPv4(192, 168, 1, 1)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(tried) != 2 || tried[0] != "admin:bad" || tried[1] != "admin:good" {
		t.Fatalf("tried = %v, want [admin:bad admin:good]", tried)
	}
	if len(devs) != 1 {
		t.Fatalf("got %d devices, want 1", len(devs))
	}
	d := devs[0]
	if d.IP.String() != "192.168.1.1" {
		t.Fatalf("IP = %s", d.IP)
	}
	if d.SysInfo.User != "admin" {
		t.Fatalf("User = %q, want admin", d.SysInfo.User)
	}
	if d.SysInfo.Model != "WS-C2960-24TT-L" {
		t.Fatalf("Model = %q", d.SysInfo.Model)
	}
	if d.Type != device.TypeNetwork {
		t.Fatalf("Type = %q, want network", d.Type)
	}
	if d.Hostname != "core-sw" {
		t.Fatalf("Hostname = %q, want core-sw", d.Hostname)
	}
}

func TestCancelledContextStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dialed := false
	m := Method{
		Users:     []string{"admin"},
		Passwords: []string{"x"},
		tcpCheck:  func(context.Context, string, time.Duration) bool { return true },
		dial: func(context.Context, string, string, string, time.Duration) (runner, error) {
			dialed = true
			return nil, errors.New("should not dial")
		},
	}
	devs, err := m.Run(ctx, testReq(net.IPv4(10, 0, 0, 1)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if dialed {
		t.Fatal("dial ran after cancel")
	}
	if len(devs) != 0 {
		t.Fatalf("devs = %+v, want none", devs)
	}
}

func TestEmptyCredsNoWork(t *testing.T) {
	m := Method{}
	devs, err := m.Run(context.Background(), testReq(net.IPv4(10, 0, 0, 1)))
	if err != nil || devs != nil {
		t.Fatalf("Run = %v, %v; want nil, nil", devs, err)
	}
}

func TestCredentialsFromEnv(t *testing.T) {
	t.Setenv("SSH_USERS", "admin, root")
	t.Setenv("SSH_PASSWORDS", "a,b")
	t.Setenv("SSH_PORT", "2222")
	users, passwords, port := CredentialsFromEnv()
	if len(users) != 2 || users[0] != "admin" || users[1] != "root" {
		t.Fatalf("users = %v", users)
	}
	if len(passwords) != 2 || passwords[0] != "a" || passwords[1] != "b" {
		t.Fatalf("passwords = %v", passwords)
	}
	if port != 2222 {
		t.Fatalf("port = %d, want 2222", port)
	}
}
