package sshprobe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func tcpOpen(ctx context.Context, addr string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func dialSSH(ctx context.Context, addr, user, password string, timeout time.Duration) (runner, error) {
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Clear the handshake deadline so collect() can use its own timeouts.
	_ = conn.SetDeadline(time.Time{})
	return &sshRunner{c: ssh.NewClient(c, chans, reqs)}, nil
}

type sshRunner struct {
	c *ssh.Client
}

func (r *sshRunner) Close() error {
	if r.c == nil {
		return nil
	}
	return r.c.Close()
}

func (r *sshRunner) CombinedOutput(ctx context.Context, cmd string) (string, error) {
	session, err := r.c.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-done:
		}
	}()
	defer close(done)

	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

func (r *sshRunner) ShellOutput(ctx context.Context, cmds []string) (string, error) {
	session, err := r.c.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	if err := session.RequestPty("vt100", 24, 80, ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return "", err
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = &buf

	if err := session.Shell(); err != nil {
		return "", err
	}

	for _, cmd := range cmds {
		if _, err := fmt.Fprintf(stdin, "%s\r", cmd); err != nil {
			break
		}
	}
	_, _ = io.WriteString(stdin, "exit\r")
	_ = stdin.Close()

	waitCh := make(chan error, 1)
	go func() { waitCh <- session.Wait() }()
	select {
	case <-ctx.Done():
		_ = session.Close()
		return buf.String(), ctx.Err()
	case <-waitCh:
		return buf.String(), nil
	}
}
