package arpscan

import (
	"errors"
	"syscall"
	"testing"
)

func TestIsNoBuffer(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"enobufs", syscall.ENOBUFS, true},
		{"pcap wrap", errors.New("send: No buffer space available"), true},
		{"other", errors.New("send: network is down"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNoBuffer(tc.err); got != tc.want {
				t.Fatalf("isNoBuffer(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
