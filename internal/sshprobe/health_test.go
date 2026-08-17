package sshprobe

import (
	"context"
	"testing"

	"github.com/local/network-scanner/internal/device"
)

const junosRE = `Routing Engine status:
    Slot 0:
        Current state                  Master
        Temperature                 42 degrees C / 107 degrees F
        CPU temperature             45 degrees C / 113 degrees F
        Memory utilization          28 percent
        CPU utilization:
          User                       3 percent
          Background                 0 percent
          Kernel                     2 percent
          Interrupt                  0 percent
          Idle                      95 percent
`

const ciscoCPU = `CPU utilization for five seconds: 8%/2%; one minute: 9%; five minutes: 10%
 PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process
   1           4          12        333  0.00%  0.00%  0.00%   0 Chunk Manager
`

const ciscoMem = `                Head    Total(b)     Used(b)     Free(b)
Processor    21C0170   205164272    45678900   159485372
`

const huaweiCPU = `CPU utilization for five seconds: 5%; one minute: 6%; five minutes: 6%.
`

const huaweiMem = `Memory utilizing information:
Memory utilization: 45%
`

func TestParseJunosHealth(t *testing.T) {
	var info device.SysInfo
	applyHealth(&info, junosRE)
	if info.CPU != "user 3% kernel 2% idle 95%" {
		t.Fatalf("CPU = %q", info.CPU)
	}
	if info.Memory != "28%" {
		t.Fatalf("Memory = %q", info.Memory)
	}
	if info.Temp != "42C" {
		t.Fatalf("Temp = %q", info.Temp)
	}
}

func TestParseCiscoHealth(t *testing.T) {
	var info device.SysInfo
	applyHealth(&info, ciscoCPU+"\n"+ciscoMem)
	if info.CPU != "5s 8% / 1m 9% / 5m 10%" {
		t.Fatalf("CPU = %q", info.CPU)
	}
	if info.Memory != "22%" {
		t.Fatalf("Memory = %q, want 22%%", info.Memory)
	}
}

func TestParseHuaweiHealth(t *testing.T) {
	var info device.SysInfo
	applyHealth(&info, huaweiCPU+"\n"+huaweiMem)
	if info.CPU != "5s 5% / 1m 6% / 5m 6%" {
		t.Fatalf("CPU = %q", info.CPU)
	}
	if info.Memory != "45%" {
		t.Fatalf("Memory = %q", info.Memory)
	}
}

func TestCollectJunosHealth(t *testing.T) {
	f := &fakeClient{exec: map[string]string{
		"show system information":     junosSystemInfo,
		"show chassis routing-engine": junosRE,
	}}
	info, netDev, _ := collect(context.Background(), f)
	if !netDev {
		t.Fatal("want network device")
	}
	if info.CPU == "" || info.Memory == "" || info.Temp == "" {
		t.Fatalf("health missing: cpu=%q mem=%q temp=%q", info.CPU, info.Memory, info.Temp)
	}
}
