package sshprobe

import (
	"context"
	"reflect"
	"testing"

	"github.com/local/network-scanner/internal/device"
)

const junosIfaces = `Physical interface: ge-0/0/6, Enabled, Physical link is Up
  Interface index: 650, SNMP ifIndex: 516
  Description: GiriKatAP
  Link-level type: Ethernet, MTU: 1514, Speed: Auto
  Statistics last cleared: Never
  Traffic statistics:
   Input  bytes  :            1203401                    0 bps
   Output bytes  :             984412                    0 bps
   Input  packets:              12034                    0 pps
   Output packets:               9844                    0 pps
  IPv6 transit statistics:
   Input  bytes  :                   0
   Output bytes  :                   0
   Input  packets:                   0
   Output packets:                   0
  Input errors:
    Errors: 1, Drops: 2, Framing errors: 0, Runts: 0, Giants: 0, Policed discards: 0, Resource errors: 0
  Output errors:
    Carrier transitions: 0, Errors: 3, Drops: 12, MTU errors: 0, Resource errors: 0

  Logical interface ge-0/0/6.0 (Index 333) (SNMP ifIndex 517)
    Flags: Up SNMP-Traps Encapsulation: ENET2
    Input packets : 999999
    Output packets: 888888

Physical interface: ge-0/0/23, Administratively down, Physical link is Down
  Traffic statistics:
   Input  bytes  :                   0
   Output bytes  :                   0
   Input  packets:                   0
   Output packets:                   0
  Input errors:
    Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Giants: 0
  Output errors:
    Carrier transitions: 0, Errors: 0, Drops: 0

Physical interface: me0, Enabled, Physical link is Up
  Traffic statistics:
   Input  bytes  :              456789
   Output bytes  :              123000
   Input  packets:                4000
   Output packets:                2100
  Input errors:
    Errors: 0, Drops: 0
  Output errors:
    Errors: 0, Drops: 0

Physical interface: xe-0/1/3.0, Enabled, Physical link is Down
  Traffic statistics:
   Input  packets:                  50
   Output packets:                  40
  Input errors:
    Errors: 0, Drops: 7
  Output errors:
    Errors: 0, Drops: 0
`

const ciscoIfaces = `Port            InOctets    InUcastPkts    InMcastPkts    InBcastPkts
Gi1/0/1         12345678           10000           200            50
Gi1/0/2                0               0             0             0

Port           OutOctets   OutUcastPkts   OutMcastPkts   OutBcastPkts
Gi1/0/1          8765432            8000           100            20
Gi1/0/2                0               0             0             0

Port      Align-Err    FCS-Err   Xmit-Err    Rcv-Err   UnderSize  OutDiscards
Gi1/0/1           0          4          1          2           0            9
Gi1/0/2           0          0          0          0           0            0
`

const huaweiIfaces = `GigabitEthernet0/0/1 current state : UP
Line protocol current state : UP
Description:
    Last 300 seconds input rate 1000 bits/sec, 2 packets/sec
    Last 300 seconds output rate 2000 bits/sec, 3 packets/sec
    Input:  12345 packets, 1234567 bytes
            10 unicasts, 20 broadcasts, 30 multicasts
            1 errors, 2 drops, 0 giants, 0 runts
    Output: 23456 packets, 2345678 bytes
            40 unicasts, 5 broadcasts, 6 multicasts
            3 errors, 4 dropped

GigabitEthernet0/0/2 current state : ADMINISTRATIVELY DOWN
Line protocol current state : DOWN
    Input:  0 packets, 0 bytes
    Output: 0 packets, 0 bytes
`

func TestParseJunosIfaces(t *testing.T) {
	got := parseIfaces(junosIfaces)
	want := []device.IfaceCounters{
		{
			Name: "ge-0/0/6", Admin: "up", Oper: "up",
			InPackets: 12034, OutPackets: 9844,
			InBytes: 1203401, OutBytes: 984412,
			InDrops: 2, OutDrops: 12, InErrors: 1, OutErrors: 3,
		},
		{
			Name: "ge-0/0/23", Admin: "down", Oper: "down",
		},
		{
			Name: "me0", Admin: "up", Oper: "up",
			InPackets: 4000, OutPackets: 2100,
			InBytes: 456789, OutBytes: 123000,
		},
		{
			Name: "xe-0/1/3", Admin: "up", Oper: "down",
			InPackets: 50, OutPackets: 40, InDrops: 7,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestParseJunosIfacesSkipsLogicalCounters(t *testing.T) {
	got := parseIfaces(junosIfaces)
	if len(got) == 0 {
		t.Fatal("expected interfaces")
	}
	if got[0].InPackets == 999999 {
		t.Fatal("picked up logical-interface packet counters")
	}
}

func TestParseCiscoIfaces(t *testing.T) {
	got := parseIfaces(ciscoIfaces)
	want := []device.IfaceCounters{
		{
			Name:      "Gi1/0/1",
			InPackets: 10250, OutPackets: 8120,
			InBytes: 12345678, OutBytes: 8765432,
			OutDrops: 9, InErrors: 6, OutErrors: 1,
		},
		{Name: "Gi1/0/2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestParseHuaweiIfaces(t *testing.T) {
	got := parseIfaces(huaweiIfaces)
	want := []device.IfaceCounters{
		{
			Name: "GigabitEthernet0/0/1", Admin: "up", Oper: "up",
			InPackets: 12345, OutPackets: 23456,
			InBytes: 1234567, OutBytes: 2345678,
			InDrops: 2, OutDrops: 4, InErrors: 1, OutErrors: 3,
		},
		{
			Name: "GigabitEthernet0/0/2", Admin: "down", Oper: "down",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestParseIfacesEmpty(t *testing.T) {
	if parseIfaces("% Invalid input detected") != nil {
		t.Fatal("garbage should yield no interfaces")
	}
	if parseIfaces("") != nil {
		t.Fatal("empty should yield no interfaces")
	}
}

func TestParseJunosCompactErrors(t *testing.T) {
	s := `Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Input  packets: 10
  Output packets: 20
  Input errors: 5, Output errors: 3
`
	got := parseIfaces(s)
	if len(got) != 1 {
		t.Fatalf("got %d ifaces", len(got))
	}
	if got[0].InErrors != 5 || got[0].OutErrors != 3 {
		t.Fatalf("errors = in %d out %d, want 5/3", got[0].InErrors, got[0].OutErrors)
	}
}

func TestCollectJunosIfaces(t *testing.T) {
	f := &fakeClient{exec: map[string]string{
		"show system information":    junosSystemInfo,
		"show interfaces statistics": junosIfaces,
	}}
	info, netDev, _ := collect(context.Background(), f)
	if !netDev {
		t.Fatal("want network device")
	}
	if len(info.Interfaces) != 4 {
		t.Fatalf("interfaces = %#v, want 4", info.Interfaces)
	}
	if info.Interfaces[0].Name != "ge-0/0/6" || info.Interfaces[0].OutDrops != 12 {
		t.Fatalf("first iface = %#v", info.Interfaces[0])
	}
}
