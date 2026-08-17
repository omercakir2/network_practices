package sshprobe

import (
	"context"
	"reflect"
	"testing"

	"github.com/local/network-scanner/internal/device"
)

const ciscoLLDP = `Capability codes:
    (R) Router, (B) Bridge, (T) Telephone

Device ID           Local Intf     Hold-time  Capability      Port ID
lab-ex              Gi1/0/1        120        B               ge-0/0/0.0
core-sw             Gi1/0/24       120        B               Gi1/0/1
`

const junosLLDP = `Local Interface    Parent Interface    Chassis Id          Port info     System Name
ge-0/0/0.0         -                   00:1f:12:34:56:78   Gi1/0/1       core-sw
xe-0/1/0           ae0                 aa:bb:cc:dd:ee:ff   xe-0/1/0      spine1
`

const huaweiLLDP = `Local Intf          Neighbor Dev             Neighbor Intf             Exptime
XGE0/0/1            spine1                   XGE0/0/24                 107
`

func TestParseCiscoLLDP(t *testing.T) {
	got := parseLLDP(ciscoLLDP)
	want := []device.Neighbor{
		{LocalPort: "Gi1/0/1", RemoteName: "lab-ex", RemotePort: "ge-0/0/0.0"},
		{LocalPort: "Gi1/0/24", RemoteName: "core-sw", RemotePort: "Gi1/0/1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestParseJunosLLDP(t *testing.T) {
	got := parseLLDP(junosLLDP)
	want := []device.Neighbor{
		{LocalPort: "ge-0/0/0.0", RemoteName: "core-sw", RemotePort: "Gi1/0/1", RemoteID: "00:1f:12:34:56:78"},
		{LocalPort: "xe-0/1/0", RemoteName: "spine1", RemotePort: "xe-0/1/0", RemoteID: "aa:bb:cc:dd:ee:ff"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestParseHuaweiLLDP(t *testing.T) {
	got := parseLLDP(huaweiLLDP)
	want := []device.Neighbor{
		{LocalPort: "XGE0/0/1", RemoteName: "spine1", RemotePort: "XGE0/0/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestParseLLDPEmpty(t *testing.T) {
	if parseLLDP("% LLDP is not enabled") != nil {
		t.Fatal("disabled LLDP should yield no neighbors")
	}
}

func TestCollectJunosLLDP(t *testing.T) {
	f := &fakeClient{exec: map[string]string{
		"show system information": junosSystemInfo,
		"show lldp neighbors":     junosLLDP,
	}}
	info, netDev, _ := collect(context.Background(), f)
	if !netDev {
		t.Fatal("want network device")
	}
	if len(info.Neighbors) != 2 {
		t.Fatalf("neighbors = %#v, want 2", info.Neighbors)
	}
	if info.Neighbors[0].RemoteName != "core-sw" {
		t.Fatalf("first neighbor = %#v", info.Neighbors[0])
	}
}
