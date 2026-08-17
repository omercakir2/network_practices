package sshprobe

import (
	"context"
	"errors"
	"testing"

	"github.com/local/network-scanner/internal/device"
)

const ciscoShowVersion = `Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)
Copyright (c) 1986-2016 by Cisco Systems, Inc.

core-sw uptime is 3 weeks, 2 days, 4 hours, 11 minutes
System returned to ROM by power-on

cisco WS-C2960-24TT-L (PowerPC405) processor (revision D0) with 65536K bytes of memory.
Model number                    : WS-C2960-24TT-L
Base ethernet MAC Address       : C8:4F:86:C1:82:E6
`

const junosSystemInfo = `Hostname: lab-ex
Model: ex4000-24p
Family: junos-ex
Junos: 24.4R1-S2.15
`

const junosChassisMAC = `MAC address information
  Public base address     00:1f:12:34:56:78
  Public count            64
`

const huaweiDisplayVersion = `Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 (S5720 V200R011C10SPC600)
Copyright (C) 2000-2018 HUAWEI TECH CO., LTD
HUAWEI S5720-28X-LI-AC Routing Switch uptime is 15 weeks, 3 days, 8 hours, 42 minutes
`

const linuxUname = `Linux openwrt 5.15.137 #0 SMP Mon Nov 13 00:00:00 2023 mips GNU/Linux`

const linuxOSRelease = `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
`

const linuxUptime = ` 14:32:01 up 21 days,  3:14,  1 user,  load average: 0.00, 0.01, 0.05`

func TestParseCisco(t *testing.T) {
	info := parseSysInfo(ciscoShowVersion)
	if info.Hostname != "core-sw" {
		t.Errorf("Hostname = %q, want core-sw", info.Hostname)
	}
	if info.Model != "WS-C2960-24TT-L" {
		t.Errorf("Model = %q, want WS-C2960-24TT-L", info.Model)
	}
	if info.Version != "15.0(2)SE11" {
		t.Errorf("Version = %q, want 15.0(2)SE11", info.Version)
	}
	if info.Uptime != "3 weeks, 2 days, 4 hours, 11 minutes" {
		t.Errorf("Uptime = %q", info.Uptime)
	}
	if !isNetworkDevice(info, ciscoShowVersion) {
		t.Error("expected network device")
	}
}

func TestParseHuawei(t *testing.T) {
	info := parseSysInfo(huaweiDisplayVersion)
	if info.Model != "S5720-28X-LI-AC" {
		t.Errorf("Model = %q, want S5720-28X-LI-AC", info.Model)
	}
	if info.Version == "" {
		t.Error("Version empty")
	}
	if !looksLikeNetworkOS(huaweiDisplayVersion) {
		t.Error("expected network OS")
	}
}

func TestParseLinux(t *testing.T) {
	blob := linuxUname + "\n" + linuxOSRelease + "\n" + linuxUptime + "\nopenwrt\n"
	info := parseSysInfo(blob)
	if info.Hostname != "openwrt" {
		t.Errorf("Hostname = %q, want openwrt", info.Hostname)
	}
	if info.Version != "Linux 5.15.137" {
		t.Errorf("Version = %q, want Linux 5.15.137", info.Version)
	}
	if info.Uptime != "21 days,  3:14" {
		t.Errorf("Uptime = %q, want 21 days,  3:14", info.Uptime)
	}
	if isNetworkDevice(info, blob) {
		t.Error("plain Linux should not be classified as a switch")
	}
}

func TestCollectExecThenStopOnCisco(t *testing.T) {
	f := &fakeClient{exec: map[string]string{
		"show version": ciscoShowVersion,
		"uname -a":     linuxUname,
	}}
	info, netDev, mac := collect(context.Background(), f)
	if !netDev {
		t.Fatal("want network device")
	}
	if info.Model != "WS-C2960-24TT-L" {
		t.Fatalf("Model = %q", info.Model)
	}
	if mac.String() != "c8:4f:86:c1:82:e6" {
		t.Fatalf("MAC = %v, want c8:4f:86:c1:82:e6", mac)
	}
}

func TestCollectShellFallback(t *testing.T) {
	f := &fakeClient{
		execErr:  errors.New("exec request failed"),
		shellOut: ciscoShowVersion,
	}
	info, netDev, _ := collect(context.Background(), f)
	if !netDev {
		t.Fatal("want network device from shell fallback")
	}
	if info.Hostname != "core-sw" {
		t.Fatalf("Hostname = %q", info.Hostname)
	}
}

func TestParseJunosSystemInformation(t *testing.T) {
	info := parseSysInfo(junosSystemInfo)
	if info.Hostname != "lab-ex" {
		t.Errorf("Hostname = %q, want lab-ex", info.Hostname)
	}
	if info.Model != "ex4000-24p" {
		t.Errorf("Model = %q, want ex4000-24p", info.Model)
	}
	if info.Version != "24.4R1-S2.15" {
		t.Errorf("Version = %q, want 24.4R1-S2.15", info.Version)
	}
	if info.Family != "junos-ex" {
		t.Errorf("Family = %q, want junos-ex", info.Family)
	}
	if device.InferVendor(info) != "Juniper" {
		t.Errorf("vendor = %q, want Juniper", device.InferVendor(info))
	}
	if !isNetworkDevice(info, junosSystemInfo) {
		t.Error("expected network device")
	}
}

func TestCollectJunosThenMAC(t *testing.T) {
	f := &fakeClient{exec: map[string]string{
		"show system information":    junosSystemInfo,
		"show chassis mac-addresses": junosChassisMAC,
	}}
	info, netDev, mac := collect(context.Background(), f)
	if !netDev {
		t.Fatal("want network device")
	}
	if info.Model != "ex4000-24p" {
		t.Fatalf("Model = %q", info.Model)
	}
	if info.Version != "24.4R1-S2.15" {
		t.Fatalf("Version = %q", info.Version)
	}
	if mac.String() != "00:1f:12:34:56:78" {
		t.Fatalf("MAC = %v, want 00:1f:12:34:56:78", mac)
	}
}

func TestParseMACMissingOK(t *testing.T) {
	if parseMAC(junosSystemInfo) != nil {
		t.Fatal("show system information has no MAC; want nil")
	}
}

func TestParseGenericFallback(t *testing.T) {
	info := parseSysInfo("% Invalid input\nSomeVendor OS build 9.1\n")
	if info.Version != "SomeVendor OS build 9.1" {
		t.Fatalf("Version = %q, want first useful line", info.Version)
	}
}

func TestSysInfoEmpty(t *testing.T) {
	if !(device.SysInfo{}).Empty() {
		t.Fatal("zero SysInfo should be empty")
	}
	if (device.SysInfo{Model: "x"}).Empty() {
		t.Fatal("filled SysInfo should not be empty")
	}
}
