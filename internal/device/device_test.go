package device

import "testing"

func TestInferVendorJunos(t *testing.T) {
	v := InferVendor(SysInfo{Model: "ex4000-24p", Version: "24.4R1-S2.15", Family: "junos-ex"})
	if v != "Juniper" {
		t.Fatalf("vendor = %q, want Juniper", v)
	}
}

func TestInferVendorCiscoModel(t *testing.T) {
	v := InferVendor(SysInfo{Model: "WS-C2960-24TT-L", Version: "15.0(2)SE11"})
	if v != "Cisco" {
		t.Fatalf("vendor = %q, want Cisco", v)
	}
}

func TestInferVendorUnknown(t *testing.T) {
	if InferVendor(SysInfo{Model: "something", Version: "1.0"}) != "" {
		t.Fatal("expected empty vendor")
	}
}

func TestVendorUnset(t *testing.T) {
	if !VendorUnset("") || !VendorUnset("Unknown") || !VendorUnset("Randomized MAC") {
		t.Fatal("placeholders should be unset")
	}
	if VendorUnset("Juniper") || VendorUnset("Cisco") {
		t.Fatal("real vendors should be set")
	}
}
