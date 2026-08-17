// Package pipeline runs discovery methods in order and unions their results.
package pipeline

import (
	"context"
	"net"
	"time"

	"github.com/local/network-scanner/internal/device"
)

// Request is the input shared by every discovery method.
// Every stage sees the full Targets list — later methods do not receive a
// filtered subset of earlier hits.
type Request struct {
	Iface    *net.Interface
	SrcIP    net.IP
	Targets  []net.IP
	Workers  int
	Timeout  time.Duration // per-attempt ICMP wait; ARP settle window
	Progress func(stage string, done, total int)
	// Warn, if non-nil, is called when a non-fatal method fails.
	Warn func(method string, err error)
}

// Method is one stage in the discovery pipeline (ICMP, ARP, …).
// Name is the progress/warning label; Run returns the hosts that stage found.
type Method interface {
	Name() string
	Run(ctx context.Context, req Request) ([]device.Device, error)
}

// SoftFailer is implemented by methods whose errors should not abort the pipeline.
// ICMP implements this: if ping cannot open a socket we still want ARP to run.
type SoftFailer interface {
	SoftFail() bool
}

// Pipeline executes methods sequentially against the same target list.
type Pipeline struct {
	methods []Method
}

// New builds a pipeline that runs methods in the given order.
func New(methods ...Method) *Pipeline {
	return &Pipeline{methods: methods}
}

// Run executes each method against req.Targets and merges hits by IP.
// Errors from methods that implement SoftFailer and return true are reported
// via req.Warn (if set) and do not stop later methods.
func (p *Pipeline) Run(ctx context.Context, req Request) ([]device.Device, error) {
	if p == nil || len(p.methods) == 0 {
		return nil, nil
	}

	merged := make(map[string]device.Device, 64)
	for _, m := range p.methods {
		if ctx.Err() != nil {
			break
		}
		devs, err := m.Run(ctx, req)
		if err != nil {
			if sf, ok := m.(SoftFailer); ok && sf.SoftFail() {
				if req.Warn != nil {
					req.Warn(m.Name(), err)
				}
				continue
			}
			return toSlice(merged), err
		}
		for _, d := range devs {
			mergeDevice(merged, d)
		}
	}
	return toSlice(merged), nil
}

// mergeDevice unions d into dst keyed by IPv4 string.
// Empty fields never overwrite filled ones, so ICMP (IP only) plus ARP
// (IP+MAC+vendor) becomes a single row with the ARP details kept.
func mergeDevice(dst map[string]device.Device, d device.Device) {
	ip := d.IP.To4()
	if ip == nil {
		ip = d.IP
	}
	if len(ip) == 0 {
		return
	}
	key := ip.String()
	existing, ok := dst[key]
	if !ok {
		out := cloneDevice(d)
		out.IP = append(net.IP(nil), ip...)
		dst[key] = out
		return
	}
	if len(existing.MAC) == 0 && len(d.MAC) > 0 {
		existing.MAC = append(net.HardwareAddr(nil), d.MAC...)
	}
	if d.Vendor != "" && !device.VendorUnset(d.Vendor) && device.VendorUnset(existing.Vendor) {
		existing.Vendor = d.Vendor
	}
	if existing.Type == "" && d.Type != "" {
		existing.Type = d.Type
	} else if existing.Type == device.TypeUnknown && d.Type == device.TypeNetwork {
		// SSH confirmed a switch NOS; vendor heuristic had nothing.
		existing.Type = d.Type
	}
	if existing.Hostname == "" && d.Hostname != "" {
		existing.Hostname = d.Hostname
	}
	if existing.Status == "" && d.Status != "" {
		existing.Status = d.Status
	} else if d.Status == device.StatusUp {
		existing.Status = device.StatusUp
	}
	if existing.SysInfo.Empty() && !d.SysInfo.Empty() {
		existing.SysInfo = d.SysInfo
	}
	dst[key] = existing
}

// toSlice turns the IP-keyed merge map into a slice and fills missing
// Status/Type so the table printer does not show blank cells.
func toSlice(m map[string]device.Device) []device.Device {
	if len(m) == 0 {
		return nil
	}
	out := make([]device.Device, 0, len(m))
	for _, d := range m {
		if d.Status == "" {
			d.Status = device.StatusUp
		}
		if d.Type == "" {
			d.Type = device.TypeUnknown
		}
		out = append(out, d)
	}
	return out
}

// cloneDevice copies IP/MAC backing arrays so later merges cannot mutate
// a device still held by the method that produced it.
func cloneDevice(d device.Device) device.Device {
	out := d
	if d.IP != nil {
		out.IP = append(net.IP(nil), d.IP...)
	}
	if d.MAC != nil {
		out.MAC = append(net.HardwareAddr(nil), d.MAC...)
	}
	return out
}
