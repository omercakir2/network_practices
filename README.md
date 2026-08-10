# network-scanner

Discover active devices on **your local IPv4 subnet** using an ARP scan.

The tool auto-detects the local interface and CIDR, sends concurrent ARP
requests, and prints a table of IP, MAC, vendor (OUI), hostname (reverse DNS),
status, and a simple device type.

Remote / arbitrary ranges are **not** supported — only the subnet of the
selected local interface is scanned.

## Requirements

- Go 1.21+ with **CGO enabled** (default)
- **libpcap** (usually preinstalled on macOS; on Linux: `libpcap-dev` / `libpcap-devel`)
- **Elevated privileges** to open capture devices:
  - macOS/Linux: `sudo`, or
  - Linux: `CAP_NET_RAW`, or
  - macOS: membership in the BPF access group (e.g. Wireshark ChmodBPF)

## Build

```bash
cd network
go build -o network-scanner .
# equivalent explicit form:
# CGO_ENABLED=1 go build -o network-scanner .
```

## Run

```bash
# Auto-detect interface and scan its subnet
sudo ./network-scanner

# Choose an interface
sudo ./network-scanner -i en0          # macOS Wi-Fi
sudo ./network-scanner -i eth0         # typical Linux

# Faster / quieter options
sudo ./network-scanner -workers 128 -timeout 300ms
sudo ./network-scanner -no-dns -quiet
sudo ./network-scanner -tcp-probe      # optional TCP connect on hits

# Help
./network-scanner -h
```

### Linux without full root

```bash
go build -o network-scanner .
sudo setcap cap_net_raw+ep ./network-scanner
./network-scanner
```

## Example output

```
Interface : en0 (aa:bb:cc:dd:ee:ff)
Local IP  : 192.168.1.42
Subnet    : 192.168.1.0/24 (254 hosts)
Workers   : 64  |  ARP timeout: 500ms
Scanning… (Ctrl-C to abort)
  progress: 254/254 (100%)
Found 12 device(s) in 1.8s

IP             MAC                VENDOR      HOSTNAME           STATUS  TYPE
─────────────── ───────────────── ──────────── ──────────────── ────── ──────────────
192.168.1.1    AA:BB:CC:11:22:33  TP-Link     router.lan        up     Network device
192.168.1.42   AA:BB:CC:DD:EE:FF  Apple       mymac.lan         up     End device
...
```

## How it works

1. **Interface detection** — picks an up, non-loopback interface with a
   non-link-local IPv4 address (prefers RFC1918 private ranges).
2. **ARP sweep** — worker pool sends ARP who-has requests for every host in
   the subnet and collects replies (`github.com/mdlayher/arp`).
3. **Enrichment** — offline OUI vendor map, optional reverse DNS, optional
   lightweight TCP connect to common ports.
4. **Output** — results sorted by IP and printed as a table.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i` / `-interface` | auto | Interface name |
| `-workers` | 64 | Concurrent ARP workers |
| `-timeout` | 500ms | Per-host ARP wait |
| `-scan-timeout` | 2m | Overall deadline |
| `-no-dns` | false | Skip reverse DNS |
| `-tcp-probe` | false | TCP connect check on hits |
| `-quiet` | false | Hide progress |
| `-version` | | Print version |

## License

MIT
