# network-scanner

Discover active devices on **your local IPv4 subnet** using an ICMP-then-ARP
discovery pipeline.

The tool auto-detects the local interface and CIDR, pings every host (up to 3
echo attempts, stop on reply), then sends concurrent ARP requests. It prints a
table of IP, MAC, vendor (OUI), hostname (reverse DNS), status, and a simple
device type.

Remote / arbitrary ranges are **not** supported — only the subnet of the
selected local interface is scanned.

## Requirements

- Go 1.21+ with **CGO enabled** (default)
- **libpcap** (usually preinstalled on macOS; on Linux: `libpcap-dev` / `libpcap-devel`)
- **Elevated privileges** to open capture devices and send ICMP:
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
sudo ./network-scanner -no-ping        # ARP only
sudo ./network-scanner -ssh            # SSH system info (needs SSH_USERS / SSH_PASSWORDS)
sudo ./network-scanner -max-hosts 65534 -scan-timeout 15m   # allow a /16

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
Workers   : 64  |  ping: 3×750ms  |  ARP timeout: 750ms
Scanning… (Ctrl-C to abort)
  icmp: 254/254 (100%)
  arp: 254/254 (100%)
Found 12 device(s) in 2.4s

IP             MAC                VENDOR      HOSTNAME           STATUS  TYPE
─────────────── ───────────────── ──────────── ──────────────── ────── ──────────────
192.168.1.1    AA:BB:CC:11:22:33  TP-Link     router.lan        up     Network device
192.168.1.42   AA:BB:CC:DD:EE:FF  Apple       mymac.lan         up     End device
...
```

## How it works

1. **Interface detection** — picks an up, non-loopback interface with a
   non-link-local IPv4 address (prefers RFC1918 private ranges).
2. **ICMP ping** — worker pool sends ICMP echo to every host (max 3 attempts;
   an IP that replies is not retried). Hosts that answer without later ARP
   replies still appear (MAC shown as `-`).
3. **ARP sweep** — worker pool sends ARP who-has requests for every host in
   the subnet and collects replies (`github.com/google/gopacket` / libpcap).
   ICMP does **not** filter ARP targets — hosts that drop ping are still found.
4. **Enrichment** — offline OUI vendor map and optional reverse DNS.
5. **SSH (opt-in, `-ssh`)** — TCP-checks port 22 on every target, then tries
   the cartesian product of `SSH_USERS` × `SSH_PASSWORDS` from the environment
   or a local `.env`. The first successful login collects hostname, model,
   software version, and uptime. Passwords are never printed. Only the local
   subnet is probed.
6. **Output** — results sorted by IP and printed as a table (plus an SSH
   system-info block when any host was reached).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i` / `-interface` | auto | Interface name |
| `-workers` | 64 | Concurrent workers per discovery method |
| `-timeout` | 750ms | Per-attempt ICMP wait and ARP settle window |
| `-ping-count` | 3 | Max ICMP echo attempts per IP |
| `-no-ping` | false | Skip the ICMP stage |
| `-scan-timeout` | 2m | Overall deadline |
| `-no-dns` | false | Skip reverse DNS |
| `-ssh` | false | Try SSH with `SSH_USERS` / `SSH_PASSWORDS` and collect system info |
| `-quiet` | false | Hide progress |
| `-max-hosts` | 4096 | Abort if the subnet has more hosts than this (`0` = no limit) |
| `-version` | | Print version |

### SSH credentials (`.env`)

`-ssh` reads comma-separated alternatives from the environment (a `.env` file
in the working directory is loaded if present; existing process env wins):

```
SSH_USERS=admin,root
SSH_PASSWORDS=password123,psw123!
SSH_PORT=22
```

That is a cartesian product: each user is tried with each password, stopping
at the first success per host. Use this only on a LAN you own. Copy
`.env.example` and never commit real passwords (`.env` is gitignored).

## License

MIT

## Docker Compose on Linux

The Compose group (`db` + `scanner` in `docker-compose.yml`) is for a **Linux
host that already has Docker Engine** (bare metal, Ubuntu VM, on-prem server).
The scanner uses **host networking** so ARP sees the real LAN. Use a
bridged or physical NIC (for example UTM bridged mode). This is **not**
intended for Docker Desktop on macOS.

You need the Compose plugin (`docker compose version`). If your user is not
in the `docker` group, prefix the commands with `sudo`.

```bash
cd network

# Build the scanner image and start the group
docker compose up --build

# Detached: keep Postgres running in the background
docker compose up --build -d db

# The scanner image defaults to -h. To run a scan, pass flags after
# the service name. Compose starts a healthy db first.
docker compose run --rm scanner
docker compose run --rm scanner -i eth0
docker compose run --rm scanner -workers 128 -timeout 300ms
docker compose run --rm scanner -no-dns -quiet
docker compose run --rm scanner -no-ping
docker compose run --rm scanner -max-hosts 65534 -scan-timeout 15m

# Help
docker compose run --rm scanner -h

# Stop containers (keeps the Postgres volume)
docker compose down

# Stop and delete the database volume
docker compose down -v
```

Notes:

- `network_mode: host` means the scanner talks to Postgres at
  `127.0.0.1:5432` (the published host port). The Compose service name
  `db` is not resolvable from the scanner.
- `NET_RAW` and `NET_ADMIN` are already granted in the Compose file, so
  you do not need to wrap the container in `sudo` for ICMP/ARP.
- Optional env vars: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`,
  `POSTGRES_PORT`, `DATABASE_URL`, `SSH_USERS`, `SSH_PASSWORDS`, `SSH_PORT`
  (defaults are in `docker-compose.yml`).
- SSH inventory: `docker compose run --rm scanner -ssh`
