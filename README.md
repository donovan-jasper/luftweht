# Luftweht

A parallel nmap scanner orchestrator written in Go. Scans multiple subnets efficiently with adaptive concurrency while maintaining per-host rate limiting to avoid overwhelming targets.

## Features

- **Parallel Scanning**: Scans multiple hosts concurrently with configurable worker pools
- **Adaptive Concurrency**: Automatically adjusts worker count based on error/timeout rates
- **Per-Host Rate Limiting**: Uses nmap's T2/T3 timing to avoid overwhelming individual hosts
- **Resume Support**: Saves progress to SQLite - interrupted scans can be resumed
- **Comprehensive Discovery**: Uses multiple probe methods (ICMP, TCP SYN/ACK, UDP, ARP)
- **Full Port Coverage**: Scans all 65535 TCP and UDP ports in chunks for progress visibility

## Scan Pipeline

```
1. Host Discovery    →  2. TCP Port Scan    →  3. Service Detection  →  4. UDP Scan
   (multi-method)         (1-65535)              (-sV on open)           (1-65535)
```

### Phase 1: Host Discovery
Uses aggressive multi-method discovery:
- ARP ping (most reliable on local networks)
- ICMP Echo, Timestamp, Address Mask
- TCP SYN probes to common ports (21,22,23,25,80,111,135,139,443,445,3389,8080,8443)
- TCP ACK probes to 80,443
- UDP probes to 53,123,137,161,500

### Phase 2-4: Port Scanning
- TCP and UDP scans split into 7 chunks (~10k ports each) for progress visibility
- Service version detection (-sV -sC) on discovered open ports
- Results saved to SQLite as discovered

## Installation

Requires:
- Go 1.21+
- nmap (must be in PATH)
- Root/sudo privileges (for SYN scans)

```bash
git clone https://github.com/donovan-jasper/luftweht.git
cd luftweht
go build -o luftweht ./cmd/scanner/
sudo mv luftweht /usr/local/bin/
```

## Usage

```bash
# Scan single subnet
sudo luftweht 10.0.0.0/24

# Scan multiple subnets
sudo luftweht 10.0.0.0/24 192.168.1.0/24

# Load targets from file
sudo luftweht --file targets.txt

# Combined (file + args)
sudo luftweht --file targets.txt 10.10.0.0/16

# Full options
sudo luftweht \
  --file targets.txt \
  --db scan_results.db \
  --timing T2 \
  --max-workers 50 \
  --verbose
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --file` | | File containing target subnets (one per line) |
| `-d, --db` | scan_results.db | SQLite database file for results |
| `-T, --timing` | T2 | nmap timing template (T0-T5) |
| `--min-workers` | 5 | Minimum concurrent workers |
| `--max-workers` | auto | Maximum concurrent workers (0=auto-detect) |
| `--tcp-chunks` | 7 | Number of port chunks for TCP scan |
| `--skip-udp` | false | Skip UDP scanning |
| `--skip-service` | false | Skip service version detection |
| `--skip-discovery` | false | Skip host discovery, scan all IPs directly (for firewall-heavy networks) |
| `--restart` | false | Force restart, ignoring existing progress |
| `-v, --verbose` | false | Verbose output |

## Adaptive Concurrency

The scanner automatically detects optimal worker count based on:
- File descriptor limits (`ulimit -n`)
- Available system memory
- Target utilization (default 80%)

During scanning, it monitors error rates and adjusts:
- >10% timeout rate: Reduces workers by 20%
- <2% timeout rate: Increases workers by 10%

## Resume Support

Progress is saved to SQLite after each scan chunk completes. If interrupted:

```bash
# Scanner will prompt to resume
sudo luftweht 10.0.0.0/24
# "Found incomplete scan with X pending jobs. Resume? [Y/n]"

# Or force a fresh start
sudo luftweht --restart 10.0.0.0/24
```

## Web Viewer

Luftweht includes a real-time web viewer for monitoring scan progress and exploring results.

### Running the Viewer

```bash
# Build the frontend (first time only)
cd viewer/frontend && npm install && npm run build && cd ../..

# Start the viewer
go run ./viewer/server.go --db scan_results.db --port 8080

# Or build and run
go build -o viewer-server ./viewer/server.go
./viewer-server --db scan_results.db --port 8080
```

Open http://localhost:8080 to view results.

### Viewer Features

- **Real-time Updates**: Auto-refreshes via Server-Sent Events (SSE) every 2 seconds
- **Scan Progress**: Live progress bar showing completion percentage
- **Host Status**: Visual indicators for each scan phase (discovered → tcp_scanning → tcp_done → svc_scanning → svc_done → complete)
- **Port Details**: Expand any host to see open ports, services, and versions
- **Filtering**: Search by IP/hostname, filter by status, or find hosts with specific open ports
- **Subnet Grouping**: Hosts organized by subnet with collapsible sections

### Running Scanner + Viewer Together

```bash
# Terminal 1: Start the scanner
sudo ./luftweht --file targets.txt --skip-udp -v

# Terminal 2: Start the viewer
go run ./viewer/server.go --db scan_results.db

# Open browser to http://localhost:8080
```

The viewer connects to the database in read-only mode, so it won't interfere with the scanner.

## Querying Results (CLI)

Results are stored in SQLite. Query with:

```bash
# List all discovered hosts
sqlite3 scan_results.db "SELECT ip, hostname, status FROM hosts"

# List all open ports
sqlite3 scan_results.db "SELECT h.ip, p.port, p.protocol, p.service, p.version
FROM ports p JOIN hosts h ON p.host_id = h.id
WHERE p.state = 'open'"

# Export to CSV
sqlite3 -header -csv scan_results.db "SELECT * FROM ports WHERE state='open'" > open_ports.csv
```

## Database Schema

```sql
-- Discovered hosts
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE NOT NULL,
    hostname TEXT,
    subnet TEXT,
    status TEXT,  -- discovered|tcp_scanning|tcp_done|svc_done|udp_scanning|complete
    discovered_at DATETIME,
    completed_at DATETIME
);

-- Discovered ports
CREATE TABLE ports (
    id INTEGER PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id),
    port INTEGER,
    protocol TEXT,  -- tcp|udp
    state TEXT,     -- open|closed|filtered
    service TEXT,
    version TEXT,
    discovered_at DATETIME,
    UNIQUE(host_id, port, protocol)
);

-- Scan progress (for resume)
CREATE TABLE scan_progress (
    id INTEGER PRIMARY KEY,
    host_id INTEGER,
    subnet TEXT,
    scan_type TEXT,  -- discovery|tcp|svc|udp
    port_start INTEGER,
    port_end INTEGER,
    status TEXT,     -- pending|running|complete|failed
    started_at DATETIME,
    completed_at DATETIME,
    error TEXT
);
```

## Security & Ethics

**IMPORTANT**: This tool is for authorized security testing only. Always ensure you have explicit permission before scanning any networks or systems you don't own.

- Only use on networks/systems you're authorized to test
- Respect rate limits to avoid disruption
- Be aware that aggressive scanning may trigger IDS/IPS

## License

MIT
