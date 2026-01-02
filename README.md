# Luftweht

Lightweight network recon orchestrator. Wraps nmap with parallel execution, progress tracking, and a collaborative web viewer.

## What it does

- Runs nmap scans across multiple subnets in parallel
- Stores results in SQLite for easy querying and resume
- Web UI shows live progress and lets multiple people annotate findings

## Quick Start

```bash
# Build
make build

# Scan (needs sudo for raw sockets)
sudo ./luftweht 10.0.0.0/24 192.168.1.0/24

# View results
./luftweht-viewer -db scan_results.db -password yourpass
# Open http://localhost:8080
```

## Scanner

```bash
sudo ./luftweht [subnets...] [options]

Options:
  -f, --file FILE      Load targets from file
  -d, --db FILE        Database path (default: scan_results.db)
  -T, --timing T0-T5   Nmap timing (default: T2)
  --max-workers N      Concurrent scans (default: auto)
  --skip-udp           Skip UDP scanning
  --skip-discovery     Skip host discovery, scan all IPs
  --restart            Ignore previous progress, start fresh
  -v                   Verbose output
```

Scan pipeline: Discovery → TCP (1-65535) → Service detection → UDP (1-65535)

## Viewer

Web UI for browsing results. Supports multiple users with password auth.

```bash
./luftweht-viewer -db scan_results.db -password <pass> -port 8080
```

Features:
- Live scan progress via SSE
- Filter by IP, port, status
- Add comments and credentials per host
- Manual OS tagging
- Database backup/download

## Building

```bash
make build           # Build for current platform
make releases        # Build for darwin-arm64, linux-amd64, linux-arm64 (needs Docker)
```

Requires: Go 1.21+, nmap, Node.js (for viewer frontend)

## License

MIT
