# Luftweht

An intelligent, event-driven network scanner built in Rust that performs phased discovery and comprehensive information gathering without overwhelming target machines.

## Features

### Scanning Modes

- **Fast Mode** (`--mode fast`): Quick rustscan discovery with top ports only
- **Discover Mode** (`--mode discover`): Comprehensive host discovery using ICMP, TCP SYN, and ARP
- **Full Mode** (`--mode full`): Complete pipeline with discovery, port scanning, info gathering, and vulnerability assessment

### Architecture Highlights

- **Event-Driven Pipeline**: Jobs are queued and processed asynchronously
- **Multi-Level Rate Limiting**: Global, per-host, and per-subnet concurrency controls
- **Adaptive Backoff**: Automatically reduces scan rate when errors/timeouts increase
- **Parallel Execution**: Background comprehensive port scans while actively investigating discovered hosts
- **Real-Time Streaming**: NDJSON output streams results as they're discovered

### Scanning Stages (Full Mode)

1. **Discovery Stage**
   - ICMP echo sweeps
   - TCP SYN probes on configurable ports (default: 22, 80, 443, 3389, 8080)
   - ARP discovery for local networks
   - Rustscan fast scan (-F equivalent)

2. **Port Scanning Stage**
   - Fast scans on discovered hosts
   - Background comprehensive `-Pn -p-` scan across all IPs
   - Adaptive prioritization based on open port count

3. **Information Gathering**
   - Service enumeration (version detection)
   - Banner grabbing
   - OS fingerprinting

4. **Vulnerability Scanning** (Default ON)
   - Service-aware nmap script selection
   - Safe, non-invasive checks only
   - Configurable scan levels (basic/extended)

### Rate Limiting & Safety

- **Conservative Defaults**: Max 100 parallel tasks, 5 per host, 20 per subnet
- **Auto-Adaptive**: Monitors error rates and backs off automatically
- **Configurable**: Fine-tune all limits via CLI flags
- **Non-Invasive**: Vuln scanning uses only "safe" nmap scripts

### Output Formats

- **NDJSON Stream**: Real-time event stream (`scan-stream.ndjson`)
- **JSON**: Structured final results (`scan-results.json`)
- **Markdown**: Human-readable report (`scan-report.md`)

## Installation

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- `rustscan` - Fast port scanner ([installation](https://github.com/RustScan/RustScan))
- `nmap` - Network mapper ([installation](https://nmap.org/download.html))
  - **Note**: Luftweht uses rustscan exclusively, which passes work to nmap via its `--` passthrough feature. All scanning goes through rustscan, which delegates service detection, OS fingerprinting, and vulnerability scanning to nmap when needed.

### Building

```bash
git clone https://github.com/donovan-jasper/luftweht.git
cd luftweht
cargo build --release
```

The compiled binary will be at `target/release/luftweht`.

## Usage

### Basic Examples

```bash
# Fast scan of a single IP
luftweht 192.168.1.1 --mode fast

# Discover all hosts in a subnet
luftweht 192.168.1.0/24 --mode discover

# Full comprehensive scan
luftweht 10.0.0.0/24 --mode full

# Multiple targets
luftweht 192.168.1.0/24 10.0.0.0/24 172.16.0.1

# Scan with custom discovery ports
luftweht 192.168.1.0/24 --discovery-ports 22,80,443,8080,3306
```

### Advanced Options

```bash
# Increase parallelism (aggressive)
luftweht 192.168.1.0/24 --max-parallel 200 --max-per-host 10

# Conservative scan (stealthy)
luftweht 192.168.1.0/24 --max-parallel 50 --max-per-host 2

# Disable vulnerability scanning
luftweht 192.168.1.0/24 --no-vuln-scan

# Extended vulnerability scan level
luftweht 192.168.1.0/24 --vuln-level extended

# Tag your scan
luftweht 192.168.1.0/24 --tag "prod-network-audit"

# Dry run (show targets without scanning)
luftweht 192.168.1.0/24 --dry-run

# Custom output directory
luftweht 192.168.1.0/24 --output ./scan-results

# Exclude specific IPs
luftweht 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254

# Verbose logging
luftweht 192.168.1.0/24 -vvv
```

### CLI Reference

```
Usage: luftweht [OPTIONS] <TARGETS>...

Arguments:
  <TARGETS>...  Target CIDR ranges or IPs (e.g., 192.168.1.0/24, 10.0.0.1)

Options:
  -m, --mode <MODE>
          Scanning mode [default: full] [possible values: fast, discover, full]
      --discovery-ports <DISCOVERY_PORTS>
          Discovery ports (comma-separated) [default: 22,80,443,3389,8080]
      --max-parallel <MAX_PARALLEL>
          Maximum parallel tasks globally [default: 100]
      --max-per-host <MAX_PER_HOST>
          Maximum parallel tasks per host [default: 5]
      --max-per-subnet <MAX_PER_SUBNET>
          Maximum parallel tasks per subnet [default: 20]
      --timeout <TIMEOUT>
          Timeout in milliseconds [default: 5000]
      --no-vuln-scan
          Disable vulnerability scanning
      --vuln-level <VULN_LEVEL>
          Vulnerability scan level [default: basic] [possible values: basic, extended]
      --vuln-max-parallel <VULN_MAX_PARALLEL>
          Maximum parallel vulnerability scans [default: 10]
      --vuln-delay <VULN_DELAY>
          Delay between vuln probes (ms) [default: 100]
  -o, --output <OUTPUT>
          Output directory [default: ./output]
      --no-json
          Disable JSON output
      --no-markdown
          Disable Markdown output
      --exclude <EXCLUDE>
          Exclude IPs or ranges (comma-separated)
      --target-file <TARGET_FILE>
          Load targets from file
      --resume <RESUME>
          Resume from state file
      --state-file <STATE_FILE>
          Save state file for resuming
      --tag <TAG>
          Tag for this scan run
      --dry-run
          Dry run (show what would be scanned without sending packets)
  -v, --verbose...
          Verbosity level (-v, -vv, -vvv)
  -h, --help
          Print help
  -V, --version
          Print version
```

## Architecture

### Event-Driven Design

```
JobQueue (MPSC Channel)
    ↓
Worker Pool (Tokio Tasks)
    ├─ Discovery Engine
    ├─ Port Scan Engine
    ├─ Info Gather Engine
    └─ Vuln Scan Engine
         ↓
Host Manager (Aggregator)
    ↓
Output Writers (Stream, JSON, Markdown)
```

### Key Components

- **Job Queue**: Central MPSC channel distributing work to workers
- **Host Manager**: Tracks all discovered hosts, schedules follow-up jobs
- **Rate Limiter**: Three-tier semaphore system (global/host/subnet)
- **Adaptive Backoff**: Monitors error rates, automatically throttles
- **Scan Executors**: Wrappers for rustscan/nmap with parsing

## Output Examples

### NDJSON Stream (`scan-stream.ndjson`)

```json
{"event":"host_discovered","timestamp":"2025-01-19T12:00:00Z","ip":"192.168.1.1","method":"IcmpEcho"}
{"event":"port_discovered","timestamp":"2025-01-19T12:00:01Z","ip":"192.168.1.1","port":22}
{"event":"port_discovered","timestamp":"2025-01-19T12:00:01Z","ip":"192.168.1.1","port":80}
```

### JSON Output (`scan-results.json`)

```json
{
  "metadata": {
    "scan_id": "abc123",
    "start_time": "2025-01-19T12:00:00Z",
    "end_time": "2025-01-19T12:05:00Z",
    "mode": "Full"
  },
  "summary": {
    "total_hosts": 10,
    "total_ports": 45
  },
  "hosts": [...]
}
```

## Limitations & Future Work

### Current Limitations

- **ICMP/TCP/ARP Discovery**: Placeholder implementations (need raw socket support)
- **XML Parsing**: Simplified nmap XML parser (should use proper XML library)
- **Resume Support**: CLI flags exist but logic not implemented
- **Exclusion Lists**: Parsing exists but filtering not implemented

### Planned Features

- Raw packet crafting for true ICMP/TCP SYN/ARP discovery
- Full nmap XML parsing with quick-xml
- State persistence and resume capability
- Web UI for real-time monitoring
- Plugin system for custom scanning logic
- Integration with CVE databases

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `cargo test` and `cargo clippy` pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Security & Ethics

**IMPORTANT**: This tool is for authorized security testing only. Always ensure you have explicit permission before scanning any networks or systems you don't own.

- Only use on networks/systems you're authorized to test
- Respect rate limits to avoid disruption
- Consider using `--dry-run` first to verify targets
- Be aware that aggressive scanning may trigger IDS/IPS

## Acknowledgments

- [RustScan](https://github.com/RustScan/RustScan) - Fast port scanner (primary scanning tool)
- [nmap](https://nmap.org/) - Network exploration and security auditing (used via rustscan passthrough)
- Built with [Tokio](https://tokio.rs/) async runtime
