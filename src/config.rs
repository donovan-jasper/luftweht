use clap::{Parser, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "luftweht")]
#[command(author, version, about = "Intelligent network scanner with phased discovery", long_about = None)]
pub struct Config {
    /// Target CIDR ranges or IPs (e.g., 192.168.1.0/24, 10.0.0.1)
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Scanning mode
    #[arg(short, long, value_enum, default_value = "full")]
    pub mode: ScanMode,

    /// Discovery ports (comma-separated)
    #[arg(long, default_value = "22,80,443,3389,8080")]
    pub discovery_ports: String,

    /// Maximum parallel tasks globally
    #[arg(long, default_value = "100")]
    pub max_parallel: usize,

    /// Maximum parallel tasks per host
    #[arg(long, default_value = "5")]
    pub max_per_host: usize,

    /// Maximum parallel tasks per subnet
    #[arg(long, default_value = "20")]
    pub max_per_subnet: usize,

    /// Timeout in milliseconds
    #[arg(long, default_value = "5000")]
    pub timeout: u64,

    /// Maximum scan time in seconds before forcing completion
    #[arg(long, default_value = "1800")]
    pub scan_timeout_secs: u64,

    /// Disable vulnerability scanning
    #[arg(long)]
    pub no_vuln_scan: bool,

    /// Vulnerability scan level
    #[arg(long, value_enum, default_value = "basic")]
    pub vuln_level: VulnLevelArg,

    /// Maximum parallel vulnerability scans
    #[arg(long, default_value = "10")]
    pub vuln_max_parallel: usize,

    /// Delay between vuln probes (ms)
    #[arg(long, default_value = "100")]
    pub vuln_delay: u64,

    /// Rustscan ulimit (max concurrent sockets) - lower is safer
    #[arg(long, default_value = "100")]
    pub rustscan_ulimit: u16,

    /// Rustscan batch size (ports scanned at once) - lower is safer
    #[arg(long, default_value = "100")]
    pub rustscan_batch_size: u16,

    /// Output directory
    #[arg(short, long, default_value = "./output")]
    pub output: PathBuf,

    /// Disable JSON output
    #[arg(long)]
    pub no_json: bool,

    /// Disable Markdown output
    #[arg(long)]
    pub no_markdown: bool,

    /// Exclude IPs or ranges (comma-separated)
    #[arg(long)]
    pub exclude: Option<String>,

    /// Load targets from file
    #[arg(long)]
    pub target_file: Option<PathBuf>,

    /// Resume from state file
    #[arg(long)]
    pub resume: Option<PathBuf>,

    /// Save state file for resuming
    #[arg(long)]
    pub state_file: Option<PathBuf>,

    /// Tag for this scan run
    #[arg(long)]
    pub tag: Option<String>,

    /// Dry run (show what would be scanned without sending packets)
    #[arg(long)]
    pub dry_run: bool,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScanMode {
    /// Quick discovery + top ports only
    Fast,
    /// Host discovery only, no port/service scanning
    DiscoverOnly,
    /// Full discovery, no deep ports
    Discover,
    /// Complete pipeline: Discovery → Port Scan → Info → Vuln
    Full,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum VulnLevelArg {
    Basic,
    Extended,
}

impl Config {
    /// Parse discovery ports from string
    pub fn parse_discovery_ports(&self) -> Vec<u16> {
        self.discovery_ports
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    }

    /// Parse exclude list
    pub fn parse_excludes(&self) -> Vec<String> {
        self.exclude
            .as_ref()
            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
            .unwrap_or_default()
    }

    /// Check if vulnerability scanning is enabled
    pub fn vuln_scan_enabled(&self) -> bool {
        !self.no_vuln_scan && matches!(self.mode, ScanMode::Full)
    }
}

/// Scan profile with default values
#[derive(Debug, Clone)]
pub struct ScanProfile {
    pub name: String,
    pub max_parallel: usize,
    pub max_per_host: usize,
    pub max_per_subnet: usize,
    pub timeout_ms: u64,
}

impl ScanProfile {
    pub fn fast() -> Self {
        Self {
            name: "fast".to_string(),
            max_parallel: 200,
            max_per_host: 10,
            max_per_subnet: 50,
            timeout_ms: 2000,
        }
    }

    pub fn balanced() -> Self {
        Self {
            name: "balanced".to_string(),
            max_parallel: 100,
            max_per_host: 5,
            max_per_subnet: 20,
            timeout_ms: 5000,
        }
    }

    pub fn thorough() -> Self {
        Self {
            name: "thorough".to_string(),
            max_parallel: 50,
            max_per_host: 3,
            max_per_subnet: 10,
            timeout_ms: 10000,
        }
    }
}
