use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::host::Host;

/// Job types that can be queued for execution
#[derive(Debug, Clone)]
pub enum Job {
    Discovery(DiscoveryJob),
    PortScan(PortScanJob),
    InfoGather(InfoGatherJob),
    VulnScan(VulnScanJob),
}

/// Discovery job to find hosts
#[derive(Debug, Clone)]
pub struct DiscoveryJob {
    pub method: DiscoveryMethodType,
    pub targets: Vec<IpAddr>,
    pub options: DiscoveryOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryMethodType {
    IcmpEcho,
    TcpSyn { ports: Vec<u16> },
    Arp,
    RustscanFast,
    RustscanCustom { ports: Vec<u16> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryOptions {
    pub timeout_ms: u64,
    pub max_retries: u32,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            max_retries: 2,
        }
    }
}

/// Port scanning job
#[derive(Debug, Clone)]
pub struct PortScanJob {
    pub host: Host,
    pub scan_type: PortScanType,
    pub options: PortScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortScanType {
    Fast,          // Top 1000 ports
    Full,          // All 65535 ports
    Custom(Vec<u16>), // Specific ports
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanOptions {
    pub timeout_ms: u64,
    pub skip_ping: bool, // -Pn flag
}

impl Default for PortScanOptions {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            skip_ping: false,
        }
    }
}

/// Information gathering job
#[derive(Debug, Clone)]
pub struct InfoGatherJob {
    pub host: Host,
    pub ports: Vec<u16>,
    pub gather_types: Vec<InfoGatherType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InfoGatherType {
    ServiceEnum,
    BannerGrab,
    OsDetection,
}

/// Vulnerability scanning job
#[derive(Debug, Clone)]
pub struct VulnScanJob {
    pub host: Host,
    pub ports: Vec<u16>,
    pub level: VulnLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnLevel {
    Basic,    // Only safest scripts
    Extended, // All "safe" category scripts
}

impl Default for VulnLevel {
    fn default() -> Self {
        Self::Basic
    }
}
