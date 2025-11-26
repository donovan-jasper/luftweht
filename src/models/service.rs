use serde::{Deserialize, Serialize};

/// Port state and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub discovered_by: String,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

/// Service information for a port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service_name: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
}

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnInfo {
    pub port: u16,
    pub vuln_id: String,
    pub title: String,
    pub severity: VulnSeverity,
    pub description: Option<String>,
    pub script: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
