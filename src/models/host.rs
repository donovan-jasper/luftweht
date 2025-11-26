use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use super::service::{PortInfo, ServiceInfo};

/// Method by which a host was discovered
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DiscoveryMethod {
    IcmpEcho,
    TcpSyn { port: u16 },
    Arp,
    RustscanFast,
    RustscanFull,
    RustscanCustom { ports: Vec<u16> },
    CidrSweep,
}

/// OS fingerprint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub confidence: f32,
    pub method: String,
}

/// Thread-safe Host representation
#[derive(Debug, Clone)]
pub struct Host {
    inner: Arc<RwLock<HostInner>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostInner {
    pub ip: IpAddr,
    pub is_local: bool,
    pub discovered_by: Vec<DiscoveryMethod>,
    pub open_ports: HashMap<u16, PortInfo>,
    pub os_guess: Option<OsFingerprint>,
    pub services: Vec<ServiceInfo>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl Host {
    pub fn new(ip: IpAddr, is_local: bool, discovered_by: DiscoveryMethod) -> Self {
        let now = chrono::Utc::now();
        Self {
            inner: Arc::new(RwLock::new(HostInner {
                ip,
                is_local,
                discovered_by: vec![discovered_by],
                open_ports: HashMap::new(),
                os_guess: None,
                services: Vec::new(),
                first_seen: now,
                last_updated: now,
            })),
        }
    }

    pub fn ip(&self) -> IpAddr {
        self.inner.read().unwrap().ip
    }

    pub fn is_local(&self) -> bool {
        self.inner.read().unwrap().is_local
    }

    pub fn add_discovery_method(&self, method: DiscoveryMethod) {
        let mut inner = self.inner.write().unwrap();
        if !inner.discovered_by.contains(&method) {
            inner.discovered_by.push(method);
        }
        inner.last_updated = chrono::Utc::now();
    }

    pub fn add_port(&self, port: u16, info: PortInfo) {
        let mut inner = self.inner.write().unwrap();
        inner.open_ports.insert(port, info);
        inner.last_updated = chrono::Utc::now();
    }

    pub fn add_service(&self, service: ServiceInfo) {
        let mut inner = self.inner.write().unwrap();
        inner.services.push(service);
        inner.last_updated = chrono::Utc::now();
    }

    pub fn set_os_fingerprint(&self, os: OsFingerprint) {
        let mut inner = self.inner.write().unwrap();
        inner.os_guess = Some(os);
        inner.last_updated = chrono::Utc::now();
    }

    pub fn get_open_ports(&self) -> Vec<u16> {
        self.inner
            .read()
            .unwrap()
            .open_ports
            .keys()
            .copied()
            .collect()
    }

    pub fn port_count(&self) -> usize {
        self.inner.read().unwrap().open_ports.len()
    }

    /// Serialize to JSON for output
    pub fn to_json(&self) -> serde_json::Value {
        let inner = self.inner.read().unwrap();
        serde_json::json!({
            "ip": inner.ip.to_string(),
            "is_local": inner.is_local,
            "discovered_by": inner.discovered_by,
            "open_ports": inner.open_ports,
            "os_guess": inner.os_guess,
            "services": inner.services,
            "first_seen": inner.first_seen.to_rfc3339(),
            "last_updated": inner.last_updated.to_rfc3339(),
        })
    }
}
