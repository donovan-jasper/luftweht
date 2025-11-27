use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::models::host::{DiscoveryMethod, Host};
use crate::models::job::{InfoGatherJob, InfoGatherType, Job, PortScanJob, PortScanType, VulnScanJob};
use crate::queue::JobQueue;

/// Event emitted when hosts or ports are discovered
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    HostDiscovered {
        host: Host,
        method: DiscoveryMethod,
    },
    PortDiscovered {
        host: Host,
        port: u16,
    },
    HostUpdated {
        host: Host,
    },
}

/// Manages all discovered hosts and coordinates job scheduling
#[derive(Clone)]
pub struct HostManager {
    hosts: Arc<RwLock<HashMap<IpAddr, Host>>>,
    job_queue: JobQueue,
    event_tx: mpsc::UnboundedSender<DiscoveryEvent>,
    vuln_scan_enabled: bool,
}

impl HostManager {
    pub fn new(job_queue: JobQueue, vuln_scan_enabled: bool) -> (Self, mpsc::UnboundedReceiver<DiscoveryEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let manager = Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
            job_queue,
            event_tx,
            vuln_scan_enabled,
        };

        (manager, event_rx)
    }

    /// Register a newly discovered host
    pub fn register_host(&self, ip: IpAddr, is_local: bool, method: DiscoveryMethod) -> Host {
        let mut hosts = self.hosts.write().unwrap();

        if let Some(existing) = hosts.get(&ip) {
            existing.add_discovery_method(method.clone());
            debug!("Host {} rediscovered via {:?}", ip, method);

            // Emit event
            let _ = self.event_tx.send(DiscoveryEvent::HostUpdated {
                host: existing.clone(),
            });

            return existing.clone();
        }

        // New host
        let host = Host::new(ip, is_local, method.clone());
        hosts.insert(ip, host.clone());

        info!("New host discovered: {} via {:?}", ip, method);

        // Emit event
        let _ = self.event_tx.send(DiscoveryEvent::HostDiscovered {
            host: host.clone(),
            method,
        });

        // NOTE: Port scanning now scheduled explicitly after discovery phase completes
        // Previously auto-scheduled here, which caused discovery to hang waiting for sudo
        // self.schedule_port_scan(host.clone());

        host
    }

    /// Register discovered port on a host
    pub fn register_port(&self, ip: IpAddr, port: u16) -> Option<Host> {
        let hosts = self.hosts.read().unwrap();
        let host = hosts.get(&ip)?;

        debug!("Port discovered: {}:{}", ip, port);

        // Add port to the host
        host.add_port(port, crate::models::service::PortInfo {
            port,
            protocol: crate::models::service::Protocol::Tcp,
            state: crate::models::service::PortState::Open,
            discovered_by: "rustscan".to_string(),
            banner: None,
        });

        // Emit event
        let _ = self.event_tx.send(DiscoveryEvent::PortDiscovered {
            host: host.clone(),
            port,
        });

        // NOTE: Info gathering now scheduled explicitly after discovery phase completes
        // Previously auto-scheduled here, causing discovery to hang (requires sudo for nmap -O)
        // self.schedule_info_gather(host.clone(), vec![port]);

        Some(host.clone())
    }

    /// Get host by IP
    pub fn get_host(&self, ip: &IpAddr) -> Option<Host> {
        self.hosts.read().unwrap().get(ip).cloned()
    }

    /// Get all hosts
    pub fn get_all_hosts(&self) -> Vec<Host> {
        self.hosts.read().unwrap().values().cloned().collect()
    }

    /// Get hosts count
    pub fn host_count(&self) -> usize {
        self.hosts.read().unwrap().len()
    }

    /// Schedule port scan for a host
    fn schedule_port_scan(&self, host: Host) {
        let job = Job::PortScan(PortScanJob {
            host,
            scan_type: PortScanType::Fast,
            options: Default::default(),
        });

        if let Err(e) = self.job_queue.submit(job) {
            tracing::error!("Failed to schedule port scan: {}", e);
        }
    }

    /// Schedule info gathering for ports
    fn schedule_info_gather(&self, host: Host, ports: Vec<u16>) {
        let job = Job::InfoGather(InfoGatherJob {
            host: host.clone(),
            ports: ports.clone(),
            gather_types: vec![
                InfoGatherType::ServiceEnum,
                InfoGatherType::BannerGrab,
                InfoGatherType::OsDetection,
            ],
        });

        if let Err(e) = self.job_queue.submit(job) {
            tracing::error!("Failed to schedule info gather: {}", e);
        }

        // Schedule vuln scan if enabled
        if self.vuln_scan_enabled {
            let vuln_job = Job::VulnScan(VulnScanJob {
                host,
                ports,
                level: Default::default(),
            });

            if let Err(e) = self.job_queue.submit(vuln_job) {
                tracing::error!("Failed to schedule vuln scan: {}", e);
            }
        }
    }

    /// Schedule comprehensive port scan for all discovered hosts
    pub fn schedule_comprehensive_scan(&self) {
        let hosts = self.get_all_hosts();
        info!("Scheduling comprehensive -Pn -p- scan for {} hosts", hosts.len());

        for host in hosts {
            let job = Job::PortScan(PortScanJob {
                host,
                scan_type: PortScanType::Full,
                options: crate::models::job::PortScanOptions {
                    timeout_ms: 5000,
                    skip_ping: true, // -Pn
                },
            });

            if let Err(e) = self.job_queue.submit(job) {
                tracing::error!("Failed to schedule comprehensive scan: {}", e);
            }
        }
    }
}
