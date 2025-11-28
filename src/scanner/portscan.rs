use tracing::{debug, info};
use anyhow::Result;

use crate::models::host::DiscoveryMethod;
use crate::models::job::{PortScanJob, PortScanType};
use crate::models::service::{PortInfo, PortState, Protocol};
use crate::queue::HostManager;
use crate::rate_limit::{AdaptiveBackoff, RateLimiter};
use crate::scanner::ScanExecutor;

/// Port scanning engine
pub struct PortScanEngine {
    host_manager: HostManager,
    rate_limiter: RateLimiter,
    backoff: AdaptiveBackoff,
}

impl PortScanEngine {
    pub fn new(
        host_manager: HostManager,
        rate_limiter: RateLimiter,
        backoff: AdaptiveBackoff,
    ) -> Self {
        Self {
            host_manager,
            rate_limiter,
            backoff,
        }
    }

    /// Execute a port scan job
    pub async fn execute(&self, job: PortScanJob) -> Result<()> {
        let ip = job.host.ip();
        let _guard = self.rate_limiter.acquire(ip).await;

        info!(
            "Port scanning {} ({:?})",
            ip,
            job.scan_type
        );

        let ports = match &job.scan_type {
            PortScanType::Fast => None, // Use rustscan defaults
            PortScanType::Full => Some(Vec::new()), // Empty vec signals full scan
            PortScanType::Custom(ports) => Some(ports.clone()),
        };

        // Execute rustscan
        match ScanExecutor::rustscan(
            &[ip],
            ports,
            job.options.timeout_ms,
            job.options.skip_ping,
        )
        .await
        {
            Ok(result) => {
                info!(
                    "Found {} open ports on {}",
                    result.open_ports.len(),
                    ip
                );

                // Register all discovered ports
                for port in result.open_ports {
                    let port_info = PortInfo {
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        discovered_by: format!("rustscan-{:?}", job.scan_type),
                        banner: None,
                    };

                    job.host.add_port(port, port_info);
                    self.host_manager.register_port(ip, port);
                }

                // Update discovery method
                let method = match job.scan_type {
                    PortScanType::Fast => DiscoveryMethod::RustscanFast,
                    PortScanType::Full => DiscoveryMethod::RustscanFull,
                    PortScanType::Custom(_) => DiscoveryMethod::RustscanFull,
                };
                job.host.add_discovery_method(method);

                // Schedule service enumeration now that port scan is complete
                // This batches all discovered ports into a single nmap -sV -O job
                self.host_manager.schedule_service_enumeration(ip);

                self.backoff.record_success().await;
                Ok(())
            }
            Err(e) => {
                self.backoff.record_error().await;
                Err(e)
            }
        }
    }

    /// Get adaptive priority for a host based on discovered ports
    pub fn get_priority(port_count: usize) -> u8 {
        match port_count {
            0 => 0,
            1..=5 => 1,
            6..=20 => 2,
            21..=50 => 3,
            _ => 4, // Many ports = high priority
        }
    }
}
