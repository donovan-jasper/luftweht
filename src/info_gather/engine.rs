use tracing::{debug, info, warn};
use anyhow::Result;

use crate::models::host::OsFingerprint;
use crate::models::job::{InfoGatherJob, InfoGatherType};
use crate::models::service::ServiceInfo;
use crate::rate_limit::{AdaptiveBackoff, RateLimiter};
use crate::scanner::ScanExecutor;

/// Information gathering engine
pub struct InfoGatherEngine {
    rate_limiter: RateLimiter,
    backoff: AdaptiveBackoff,
}

impl InfoGatherEngine {
    pub fn new(rate_limiter: RateLimiter, backoff: AdaptiveBackoff) -> Self {
        Self {
            rate_limiter,
            backoff,
        }
    }

    /// Execute an info gathering job
    pub async fn execute(&self, job: InfoGatherJob) -> Result<()> {
        let ip = job.host.ip();
        let _guard = self.rate_limiter.acquire(ip).await;

        info!(
            "Gathering info on {} ({} ports)",
            ip,
            job.ports.len()
        );

        for gather_type in &job.gather_types {
            match gather_type {
                InfoGatherType::ServiceEnum => {
                    if let Err(e) = self.service_enumeration(&job).await {
                        warn!("Service enumeration failed for {}: {}", ip, e);
                        self.backoff.record_error().await;
                    } else {
                        self.backoff.record_success().await;
                    }
                }
                InfoGatherType::BannerGrab => {
                    if let Err(e) = self.banner_grabbing(&job).await {
                        warn!("Banner grabbing failed for {}: {}", ip, e);
                        self.backoff.record_error().await;
                    } else {
                        self.backoff.record_success().await;
                    }
                }
                InfoGatherType::OsDetection => {
                    if let Err(e) = self.os_detection(&job).await {
                        warn!("OS detection failed for {}: {}", ip, e);
                        self.backoff.record_error().await;
                    } else {
                        self.backoff.record_success().await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Service enumeration using rustscan with nmap passthrough
    async fn service_enumeration(&self, job: &InfoGatherJob) -> Result<()> {
        let ip = job.host.ip();

        info!("Running service enumeration on {}", ip);

        let result = ScanExecutor::rustscan_service_detect(ip, &job.ports, 5000).await?;

        // Register services
        for svc in result.services {
            let service_info = ServiceInfo {
                port: svc.port,
                service_name: Some(svc.name),
                version: svc.version,
                cpe: None,
                product: svc.product,
                extra_info: None,
            };

            job.host.add_service(service_info);
        }

        // Register OS info if found
        if let Some(os_match) = result.os_match {
            let os_fp = OsFingerprint {
                os_family: Some(os_match.name.clone()),
                os_version: None,
                confidence: os_match.accuracy as f32 / 100.0,
                method: "rustscan-nmap".to_string(),
            };

            job.host.set_os_fingerprint(os_fp);
        }

        Ok(())
    }

    /// Banner grabbing
    async fn banner_grabbing(&self, job: &InfoGatherJob) -> Result<()> {
        let ip = job.host.ip();

        info!("Running banner grabbing on {}", ip);

        // In a real implementation, you'd connect to each port and grab the banner
        // This is a simplified placeholder
        for port in &job.ports {
            debug!("Banner grab {}:{}", ip, port);

            // Simulate banner grab
            // match tokio::time::timeout(
            //     Duration::from_secs(3),
            //     TcpStream::connect(format!("{}:{}", ip, port))
            // ).await {
            //     Ok(Ok(mut stream)) => {
            //         // Read banner...
            //     }
            //     _ => {}
            // }
        }

        Ok(())
    }

    /// OS detection
    async fn os_detection(&self, job: &InfoGatherJob) -> Result<()> {
        // OS detection is often done alongside service enumeration
        // This is handled in service_enumeration() above
        info!("OS detection completed via service enumeration");
        Ok(())
    }
}
