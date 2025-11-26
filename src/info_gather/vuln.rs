use tracing::{info, warn};
use anyhow::Result;

use crate::models::job::{VulnScanJob, VulnLevel};
use crate::rate_limit::{AdaptiveBackoff, RateLimiter};
use crate::scanner::ScanExecutor;

/// Vulnerability scanning engine
pub struct VulnScanEngine {
    rate_limiter: RateLimiter,
    backoff: AdaptiveBackoff,
}

impl VulnScanEngine {
    pub fn new(rate_limiter: RateLimiter, backoff: AdaptiveBackoff) -> Self {
        Self {
            rate_limiter,
            backoff,
        }
    }

    /// Execute a vulnerability scan job
    pub async fn execute(&self, job: VulnScanJob) -> Result<()> {
        let ip = job.host.ip();
        let _guard = self.rate_limiter.acquire(ip).await;

        info!(
            "Running vulnerability scan on {} ({} ports, level: {:?})",
            ip,
            job.ports.len(),
            job.level
        );

        let scripts = self.get_scripts_for_level(&job.level);

        match ScanExecutor::rustscan_vuln_scan(ip, &job.ports, &scripts).await {
            Ok(result) => {
                info!(
                    "Vulnerability scan completed on {}: {} findings",
                    ip,
                    result.vulns.len()
                );

                // In a real implementation, you'd register vulns with the host
                // For now, just log them
                for vuln in result.vulns {
                    info!("  [{}] {} - {}", vuln.severity, vuln.id, vuln.title);
                }

                self.backoff.record_success().await;
                Ok(())
            }
            Err(e) => {
                warn!("Vulnerability scan failed for {}: {}", ip, e);
                self.backoff.record_error().await;
                Err(e)
            }
        }
    }

    /// Get appropriate scripts based on vulnerability scan level (passed to nmap via rustscan)
    fn get_scripts_for_level(&self, level: &VulnLevel) -> Vec<String> {
        match level {
            VulnLevel::Basic => vec![
                // Only the safest scripts
                "vuln".to_string(),
            ],
            VulnLevel::Extended => vec![
                // All "safe" category scripts
                "safe".to_string(),
                "vuln".to_string(),
            ],
        }
    }

    /// Get service-aware scripts for specific services
    pub fn get_service_scripts(service_name: &str) -> Vec<String> {
        match service_name.to_lowercase().as_str() {
            "http" | "https" => vec![
                "http-vuln-*".to_string(),
                "http-enum".to_string(),
            ],
            "ssh" => vec![
                "ssh2-enum-algos".to_string(),
                "ssh-auth-methods".to_string(),
            ],
            "smb" => vec![
                "smb-vuln-*".to_string(),
                "smb-enum-shares".to_string(),
            ],
            "ftp" => vec![
                "ftp-anon".to_string(),
                "ftp-bounce".to_string(),
            ],
            _ => vec!["safe".to_string()],
        }
    }
}
