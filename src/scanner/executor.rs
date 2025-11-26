use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error, warn};
use anyhow::{Context, Result};

/// Wrapper for executing external scanning tools
pub struct ScanExecutor;

impl ScanExecutor {
    /// Execute rustscan with specified options
    pub async fn rustscan(
        targets: &[IpAddr],
        ports: Option<Vec<u16>>,
        timeout_ms: u64,
        skip_ping: bool,
    ) -> Result<RustscanResult> {
        let mut cmd = Command::new("rustscan");

        // Add targets as comma-separated list (more efficient than multiple -a flags)
        let targets_str = targets
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        cmd.arg("-a").arg(targets_str);

        // Add ports if specified
        if let Some(port_list) = ports {
            if port_list.is_empty() {
                // Full port scan
                cmd.arg("-p").arg("1-65535");
            } else {
                let ports_str = port_list
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                cmd.arg("-p").arg(ports_str);
            }
        }

        // Timeout (rustscan expects milliseconds)
        cmd.arg("--timeout").arg(timeout_ms.to_string());

        // CONSERVATIVE rate limiting to never overwhelm networks or target hosts
        // Use -b (batch size) which limits concurrent port scans
        // Default rustscan is 5000 which crashes networks - we use 50 for safety
        cmd.arg("-b").arg("50");  // Very conservative: only 50 concurrent port scans

        // Skip ping if requested (-Pn equivalent in nmap mode)
        if skip_ping {
            cmd.arg("--").arg("-Pn");
        }

        // JSON output
        cmd.arg("--greppable");

        debug!("Executing rustscan: {:?}", cmd);

        let output = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute rustscan")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Rustscan exited with error: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        debug!("Rustscan stdout: {}", stdout);
        debug!("Rustscan stderr: {}", stderr);

        Ok(Self::parse_rustscan_output(&stdout))
    }

    /// Execute rustscan with nmap passthrough for service detection
    pub async fn rustscan_service_detect(
        ip: IpAddr,
        ports: &[u16],
        timeout_ms: u64,
    ) -> Result<ServiceDetectionResult> {
        let mut cmd = Command::new("rustscan");

        // Target
        cmd.arg("-a").arg(ip.to_string());

        // Ports
        let ports_str = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        cmd.arg("-p").arg(ports_str);

        // Timeout (rustscan expects milliseconds)
        cmd.arg("--timeout").arg(timeout_ms.to_string());

        // Passthrough to nmap for service version detection and OS detection
        cmd.arg("--")
            .arg("-sV")  // Service version detection
            .arg("-O")   // OS detection (requires root/sudo)
            .arg("--max-rtt-timeout").arg(format!("{}ms", timeout_ms))
            .arg("-oG").arg("-");  // Greppable output

        debug!("Executing rustscan service detect: {:?}", cmd);

        let output = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute rustscan")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Rustscan exited with error: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_nmap_greppable(&stdout))
    }

    /// Execute rustscan with nmap passthrough for vulnerability scan
    pub async fn rustscan_vuln_scan(
        ip: IpAddr,
        ports: &[u16],
        scripts: &[String],
    ) -> Result<VulnScanResult> {
        let mut cmd = Command::new("rustscan");

        // Target
        cmd.arg("-a").arg(ip.to_string());

        // Ports
        let ports_str = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        cmd.arg("-p").arg(ports_str);

        // Passthrough to nmap for vulnerability scanning
        cmd.arg("--");

        // Scripts
        if scripts.is_empty() {
            cmd.arg("--script=safe");
        } else {
            cmd.arg("--script").arg(scripts.join(","));
        }

        // Greppable output
        cmd.arg("-oG").arg("-");

        debug!("Executing rustscan vuln scan: {:?}", cmd);

        let output = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute rustscan vuln scan")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Rustscan vuln scan exited with error: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_vuln_greppable(&stdout))
    }

    /// Parse rustscan output
    fn parse_rustscan_output(output: &str) -> RustscanResult {
        let mut result = RustscanResult {
            open_ports: Vec::new(),
            host_ports: std::collections::HashMap::new(),
        };

        // Parse greppable output format
        // Example: 192.168.1.1 -> [22,80,443]
        for line in output.lines() {
            if line.contains("->") && line.contains("[") {
                // Extract IP and ports
                let parts: Vec<&str> = line.split("->").collect();
                if parts.len() == 2 {
                    let ip_str = parts[0].trim();
                    let ports_str = parts[1].trim().trim_matches(|c| c == '[' || c == ']');

                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        let mut ports = Vec::new();
                        for port_str in ports_str.split(',') {
                            if let Ok(port) = port_str.trim().parse::<u16>() {
                                ports.push(port);
                                result.open_ports.push(port); // Also add to legacy field
                            }
                        }
                        result.host_ports.insert(ip, ports);
                    }
                }
            }
        }

        result
    }

    /// Parse nmap greppable output for service detection
    fn parse_nmap_greppable(output: &str) -> ServiceDetectionResult {
        let mut result = ServiceDetectionResult {
            services: Vec::new(),
            os_match: None,
        };

        for line in output.lines() {
            // Parse service information from greppable format
            // Format: Host: <ip> (<hostname>) Ports: <port>/state/proto/owner/service/rpc/version/
            if line.starts_with("Host:") && line.contains("Ports:") {
                if let Some(ports_section) = line.split("Ports:").nth(1) {
                    let ports_section = ports_section.split("Ignored").next().unwrap_or(ports_section);

                    for port_info in ports_section.split(',') {
                        let parts: Vec<&str> = port_info.trim().split('/').collect();
                        if parts.len() >= 7 {
                            if let Ok(port_num) = parts[0].parse::<u16>() {
                                let service = ServiceInfo {
                                    port: port_num,
                                    name: if !parts[4].is_empty() {
                                        parts[4].to_string()
                                    } else {
                                        "unknown".to_string()
                                    },
                                    product: if !parts[6].is_empty() {
                                        Some(parts[6].to_string())
                                    } else {
                                        None
                                    },
                                    version: None, // Version would be in extra info
                                };
                                result.services.push(service);
                            }
                        }
                    }
                }
            }

            // Parse OS information
            // Format: OS: <os_name>
            if line.starts_with("OS:") {
                if let Some(os_info) = line.strip_prefix("OS:") {
                    let os_name = os_info.trim().to_string();
                    if !os_name.is_empty() && os_name != "Unknown" {
                        result.os_match = Some(OsInfo {
                            name: os_name,
                            accuracy: 85, // Greppable doesn't provide accuracy
                        });
                    }
                }
            }
        }

        result
    }

    /// Parse nmap greppable output for vulnerability scan
    fn parse_vuln_greppable(output: &str) -> VulnScanResult {
        let mut result = VulnScanResult {
            vulns: Vec::new(),
        };

        // Nmap greppable format doesn't include script output by default
        // For vulnerability scanning, we'd typically need to parse full output
        // This is a simplified implementation that looks for vulnerability indicators
        for line in output.lines() {
            if line.contains("vuln") || line.contains("CVE-") {
                // This is a simplification - real parsing would be more complex
                debug!("Potential vulnerability found: {}", line);
            }
        }

        result
    }
}

#[derive(Debug, Clone)]
pub struct RustscanResult {
    pub open_ports: Vec<u16>, // Deprecated - use host_ports instead
    pub host_ports: std::collections::HashMap<std::net::IpAddr, Vec<u16>>,
}

#[derive(Debug, Clone)]
pub struct ServiceDetectionResult {
    pub services: Vec<ServiceInfo>,
    pub os_match: Option<OsInfo>,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OsInfo {
    pub name: String,
    pub accuracy: u8,
}

#[derive(Debug, Clone)]
pub struct VulnScanResult {
    pub vulns: Vec<VulnInfo>,
}

#[derive(Debug, Clone)]
pub struct VulnInfo {
    pub id: String,
    pub title: String,
    pub severity: String,
}
