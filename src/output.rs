use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::models::Host;
use crate::queue::DiscoveryEvent;

/// Metadata about a scan session
#[derive(Debug, Clone, Serialize)]
pub struct ScanMetadata {
    pub scan_id: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub command: String,
    pub tag: Option<String>,
    pub mode: String,
}

/// Writes real-time events to NDJSON stream file
pub struct StreamWriter {
    output_dir: PathBuf,
    file: Arc<Mutex<Option<File>>>,
}

impl StreamWriter {
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            output_dir,
            file: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn write_event(&self, event: &DiscoveryEvent) -> Result<()> {
        let mut file_guard = self.file.lock().await;

        // Lazy initialize file on first write
        if file_guard.is_none() {
            let path = self.output_dir.join("scan-stream.ndjson");
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await?;
            *file_guard = Some(file);
        }

        let file = file_guard.as_mut().unwrap();

        // Convert event to JSON line
        let json_line = match event {
            DiscoveryEvent::HostDiscovered { host, method } => {
                serde_json::json!({
                    "event": "host_discovered",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": host.ip().to_string(),
                    "method": format!("{:?}", method),
                })
            }
            DiscoveryEvent::PortDiscovered { host, port } => {
                serde_json::json!({
                    "event": "port_discovered",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": host.ip().to_string(),
                    "port": port,
                })
            }
            DiscoveryEvent::HostUpdated { host } => {
                serde_json::json!({
                    "event": "host_updated",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": host.ip().to_string(),
                })
            }
            DiscoveryEvent::PortScanStarted { ip } => {
                serde_json::json!({
                    "event": "port_scan_started",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": ip.to_string(),
                })
            }
            DiscoveryEvent::PortScanProgress { ip, progress, ports_found } => {
                serde_json::json!({
                    "event": "port_scan_progress",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": ip.to_string(),
                    "progress": progress,
                    "ports_found": ports_found,
                })
            }
            DiscoveryEvent::PortScanComplete { ip, total_ports } => {
                serde_json::json!({
                    "event": "port_scan_complete",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": ip.to_string(),
                    "total_ports": total_ports,
                })
            }
            DiscoveryEvent::ServiceEnumStarted { ip, port_count } => {
                serde_json::json!({
                    "event": "service_enum_started",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": ip.to_string(),
                    "port_count": port_count,
                })
            }
            DiscoveryEvent::ServiceEnumProgress { ip, services_found } => {
                serde_json::json!({
                    "event": "service_enum_progress",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": ip.to_string(),
                    "services_found": services_found,
                })
            }
            DiscoveryEvent::ServiceEnumComplete { ip, services } => {
                serde_json::json!({
                    "event": "service_enum_complete",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": ip.to_string(),
                    "service_count": services.len(),
                    "services": services.iter().map(|s| {
                        serde_json::json!({
                            "port": s.port,
                            "service_name": s.service_name,
                            "version": s.version,
                            "product": s.product,
                        })
                    }).collect::<Vec<_>>(),
                })
            }
            DiscoveryEvent::OsDetectionComplete { ip, os_info } => {
                serde_json::json!({
                    "event": "os_detection_complete",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "ip": ip.to_string(),
                    "os_family": os_info.os_family,
                    "os_version": os_info.os_version,
                    "confidence": os_info.confidence,
                    "method": os_info.method,
                })
            }
        };

        // Write as NDJSON (newline-delimited JSON)
        let mut line = serde_json::to_string(&json_line)?;
        line.push('\n');
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;

        Ok(())
    }
}

/// Writes final structured JSON results
pub struct JsonWriter {
    output_dir: PathBuf,
}

impl JsonWriter {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }

    pub async fn write_results(&self, hosts: Vec<Host>, metadata: ScanMetadata) -> Result<()> {
        let path = self.output_dir.join("scan-results.json");

        // Calculate summary statistics
        let total_hosts = hosts.len();
        let total_ports: usize = hosts.iter().map(|h| h.port_count()).sum();

        // Build output structure
        let output = serde_json::json!({
            "metadata": metadata,
            "summary": {
                "total_hosts": total_hosts,
                "total_ports": total_ports,
            },
            "hosts": hosts.iter().map(|h| h.to_json()).collect::<Vec<_>>(),
        });

        // Write to file
        let json_string = serde_json::to_string_pretty(&output)?;
        tokio::fs::write(&path, json_string).await?;

        Ok(())
    }
}

/// Writes human-readable Markdown report
pub struct MarkdownWriter {
    output_dir: PathBuf,
}

impl MarkdownWriter {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }

    pub async fn write_report(&self, hosts: Vec<Host>, metadata: ScanMetadata) -> Result<()> {
        let path = self.output_dir.join("scan-report.md");

        let mut report = String::new();

        // Header
        report.push_str("# Network Scan Report\n\n");

        // Metadata section
        report.push_str("## Scan Metadata\n\n");
        report.push_str(&format!("- **Scan ID:** `{}`\n", metadata.scan_id));
        report.push_str(&format!(
            "- **Start Time:** {}\n",
            metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        report.push_str(&format!(
            "- **End Time:** {}\n",
            metadata.end_time.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        let duration = metadata
            .end_time
            .signed_duration_since(metadata.start_time);
        let duration_str = if duration.num_hours() > 0 {
            format!(
                "{}h {}m {}s",
                duration.num_hours(),
                duration.num_minutes() % 60,
                duration.num_seconds() % 60
            )
        } else if duration.num_minutes() > 0 {
            format!(
                "{}m {}s",
                duration.num_minutes(),
                duration.num_seconds() % 60
            )
        } else {
            format!("{}s", duration.num_seconds())
        };
        report.push_str(&format!("- **Duration:** {}\n", duration_str));
        report.push_str(&format!("- **Mode:** {}\n", metadata.mode));
        report.push_str(&format!("- **Command:** `{}`\n", metadata.command));
        if let Some(tag) = &metadata.tag {
            report.push_str(&format!("- **Tag:** `{}`\n", tag));
        }
        report.push_str("\n");

        // Summary section
        let total_hosts = hosts.len();
        let total_ports: usize = hosts.iter().map(|h| h.port_count()).sum();

        report.push_str("## Summary\n\n");
        report.push_str(&format!("- **Total Hosts Discovered:** {}\n", total_hosts));
        report.push_str(&format!("- **Total Open Ports:** {}\n", total_ports));
        report.push_str("\n");

        if hosts.is_empty() {
            report.push_str("No hosts were discovered during this scan.\n");
        } else {
            // Discovered hosts section
            report.push_str("## Discovered Hosts\n\n");

            // Sort hosts by IP for consistent output
            let mut sorted_hosts = hosts.clone();
            sorted_hosts.sort_by_key(|h| h.ip());

            for host in sorted_hosts {
                let host_json = host.to_json();

                report.push_str(&format!("### {}\n\n", host.ip()));

                // Host details
                if let Some(first_seen) = host_json.get("first_seen") {
                    report.push_str(&format!(
                        "- **First Seen:** {}\n",
                        first_seen.as_str().unwrap_or("N/A")
                    ));
                }

                if let Some(methods) = host_json.get("discovered_by") {
                    if let Some(arr) = methods.as_array() {
                        let method_strs: Vec<String> = arr
                            .iter()
                            .filter_map(|v| {
                                if let Some(obj) = v.as_object() {
                                    // Handle different discovery method formats
                                    if obj.contains_key("RustscanFast") {
                                        Some("RustscanFast".to_string())
                                    } else if obj.contains_key("RustscanFull") {
                                        Some("RustscanFull".to_string())
                                    } else if obj.contains_key("IcmpEcho") {
                                        Some("IcmpEcho".to_string())
                                    } else if let Some(tcp_syn) = obj.get("TcpSyn") {
                                        Some(format!("TcpSyn({})", tcp_syn))
                                    } else if let Some(custom) = obj.get("RustscanCustom") {
                                        Some(format!("RustscanCustom({:?})", custom))
                                    } else {
                                        Some(format!("{:?}", obj))
                                    }
                                } else {
                                    Some(format!("{}", v))
                                }
                            })
                            .collect();
                        report.push_str(&format!(
                            "- **Discovery Methods:** {}\n",
                            method_strs.join(", ")
                        ));
                    }
                }

                // Open ports
                let open_ports = host.get_open_ports();
                if !open_ports.is_empty() {
                    let mut sorted_ports = open_ports;
                    sorted_ports.sort();
                    let ports_str = sorted_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    report.push_str(&format!("- **Open Ports ({}):** {}\n", sorted_ports.len(), ports_str));
                } else {
                    report.push_str("- **Open Ports:** None detected\n");
                }

                // Services
                if let Some(services) = host_json.get("services") {
                    if let Some(service_arr) = services.as_array() {
                        if !service_arr.is_empty() {
                            report.push_str("- **Services:**\n");
                            for service in service_arr {
                                let port = service.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
                                let name = service
                                    .get("service_name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or("unknown");
                                let version = service
                                    .get("version")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");

                                if version.is_empty() {
                                    report.push_str(&format!("  - Port {}: {}\n", port, name));
                                } else {
                                    report.push_str(&format!("  - Port {}: {} ({})\n", port, name, version));
                                }
                            }
                        }
                    }
                }

                // OS guess
                if let Some(os_guess) = host_json.get("os_guess") {
                    if !os_guess.is_null() {
                        if let Some(os_obj) = os_guess.as_object() {
                            let os_family = os_obj
                                .get("os_family")
                                .and_then(|f| f.as_str())
                                .unwrap_or("Unknown");
                            let os_version = os_obj
                                .get("os_version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let confidence = os_obj
                                .get("confidence")
                                .and_then(|c| c.as_f64())
                                .unwrap_or(0.0);

                            if os_version.is_empty() {
                                report.push_str(&format!(
                                    "- **OS Guess:** {} ({:.0}% confidence)\n",
                                    os_family,
                                    confidence * 100.0
                                ));
                            } else {
                                report.push_str(&format!(
                                    "- **OS Guess:** {} {} ({:.0}% confidence)\n",
                                    os_family,
                                    os_version,
                                    confidence * 100.0
                                ));
                            }
                        }
                    }
                }

                report.push_str("\n");
            }
        }

        // Write to file
        tokio::fs::write(&path, report).await?;

        Ok(())
    }
}
