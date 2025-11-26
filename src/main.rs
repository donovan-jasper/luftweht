mod config;
mod models;
mod queue;
mod rate_limit;
mod scanner;
mod info_gather;
mod output;

use clap::Parser;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use anyhow::Result;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use uuid::Uuid;

use config::{Config, ScanMode};
use models::job::{
    DiscoveryJob, DiscoveryMethodType, DiscoveryOptions, Job,
};
use queue::{DiscoveryEvent, HostManager, JobQueue};
use rate_limit::{AdaptiveBackoff, RateLimiter};
use scanner::{DiscoveryEngine, PortScanEngine};
use info_gather::{InfoGatherEngine, VulnScanEngine};
use output::{JsonWriter, MarkdownWriter, ScanMetadata, StreamWriter};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let config = Config::parse();

    // Setup logging
    setup_logging(config.verbose);

    info!("Luftweht Network Scanner starting");
    info!("Mode: {:?}", config.mode);

    // Create output directory
    tokio::fs::create_dir_all(&config.output).await?;

    // Initialize components
    let (job_queue, job_receiver) = JobQueue::new();
    let (host_manager, event_receiver) = HostManager::new(
        job_queue.clone(),
        config.vuln_scan_enabled(),
    );

    let rate_limiter = RateLimiter::new(
        config.max_parallel,
        config.max_per_host,
        config.max_per_subnet,
    );

    let backoff = AdaptiveBackoff::default();

    let discovery_engine = Arc::new(DiscoveryEngine::new(
        host_manager.clone(),
        rate_limiter.clone(),
        backoff.clone(),
    ));

    let portscan_engine = Arc::new(PortScanEngine::new(
        host_manager.clone(),
        rate_limiter.clone(),
        backoff.clone(),
    ));

    let infogather_engine = Arc::new(InfoGatherEngine::new(
        rate_limiter.clone(),
        backoff.clone(),
    ));

    let vulnscan_engine = Arc::new(VulnScanEngine::new(
        rate_limiter.clone(),
        backoff.clone(),
    ));

    // Setup output writers
    let stream_writer = Arc::new(StreamWriter::new(config.output.clone()));
    let json_writer = JsonWriter::new(config.output.clone());
    let markdown_writer = MarkdownWriter::new(config.output.clone());

    // Scan metadata
    let scan_id = Uuid::new_v4().to_string();
    let start_time = chrono::Utc::now();

    info!("Scan ID: {}", scan_id);

    // Check for dry run
    if config.dry_run {
        info!("DRY RUN MODE - No packets will be sent");
        return Ok(());
    }

    // Parse targets
    let targets = parse_targets(&config)?;
    info!("Parsed {} target IPs", targets.len());

    // Spawn event handler
    tokio::spawn(handle_events(event_receiver, stream_writer.clone()));

    // Spawn job workers
    spawn_workers(
        job_receiver,
        discovery_engine,
        portscan_engine,
        infogather_engine,
        vulnscan_engine,
    );

    // Execute scan based on mode
    match config.mode {
        ScanMode::Fast => {
            execute_fast_mode(&config, &job_queue, &targets).await?;
        }
        ScanMode::Discover => {
            execute_discover_mode(&config, &job_queue, &targets).await?;
        }
        ScanMode::Full => {
            execute_full_mode(&config, &job_queue, &host_manager, &targets).await?;
        }
    }

    // Wait for jobs to complete
    info!("Waiting for scan to complete...");
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

    // Generate final reports
    let end_time = chrono::Utc::now();
    let hosts = host_manager.get_all_hosts();

    info!("Scan complete. Discovered {} hosts", hosts.len());

    let metadata = ScanMetadata {
        scan_id,
        start_time,
        end_time,
        command: std::env::args().collect::<Vec<_>>().join(" "),
        tag: config.tag,
        mode: format!("{:?}", config.mode),
    };

    if !config.no_json {
        info!("Writing JSON output...");
        json_writer.write_results(hosts.clone(), metadata.clone()).await?;
    }

    if !config.no_markdown {
        info!("Writing Markdown report...");
        markdown_writer.write_report(hosts, metadata).await?;
    }

    info!("Scan complete! Results written to {:?}", config.output);

    Ok(())
}

fn setup_logging(verbosity: u8) {
    let level = match verbosity {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");
}

fn parse_targets(config: &Config) -> Result<Vec<IpAddr>> {
    let mut targets = Vec::new();

    for target_str in &config.targets {
        // Try parsing as CIDR
        if let Ok(network) = target_str.parse::<IpNetwork>() {
            for ip in network.iter() {
                targets.push(ip);
            }
        } else if let Ok(ip) = target_str.parse::<IpAddr>() {
            // Single IP
            targets.push(ip);
        } else {
            error!("Invalid target: {}", target_str);
        }
    }

    // Apply exclusions
    let excludes = config.parse_excludes();
    if !excludes.is_empty() {
        info!("Applying {} exclusions", excludes.len());
        // TODO: Implement exclusion filtering
    }

    Ok(targets)
}

async fn handle_events(
    mut event_rx: mpsc::UnboundedReceiver<DiscoveryEvent>,
    stream_writer: Arc<StreamWriter>,
) {
    while let Some(event) = event_rx.recv().await {
        if let Err(e) = stream_writer.write_event(&event).await {
            error!("Failed to write event: {}", e);
        }
    }
}

fn spawn_workers(
    mut job_rx: mpsc::UnboundedReceiver<Job>,
    discovery: Arc<DiscoveryEngine>,
    portscan: Arc<PortScanEngine>,
    infogather: Arc<InfoGatherEngine>,
    vulnscan: Arc<VulnScanEngine>,
) {
    tokio::spawn(async move {
        while let Some(job) = job_rx.recv().await {
            match job {
                Job::Discovery(j) => {
                    let engine = discovery.clone();
                    tokio::spawn(async move {
                        if let Err(e) = engine.execute(j).await {
                            error!("Discovery job failed: {}", e);
                        }
                    });
                }
                Job::PortScan(j) => {
                    let engine = portscan.clone();
                    tokio::spawn(async move {
                        if let Err(e) = engine.execute(j).await {
                            error!("Port scan job failed: {}", e);
                        }
                    });
                }
                Job::InfoGather(j) => {
                    let engine = infogather.clone();
                    tokio::spawn(async move {
                        if let Err(e) = engine.execute(j).await {
                            error!("Info gather job failed: {}", e);
                        }
                    });
                }
                Job::VulnScan(j) => {
                    let engine = vulnscan.clone();
                    tokio::spawn(async move {
                        if let Err(e) = engine.execute(j).await {
                            error!("Vuln scan job failed: {}", e);
                        }
                    });
                }
            }
        }
    });
}

async fn execute_fast_mode(
    config: &Config,
    job_queue: &JobQueue,
    targets: &[IpAddr],
) -> Result<()> {
    info!("Executing FAST mode");

    // Quick rustscan discovery only
    let job = Job::Discovery(DiscoveryJob {
        method: DiscoveryMethodType::RustscanFast,
        targets: targets.to_vec(),
        options: DiscoveryOptions {
            timeout_ms: config.timeout,
            max_retries: 1,
        },
    });

    job_queue.submit(job)?;

    Ok(())
}

async fn execute_discover_mode(
    config: &Config,
    job_queue: &JobQueue,
    targets: &[IpAddr],
) -> Result<()> {
    info!("Executing DISCOVER mode");

    let discovery_ports = config.parse_discovery_ports();

    // Use rustscan for discovery with specified ports
    // This is the only discovery method that actually works (others are placeholders)
    job_queue.submit(Job::Discovery(DiscoveryJob {
        method: DiscoveryMethodType::RustscanCustom {
            ports: discovery_ports,
        },
        targets: targets.to_vec(),
        options: DiscoveryOptions {
            timeout_ms: config.timeout,
            max_retries: 1,
        },
    }))?;

    Ok(())
}

async fn execute_full_mode(
    config: &Config,
    job_queue: &JobQueue,
    host_manager: &HostManager,
    targets: &[IpAddr],
) -> Result<()> {
    info!("Executing FULL mode");

    // Stage 1: Discovery
    execute_discover_mode(config, job_queue, targets).await?;

    // Wait a bit for initial discovery
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    // Stage 2: Comprehensive port scan (runs in background)
    info!("Starting comprehensive -Pn -p- scan in background");
    host_manager.schedule_comprehensive_scan();

    // Stages 3 & 4 (info gathering and vuln scanning) happen automatically
    // via the HostManager when ports are discovered

    Ok(())
}
