use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn, error};
use anyhow::Result;
use futures::future::join_all;
use tokio::sync::Semaphore;

use crate::models::host::DiscoveryMethod;
use crate::models::job::{DiscoveryJob, DiscoveryMethodType};
use crate::queue::HostManager;
use crate::rate_limit::{AdaptiveBackoff, RateLimiter};
use crate::scanner::ScanExecutor;

/// Discovery engine for finding hosts
pub struct DiscoveryEngine {
    host_manager: HostManager,
    rate_limiter: RateLimiter,
    backoff: AdaptiveBackoff,
}

impl DiscoveryEngine {
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

    /// Execute a discovery job
    pub async fn execute(&self, job: DiscoveryJob) -> Result<Vec<IpAddr>> {
        info!("Starting discovery: {:?} on {} targets", job.method, job.targets.len());

        match job.method {
            DiscoveryMethodType::IcmpEcho => self.icmp_discovery(&job.targets, &job.options).await,
            DiscoveryMethodType::TcpSyn { ports } => {
                self.tcp_syn_discovery(&job.targets, &ports, &job.options).await
            }
            DiscoveryMethodType::Arp => self.arp_discovery(&job.targets, &job.options).await,
            DiscoveryMethodType::RustscanFast => {
                self.rustscan_discovery(&job.targets, &job.options).await
            }
            DiscoveryMethodType::RustscanCustom { ports } => {
                self.rustscan_custom_ports(&job.targets, &ports, &job.options).await
            }
        }
    }

    /// ICMP echo discovery
    async fn icmp_discovery(&self, targets: &[IpAddr], options: &crate::models::job::DiscoveryOptions) -> Result<Vec<IpAddr>> {
        use pnet::packet::icmp::{echo_request, IcmpTypes};
        use pnet::packet::icmp::IcmpPacket;
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::Packet;
        use pnet::transport::{transport_channel, TransportChannelType, icmp_packet_iter};

        info!("Running ICMP echo discovery on {} targets", targets.len());

        let protocol = TransportChannelType::Layer4(
            pnet::transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)
        );

        let (mut tx, mut rx) = match transport_channel(1024, protocol) {
            Ok(channels) => channels,
            Err(e) => {
                if e.to_string().contains("Operation not permitted") || e.to_string().contains("Permission denied") {
                    tracing::warn!("ICMP discovery requires sudo - skipping");
                    return Ok(Vec::new());
                }
                return Err(e.into());
            }
        };

        let mut discovered = Vec::new();
        let ipv4_targets: Vec<_> = targets.iter().filter(|ip| ip.is_ipv4()).collect();

        // Send ICMP echo requests
        for target in &ipv4_targets {
            // Build ICMP echo request packet
            let mut buffer = vec![0u8; 64];
            let mut echo_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();

            echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
            echo_packet.set_identifier(rand::random::<u16>());
            echo_packet.set_sequence_number(1);

            // Calculate checksum
            let icmp_packet = IcmpPacket::new(echo_packet.packet()).unwrap();
            let checksum = pnet::packet::icmp::checksum(&icmp_packet);
            echo_packet.set_checksum(checksum);

            // Send packet
            if let Err(e) = tx.send_to(echo_packet, **target) {
                debug!("Failed to send ICMP to {}: {}", target, e);
            }
        }

        // Wait for responses with timeout (in a blocking task)
        let timeout_ms = options.timeout_ms;
        let host_manager = self.host_manager.clone();
        let backoff = self.backoff.clone();

        let discovered_hosts = tokio::task::spawn_blocking(move || {
            let mut discovered = Vec::new();
            let mut iter = icmp_packet_iter(&mut rx);
            let start = std::time::Instant::now();

            loop {
                if start.elapsed().as_millis() > timeout_ms as u128 {
                    break;
                }

                match iter.next_with_timeout(std::time::Duration::from_millis(100)) {
                    Ok(Some((packet, addr))) => {
                        if let Some(icmp) = IcmpPacket::new(packet.packet()) {
                            if icmp.get_icmp_type() == IcmpTypes::EchoReply {
                                discovered.push(addr);
                            }
                        }
                    }
                    Ok(None) => continue,
                    Err(_) => continue,
                }
            }
            discovered
        }).await?;

        // Register discovered hosts
        for addr in discovered_hosts {
            self.host_manager.register_host(addr, false, DiscoveryMethod::IcmpEcho);
            discovered.push(addr);
            info!("ICMP response from {}", addr);
            self.backoff.record_success().await;
        }

        info!("ICMP discovery found {} hosts", discovered.len());
        Ok(discovered)
    }

    /// TCP SYN discovery
    async fn tcp_syn_discovery(&self, targets: &[IpAddr], ports: &[u16], options: &crate::models::job::DiscoveryOptions) -> Result<Vec<IpAddr>> {
        use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::Packet;
        use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, tcp_packet_iter};

        info!("Running TCP SYN discovery on {} targets, {} ports", targets.len(), ports.len());

        let protocol = TransportChannelType::Layer4(
            TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)
        );

        let (mut tx, mut rx) = match transport_channel(1024, protocol) {
            Ok(channels) => channels,
            Err(e) => {
                if e.to_string().contains("Operation not permitted") || e.to_string().contains("Permission denied") {
                    tracing::warn!("TCP SYN discovery requires sudo - skipping");
                    return Ok(Vec::new());
                }
                return Err(e.into());
            }
        };

        let mut discovered = std::collections::HashSet::new();
        let ipv4_targets: Vec<_> = targets.iter().filter(|ip| ip.is_ipv4()).collect();

        // Send SYN packets to each target:port combination
        for target in &ipv4_targets {
            for &port in ports {
                let mut tcp_buffer = vec![0u8; 20]; // Minimum TCP header size
                let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

                tcp_packet.set_source(rand::random::<u16>());
                tcp_packet.set_destination(port);
                tcp_packet.set_sequence(rand::random::<u32>());
                tcp_packet.set_acknowledgement(0);
                tcp_packet.set_data_offset(5); // 5 * 4 = 20 bytes
                tcp_packet.set_flags(TcpFlags::SYN);
                tcp_packet.set_window(65535);

                // Calculate checksum
                let target_v4 = match target {
                    IpAddr::V4(v4) => *v4,
                    _ => continue,
                };
                let checksum = pnet::packet::tcp::ipv4_checksum(
                    &tcp_packet.to_immutable(),
                    &target_v4,
                    &std::net::Ipv4Addr::UNSPECIFIED,
                );
                tcp_packet.set_checksum(checksum);

                if let Err(e) = tx.send_to(tcp_packet, **target) {
                    debug!("Failed to send TCP SYN to {}:{}: {}", target, port, e);
                }
            }
        }

        // Wait for SYN-ACK responses (in a blocking task)
        let timeout_ms = options.timeout_ms;
        let host_manager = self.host_manager.clone();
        let backoff = self.backoff.clone();

        let results = tokio::task::spawn_blocking(move || {
            let mut discovered_set = std::collections::HashSet::new();
            let mut host_ports: Vec<(IpAddr, u16)> = Vec::new();
            let mut iter = tcp_packet_iter(&mut rx);
            let start = std::time::Instant::now();

            loop {
                if start.elapsed().as_millis() > timeout_ms as u128 {
                    break;
                }

                match iter.next_with_timeout(std::time::Duration::from_millis(100)) {
                    Ok(Some((packet, addr))) => {
                        if let Some(tcp) = pnet::packet::tcp::TcpPacket::new(packet.packet()) {
                            // Check for SYN-ACK (host is alive and port is open)
                            if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                                discovered_set.insert(addr);
                                host_ports.push((addr, tcp.get_source()));
                            }
                        }
                    }
                    Ok(None) => continue,
                    Err(_) => continue,
                }
            }
            (discovered_set, host_ports)
        }).await?;

        // Register discovered hosts and ports
        let (discovered_set, host_ports) = results;
        for addr in &discovered_set {
            self.host_manager.register_host(*addr, false, DiscoveryMethod::TcpSyn { port: 0 });
            discovered.insert(*addr);
            self.backoff.record_success().await;
        }

        for (addr, port) in host_ports {
            self.host_manager.register_port(addr, port);
            info!("TCP SYN-ACK from {}:{}", addr, port);
        }

        info!("TCP SYN discovery found {} hosts", discovered.len());
        Ok(discovered.into_iter().collect())
    }

    /// ARP discovery (for local networks)
    async fn arp_discovery(&self, targets: &[IpAddr], _options: &crate::models::job::DiscoveryOptions) -> Result<Vec<IpAddr>> {
        use pnet::datalink::{self, Channel};
        use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
        use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
        use pnet::packet::{Packet, MutablePacket};
        use pnet::util::MacAddr;

        info!("Running ARP discovery on {} targets", targets.len());

        // Filter to only IPv4 addresses
        let ipv4_targets: Vec<_> = targets
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                _ => None,
            })
            .collect();

        if ipv4_targets.is_empty() {
            info!("No IPv4 targets for ARP discovery");
            return Ok(Vec::new());
        }

        // Get the network interface for the target subnet
        let interfaces = datalink::interfaces();
        let interface = match interfaces
            .into_iter()
            .find(|iface| !iface.is_loopback() && iface.is_up() && iface.mac.is_some())
        {
            Some(iface) => iface,
            None => {
                tracing::warn!("No suitable network interface found for ARP discovery");
                return Ok(Vec::new());
            }
        };

        let source_mac = interface.mac.unwrap();
        let source_ip = match interface
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
        {
            Some(ip) => ip,
            None => {
                tracing::warn!("No IPv4 address on interface for ARP discovery");
                return Ok(Vec::new());
            }
        };

        // Create datalink channel
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                tracing::warn!("Unsupported channel type for ARP discovery");
                return Ok(Vec::new());
            }
            Err(e) => {
                if e.to_string().contains("Operation not permitted") || e.to_string().contains("Permission denied") {
                    tracing::warn!("ARP discovery requires sudo - skipping");
                    return Ok(Vec::new());
                }
                return Err(e.into());
            }
        };

        let mut discovered = Vec::new();

        // Send ARP requests
        for target_ip in &ipv4_targets {
            let mut ethernet_buffer = [0u8; 42];
            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

            ethernet_packet.set_destination(MacAddr::broadcast());
            ethernet_packet.set_source(source_mac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_buffer = [0u8; 28];
            let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(source_mac);
            arp_packet.set_sender_proto_addr(source_ip);
            arp_packet.set_target_hw_addr(MacAddr::zero());
            arp_packet.set_target_proto_addr(*target_ip);

            ethernet_packet.set_payload(arp_packet.packet_mut());

            if let Some(Err(e)) = tx.send_to(ethernet_packet.packet(), None) {
                debug!("Failed to send ARP to {}: {}", target_ip, e);
            }
        }

        // Wait for ARP replies (in a blocking task)
        let discovered_hosts = tokio::task::spawn_blocking(move || {
            let mut discovered = Vec::new();
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(2);

            loop {
                if start.elapsed() > timeout {
                    break;
                }

                match rx.next() {
                    Ok(packet) => {
                        if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                            if ethernet.get_ethertype() == EtherTypes::Arp {
                                if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
                                    if arp.get_operation() == ArpOperations::Reply {
                                        let sender_ip = IpAddr::V4(arp.get_sender_proto_addr());
                                        discovered.push(sender_ip);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::TimedOut {
                            debug!("ARP receive error: {}", e);
                        }
                        break;
                    }
                }
            }
            discovered
        }).await?;

        // Register discovered hosts
        for sender_ip in discovered_hosts {
            self.host_manager.register_host(
                sender_ip,
                true, // ARP means it's on local network
                DiscoveryMethod::Arp
            );
            discovered.push(sender_ip);
            info!("ARP reply from {}", sender_ip);
            self.backoff.record_success().await;
        }

        info!("ARP discovery found {} hosts", discovered.len());
        Ok(discovered)
    }

    /// Rustscan fast discovery
    async fn rustscan_discovery(
        &self,
        targets: &[IpAddr],
        options: &crate::models::job::DiscoveryOptions,
    ) -> Result<Vec<IpAddr>> {
        info!("Running rustscan fast discovery on {} targets", targets.len());

        let mut discovered = Vec::new();

        // Batch targets to avoid command-line length limits
        // Rustscan can handle ~50-100 IPs comfortably in one command
        const BATCH_SIZE: usize = 50;

        for batch in targets.chunks(BATCH_SIZE) {
            info!("Scanning batch of {} targets", batch.len());

            // Use rustscan in fast mode (-F equivalent: top 1000 ports)
            let result = ScanExecutor::rustscan(
                batch,
                None, // None means use default ports
                options.timeout_ms,
                false,
            )
            .await?;

            // Register discovered hosts using the host_ports mapping
            for (ip, ports) in result.host_ports.iter() {
                let _host = self.host_manager.register_host(
                    *ip,
                    false,
                    DiscoveryMethod::RustscanFast,
                );

                // Register the open ports for this specific host
                for &port in ports {
                    self.host_manager.register_port(*ip, port);
                }

                discovered.push(*ip);
                self.backoff.record_success().await;
            }

            info!("Batch discovered {} hosts", result.host_ports.len());
        }

        info!("Rustscan discovered total of {} hosts", discovered.len());

        Ok(discovered)
    }

    /// Rustscan discovery with custom ports (parallelized with timeouts)
    async fn rustscan_custom_ports(
        &self,
        targets: &[IpAddr],
        ports: &[u16],
        options: &crate::models::job::DiscoveryOptions,
    ) -> Result<Vec<IpAddr>> {
        info!("Running PARALLEL rustscan discovery on {} targets with custom ports: {:?}",
            targets.len(), ports);

        // Batch targets to avoid command-line length limits
        const BATCH_SIZE: usize = 50;
        const MAX_CONCURRENT_BATCHES: usize = 5; // Limit concurrent batches to avoid overwhelming network
        const BATCH_TIMEOUT_SECS: u64 = 60; // 60 second timeout per batch

        let batches: Vec<Vec<IpAddr>> = targets
            .chunks(BATCH_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect();

        let total_batches = batches.len();
        info!("Split into {} batches, max {} concurrent", total_batches, MAX_CONCURRENT_BATCHES);

        // Semaphore to limit concurrent batches
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_BATCHES));

        // Spawn all batch tasks
        let batch_tasks: Vec<_> = batches
            .into_iter()
            .enumerate()
            .map(|(batch_num, batch)| {
                let host_manager = self.host_manager.clone();
                let backoff = self.backoff.clone();
                let ports = ports.to_vec();
                let timeout_ms = options.timeout_ms;
                let sem = semaphore.clone();

                tokio::spawn(async move {
                    // Acquire permit before running batch
                    let _permit = sem.acquire().await.unwrap();

                    info!("Executing batch {}/{} ({} targets)", batch_num + 1, total_batches, batch.len());

                    // Timeout wrapper: BATCH_TIMEOUT_SECS per batch max
                    let result = tokio::time::timeout(
                        Duration::from_secs(BATCH_TIMEOUT_SECS),
                        ScanExecutor::rustscan(
                            &batch,
                            Some(ports.clone()),
                            timeout_ms,
                            false,
                        )
                    )
                    .await;

                    match result {
                        Ok(Ok(scan_result)) => {
                            // Process successful scan
                            let host_count = scan_result.host_ports.len();
                            let port_count: usize = scan_result.host_ports.values().map(|p| p.len()).sum();

                            // Register discovered hosts
                            let mut discovered = Vec::new();
                            for (ip, open_ports) in scan_result.host_ports.iter() {
                                let _host = host_manager.register_host(
                                    *ip,
                                    false,
                                    DiscoveryMethod::RustscanCustom { ports: ports.clone() },
                                );

                                for &port in open_ports {
                                    host_manager.register_port(*ip, port);
                                }

                                discovered.push(*ip);
                                backoff.record_success().await;
                            }

                            info!("Batch {}/{} completed: {} hosts, {} ports",
                                batch_num + 1, total_batches, host_count, port_count);
                            Ok((batch_num, discovered))
                        }
                        Ok(Err(e)) => {
                            error!("Batch {}/{} failed: {}", batch_num + 1, total_batches, e);
                            Err(anyhow::anyhow!("Batch {} scan error: {}", batch_num + 1, e))
                        }
                        Err(_) => {
                            error!("Batch {}/{} timed out after {}s", batch_num + 1, total_batches, BATCH_TIMEOUT_SECS);
                            Err(anyhow::anyhow!("Batch {} timeout", batch_num + 1))
                        }
                    }
                })
            })
            .collect();

        // Wait for all batches to complete
        info!("Waiting for all {} batches to complete...", total_batches);
        let results = join_all(batch_tasks).await;

        // Aggregate results
        let mut total_discovered = Vec::new();
        let mut successful_batches = 0;
        let mut failed_batches = 0;

        for batch_result in results {
            match batch_result {
                Ok(Ok((batch_num, discovered))) => {
                    successful_batches += 1;
                    total_discovered.extend(discovered);
                }
                Ok(Err(e)) => {
                    failed_batches += 1;
                    warn!("Batch error (continuing): {}", e);
                }
                Err(e) => {
                    failed_batches += 1;
                    error!("Batch task panicked: {}", e);
                }
            }
        }

        info!("Discovery complete: {} total hosts found", total_discovered.len());
        info!("Batches: {}/{} successful, {} failed/timeout",
            successful_batches, total_batches, failed_batches);

        Ok(total_discovered)
    }
}
