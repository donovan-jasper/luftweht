use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Semaphore, RwLock};
use tracing::debug;

/// Multi-level rate limiter with global, per-host, and per-subnet limits
#[derive(Clone)]
pub struct RateLimiter {
    global_sem: Arc<Semaphore>,
    per_host_limit: usize,
    per_subnet_limit: usize,
    host_semaphores: Arc<RwLock<HashMap<IpAddr, Arc<Semaphore>>>>,
    subnet_semaphores: Arc<RwLock<HashMap<String, Arc<Semaphore>>>>,
}

impl RateLimiter {
    pub fn new(max_parallel: usize, max_per_host: usize, max_per_subnet: usize) -> Self {
        Self {
            global_sem: Arc::new(Semaphore::new(max_parallel)),
            per_host_limit: max_per_host,
            per_subnet_limit: max_per_subnet,
            host_semaphores: Arc::new(RwLock::new(HashMap::new())),
            subnet_semaphores: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Acquire permits for a specific IP address
    /// Returns guards that must be held while the operation is running
    pub async fn acquire(&self, ip: IpAddr) -> RateLimitGuard {
        // Acquire global permit first
        let global_permit = self.global_sem.clone().acquire_owned().await.unwrap();

        // Get or create host semaphore
        let host_sem = {
            let mut sems = self.host_semaphores.write().await;
            sems.entry(ip)
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_host_limit)))
                .clone()
        };
        let host_permit = host_sem.acquire_owned().await.unwrap();

        // Get subnet key and semaphore
        let subnet_key = self.get_subnet_key(&ip);
        let subnet_sem = {
            let mut sems = self.subnet_semaphores.write().await;
            sems.entry(subnet_key.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_subnet_limit)))
                .clone()
        };
        let subnet_permit = subnet_sem.acquire_owned().await.unwrap();

        debug!("Acquired rate limit permits for {}", ip);

        RateLimitGuard {
            _global: global_permit,
            _host: host_permit,
            _subnet: subnet_permit,
        }
    }

    /// Get subnet key for an IP (truncates to /24 for IPv4, /64 for IPv6)
    fn get_subnet_key(&self, ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3])
            }
        }
    }

    /// Get current global available permits
    pub fn available_global(&self) -> usize {
        self.global_sem.available_permits()
    }

    /// Reduce global limit (for adaptive backoff)
    pub async fn reduce_global_limit(&self, factor: f32) {
        let current = self.global_sem.available_permits();
        let new_limit = ((current as f32) * factor) as usize;
        debug!("Reducing global rate limit: {} -> {}", current, new_limit);

        // This is a simplified version - in production you'd want to properly
        // handle semaphore resizing which is more complex
    }
}

/// Guard that holds rate limit permits
/// Permits are automatically released when dropped
pub struct RateLimitGuard {
    _global: tokio::sync::OwnedSemaphorePermit,
    _host: tokio::sync::OwnedSemaphorePermit,
    _subnet: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(10, 2, 5);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let _guard1 = limiter.acquire(ip).await;
        let _guard2 = limiter.acquire(ip).await;

        // Should have consumed some permits
        assert!(limiter.available_global() < 10);
    }
}
