use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Tracks operation results and adapts rate limits based on error/timeout patterns
#[derive(Clone)]
pub struct AdaptiveBackoff {
    state: Arc<RwLock<BackoffState>>,
    window_size: Duration,
    error_threshold: f32,
}

struct BackoffState {
    window_start: Instant,
    total_ops: usize,
    timeouts: usize,
    errors: usize,
    backoff_factor: f32,
}

impl AdaptiveBackoff {
    pub fn new(window_size: Duration, error_threshold: f32) -> Self {
        Self {
            state: Arc::new(RwLock::new(BackoffState {
                window_start: Instant::now(),
                total_ops: 0,
                timeouts: 0,
                errors: 0,
                backoff_factor: 1.0,
            })),
            window_size,
            error_threshold,
        }
    }

    /// Record a successful operation
    pub async fn record_success(&self) {
        let mut state = self.state.write().await;
        self.check_window_reset(&mut state);
        state.total_ops += 1;
    }

    /// Record a timeout
    pub async fn record_timeout(&self) {
        let mut state = self.state.write().await;
        self.check_window_reset(&mut state);
        state.total_ops += 1;
        state.timeouts += 1;

        self.evaluate_backoff(&mut state);
    }

    /// Record an error (RST, ICMP unreachable, etc.)
    pub async fn record_error(&self) {
        let mut state = self.state.write().await;
        self.check_window_reset(&mut state);
        state.total_ops += 1;
        state.errors += 1;

        self.evaluate_backoff(&mut state);
    }

    /// Get current backoff factor (1.0 = normal, < 1.0 = backed off)
    pub async fn backoff_factor(&self) -> f32 {
        self.state.read().await.backoff_factor
    }

    /// Check if we need to reset the sliding window
    fn check_window_reset(&self, state: &mut BackoffState) {
        if state.window_start.elapsed() > self.window_size {
            state.window_start = Instant::now();
            state.total_ops = 0;
            state.timeouts = 0;
            state.errors = 0;
        }
    }

    /// Evaluate whether we should back off based on error rates
    fn evaluate_backoff(&self, state: &mut BackoffState) {
        if state.total_ops < 10 {
            // Not enough data yet
            return;
        }

        let error_rate = (state.timeouts + state.errors) as f32 / state.total_ops as f32;

        if error_rate > self.error_threshold && state.backoff_factor > 0.25 {
            // High error rate - back off
            state.backoff_factor *= 0.75;
            warn!(
                "High error rate detected ({:.1}%), backing off to {:.0}% capacity",
                error_rate * 100.0,
                state.backoff_factor * 100.0
            );
        } else if error_rate < self.error_threshold * 0.5 && state.backoff_factor < 1.0 {
            // Error rate is low - gradually recover
            state.backoff_factor = (state.backoff_factor * 1.1).min(1.0);
            if state.backoff_factor == 1.0 {
                info!("Error rate normalized, returning to full capacity");
            }
        }
    }

    /// Get current statistics
    pub async fn stats(&self) -> BackoffStats {
        let state = self.state.read().await;
        BackoffStats {
            total_ops: state.total_ops,
            timeouts: state.timeouts,
            errors: state.errors,
            backoff_factor: state.backoff_factor,
        }
    }
}

impl Default for AdaptiveBackoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(60), 0.15) // 15% error threshold
    }
}

#[derive(Debug, Clone)]
pub struct BackoffStats {
    pub total_ops: usize,
    pub timeouts: usize,
    pub errors: usize,
    pub backoff_factor: f32,
}

impl BackoffStats {
    pub fn error_rate(&self) -> f32 {
        if self.total_ops == 0 {
            0.0
        } else {
            (self.timeouts + self.errors) as f32 / self.total_ops as f32
        }
    }
}
