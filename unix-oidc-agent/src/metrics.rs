//! Metrics collection for unix-oidc-agent
//!
//! Provides counters and histograms for monitoring agent health and performance.
//! Metrics can be queried via IPC or exported to syslog in JSON format.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Metrics collector for the agent daemon
pub struct MetricsCollector {
    /// When the agent started
    start_time: Instant,
    start_timestamp: u64,

    // Counters (atomic for lock-free updates)
    /// Total proof requests received
    pub proof_requests_total: AtomicU64,
    /// Successful proof generations
    pub proof_requests_success: AtomicU64,
    /// Failed proof generations
    pub proof_requests_failed: AtomicU64,

    /// Total token refresh attempts
    pub token_refresh_total: AtomicU64,
    /// Successful token refreshes
    pub token_refresh_success: AtomicU64,
    /// Failed token refreshes
    pub token_refresh_failed: AtomicU64,

    /// Total IPC connections handled
    pub ipc_connections_total: AtomicU64,
    /// Total IPC requests processed
    pub ipc_requests_total: AtomicU64,
    /// IPC request errors
    pub ipc_errors_total: AtomicU64,

    // Latency tracking (requires lock for histogram updates)
    /// Proof generation latencies (microseconds)
    proof_latencies: RwLock<LatencyHistogram>,
    /// Token refresh latencies (microseconds)
    refresh_latencies: RwLock<LatencyHistogram>,

    // Last event timestamps
    /// Last successful proof generation (unix timestamp)
    pub last_proof_time: AtomicU64,
    /// Last token refresh (unix timestamp)
    pub last_refresh_time: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            start_time: Instant::now(),
            start_timestamp: now,
            proof_requests_total: AtomicU64::new(0),
            proof_requests_success: AtomicU64::new(0),
            proof_requests_failed: AtomicU64::new(0),
            token_refresh_total: AtomicU64::new(0),
            token_refresh_success: AtomicU64::new(0),
            token_refresh_failed: AtomicU64::new(0),
            ipc_connections_total: AtomicU64::new(0),
            ipc_requests_total: AtomicU64::new(0),
            ipc_errors_total: AtomicU64::new(0),
            proof_latencies: RwLock::new(LatencyHistogram::new()),
            refresh_latencies: RwLock::new(LatencyHistogram::new()),
            last_proof_time: AtomicU64::new(0),
            last_refresh_time: AtomicU64::new(0),
        }
    }

    /// Record a proof request
    pub fn record_proof_request(&self, success: bool, latency: Duration) {
        self.proof_requests_total.fetch_add(1, Ordering::Relaxed);

        if success {
            self.proof_requests_success.fetch_add(1, Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.last_proof_time.store(now, Ordering::Relaxed);
        } else {
            self.proof_requests_failed.fetch_add(1, Ordering::Relaxed);
        }

        if let Ok(mut hist) = self.proof_latencies.write() {
            hist.record(latency.as_micros() as u64);
        }
    }

    /// Record a token refresh attempt
    pub fn record_token_refresh(&self, success: bool, latency: Duration) {
        self.token_refresh_total.fetch_add(1, Ordering::Relaxed);

        if success {
            self.token_refresh_success.fetch_add(1, Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.last_refresh_time.store(now, Ordering::Relaxed);
        } else {
            self.token_refresh_failed.fetch_add(1, Ordering::Relaxed);
        }

        if let Ok(mut hist) = self.refresh_latencies.write() {
            hist.record(latency.as_micros() as u64);
        }
    }

    /// Record a new IPC connection
    pub fn record_connection(&self) {
        self.ipc_connections_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an IPC request
    pub fn record_request(&self, is_error: bool) {
        self.ipc_requests_total.fetch_add(1, Ordering::Relaxed);
        if is_error {
            self.ipc_errors_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Export metrics as a snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        let proof_hist = self.proof_latencies.read().ok();
        let refresh_hist = self.refresh_latencies.read().ok();

        MetricsSnapshot {
            uptime_seconds: self.uptime_seconds(),
            start_timestamp: self.start_timestamp,

            proof_requests_total: self.proof_requests_total.load(Ordering::Relaxed),
            proof_requests_success: self.proof_requests_success.load(Ordering::Relaxed),
            proof_requests_failed: self.proof_requests_failed.load(Ordering::Relaxed),
            proof_latency_p50_us: proof_hist.as_ref().map(|h| h.percentile(50)).unwrap_or(0),
            proof_latency_p95_us: proof_hist.as_ref().map(|h| h.percentile(95)).unwrap_or(0),
            proof_latency_p99_us: proof_hist.as_ref().map(|h| h.percentile(99)).unwrap_or(0),

            token_refresh_total: self.token_refresh_total.load(Ordering::Relaxed),
            token_refresh_success: self.token_refresh_success.load(Ordering::Relaxed),
            token_refresh_failed: self.token_refresh_failed.load(Ordering::Relaxed),
            refresh_latency_p50_us: refresh_hist.as_ref().map(|h| h.percentile(50)).unwrap_or(0),
            refresh_latency_p95_us: refresh_hist.as_ref().map(|h| h.percentile(95)).unwrap_or(0),
            refresh_latency_p99_us: refresh_hist.as_ref().map(|h| h.percentile(99)).unwrap_or(0),

            ipc_connections_total: self.ipc_connections_total.load(Ordering::Relaxed),
            ipc_requests_total: self.ipc_requests_total.load(Ordering::Relaxed),
            ipc_errors_total: self.ipc_errors_total.load(Ordering::Relaxed),

            last_proof_time: self.last_proof_time.load(Ordering::Relaxed),
            last_refresh_time: self.last_refresh_time.load(Ordering::Relaxed),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics at a point in time (serializable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Agent uptime in seconds
    pub uptime_seconds: u64,
    /// When the agent started (unix timestamp)
    pub start_timestamp: u64,

    // Proof generation metrics
    pub proof_requests_total: u64,
    pub proof_requests_success: u64,
    pub proof_requests_failed: u64,
    /// 50th percentile latency in microseconds
    pub proof_latency_p50_us: u64,
    /// 95th percentile latency in microseconds
    pub proof_latency_p95_us: u64,
    /// 99th percentile latency in microseconds
    pub proof_latency_p99_us: u64,

    // Token refresh metrics
    pub token_refresh_total: u64,
    pub token_refresh_success: u64,
    pub token_refresh_failed: u64,
    pub refresh_latency_p50_us: u64,
    pub refresh_latency_p95_us: u64,
    pub refresh_latency_p99_us: u64,

    // IPC metrics
    pub ipc_connections_total: u64,
    pub ipc_requests_total: u64,
    pub ipc_errors_total: u64,

    // Timestamps
    pub last_proof_time: u64,
    pub last_refresh_time: u64,
}

impl MetricsSnapshot {
    /// Format as Prometheus text exposition format
    pub fn to_prometheus(&self) -> String {
        let mut lines = Vec::new();

        // Uptime
        lines.push("# HELP unix_oidc_agent_uptime_seconds Agent uptime in seconds".to_string());
        lines.push("# TYPE unix_oidc_agent_uptime_seconds gauge".to_string());
        lines.push(format!(
            "unix_oidc_agent_uptime_seconds {}",
            self.uptime_seconds
        ));

        // Proof requests
        lines.push("# HELP unix_oidc_agent_proof_requests_total Total proof requests".to_string());
        lines.push("# TYPE unix_oidc_agent_proof_requests_total counter".to_string());
        lines.push(format!(
            "unix_oidc_agent_proof_requests_total{{status=\"success\"}} {}",
            self.proof_requests_success
        ));
        lines.push(format!(
            "unix_oidc_agent_proof_requests_total{{status=\"failed\"}} {}",
            self.proof_requests_failed
        ));

        // Proof latency
        lines.push(
            "# HELP unix_oidc_agent_proof_latency_us Proof generation latency in microseconds"
                .to_string(),
        );
        lines.push("# TYPE unix_oidc_agent_proof_latency_us summary".to_string());
        lines.push(format!(
            "unix_oidc_agent_proof_latency_us{{quantile=\"0.5\"}} {}",
            self.proof_latency_p50_us
        ));
        lines.push(format!(
            "unix_oidc_agent_proof_latency_us{{quantile=\"0.95\"}} {}",
            self.proof_latency_p95_us
        ));
        lines.push(format!(
            "unix_oidc_agent_proof_latency_us{{quantile=\"0.99\"}} {}",
            self.proof_latency_p99_us
        ));

        // Token refresh
        lines.push(
            "# HELP unix_oidc_agent_token_refresh_total Total token refresh attempts".to_string(),
        );
        lines.push("# TYPE unix_oidc_agent_token_refresh_total counter".to_string());
        lines.push(format!(
            "unix_oidc_agent_token_refresh_total{{status=\"success\"}} {}",
            self.token_refresh_success
        ));
        lines.push(format!(
            "unix_oidc_agent_token_refresh_total{{status=\"failed\"}} {}",
            self.token_refresh_failed
        ));

        // IPC
        lines
            .push("# HELP unix_oidc_agent_ipc_connections_total Total IPC connections".to_string());
        lines.push("# TYPE unix_oidc_agent_ipc_connections_total counter".to_string());
        lines.push(format!(
            "unix_oidc_agent_ipc_connections_total {}",
            self.ipc_connections_total
        ));

        lines.push("# HELP unix_oidc_agent_ipc_requests_total Total IPC requests".to_string());
        lines.push("# TYPE unix_oidc_agent_ipc_requests_total counter".to_string());
        lines.push(format!(
            "unix_oidc_agent_ipc_requests_total {}",
            self.ipc_requests_total
        ));

        lines.push("# HELP unix_oidc_agent_ipc_errors_total Total IPC errors".to_string());
        lines.push("# TYPE unix_oidc_agent_ipc_errors_total counter".to_string());
        lines.push(format!(
            "unix_oidc_agent_ipc_errors_total {}",
            self.ipc_errors_total
        ));

        lines.join("\n")
    }
}

/// Simple latency histogram for percentile calculations
struct LatencyHistogram {
    /// Sorted list of recorded latencies
    values: Vec<u64>,
    /// Maximum values to keep (for memory bounds)
    max_size: usize,
}

impl LatencyHistogram {
    fn new() -> Self {
        Self {
            values: Vec::with_capacity(1000),
            max_size: 10000,
        }
    }

    fn record(&mut self, value: u64) {
        // If at capacity, remove oldest values (simple FIFO)
        if self.values.len() >= self.max_size {
            self.values.remove(0);
        }
        self.values.push(value);
    }

    fn percentile(&self, p: u8) -> u64 {
        if self.values.is_empty() {
            return 0;
        }

        let mut sorted = self.values.clone();
        sorted.sort_unstable();

        let idx = ((p as f64 / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        // Record some proof requests
        collector.record_proof_request(true, Duration::from_micros(100));
        collector.record_proof_request(true, Duration::from_micros(200));
        collector.record_proof_request(false, Duration::from_micros(50));

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.proof_requests_total, 3);
        assert_eq!(snapshot.proof_requests_success, 2);
        assert_eq!(snapshot.proof_requests_failed, 1);
    }

    #[test]
    fn test_latency_histogram() {
        let mut hist = LatencyHistogram::new();

        for i in 1..=100 {
            hist.record(i);
        }

        // Percentile calculations may vary by +/- 1 due to rounding
        let p50 = hist.percentile(50);
        let p95 = hist.percentile(95);
        let p99 = hist.percentile(99);

        assert!((49..=51).contains(&p50), "p50 was {}", p50);
        assert!((94..=96).contains(&p95), "p95 was {}", p95);
        assert!((98..=100).contains(&p99), "p99 was {}", p99);
    }

    #[test]
    fn test_prometheus_format() {
        let collector = MetricsCollector::new();
        collector.record_proof_request(true, Duration::from_micros(100));

        let snapshot = collector.snapshot();
        let prom = snapshot.to_prometheus();

        assert!(prom.contains("unix_oidc_agent_uptime_seconds"));
        assert!(prom.contains("unix_oidc_agent_proof_requests_total"));
    }
}
