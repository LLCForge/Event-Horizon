//! Lock-free alert counters with a Prometheus text renderer.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Per-sink counters.
#[derive(Debug)]
pub struct SinkMetrics {
    pub name: String,
    pub kind: &'static str,
    sent: AtomicU64,
    failed: AtomicU64,
    suppressed: AtomicU64,
    queued: AtomicU64,
    retries: AtomicU64,
    rate_limited: AtomicU64,
}

/// Point-in-time copy of [`SinkMetrics`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SinkSnapshot {
    pub sent: u64,
    pub failed: u64,
    pub suppressed: u64,
    pub queued: u64,
    pub retries: u64,
    pub rate_limited: u64,
}

impl SinkMetrics {
    pub fn new(name: &str, kind: &'static str) -> Self {
        SinkMetrics {
            name: name.to_string(),
            kind,
            sent: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
            queued: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }
    pub(crate) fn inc_sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_suppressed(&self) {
        self.suppressed.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_retries(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn set_queued(&self, n: u64) {
        self.queued.store(n, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> SinkSnapshot {
        SinkSnapshot {
            sent: self.sent.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            suppressed: self.suppressed.load(Ordering::Relaxed),
            queued: self.queued.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
        }
    }
}

/// Dispatcher-wide counters plus every sink's counters.
#[derive(Debug)]
pub struct Metrics {
    pub tool: String,
    received: AtomicU64,
    deduplicated: AtomicU64,
    silenced: AtomicU64,
    dropped: AtomicU64,
    invalid: AtomicU64,
    queue_depth: AtomicU64,
    pub sinks: Vec<Arc<SinkMetrics>>,
}

/// Point-in-time copy of [`Metrics`] (without sinks).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub received: u64,
    pub deduplicated: u64,
    pub silenced: u64,
    pub dropped: u64,
    pub invalid: u64,
    pub queue_depth: u64,
}

impl Metrics {
    pub fn new(tool: &str, sinks: Vec<Arc<SinkMetrics>>) -> Self {
        Metrics {
            tool: tool.to_string(),
            received: AtomicU64::new(0),
            deduplicated: AtomicU64::new(0),
            silenced: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            sinks,
        }
    }
    pub(crate) fn inc_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_deduplicated(&self) {
        self.deduplicated.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_silenced(&self) {
        self.silenced.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn inc_invalid(&self) {
        self.invalid.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn set_queue_depth(&self, n: u64) {
        self.queue_depth.store(n, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            received: self.received.load(Ordering::Relaxed),
            deduplicated: self.deduplicated.load(Ordering::Relaxed),
            silenced: self.silenced.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
        }
    }

    /// Appends Prometheus text exposition (with HELP/TYPE lines) to `out`.
    pub fn render_prometheus(&self, out: &mut String) {
        let s = self.snapshot();
        let tool = label(&self.tool);
        let global: [(&str, &str, &str, u64); 6] = [
            (
                "llcforge_beacon_received_total",
                "counter",
                "Alerts submitted to the dispatcher.",
                s.received,
            ),
            (
                "llcforge_beacon_deduplicated_total",
                "counter",
                "Alerts suppressed as duplicates.",
                s.deduplicated,
            ),
            (
                "llcforge_beacon_silenced_total",
                "counter",
                "Alerts suppressed by a silence.",
                s.silenced,
            ),
            (
                "llcforge_beacon_dropped_total",
                "counter",
                "Alerts dropped (channel full, queue bound, expiry).",
                s.dropped,
            ),
            (
                "llcforge_beacon_invalid_total",
                "counter",
                "Alerts rejected as invalid.",
                s.invalid,
            ),
            (
                "llcforge_beacon_queue_depth",
                "gauge",
                "Alerts awaiting delivery to at least one sink.",
                s.queue_depth,
            ),
        ];
        for (name, ty, help, v) in global {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} {ty}\n{name}{{tool=\"{tool}\"}} {v}"
            );
        }
        type Get = fn(&SinkSnapshot) -> u64;
        let per_sink: [(&str, &str, &str, Get); 6] = [
            (
                "llcforge_beacon_sink_sent_total",
                "counter",
                "Alerts delivered by sink.",
                |x| x.sent,
            ),
            (
                "llcforge_beacon_sink_failed_total",
                "counter",
                "Delivery failures by sink (after retries).",
                |x| x.failed,
            ),
            (
                "llcforge_beacon_sink_suppressed_total",
                "counter",
                "Alerts not routed to the sink by its filter.",
                |x| x.suppressed,
            ),
            (
                "llcforge_beacon_sink_queued",
                "gauge",
                "Alerts pending delivery to the sink.",
                |x| x.queued,
            ),
            (
                "llcforge_beacon_sink_retries_total",
                "counter",
                "Delivery retries by sink.",
                |x| x.retries,
            ),
            (
                "llcforge_beacon_sink_rate_limited_total",
                "counter",
                "Times delivery waited for the rate limiter.",
                |x| x.rate_limited,
            ),
        ];
        let snaps: Vec<_> = self.sinks.iter().map(|m| (m, m.snapshot())).collect();
        for (name, ty, help, get) in per_sink {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {ty}");
            for (m, snap) in &snaps {
                let _ = writeln!(
                    out,
                    "{name}{{tool=\"{tool}\",sink=\"{}\",type=\"{}\"}} {}",
                    label(&m.name),
                    m.kind,
                    get(snap)
                );
            }
        }
    }
}

fn label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus() {
        let sm = Arc::new(SinkMetrics::new("noc", "telegram"));
        sm.inc_sent();
        sm.inc_sent();
        let m = Metrics::new("vigil", vec![sm]);
        m.inc_received();
        let mut out = String::new();
        m.render_prometheus(&mut out);
        assert!(out.contains("llcforge_beacon_received_total{tool=\"vigil\"} 1"));
        assert!(out.contains(
            "llcforge_beacon_sink_sent_total{tool=\"vigil\",sink=\"noc\",type=\"telegram\"} 2"
        ));
        assert!(out.contains("# TYPE llcforge_beacon_queue_depth gauge"));
    }
}
