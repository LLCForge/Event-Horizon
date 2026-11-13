//! Prometheus metrics in the text exposition format, without extra dependencies.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

use crate::propagation::PropStatus;

#[derive(Default)]
pub struct Metrics {
    pub decisions_allowed: AtomicU64,
    pub decisions_denied: AtomicU64,
    pub withdrawn: AtomicU64,
    pub expired: AtomicU64,
    pub active: AtomicU64,
    pub updates_sent_announce: AtomicU64,
    pub updates_sent_withdraw: AtomicU64,
    pub updates_received: AtomicU64,
    pub sflow_accepted: AtomicU64,
    pub sflow_rejected: AtomicU64,
    pub sflow_malformed: AtomicU64,
    pub sflow_untracked: AtomicU64,
    pub netflow_accepted: AtomicU64,
    pub netflow_rejected: AtomicU64,
    pub netflow_malformed: AtomicU64,
    pub netflow_no_template: AtomicU64,
    pub netflow_templates: AtomicU64,
    pub api_unauthorized: AtomicU64,
    pub api_rate_limited: AtomicU64,
    pub api_tls_failed: AtomicU64,
    pub flowspec_allowed: AtomicU64,
    pub flowspec_withdrawn: AtomicU64,
    pub flowspec_expired: AtomicU64,
    pub flowspec_active: AtomicU64,
    pub flowspec_updates_announce: AtomicU64,
    pub flowspec_updates_withdraw: AtomicU64,
    pub escalations: AtomicU64,
    pub approvals_requested: AtomicU64,
    pub approvals_approved: AtomicU64,
    pub approvals_denied: AtomicU64,
    pub approvals_timeout: AtomicU64,
    pub pending: AtomicU64,
    pub reports_written: AtomicU64,
    pub prop_propagated: AtomicU64,
    pub prop_not_seen: AtomicU64,
    pub prop_unknown: AtomicU64,
    attacks: Mutex<BTreeMap<String, u64>>,
    sessions: Mutex<BTreeMap<String, bool>>,
}

impl Metrics {
    pub fn new<'a>(upstreams: impl IntoIterator<Item = &'a str>) -> Self {
        let m = Self::default();
        if let Ok(mut s) = m.sessions.lock() {
            for u in upstreams {
                s.insert(u.to_owned(), false);
            }
        }
        m
    }

    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Relaxed);
    }

    pub fn set_session(&self, upstream: &str, up: bool) {
        if let Ok(mut s) = self.sessions.lock() {
            s.insert(upstream.to_owned(), up);
        }
    }

    pub fn any_session_up(&self) -> bool {
        self.sessions
            .lock()
            .map(|s| s.values().any(|v| *v))
            .unwrap_or(false)
    }

    /// Counts a detected attack by classification (bounded label set).
    pub fn attack(&self, class: &'static str) {
        if let Ok(mut a) = self.attacks.lock() {
            *a.entry(class.to_owned()).or_default() += 1;
        }
    }

    pub fn propagation(&self, s: PropStatus) {
        Self::inc(match s {
            PropStatus::Propagated => &self.prop_propagated,
            PropStatus::NotSeen => &self.prop_not_seen,
            PropStatus::Unknown => &self.prop_unknown,
        });
    }

    pub fn render(&self) -> String {
        let mut o = String::with_capacity(4096);
        let mut metric = |name: &str, kind: &str, help: &str, samples: &[(&str, u64)]| {
            let _ = writeln!(o, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for (labels, v) in samples {
                let _ = writeln!(o, "{name}{labels} {v}");
            }
        };
        let g = |c: &AtomicU64| c.load(Relaxed);
        metric(
            "event_horizon_active_blackholes",
            "gauge",
            "Blackholes currently in the active set.",
            &[("", g(&self.active))],
        );
        metric(
            "event_horizon_active_flowspec_rules",
            "gauge",
            "FlowSpec rules currently in the active set.",
            &[("", g(&self.flowspec_active))],
        );
        metric(
            "event_horizon_decisions_total",
            "counter",
            "Policy decisions by result.",
            &[
                (r#"{result="allow"}"#, g(&self.decisions_allowed)),
                (r#"{result="deny"}"#, g(&self.decisions_denied)),
            ],
        );
        metric(
            "event_horizon_flowspec_decisions_total",
            "counter",
            "FlowSpec rules allowed by the policy.",
            &[(r#"{result="allow"}"#, g(&self.flowspec_allowed))],
        );
        metric(
            "event_horizon_removals_total",
            "counter",
            "Blackholes removed from the active set by cause.",
            &[
                (r#"{cause="withdraw"}"#, g(&self.withdrawn)),
                (r#"{cause="expire"}"#, g(&self.expired)),
            ],
        );
        metric(
            "event_horizon_flowspec_removals_total",
            "counter",
            "FlowSpec rules removed by cause.",
            &[
                (r#"{cause="withdraw"}"#, g(&self.flowspec_withdrawn)),
                (r#"{cause="expire"}"#, g(&self.flowspec_expired)),
            ],
        );
        metric(
            "event_horizon_escalations_total",
            "counter",
            "Attacks escalated from FlowSpec to RTBH.",
            &[("", g(&self.escalations))],
        );
        metric(
            "event_horizon_bgp_updates_sent_total",
            "counter",
            "BGP UPDATE messages sent (or logged in dry-run).",
            &[
                (r#"{kind="announce"}"#, g(&self.updates_sent_announce)),
                (r#"{kind="withdraw"}"#, g(&self.updates_sent_withdraw)),
                (
                    r#"{kind="flowspec_announce"}"#,
                    g(&self.flowspec_updates_announce),
                ),
                (
                    r#"{kind="flowspec_withdraw"}"#,
                    g(&self.flowspec_updates_withdraw),
                ),
            ],
        );
        metric(
            "event_horizon_bgp_updates_received_total",
            "counter",
            "BGP UPDATE messages received and ignored.",
            &[("", g(&self.updates_received))],
        );
        metric(
            "event_horizon_sflow_datagrams_total",
            "counter",
            "sFlow datagrams by result.",
            &[
                (r#"{result="accepted"}"#, g(&self.sflow_accepted)),
                (r#"{result="rejected_source"}"#, g(&self.sflow_rejected)),
                (r#"{result="malformed"}"#, g(&self.sflow_malformed)),
            ],
        );
        metric(
            "event_horizon_netflow_datagrams_total",
            "counter",
            "NetFlow v9 / IPFIX datagrams by result.",
            &[
                (r#"{result="accepted"}"#, g(&self.netflow_accepted)),
                (r#"{result="rejected_source"}"#, g(&self.netflow_rejected)),
                (r#"{result="malformed"}"#, g(&self.netflow_malformed)),
            ],
        );
        metric(
            "event_horizon_netflow_records_without_template_total",
            "counter",
            "NetFlow v9 / IPFIX data sets skipped because the template is unknown.",
            &[("", g(&self.netflow_no_template))],
        );
        metric(
            "event_horizon_netflow_templates",
            "gauge",
            "Cached NetFlow v9 / IPFIX templates.",
            &[("", g(&self.netflow_templates))],
        );
        metric(
            "event_horizon_detector_untracked_total",
            "counter",
            "Flow samples dropped because the destination table was full.",
            &[("", g(&self.sflow_untracked))],
        );
        let attacks: Vec<(String, u64)> = self
            .attacks
            .lock()
            .map(|a| {
                a.iter()
                    .map(|(k, v)| (format!(r#"{{class="{k}"}}"#), *v))
                    .collect()
            })
            .unwrap_or_default();
        let refs: Vec<(&str, u64)> = attacks.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        metric(
            "event_horizon_attacks_total",
            "counter",
            "Detected attacks by classification.",
            &refs,
        );
        metric(
            "event_horizon_reports_written_total",
            "counter",
            "Per-victim attack reports written.",
            &[("", g(&self.reports_written))],
        );
        metric(
            "event_horizon_approvals_total",
            "counter",
            "Manual approval requests by outcome.",
            &[
                (r#"{outcome="requested"}"#, g(&self.approvals_requested)),
                (r#"{outcome="approved"}"#, g(&self.approvals_approved)),
                (r#"{outcome="denied"}"#, g(&self.approvals_denied)),
                (r#"{outcome="timeout"}"#, g(&self.approvals_timeout)),
            ],
        );
        metric(
            "event_horizon_approvals_pending",
            "gauge",
            "Requests waiting for manual approval.",
            &[("", g(&self.pending))],
        );
        metric(
            "event_horizon_propagation_checks_total",
            "counter",
            "Blackhole propagation checks by result.",
            &[
                (r#"{status="propagated"}"#, g(&self.prop_propagated)),
                (r#"{status="not_seen"}"#, g(&self.prop_not_seen)),
                (r#"{status="unknown"}"#, g(&self.prop_unknown)),
            ],
        );
        metric(
            "event_horizon_api_rejected_total",
            "counter",
            "Trigger API requests rejected before reaching the policy engine.",
            &[
                (r#"{reason="unauthorized"}"#, g(&self.api_unauthorized)),
                (r#"{reason="rate_limited"}"#, g(&self.api_rate_limited)),
                (r#"{reason="tls_handshake"}"#, g(&self.api_tls_failed)),
            ],
        );
        let sessions: Vec<(String, u64)> = self
            .sessions
            .lock()
            .map(|s| {
                s.iter()
                    .map(|(k, v)| (format!(r#"{{upstream="{k}"}}"#), u64::from(*v)))
                    .collect()
            })
            .unwrap_or_default();
        let refs: Vec<(&str, u64)> = sessions.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        metric(
            "event_horizon_bgp_session_established",
            "gauge",
            "1 when the BGP session to the upstream is established.",
            &refs,
        );
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let m = Metrics::new(["transit-a"]);
        Metrics::inc(&m.decisions_denied);
        m.set_session("transit-a", true);
        m.attack("udp_amplification_dns");
        m.propagation(PropStatus::NotSeen);
        let t = m.render();
        assert!(t.contains("event_horizon_decisions_total{result=\"deny\"} 1\n"));
        assert!(t.contains("event_horizon_bgp_session_established{upstream=\"transit-a\"} 1\n"));
        assert!(t.contains("# TYPE event_horizon_active_blackholes gauge\n"));
        assert!(t.contains("event_horizon_attacks_total{class=\"udp_amplification_dns\"} 1\n"));
        assert!(t.contains("event_horizon_propagation_checks_total{status=\"not_seen\"} 1\n"));
        assert!(m.any_session_up());
    }
}
