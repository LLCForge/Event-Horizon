//! Per-destination rate detector with hysteresis, attack classification (37),
//! dynamic EWMA baselines (39), per-attack statistics (44), the mitigation
//! logic (FlowSpec first, RTBH on escalation, 38) and the collector tasks.
//!
//! Traffic is kept in one-second buckets over a sliding window. A destination
//! triggers after its rate stays above its threshold for `trigger_after`, and
//! is released after its rate stays below the release level for
//! `release_after`. While an attack persists the detector re-requests every
//! `trigger_after`; the engine treats that as a no-op if the mitigation is
//! still active, so a route that hit its TTL is re-announced while the attack
//! is still running. Every request goes through `Engine::submit`, i.e. the
//! policy engine (and the approval gate when enabled).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipnet::IpNet;
use llcforge_beacon::Severity;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::alerts::{alert, Alerts};
use crate::bgp::flowspec::{FlowAction, FlowRule, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::config::{
    BaselineConfig, FlowActionKind, FlowspecConfig, NetflowConfig, Rate, SflowConfig, Thresholds,
};
use crate::engine::{Engine, Submitted, Target};
use crate::flow::FlowSample;
use crate::metrics::Metrics;
use crate::netflow::Collector;
use crate::report::{human_bps, AttackStats, ReportStore};
use crate::sflow::parse_datagram;
use crate::state::Source;
use crate::unix_now;

/// Hard cap on tracked destinations so spoofed flows cannot exhaust memory.
pub const MAX_TRACKED: usize = 65_536;
/// Idle destinations keep their baseline this long.
const BASELINE_IDLE: u64 = 3600;
const PORT_CAP: usize = 64;
const MAX_STEPS: usize = 50;

/// UDP amplification vectors recognised by source port.
pub const AMP_PORTS: [(u16, &str); 6] = [
    (53, "udp_amplification_dns"),
    (123, "udp_amplification_ntp"),
    (11211, "udp_amplification_memcached"),
    (1900, "udp_amplification_ssdp"),
    (389, "udp_amplification_cldap"),
    (19, "udp_amplification_chargen"),
];

#[derive(Debug, Clone)]
pub struct Params {
    pub threshold: Rate,
    pub release: Rate,
    pub window: u64,
    pub trigger_after: u64,
    pub release_after: u64,
    pub baseline: Option<BaselineConfig>,
}

impl Params {
    pub fn from_thresholds(t: Thresholds, baseline: Option<BaselineConfig>) -> Self {
        Self {
            threshold: t.threshold,
            release: t.release,
            window: t.window.max(1),
            trigger_after: t.trigger_after,
            release_after: t.release_after,
            baseline,
        }
    }
}

/// What a FlowSpec rule should match for a classified attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Attack {
        dst: IpAddr,
        pps: u64,
        mbps: f64,
        class: &'static str,
        signature: Option<Signature>,
    },
    Release {
        dst: IpAddr,
        stats: Option<Box<AttackStats>>,
    },
}

/// Packet mix of one destination over the last one or two windows.
#[derive(Debug, Clone, Default)]
struct Profile {
    total: u64,
    udp: u64,
    amp: [u64; AMP_PORTS.len()],
    tcp: u64,
    syn: u64,
    icmp: u64,
    tcp_dports: HashMap<u16, u64>,
    udp_dports: HashMap<u16, u64>,
}

fn bump(m: &mut HashMap<u16, u64>, k: u16, v: u64) {
    if let Some(c) = m.get_mut(&k) {
        *c = c.saturating_add(v);
    } else if m.len() < PORT_CAP {
        m.insert(k, v);
    }
}

fn dominant(m: &HashMap<u16, u64>, of: u64) -> Option<u16> {
    m.iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .filter(|(_, c)| **c * 2 >= of && of > 0)
        .map(|(k, _)| *k)
}

impl Profile {
    fn add(&mut self, s: &FlowSample) {
        let n = s.packets;
        self.total = self.total.saturating_add(n);
        match s.protocol {
            Some(PROTO_UDP) => {
                self.udp = self.udp.saturating_add(n);
                if let Some(i) = s
                    .src_port
                    .and_then(|p| AMP_PORTS.iter().position(|(ap, _)| *ap == p))
                {
                    self.amp[i] = self.amp[i].saturating_add(n);
                }
                if let Some(p) = s.dst_port {
                    bump(&mut self.udp_dports, p, n);
                }
            }
            Some(PROTO_TCP) => {
                self.tcp = self.tcp.saturating_add(n);
                // SYN without ACK.
                if s.tcp_flags.is_some_and(|f| f & 0x12 == 0x02) {
                    self.syn = self.syn.saturating_add(n);
                }
                if let Some(p) = s.dst_port {
                    bump(&mut self.tcp_dports, p, n);
                }
            }
            Some(PROTO_ICMP | PROTO_ICMPV6) => self.icmp = self.icmp.saturating_add(n),
            _ => {}
        }
    }

    fn merge(&self, other: &Profile) -> Profile {
        let mut p = self.clone();
        p.total = p.total.saturating_add(other.total);
        p.udp = p.udp.saturating_add(other.udp);
        p.tcp = p.tcp.saturating_add(other.tcp);
        p.syn = p.syn.saturating_add(other.syn);
        p.icmp = p.icmp.saturating_add(other.icmp);
        for (a, b) in p.amp.iter_mut().zip(other.amp) {
            *a = a.saturating_add(b);
        }
        for (k, v) in &other.tcp_dports {
            bump(&mut p.tcp_dports, *k, *v);
        }
        for (k, v) in &other.udp_dports {
            bump(&mut p.udp_dports, *k, *v);
        }
        p
    }

    /// Majority vote by packets: amplification source port, SYN, ICMP, UDP.
    fn classify(&self, dst: IpAddr) -> (&'static str, Option<Signature>) {
        let half = |x: u64| self.total > 0 && x * 2 >= self.total;
        if let Some((i, n)) = self.amp.iter().enumerate().max_by_key(|(_, n)| **n) {
            if half(*n) {
                return (
                    AMP_PORTS[i].1,
                    Some(Signature {
                        protocol: PROTO_UDP,
                        src_port: Some(AMP_PORTS[i].0),
                        dst_port: None,
                    }),
                );
            }
        }
        if half(self.syn) {
            return (
                "syn_flood",
                Some(Signature {
                    protocol: PROTO_TCP,
                    src_port: None,
                    dst_port: dominant(&self.tcp_dports, self.syn),
                }),
            );
        }
        if half(self.icmp) {
            let protocol = if dst.is_ipv4() {
                PROTO_ICMP
            } else {
                PROTO_ICMPV6
            };
            return (
                "icmp_flood",
                Some(Signature {
                    protocol,
                    src_port: None,
                    dst_port: None,
                }),
            );
        }
        if half(self.udp) {
            return (
                "udp_flood",
                Some(Signature {
                    protocol: PROTO_UDP,
                    src_port: None,
                    dst_port: dominant(&self.udp_dports, self.udp),
                }),
            );
        }
        ("unknown", None)
    }
}

#[derive(Default)]
struct DstState {
    buckets: VecDeque<(u64, u64, u64)>, // (second, packets, bytes)
    above_since: Option<u64>,
    below_since: Option<u64>,
    triggered: bool,
    last_emit: u64,
    last_seen: u64,
    epoch: u64,
    cur: Profile,
    prev: Profile,
    ewma_pps: f64,
    ewma_mbps: f64,
    samples: u64,
    stats: Option<AttackStats>,
}

pub struct Detector {
    p: Params,
    protected: Vec<IpNet>,
    dsts: HashMap<IpAddr, DstState>,
}

fn exceeds(pps_thr: Option<f64>, mbps_thr: Option<f64>, pps: u64, mbps: f64) -> bool {
    pps_thr.is_some_and(|t| pps as f64 > t) || mbps_thr.is_some_and(|t| mbps > t)
}

impl Detector {
    pub fn new(p: Params, protected: Vec<IpNet>) -> Self {
        Self {
            p,
            protected,
            dsts: HashMap::new(),
        }
    }

    /// Records traffic. Only destinations inside `protected` are tracked.
    /// Returns false when the sample was dropped because the table is full.
    pub fn record(&mut self, s: &FlowSample, now: u64) -> bool {
        let dst = s.dst.to_canonical();
        if !self.protected.iter().any(|p| p.contains(&dst)) {
            return true;
        }
        if !self.dsts.contains_key(&dst) && self.dsts.len() >= MAX_TRACKED {
            return false;
        }
        let window = self.p.window;
        let st = self.dsts.entry(dst).or_default();
        st.last_seen = now;
        match st.buckets.back_mut() {
            Some(b) if b.0 == now => {
                b.1 = b.1.saturating_add(s.packets);
                b.2 = b.2.saturating_add(s.bytes);
            }
            _ => st.buckets.push_back((now, s.packets, s.bytes)),
        }
        let epoch = now / window;
        if epoch != st.epoch {
            st.prev = if epoch == st.epoch + 1 {
                std::mem::take(&mut st.cur)
            } else {
                Profile::default()
            };
            st.cur = Profile::default();
            st.epoch = epoch;
        }
        st.cur.add(s);
        if let Some(a) = st.stats.as_mut() {
            a.add(s);
        }
        true
    }

    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.dsts.len()
    }

    /// (trigger pps, trigger mbps, release pps, release mbps) for one destination.
    fn levels(p: &Params, st: &DstState) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
        let s_pps = p.threshold.pps.map(|v| v as f64);
        let s_mbps = p.threshold.mbps.map(|v| v as f64);
        let r_pps = p.release.pps.map(|v| v as f64);
        let r_mbps = p.release.mbps.map(|v| v as f64);
        let Some(bl) = p.baseline.filter(|b| st.samples >= b.warmup.0) else {
            return (s_pps, s_mbps, r_pps, r_mbps);
        };
        // The baseline can only lower a static threshold, never raise it.
        let dynamic = |floor: u64, ewma: f64, stat: Option<f64>| -> Option<f64> {
            let d = (ewma * bl.multiplier).max(floor as f64);
            match stat {
                Some(s) => Some(s.min(d)),
                None if floor > 0 => Some(d),
                None => None,
            }
        };
        let t_pps = dynamic(bl.min_pps, st.ewma_pps, s_pps);
        let t_mbps = dynamic(bl.min_mbps, st.ewma_mbps, s_mbps);
        let rel = |t: Option<f64>, r: Option<f64>| match (t, r) {
            (Some(t), Some(r)) => Some(r.min(t / 2.0)),
            (Some(t), None) => Some(t / 2.0),
            (None, r) => r,
        };
        (t_pps, t_mbps, rel(t_pps, r_pps), rel(t_mbps, r_mbps))
    }

    pub fn evaluate(&mut self, now: u64) -> Vec<Event> {
        let p = &self.p;
        let mut events = Vec::new();
        self.dsts.retain(|dst, st| {
            while st
                .buckets
                .front()
                .is_some_and(|b| b.0.saturating_add(p.window) <= now)
            {
                st.buckets.pop_front();
            }
            let (pk, by) = st.buckets.iter().fold((0u64, 0u64), |a, b| {
                (a.0.saturating_add(b.1), a.1.saturating_add(b.2))
            });
            let pps = pk / p.window;
            let bps = by.saturating_mul(8) / p.window;
            let mbps = bps as f64 / 1_000_000.0;
            let (t_pps, t_mbps, r_pps, r_mbps) = Self::levels(p, st);

            if st.triggered {
                if let Some(a) = st.stats.as_mut() {
                    a.peak(pps, bps);
                }
                if exceeds(r_pps, r_mbps, pps, mbps) {
                    st.below_since = None;
                    if now.saturating_sub(st.last_emit) >= p.trigger_after.max(1) {
                        st.last_emit = now;
                        let (class, signature) = st.cur.merge(&st.prev).classify(*dst);
                        if let Some(a) = st.stats.as_mut() {
                            a.class = class;
                        }
                        events.push(Event::Attack {
                            dst: *dst,
                            pps,
                            mbps,
                            class,
                            signature,
                        });
                    }
                } else {
                    let since = *st.below_since.get_or_insert(now);
                    if now.saturating_sub(since) >= p.release_after {
                        st.triggered = false;
                        st.below_since = None;
                        st.above_since = None;
                        events.push(Event::Release {
                            dst: *dst,
                            stats: st.stats.take().map(Box::new),
                        });
                    }
                }
            } else if exceeds(t_pps, t_mbps, pps, mbps) {
                let since = *st.above_since.get_or_insert(now);
                if now.saturating_sub(since) >= p.trigger_after {
                    st.triggered = true;
                    st.last_emit = now;
                    let (class, signature) = st.cur.merge(&st.prev).classify(*dst);
                    let mut stats = AttackStats::new(since, class);
                    stats.peak(pps, bps);
                    st.stats = Some(stats);
                    events.push(Event::Attack {
                        dst: *dst,
                        pps,
                        mbps,
                        class,
                        signature,
                    });
                }
            } else {
                st.above_since = None;
                // Learn the normal rate only while not under attack.
                if let Some(bl) = p.baseline {
                    if st.samples == 0 {
                        st.ewma_pps = pps as f64;
                        st.ewma_mbps = mbps;
                    } else {
                        st.ewma_pps += bl.alpha * (pps as f64 - st.ewma_pps);
                        st.ewma_mbps += bl.alpha * (mbps - st.ewma_mbps);
                    }
                    st.samples = st.samples.saturating_add(1);
                }
            }
            st.triggered
                || !st.buckets.is_empty()
                || (p.baseline.is_some() && now.saturating_sub(st.last_seen) < BASELINE_IDLE)
        });
        events
    }
}

/// FlowSpec part of the mitigation settings.
#[derive(Debug, Clone, Copy)]
pub struct FlowSettings {
    pub action: FlowAction,
    pub escalate: bool,
    pub escalate_after: u64,
}

impl FlowSettings {
    pub fn from_config(f: &FlowspecConfig) -> Self {
        Self {
            action: match f.action {
                FlowActionKind::Discard => FlowAction::Discard,
                FlowActionKind::RateLimit => FlowAction::RateLimit {
                    kbps: f.rate_limit_kbps,
                },
            },
            escalate: f.escalate,
            escalate_after: f.escalate_after.0,
        }
    }
}

#[derive(Default)]
struct MitState {
    flowspec_since: Option<u64>,
    escalated: bool,
    steps: Vec<String>,
}

impl MitState {
    fn step(&mut self, now: u64, s: String) {
        if self.steps.len() < MAX_STEPS {
            self.steps
                .push(format!("{} {s}", crate::report::fmt_time(now)));
        }
    }
}

/// Turns detector events into policy-checked requests: FlowSpec first when the
/// attack has a signature, RTBH when FlowSpec is unavailable, denied, or the
/// attack persists `escalate_after` past the FlowSpec rule.
pub struct Mitigator {
    flowspec: Option<FlowSettings>,
    attacks: HashMap<IpAddr, MitState>,
    alerts: Alerts,
    metrics: Arc<Metrics>,
    reports: Option<Arc<ReportStore>>,
}

impl Mitigator {
    pub fn new(
        flowspec: Option<FlowSettings>,
        alerts: Alerts,
        metrics: Arc<Metrics>,
        reports: Option<Arc<ReportStore>>,
    ) -> Self {
        Self {
            flowspec,
            attacks: HashMap::new(),
            alerts,
            metrics,
            reports,
        }
    }

    fn rtbh(e: &mut Engine, st: &mut MitState, dst: IpAddr, reason: &str, now: u64) -> bool {
        match e.submit(Target::blackhole(dst), None, reason, Source::Detector, now) {
            Ok(Submitted::Pending(p)) => {
                if st.steps.last().is_none_or(|s| !s.contains(&p.id)) {
                    st.step(now, format!("RTBH waiting for approval ({})", p.id));
                }
                true
            }
            Ok(_) => {
                st.step(now, format!("RTBH host route announced: {reason}"));
                true
            }
            Err(d) => d.is_duplicate(),
        }
    }

    pub fn handle(&mut self, engine: &Mutex<Engine>, events: Vec<Event>, now: u64) {
        let Ok(mut e) = engine.lock() else { return };
        for ev in events {
            match ev {
                Event::Attack {
                    dst,
                    pps,
                    mbps,
                    class,
                    signature,
                } => {
                    if !self.attacks.contains_key(&dst) {
                        self.metrics.attack(class);
                        self.alerts.send(
                            alert(
                                "attack",
                                Severity::Warning,
                                format!("DDoS attack on {dst}: {class}"),
                            )
                            .resource(dst.to_string())
                            .field("pps", pps)
                            .field("rate", human_bps((mbps * 1e6) as u64))
                            .field("class", class),
                        );
                    }
                    let st = self.attacks.entry(dst).or_default();
                    let reason = format!("detector: {class}, {pps} pps, {mbps:.1} Mbps");
                    let flow = match (self.flowspec, signature) {
                        (Some(fs), Some(sig)) if !st.escalated => Some((fs, sig)),
                        _ => None,
                    };
                    let Some((fs, sig)) = flow else {
                        Self::rtbh(&mut e, st, dst, &reason, now);
                        continue;
                    };
                    let rule = FlowRule {
                        dst,
                        protocol: sig.protocol,
                        src_port: sig.src_port,
                        dst_port: sig.dst_port,
                        action: fs.action,
                    };
                    match e.submit(
                        Target::Flowspec { rule: rule.clone() },
                        None,
                        &reason,
                        Source::Detector,
                        now,
                    ) {
                        Ok(Submitted::Pending(p)) => {
                            if st.steps.last().is_none_or(|s| !s.contains(&p.id)) {
                                st.step(now, format!("FlowSpec waiting for approval ({})", p.id));
                            }
                        }
                        Ok(_) => {
                            st.flowspec_since.get_or_insert(now);
                            st.step(now, format!("FlowSpec {rule}"));
                        }
                        Err(d) if d.is_duplicate() => {
                            st.flowspec_since.get_or_insert(now);
                        }
                        Err(d) => {
                            // FlowSpec refused by policy: fall back to RTBH (policy-checked too).
                            st.escalated = true;
                            let why = format!("{reason}; FlowSpec denied ({})", d.code());
                            Self::rtbh(&mut e, st, dst, &why, now);
                            continue;
                        }
                    }
                    let persisted = st
                        .flowspec_since
                        .is_some_and(|t| now.saturating_sub(t) >= fs.escalate_after);
                    if fs.escalate && persisted {
                        let why = format!(
                            "{reason}; escalated, attack persisted {}s after FlowSpec",
                            now.saturating_sub(st.flowspec_since.unwrap_or(now))
                        );
                        if Self::rtbh(&mut e, st, dst, &why, now) {
                            st.escalated = true;
                            Metrics::inc(&self.metrics.escalations);
                            info!(%dst, "escalated from FlowSpec to RTBH");
                            self.alerts.send(
                                alert(
                                    "escalation",
                                    Severity::Critical,
                                    format!("Attack on {dst} escalated to RTBH"),
                                )
                                .resource(dst.to_string())
                                .summary(why)
                                .field("class", class),
                            );
                        }
                    }
                }
                Event::Release { dst, stats } => {
                    e.release(dst, now);
                    e.release_flowspec(dst, now);
                    let mut st = self.attacks.remove(&dst).unwrap_or_default();
                    st.step(
                        now,
                        "traffic below release level; detector mitigations withdrawn".into(),
                    );
                    let mut al = alert("attack", Severity::Info, format!("Attack on {dst} ended"))
                        .resource(dst.to_string())
                        .resolved(true);
                    if let Some(stats) = stats {
                        let r = stats.finish(dst, now, st.steps);
                        al = al
                            .summary(format!(
                                "{} for {}s, peak {} pps / {}",
                                r.classification,
                                r.duration_secs,
                                r.peak_pps,
                                human_bps(r.peak_bps)
                            ))
                            .field("report", &r.id);
                        if let Some(store) = &self.reports {
                            match store.save(&r) {
                                Ok(()) => Metrics::inc(&self.metrics.reports_written),
                                Err(err) => warn!(error = %err, "cannot write attack report"),
                            }
                        }
                    }
                    self.alerts.send(al);
                }
            }
        }
    }
}

fn record_all(det: &Mutex<Detector>, samples: &[FlowSample], metrics: &Metrics) {
    let now = unix_now();
    let Ok(mut d) = det.lock() else { return };
    for s in samples {
        if !d.record(s, now) {
            Metrics::inc(&metrics.sflow_untracked);
        }
    }
}

/// sFlow UDP collector. Datagrams from sources not in `exporters` are dropped.
pub async fn run_sflow(
    sock: UdpSocket,
    cfg: SflowConfig,
    det: Arc<Mutex<Detector>>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; 65_535];
    info!(listen = %cfg.listen, "sFlow collector started");
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(v) => v,
                    Err(e) => { debug!(error = %e, "sFlow recv error"); continue; }
                };
                if !cfg.exporters.contains(&src.ip().to_canonical()) {
                    Metrics::inc(&metrics.sflow_rejected);
                    debug!(%src, "sFlow datagram from unknown exporter dropped");
                    continue;
                }
                match parse_datagram(&buf[..n]) {
                    Ok(samples) => {
                        Metrics::inc(&metrics.sflow_accepted);
                        record_all(&det, &samples, &metrics);
                    }
                    Err(e) => {
                        Metrics::inc(&metrics.sflow_malformed);
                        debug!(%src, error = %e, "malformed sFlow datagram");
                    }
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

/// NetFlow v9 / IPFIX UDP collector.
pub async fn run_netflow(
    sock: UdpSocket,
    cfg: NetflowConfig,
    det: Arc<Mutex<Detector>>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; 65_535];
    let mut c = Collector::new(cfg.max_templates, cfg.sampling_rate);
    info!(listen = %cfg.listen, "NetFlow v9 / IPFIX collector started");
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(v) => v,
                    Err(e) => { debug!(error = %e, "NetFlow recv error"); continue; }
                };
                let exporter = src.ip().to_canonical();
                if !cfg.exporters.contains(&exporter) {
                    Metrics::inc(&metrics.netflow_rejected);
                    debug!(%src, "NetFlow datagram from unknown exporter dropped");
                    continue;
                }
                match c.parse(exporter, &buf[..n]) {
                    Ok(p) => {
                        Metrics::inc(&metrics.netflow_accepted);
                        metrics.netflow_no_template.fetch_add(p.missing_template as u64, std::sync::atomic::Ordering::Relaxed);
                        if p.rejected_templates > 0 {
                            warn!(%src, rejected = p.rejected_templates, "NetFlow template cache full");
                        }
                        metrics.netflow_templates.store(c.templates() as u64, std::sync::atomic::Ordering::Relaxed);
                        record_all(&det, &p.samples, &metrics);
                    }
                    Err(e) => {
                        Metrics::inc(&metrics.netflow_malformed);
                        debug!(%src, error = %e, "malformed NetFlow datagram");
                    }
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

/// Evaluates the detector every second and hands events to the mitigator.
pub async fn run_detector(
    det: Arc<Mutex<Detector>>,
    mut mit: Mitigator,
    engine: Arc<Mutex<Engine>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let now = unix_now();
                let events = match det.lock() {
                    Ok(mut d) => d.evaluate(now),
                    Err(_) => continue,
                };
                if !events.is_empty() {
                    for ev in &events {
                        match ev {
                            Event::Attack { dst, pps, mbps, class, .. } => warn!(%dst, pps, mbps, class, "attack"),
                            Event::Release { dst, .. } => info!(%dst, "attack ended"),
                        }
                    }
                    mit.handle(&engine, events, now);
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApprovalMode, Secs};
    use crate::report::tests::sample;

    fn params() -> Params {
        Params {
            threshold: Rate {
                pps: Some(1000),
                mbps: Some(100),
            },
            release: Rate {
                pps: Some(200),
                mbps: Some(20),
            },
            window: 10,
            trigger_after: 5,
            release_after: 10,
            baseline: None,
        }
    }

    fn det() -> Detector {
        Detector::new(params(), vec!["198.51.100.0/24".parse().unwrap()])
    }

    const V: &str = "198.51.100.7";

    fn ip() -> IpAddr {
        V.parse().unwrap()
    }

    fn rec(d: &mut Detector, dst: IpAddr, packets: u64, bytes: u64, t: u64) -> bool {
        d.record(&FlowSample::new(dst, packets, bytes), t)
    }

    /// Feeds `pps` packets of 100 bytes per second from `from` to `to` and collects events.
    fn feed(d: &mut Detector, from: u64, to: u64, pps: u64) -> Vec<(u64, Event)> {
        feed_with(d, from, to, pps, |mut s| {
            s.protocol = None;
            s
        })
    }

    fn feed_with(
        d: &mut Detector,
        from: u64,
        to: u64,
        pps: u64,
        f: impl Fn(FlowSample) -> FlowSample,
    ) -> Vec<(u64, Event)> {
        let mut out = Vec::new();
        for t in from..to {
            if pps > 0 {
                let mut s = sample(53, 64511, pps);
                s.bytes = pps * 100;
                d.record(&f(s), t);
            }
            out.extend(d.evaluate(t).into_iter().map(|e| (t, e)));
        }
        out
    }

    #[test]
    fn triggers_only_after_sustained_excess() {
        let mut d = det();
        // 10 s window: at 5000 pps the averaged rate passes 1000 pps at t=2.
        let ev = feed(&mut d, 0, 8, 5000);
        assert_eq!(ev.len(), 1);
        let (t, e) = &ev[0];
        assert_eq!(*t, 7); // above since t=2, trigger_after 5
        assert!(matches!(e, Event::Attack { dst, class: "unknown", .. } if *dst == ip()));
    }

    #[test]
    fn burst_below_window_average_does_not_trigger() {
        let mut d = det();
        let mut ev = feed(&mut d, 0, 3, 3000);
        ev.extend(feed(&mut d, 3, 40, 0));
        assert!(ev.is_empty());
        assert_eq!(d.tracked(), 0, "idle destinations are forgotten");
    }

    #[test]
    fn hysteresis_and_release() {
        let mut d = det();
        feed(&mut d, 0, 8, 5000);
        // 500 pps sits between release (200) and threshold (1000): stays triggered.
        let ev = feed(&mut d, 8, 40, 500);
        assert!(ev.iter().all(|(_, e)| matches!(e, Event::Attack { .. })));
        assert!(!ev.is_empty(), "ongoing attack is re-requested");
        // Silence: release after the window drains plus release_after.
        let ev = feed(&mut d, 40, 80, 0);
        let rel: Vec<_> = ev
            .iter()
            .filter(|(_, e)| matches!(e, Event::Release { .. }))
            .collect();
        assert_eq!(rel.len(), 1);
        assert!(rel[0].0 >= 40 + 10);
        let Event::Release { stats: Some(s), .. } = &rel[0].1 else {
            panic!("release carries stats")
        };
        assert_eq!(s.started_at, 2);
        assert!(s.peak_pps >= 4000, "{}", s.peak_pps);
    }

    #[test]
    fn mbps_threshold_alone_triggers() {
        let mut d = det();
        // 500 pps x 50 000 bytes = 200 Mbps
        let mut ev = Vec::new();
        for t in 0..20 {
            rec(&mut d, ip(), 500, 25_000_000, t);
            ev.extend(d.evaluate(t));
        }
        assert!(matches!(ev.first(), Some(Event::Attack { .. })));
    }

    #[test]
    fn ignores_unprotected_and_caps_table() {
        let mut d = det();
        assert!(rec(&mut d, "203.0.113.7".parse().unwrap(), 1_000_000, 1, 0));
        assert_eq!(d.tracked(), 0);
        // mapped form of a protected address is tracked under its canonical v4 form
        rec(&mut d, "::ffff:198.51.100.7".parse().unwrap(), 1, 1, 0);
        assert!(d.dsts.contains_key(&ip()));

        let mut d = Detector::new(params(), vec!["2001:db8::/32".parse().unwrap()]);
        for i in 0..MAX_TRACKED as u128 {
            let a = std::net::Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0000u128 + i);
            assert!(rec(&mut d, IpAddr::V6(a), 1, 1, 0));
        }
        assert!(!rec(&mut d, "2001:db8:ffff::1".parse().unwrap(), 1, 1, 0));
    }

    fn class_of(f: impl Fn(FlowSample) -> FlowSample) -> (&'static str, Option<Signature>) {
        let mut d = det();
        match feed_with(&mut d, 0, 8, 5000, f).pop() {
            Some((
                _,
                Event::Attack {
                    class, signature, ..
                },
            )) => (class, signature),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn classifies_amplification_by_source_port() {
        for (port, name) in AMP_PORTS {
            let (c, sig) = class_of(|mut s| {
                s.src_port = Some(port);
                s
            });
            assert_eq!(c, name);
            assert_eq!(
                sig,
                Some(Signature {
                    protocol: PROTO_UDP,
                    src_port: Some(port),
                    dst_port: None
                })
            );
        }
    }

    #[test]
    fn classifies_syn_icmp_udp_and_unknown() {
        let (c, sig) = class_of(|mut s| {
            s.protocol = Some(PROTO_TCP);
            s.tcp_flags = Some(0x02);
            s.dst_port = Some(443);
            s
        });
        assert_eq!(c, "syn_flood");
        assert_eq!(sig.unwrap().dst_port, Some(443));
        // SYN+ACK is not a SYN flood
        let (c, _) = class_of(|mut s| {
            s.protocol = Some(PROTO_TCP);
            s.tcp_flags = Some(0x12);
            s
        });
        assert_eq!(c, "unknown");
        let (c, sig) = class_of(|mut s| {
            s.protocol = Some(PROTO_ICMP);
            s
        });
        assert_eq!((c, sig.unwrap().protocol), ("icmp_flood", PROTO_ICMP));
        let (c, sig) = class_of(|mut s| {
            s.src_port = Some(40000);
            s
        });
        assert_eq!(c, "udp_flood");
        assert_eq!(sig.unwrap().dst_port, Some(4444));
        assert_eq!(
            class_of(|mut s| {
                s.protocol = Some(47);
                s
            })
            .0,
            "unknown"
        );
        // ICMPv6 for an IPv6 victim
        let p = Profile {
            total: 10,
            icmp: 10,
            ..Default::default()
        };
        assert_eq!(
            p.classify("2001:db8:100::7".parse().unwrap())
                .1
                .unwrap()
                .protocol,
            PROTO_ICMPV6
        );
    }

    #[test]
    fn baseline_lowers_threshold_for_quiet_hosts_only() {
        let bl = BaselineConfig {
            alpha: 0.05,
            multiplier: 4.0,
            min_pps: 100,
            min_mbps: 0,
            warmup: Secs(30),
        };
        let mut p = params();
        p.baseline = Some(bl);
        let mut d = Detector::new(p.clone(), vec!["198.51.100.0/24".parse().unwrap()]);
        // Quiet host at ~50 pps learns its baseline, then 600 pps (< static 1000) triggers.
        let ev = feed(&mut d, 0, 60, 50);
        assert!(ev.is_empty());
        let ev = feed(&mut d, 60, 90, 600);
        assert!(
            ev.iter().any(|(_, e)| matches!(e, Event::Attack { .. })),
            "dynamic threshold"
        );
        // Without the baseline 600 pps never triggers.
        let mut d = det();
        assert!(feed(&mut d, 0, 90, 600).is_empty());
        // The baseline never raises the static threshold: a busy host still triggers at the static level.
        let mut d = Detector::new(p, vec!["198.51.100.0/24".parse().unwrap()]);
        assert!(feed(&mut d, 0, 60, 900).is_empty());
        let ev = feed(&mut d, 60, 90, 5000);
        assert!(ev.iter().any(|(_, e)| matches!(e, Event::Attack { .. })));
        assert!(d.tracked() > 0);
    }

    fn engine_with_flowspec() -> (
        Mutex<Engine>,
        crate::engine::Routes,
        crate::audit::tests::Sink,
    ) {
        let (e, rx, sink) = crate::engine::tests::engine();
        (Mutex::new(e), rx, sink)
    }

    fn fs(escalate_after: u64) -> Option<FlowSettings> {
        Some(FlowSettings {
            action: FlowAction::RateLimit { kbps: 1000 },
            escalate: true,
            escalate_after,
        })
    }

    fn attack(dst: &str, sig: Option<Signature>) -> Event {
        Event::Attack {
            dst: dst.parse().unwrap(),
            pps: 5000,
            mbps: 4.0,
            class: if sig.is_some() {
                "udp_amplification_dns"
            } else {
                "unknown"
            },
            signature: sig,
        }
    }

    const DNS: Signature = Signature {
        protocol: PROTO_UDP,
        src_port: Some(53),
        dst_port: None,
    };

    #[test]
    fn attack_reaches_engine_as_rtbh_without_flowspec() {
        let (e, rx, _) = engine_with_flowspec();
        let mut m = Mitigator::new(None, Alerts::disabled(), Arc::new(Metrics::default()), None);
        let mut d = det();
        let ev: Vec<Event> = feed(&mut d, 0, 8, 5000).into_iter().map(|x| x.1).collect();
        m.handle(&e, ev, 7);
        assert!(rx.borrow().contains(&ip()));
        let ev: Vec<Event> = feed(&mut d, 8, 60, 0).into_iter().map(|x| x.1).collect();
        m.handle(&e, ev, 60);
        assert!(rx.borrow().is_empty());
    }

    #[test]
    fn flowspec_first_then_escalation_to_rtbh() {
        let (e, rx, _) = engine_with_flowspec();
        let metrics = Arc::new(Metrics::default());
        let d = crate::state::tests::tmpdir("mitigation-reports");
        let store = Arc::new(ReportStore::new(Some(d.clone()), 10));
        let mut m = Mitigator::new(
            fs(60),
            Alerts::disabled(),
            metrics.clone(),
            Some(store.clone()),
        );
        m.handle(&e, vec![attack(V, Some(DNS))], 100);
        assert_eq!(rx.borrow().flowspec.len(), 1);
        assert!(!rx.borrow().contains(&ip()), "no RTBH yet");
        m.handle(&e, vec![attack(V, Some(DNS))], 130);
        assert!(!rx.borrow().contains(&ip()));
        m.handle(&e, vec![attack(V, Some(DNS))], 160);
        assert!(rx.borrow().contains(&ip()), "escalated after 60 s");
        assert_eq!(
            metrics
                .escalations
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        // Release removes both, writes the report with the timeline.
        let mut stats = AttackStats::new(90, "udp_amplification_dns");
        stats.add(&sample(53, 64511, 1000));
        m.handle(
            &e,
            vec![Event::Release {
                dst: ip(),
                stats: Some(Box::new(stats)),
            }],
            400,
        );
        assert!(rx.borrow().is_empty() && rx.borrow().flowspec.is_empty());
        let r = &store.recent()[0];
        assert_eq!(r.duration_secs, 310);
        assert!(r
            .mitigation
            .iter()
            .any(|s| s.contains("FlowSpec dst 198.51.100.7 proto 17 src-port 53")));
        assert!(r.mitigation.iter().any(|s| s.contains("escalated")));
        assert_eq!(
            metrics
                .reports_written
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn unclassified_attack_goes_straight_to_rtbh() {
        let (e, rx, _) = engine_with_flowspec();
        let mut m = Mitigator::new(
            fs(60),
            Alerts::disabled(),
            Arc::new(Metrics::default()),
            None,
        );
        m.handle(&e, vec![attack(V, None)], 100);
        assert!(rx.borrow().contains(&ip()));
        assert!(rx.borrow().flowspec.is_empty());
    }

    #[test]
    fn flowspec_denied_falls_back_to_policy_checked_rtbh() {
        let (e, rx, _) = engine_with_flowspec();
        let mut m = Mitigator::new(
            Some(FlowSettings {
                action: FlowAction::Discard, // policy() does not allow discard
                escalate: true,
                escalate_after: 60,
            }),
            Alerts::disabled(),
            Arc::new(Metrics::default()),
            None,
        );
        m.handle(&e, vec![attack(V, Some(DNS))], 100);
        assert!(rx.borrow().flowspec.is_empty());
        assert!(rx.borrow().contains(&ip()));
        // The fallback can never reach a never-listed address.
        m.handle(&e, vec![attack("198.51.100.1", Some(DNS))], 100);
        assert!(!rx.borrow().contains(&"198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn escalation_disabled_keeps_flowspec_only() {
        let (e, rx, _) = engine_with_flowspec();
        let mut m = Mitigator::new(
            Some(FlowSettings {
                action: FlowAction::RateLimit { kbps: 1000 },
                escalate: false,
                escalate_after: 0,
            }),
            Alerts::disabled(),
            Arc::new(Metrics::default()),
            None,
        );
        for t in [100, 200, 300] {
            m.handle(&e, vec![attack(V, Some(DNS))], t);
        }
        assert!(!rx.borrow().contains(&ip()));
        assert_eq!(rx.borrow().flowspec.len(), 1);
    }

    #[test]
    fn approval_gates_detector_mitigation() {
        let (e, rx, _) = engine_with_flowspec();
        e.lock().unwrap().set_approval(ApprovalMode::Detector, 60);
        let mut m = Mitigator::new(
            fs(30),
            Alerts::disabled(),
            Arc::new(Metrics::default()),
            None,
        );
        m.handle(&e, vec![attack(V, Some(DNS))], 100);
        m.handle(&e, vec![attack(V, Some(DNS))], 200);
        assert!(rx.borrow().flowspec.is_empty() && rx.borrow().is_empty());
        let pending = e.lock().unwrap().list_pending();
        assert_eq!(pending.len(), 1, "repeats do not create new approvals");
        // Release cancels the pending request.
        m.handle(
            &e,
            vec![Event::Release {
                dst: ip(),
                stats: None,
            }],
            210,
        );
        assert!(e.lock().unwrap().list_pending().is_empty());
    }
}
