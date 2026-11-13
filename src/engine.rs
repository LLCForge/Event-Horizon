//! Active blackhole and FlowSpec sets plus requests waiting for approval.
//!
//! Every change goes through the policy engine, is audited, persisted,
//! reported as an alert and published to the BGP speakers via a watch
//! channel. Manual approval (41) is a gate in front of the same functions:
//! the policy runs when the request arrives and again when it is approved.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use llcforge_beacon::Severity;
use serde::Serialize;
use serde_json::json;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use crate::alerts::{alert, Alerts};
use crate::audit::Audit;
use crate::bgp::flowspec::FlowRule;
use crate::config::{fmt_duration, ApprovalMode};
use crate::metrics::Metrics;
use crate::policy::{Deny, Policy};
use crate::propagation::Propagation;
use crate::state::{self, Entry, FlowEntry, Source};

pub const MAX_REASON_LEN: usize = 200;

/// Where a blackhole is announced (34): a region and / or an upstream subset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    pub region: Option<String>,
    pub upstreams: Vec<String>,
}

/// What the BGP sessions mirror.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Published {
    pub blackholes: BTreeMap<IpAddr, Scope>,
    pub flowspec: BTreeMap<String, FlowRule>,
}

#[cfg(test)]
impl Published {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.blackholes.contains_key(ip)
    }

    pub fn is_empty(&self) -> bool {
        self.blackholes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.blackholes.len()
    }
}

pub type Routes = watch::Receiver<Published>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Target {
    Blackhole {
        ip: IpAddr,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        upstreams: Vec<String>,
    },
    Flowspec {
        rule: FlowRule,
    },
}

impl Target {
    pub fn blackhole(ip: IpAddr) -> Self {
        Target::Blackhole {
            ip,
            scope: None,
            upstreams: Vec::new(),
        }
    }

    pub fn key(&self) -> String {
        match self {
            Target::Blackhole { ip, .. } => ip.to_string(),
            Target::Flowspec { rule } => rule.key(),
        }
    }

    pub fn dst(&self) -> IpAddr {
        match self {
            Target::Blackhole { ip, .. } => *ip,
            Target::Flowspec { rule } => rule.dst,
        }
    }

    fn describe(&self) -> String {
        match self {
            Target::Blackhole { ip, scope, .. } => match scope {
                Some(s) => format!("blackhole {ip} (scope {s})"),
                None => format!("blackhole {ip}"),
            },
            Target::Flowspec { rule } => format!("FlowSpec {rule}"),
        }
    }
}

/// A request waiting for an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pending {
    pub id: String,
    #[serde(flatten)]
    pub target: Target,
    pub ttl: Option<u64>,
    pub reason: String,
    pub source: Source,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submitted {
    Blackhole(Entry),
    Flowspec(FlowEntry),
    Pending(Pending),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveError {
    NotFound,
    Denied(Deny),
}

pub struct Engine {
    policy: Policy,
    active: BTreeMap<IpAddr, Entry>,
    flows: BTreeMap<String, FlowEntry>,
    pending: BTreeMap<String, Pending>,
    approval_mode: ApprovalMode,
    approval_timeout: u64,
    notify: Option<mpsc::Sender<Pending>>,
    propagation: HashMap<IpAddr, Propagation>,
    state_path: Option<PathBuf>,
    audit: Arc<Audit>,
    routes: watch::Sender<Published>,
    metrics: Arc<Metrics>,
    alerts: Alerts,
}

/// Strips control characters and caps the length so reasons are safe to log.
pub fn sanitize_reason(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_REASON_LEN)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// 128-bit random identifier (approval ids are not guessable).
fn new_id() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    if ring::rand::SystemRandom::new().fill(&mut b).is_err() {
        // shortcut: no OS RNG is effectively impossible; fall back to time+counter uniqueness.
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        b[..8].copy_from_slice(&crate::unix_now().to_be_bytes());
        b[8..].copy_from_slice(&n.to_be_bytes());
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Engine {
    pub fn new(
        policy: Policy,
        state_path: Option<PathBuf>,
        audit: Arc<Audit>,
        metrics: Arc<Metrics>,
    ) -> (Self, Routes) {
        let (tx, rx) = watch::channel(Published::default());
        let e = Self {
            policy,
            active: BTreeMap::new(),
            flows: BTreeMap::new(),
            pending: BTreeMap::new(),
            approval_mode: ApprovalMode::Off,
            approval_timeout: 300,
            notify: None,
            propagation: HashMap::new(),
            state_path,
            audit,
            routes: tx,
            metrics,
            alerts: Alerts::disabled(),
        };
        (e, rx)
    }

    pub fn set_alerts(&mut self, alerts: Alerts) {
        self.alerts = alerts;
    }

    pub fn set_approval(&mut self, mode: ApprovalMode, timeout: u64) {
        self.approval_mode = mode;
        self.approval_timeout = timeout;
    }

    pub fn set_notifier(&mut self, tx: mpsc::Sender<Pending>) {
        self.notify = Some(tx);
    }

    /// Re-admits persisted entries. Expired entries, entries recorded under a
    /// different dry-run mode and entries the current policy rejects are dropped.
    #[cfg(test)]
    pub fn restore(&mut self, entries: Vec<Entry>, now: u64) {
        self.restore_all(entries, Vec::new(), now);
    }

    pub fn restore_all(&mut self, entries: Vec<Entry>, flows: Vec<FlowEntry>, now: u64) {
        for mut e in entries {
            let drop_reason = if e.expires_at <= now {
                Some("expired".to_owned())
            } else if e.dry_run != self.policy.dry_run() {
                Some("recorded under a different dry_run mode".to_owned())
            } else if self.active.contains_key(&e.ip) {
                Some("duplicate entry".to_owned())
            } else if self.active.len() >= self.policy.max_active() {
                Some("max_active reached".to_owned())
            } else {
                self.policy
                    .check_address(e.ip)
                    .and_then(|_| self.policy.check_scope(e.scope.as_deref(), &e.upstreams))
                    .err()
                    .map(|d| d.to_string())
            };
            if let Some(why) = drop_reason {
                warn!(ip = %e.ip, %why, "dropping persisted blackhole");
                self.audit.record(
                    now,
                    "restore_drop",
                    json!({"ip": e.ip, "source": e.source, "why": why}),
                );
                continue;
            }
            e.expires_at = e.expires_at.min(now.saturating_add(self.policy.ttl_max()));
            e.reason = sanitize_reason(&e.reason);
            self.audit.record(
                now,
                "restore",
                json!({"ip": e.ip, "source": e.source, "expires_at": e.expires_at, "dry_run": e.dry_run}),
            );
            self.active.insert(e.ip, e);
        }
        for mut f in flows {
            let key = f.rule.key();
            let remaining = f.expires_at.saturating_sub(now);
            let drop_reason = if f.expires_at <= now {
                Some("expired".to_owned())
            } else if f.dry_run != self.policy.dry_run() {
                Some("recorded under a different dry_run mode".to_owned())
            } else {
                // TTL is checked against the remaining lifetime, clamped to the maximum.
                let ttl = remaining.min(self.policy.ttl_max()).max(1);
                match self.policy.evaluate_flowspec(
                    &f.rule,
                    None,
                    self.flows.len(),
                    self.flows.contains_key(&key),
                ) {
                    Ok(_) => {
                        f.expires_at = now.saturating_add(ttl);
                        None
                    }
                    Err(d) => Some(d.to_string()),
                }
            };
            if let Some(why) = drop_reason {
                warn!(rule = %f.rule, %why, "dropping persisted FlowSpec rule");
                self.audit.record(
                    now,
                    "restore_drop",
                    json!({"flowspec": key, "source": f.source, "why": why}),
                );
                continue;
            }
            f.id = key.clone();
            f.reason = sanitize_reason(&f.reason);
            self.audit.record(
                now,
                "restore",
                json!({"flowspec": key, "source": f.source, "expires_at": f.expires_at}),
            );
            self.flows.insert(key, f);
        }
        self.commit();
    }

    fn needs_approval(&self, source: Source) -> bool {
        match self.approval_mode {
            ApprovalMode::Off => false,
            ApprovalMode::Detector => source.is_detector(),
            ApprovalMode::All => true,
        }
    }

    fn denied(&self, what: &str, source: Source, d: &Deny, reason: &str, now: u64) {
        // A detector re-requesting an ongoing attack is not a new decision.
        if source.is_detector() && d.is_duplicate() {
            return;
        }
        Metrics::inc(&self.metrics.decisions_denied);
        warn!(target_ = %what, ?source, deny = d.code(), %reason, "request denied: {d}");
        self.audit.record(
            now,
            "deny",
            json!({"ip": what, "source": source, "deny": d.code(), "detail": d.to_string(), "reason": reason}),
        );
        if source.is_detector() {
            self.alerts.send(
                alert(
                    "policy_deny",
                    Severity::Warning,
                    format!("Mitigation for {what} denied by policy"),
                )
                .resource(what)
                .summary(d.to_string())
                .field("code", d.code())
                .field("reason", reason),
            );
        }
    }

    #[cfg(test)]
    pub fn request(
        &mut self,
        ip: IpAddr,
        ttl: Option<u64>,
        reason: &str,
        source: Source,
        now: u64,
    ) -> Result<Entry, Deny> {
        self.request_blackhole(ip, ttl, None, Vec::new(), reason, source, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_blackhole(
        &mut self,
        ip: IpAddr,
        ttl: Option<u64>,
        scope: Option<String>,
        upstreams: Vec<String>,
        reason: &str,
        source: Source,
        now: u64,
    ) -> Result<Entry, Deny> {
        let reason = sanitize_reason(reason);
        let scope = scope.filter(|s| s != "global");
        let already = self.active.contains_key(&ip);
        match self.policy.evaluate_scoped(
            ip,
            ttl,
            scope.as_deref(),
            &upstreams,
            self.active.len(),
            already,
        ) {
            Ok(a) => {
                let e = Entry {
                    ip,
                    reason,
                    source,
                    created_at: now,
                    expires_at: now.saturating_add(a.ttl),
                    dry_run: a.dry_run,
                    scope,
                    upstreams,
                };
                Metrics::inc(&self.metrics.decisions_allowed);
                info!(%ip, ttl = a.ttl, ?source, dry_run = a.dry_run, reason = %e.reason, "blackhole allowed");
                self.audit.record(
                    now,
                    "allow",
                    json!({"ip": ip, "source": source, "ttl": a.ttl, "reason": e.reason,
                           "dry_run": a.dry_run, "scope": e.scope, "upstreams": e.upstreams}),
                );
                let mut al = alert(
                    "blackhole",
                    if a.dry_run {
                        Severity::Info
                    } else {
                        Severity::Critical
                    },
                    if a.dry_run {
                        format!("Blackhole for {ip} (dry-run, not announced)")
                    } else {
                        format!("Blackhole announced for {ip}")
                    },
                )
                .resource(ip.to_string())
                .summary(e.reason.clone())
                .field("source", source.as_str())
                .field("ttl", fmt_duration(a.ttl))
                .field("dry_run", a.dry_run)
                .link("RIPEstat", format!("https://stat.ripe.net/{ip}"));
                if let Some(s) = &e.scope {
                    al = al.field("scope", s);
                }
                if !e.upstreams.is_empty() {
                    al = al.field("upstreams", e.upstreams.join(","));
                }
                self.alerts.send(al);
                self.active.insert(ip, e.clone());
                self.commit();
                Ok(e)
            }
            Err(d) => {
                self.denied(&ip.to_string(), source, &d, &reason, now);
                Err(d)
            }
        }
    }

    pub fn request_flowspec(
        &mut self,
        rule: FlowRule,
        ttl: Option<u64>,
        reason: &str,
        source: Source,
        now: u64,
    ) -> Result<FlowEntry, Deny> {
        let reason = sanitize_reason(reason);
        let key = rule.key();
        let already = self.flows.contains_key(&key);
        match self
            .policy
            .evaluate_flowspec(&rule, ttl, self.flows.len(), already)
        {
            Ok(a) => {
                let f = FlowEntry {
                    id: key.clone(),
                    rule,
                    reason,
                    source,
                    created_at: now,
                    expires_at: now.saturating_add(a.ttl),
                    dry_run: a.dry_run,
                };
                Metrics::inc(&self.metrics.flowspec_allowed);
                info!(rule = %f.rule, ttl = a.ttl, ?source, dry_run = a.dry_run, "FlowSpec rule allowed");
                self.audit.record(
                    now,
                    "flowspec_allow",
                    json!({"flowspec": key, "rule": f.rule, "source": source, "ttl": a.ttl,
                           "reason": f.reason, "dry_run": a.dry_run}),
                );
                self.alerts.send(
                    alert(
                        "flowspec",
                        Severity::Warning,
                        format!("FlowSpec rule for {}: {}", f.rule.dst, f.rule.action),
                    )
                    .resource(key.clone())
                    .summary(f.reason.clone())
                    .field("rule", &f.rule)
                    .field("source", source.as_str())
                    .field("ttl", fmt_duration(a.ttl))
                    .field("dry_run", a.dry_run),
                );
                self.flows.insert(key, f.clone());
                self.commit();
                Ok(f)
            }
            Err(d) => {
                self.denied(&key, source, &d, &reason, now);
                Err(d)
            }
        }
    }

    fn apply(
        &mut self,
        target: Target,
        ttl: Option<u64>,
        reason: &str,
        source: Source,
        now: u64,
    ) -> Result<Submitted, Deny> {
        match target {
            Target::Blackhole {
                ip,
                scope,
                upstreams,
            } => self
                .request_blackhole(ip, ttl, scope, upstreams, reason, source, now)
                .map(Submitted::Blackhole),
            Target::Flowspec { rule } => self
                .request_flowspec(rule, ttl, reason, source, now)
                .map(Submitted::Flowspec),
        }
    }

    /// Policy decision without side effects.
    fn precheck(&self, target: &Target, ttl: Option<u64>) -> Result<(), Deny> {
        match target {
            Target::Blackhole {
                ip,
                scope,
                upstreams,
            } => self
                .policy
                .evaluate_scoped(
                    *ip,
                    ttl,
                    scope.as_deref().filter(|s| *s != "global"),
                    upstreams,
                    self.active.len(),
                    self.active.contains_key(ip),
                )
                .map(|_| ()),
            Target::Flowspec { rule } => self
                .policy
                .evaluate_flowspec(
                    rule,
                    ttl,
                    self.flows.len(),
                    self.flows.contains_key(&rule.key()),
                )
                .map(|_| ()),
        }
    }

    /// Entry point for API and detector requests: applies directly, or parks
    /// the request for approval when the approval mode covers `source`.
    pub fn submit(
        &mut self,
        target: Target,
        ttl: Option<u64>,
        reason: &str,
        source: Source,
        now: u64,
    ) -> Result<Submitted, Deny> {
        if !self.needs_approval(source) {
            return self.apply(target, ttl, reason, source, now);
        }
        let key = target.key();
        if let Some(p) = self.pending.values().find(|p| p.target.key() == key) {
            return Ok(Submitted::Pending(p.clone()));
        }
        let reason = sanitize_reason(reason);
        if let Err(d) = self
            .precheck(&target, ttl)
            .and_then(|_| self.policy.check_pending(self.pending.len()))
        {
            self.denied(&key, source, &d, &reason, now);
            return Err(d);
        }
        let p = Pending {
            id: new_id(),
            target,
            ttl,
            reason,
            source,
            created_at: now,
            expires_at: now.saturating_add(self.approval_timeout),
        };
        Metrics::inc(&self.metrics.approvals_requested);
        info!(id = %p.id, target = %p.target.describe(), ?source, "waiting for approval");
        self.audit.record(
            now,
            "approval_pending",
            json!({"id": p.id, "target": p.target, "source": source, "reason": p.reason,
                   "expires_at": p.expires_at}),
        );
        self.alerts.send(
            alert(
                "approval_pending",
                Severity::Warning,
                format!("Approval needed: {}", p.target.describe()),
            )
            .resource(p.id.clone())
            .summary(p.reason.clone())
            .field("expires_in", fmt_duration(self.approval_timeout)),
        );
        if let Some(tx) = &self.notify {
            if tx.try_send(p.clone()).is_err() {
                warn!(id = %p.id, "approval notifier queue full; approve through the API");
            }
        }
        self.pending.insert(p.id.clone(), p.clone());
        self.metrics.pending.store(
            self.pending.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(Submitted::Pending(p))
    }

    fn close_pending(&mut self, p: &Pending, event: &str, actor: &str, now: u64) {
        self.audit.record(
            now,
            event,
            json!({"id": p.id, "target": p.target, "actor": actor}),
        );
        self.alerts.send(
            alert(
                "approval_pending",
                Severity::Info,
                format!("{}: {}", event.replace('_', " "), p.target.describe()),
            )
            .resource(p.id.clone())
            .field("actor", actor)
            .resolved(true),
        );
        self.metrics.pending.store(
            self.pending.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Approves a pending request; the policy is evaluated again right now.
    pub fn approve(&mut self, id: &str, actor: &str, now: u64) -> Result<Submitted, ApproveError> {
        let p = self.pending.remove(id).ok_or(ApproveError::NotFound)?;
        Metrics::inc(&self.metrics.approvals_approved);
        info!(%id, %actor, "request approved");
        self.close_pending(&p, "approval_approved", actor, now);
        self.apply(p.target, p.ttl, &p.reason, p.source, now)
            .map_err(ApproveError::Denied)
    }

    pub fn reject(&mut self, id: &str, actor: &str, now: u64) -> Option<Pending> {
        let p = self.pending.remove(id)?;
        Metrics::inc(&self.metrics.approvals_denied);
        info!(%id, %actor, "request rejected");
        self.close_pending(&p, "approval_denied", actor, now);
        Some(p)
    }

    pub fn list_pending(&self) -> Vec<Pending> {
        self.pending.values().cloned().collect()
    }

    pub fn withdraw(
        &mut self,
        ip: IpAddr,
        reason: &str,
        source: Source,
        now: u64,
    ) -> Option<Entry> {
        let e = self.active.remove(&ip)?;
        let reason = sanitize_reason(reason);
        Metrics::inc(&self.metrics.withdrawn);
        info!(%ip, ?source, %reason, "blackhole withdrawn");
        self.audit.record(
            now,
            "withdraw",
            json!({"ip": ip, "source": source, "reason": reason}),
        );
        self.resolved_blackhole(ip, &reason);
        self.commit();
        Some(e)
    }

    fn resolved_blackhole(&mut self, ip: IpAddr, cause: &str) {
        self.propagation.remove(&ip);
        self.alerts.send(
            alert(
                "blackhole",
                Severity::Info,
                format!("Blackhole withdrawn for {ip}"),
            )
            .resource(ip.to_string())
            .field("cause", cause)
            .resolved(true),
        );
        self.alerts.send(
            alert(
                "propagation",
                Severity::Info,
                format!("Blackhole for {ip} withdrawn"),
            )
            .resource(ip.to_string())
            .resolved(true),
        );
    }

    fn resolved_flow(&self, f: &FlowEntry, cause: &str) {
        self.alerts.send(
            alert(
                "flowspec",
                Severity::Info,
                format!("FlowSpec rule for {} withdrawn", f.rule.dst),
            )
            .resource(f.id.clone())
            .field("cause", cause)
            .resolved(true),
        );
    }

    pub fn withdraw_flowspec(
        &mut self,
        id: &str,
        reason: &str,
        source: Source,
        now: u64,
    ) -> Option<FlowEntry> {
        let f = self.flows.remove(id)?;
        let reason = sanitize_reason(reason);
        Metrics::inc(&self.metrics.flowspec_withdrawn);
        info!(rule = %f.rule, ?source, %reason, "FlowSpec rule withdrawn");
        self.audit.record(
            now,
            "flowspec_withdraw",
            json!({"flowspec": id, "source": source, "reason": reason}),
        );
        self.resolved_flow(&f, &reason);
        self.commit();
        Some(f)
    }

    /// Detector release: only removes blackholes the detector itself created.
    pub fn release(&mut self, ip: IpAddr, now: u64) -> Option<Entry> {
        if !self.active.get(&ip)?.source.is_detector() {
            return None;
        }
        self.withdraw(ip, "traffic below release threshold", Source::Detector, now)
    }

    /// Detector release of its own FlowSpec rules and pending requests for `dst`.
    pub fn release_flowspec(&mut self, dst: IpAddr, now: u64) -> usize {
        let ids: Vec<String> = self
            .flows
            .values()
            .filter(|f| f.rule.dst == dst && f.source.is_detector())
            .map(|f| f.id.clone())
            .collect();
        for id in &ids {
            self.withdraw_flowspec(id, "traffic below release threshold", Source::Detector, now);
        }
        let pend: Vec<String> = self
            .pending
            .values()
            .filter(|p| p.target.dst() == dst && p.source.is_detector())
            .map(|p| p.id.clone())
            .collect();
        for id in pend {
            if let Some(p) = self.pending.remove(&id) {
                self.close_pending(&p, "approval_cancelled", "detector", now);
            }
        }
        ids.len()
    }

    pub fn expire(&mut self, now: u64) -> usize {
        let expired: Vec<IpAddr> = self
            .active
            .values()
            .filter(|e| e.expires_at <= now)
            .map(|e| e.ip)
            .collect();
        for ip in &expired {
            self.active.remove(ip);
            Metrics::inc(&self.metrics.expired);
            info!(%ip, "blackhole TTL expired");
            self.audit.record(now, "expire", json!({"ip": ip}));
            self.resolved_blackhole(*ip, "ttl expired");
        }
        let flows: Vec<String> = self
            .flows
            .values()
            .filter(|f| f.expires_at <= now)
            .map(|f| f.id.clone())
            .collect();
        for id in &flows {
            if let Some(f) = self.flows.remove(id) {
                Metrics::inc(&self.metrics.flowspec_expired);
                info!(rule = %f.rule, "FlowSpec TTL expired");
                self.audit
                    .record(now, "flowspec_expire", json!({"flowspec": id}));
                self.resolved_flow(&f, "ttl expired");
            }
        }
        let timed_out: Vec<String> = self
            .pending
            .values()
            .filter(|p| p.expires_at <= now)
            .map(|p| p.id.clone())
            .collect();
        for id in timed_out {
            if let Some(p) = self.pending.remove(&id) {
                // Timeout = deny.
                Metrics::inc(&self.metrics.approvals_timeout);
                warn!(%id, target = %p.target.describe(), "approval timed out; request denied");
                self.close_pending(&p, "approval_timeout", "timeout", now);
            }
        }
        if !expired.is_empty() || !flows.is_empty() {
            self.commit();
        }
        expired.len() + flows.len()
    }

    /// Replaces the policy (configuration reload) and withdraws everything the
    /// new policy no longer allows.
    pub fn set_policy(&mut self, policy: Policy, now: u64) {
        self.policy = policy;
        let bad: Vec<(IpAddr, String)> = self
            .active
            .values()
            .filter_map(|e| {
                self.policy
                    .check_address(e.ip)
                    .and_then(|_| self.policy.check_scope(e.scope.as_deref(), &e.upstreams))
                    .err()
                    .map(|d| (e.ip, d.to_string()))
            })
            .collect();
        for (ip, why) in bad {
            self.withdraw(
                ip,
                &format!("no longer allowed after reload: {why}"),
                Source::Api,
                now,
            );
        }
        let fs = self.policy.flowspec();
        let bad: Vec<String> = self
            .flows
            .values()
            .filter(|f| fs.is_none() || self.policy.check_address(f.rule.dst).is_err())
            .map(|f| f.id.clone())
            .collect();
        for id in bad {
            self.withdraw_flowspec(&id, "no longer allowed after reload", Source::Api, now);
        }
    }

    pub fn list(&self) -> Vec<Entry> {
        self.active.values().cloned().collect()
    }

    pub fn list_flowspec(&self) -> Vec<FlowEntry> {
        self.flows.values().cloned().collect()
    }

    pub fn propagation(&self, ip: IpAddr) -> Option<&Propagation> {
        self.propagation.get(&ip)
    }

    /// Stores a check result for an active blackhole and alerts on changes.
    pub fn set_propagation(&mut self, ip: IpAddr, p: Propagation) {
        if !self.active.contains_key(&ip) {
            return;
        }
        use crate::propagation::PropStatus;
        let before = self.propagation.get(&ip).map(|x| x.status);
        if before != Some(p.status) {
            match p.status {
                PropStatus::NotSeen => self.alerts.send(
                    alert(
                        "propagation",
                        Severity::Warning,
                        format!("Blackhole for {ip} not visible outside"),
                    )
                    .resource(ip.to_string())
                    .summary("No looking-glass peer carries the host route; check the upstream session and filters.")
                    .field("visible_peers", p.visible_peers),
                ),
                PropStatus::Propagated if before == Some(PropStatus::NotSeen) => self.alerts.send(
                    alert(
                        "propagation",
                        Severity::Info,
                        format!("Blackhole for {ip} is now visible"),
                    )
                    .resource(ip.to_string())
                    .field("visible_peers", p.visible_peers)
                    .resolved(true),
                ),
                _ => {}
            }
        }
        self.propagation.insert(ip, p);
    }

    fn commit(&mut self) {
        let entries = self.list();
        let flows = self.list_flowspec();
        if let Some(p) = &self.state_path {
            if let Err(e) = state::save(p, &entries, &flows) {
                error!(error = %e, path = %p.display(), "failed to persist active set");
            }
        }
        use std::sync::atomic::Ordering::Relaxed;
        self.metrics.active.store(entries.len() as u64, Relaxed);
        self.metrics
            .flowspec_active
            .store(flows.len() as u64, Relaxed);
        self.routes.send_replace(Published {
            blackholes: self
                .active
                .values()
                .map(|e| {
                    (
                        e.ip,
                        Scope {
                            region: e.scope.clone(),
                            upstreams: e.upstreams.clone(),
                        },
                    )
                })
                .collect(),
            flowspec: self
                .flows
                .iter()
                .map(|(k, f)| (k.clone(), f.rule.clone()))
                .collect(),
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::audit::tests::Sink;
    use crate::bgp::flowspec::{FlowAction, PROTO_UDP};
    use crate::policy::tests::policy;

    pub fn engine() -> (Engine, Routes, Sink) {
        let sink = Sink::default();
        let audit = Arc::new(Audit::to_writer(Box::new(sink.clone())));
        let (e, rx) = Engine::new(policy(), None, audit, Arc::new(Metrics::default()));
        (e, rx, sink)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    pub fn rule(dst: &str) -> FlowRule {
        FlowRule {
            dst: dst.parse().unwrap(),
            protocol: PROTO_UDP,
            src_port: Some(53),
            dst_port: None,
            action: FlowAction::RateLimit { kbps: 1000 },
        }
    }

    fn mk(s: &str, exp: u64, dry: bool) -> Entry {
        Entry {
            ip: ip(s),
            reason: "r".into(),
            source: Source::Api,
            created_at: 0,
            expires_at: exp,
            dry_run: dry,
            scope: None,
            upstreams: Vec::new(),
        }
    }

    #[test]
    fn request_publishes_and_audits() {
        let (mut e, rx, sink) = engine();
        let got = e
            .request(ip("198.51.100.7"), None, "attack\r\nfake", Source::Api, 100)
            .unwrap();
        assert_eq!(got.expires_at, 1900);
        assert_eq!(got.reason, "attack  fake");
        assert!(rx.borrow().contains(&ip("198.51.100.7")));
        assert_eq!(sink.lines()[0]["event"], "allow");
    }

    #[test]
    fn denial_is_audited_and_not_published() {
        let (mut e, rx, sink) = engine();
        let d = e
            .request(ip("203.0.113.7"), None, "x", Source::Api, 1)
            .unwrap_err();
        assert_eq!(d.code(), "not_protected");
        assert!(rx.borrow().is_empty());
        assert_eq!(sink.lines()[0]["deny"], "not_protected");
    }

    #[test]
    fn max_active_is_enforced_through_engine() {
        let (mut e, _rx, _) = engine();
        for i in 2..5 {
            e.request(ip(&format!("198.51.100.{i}")), None, "x", Source::Api, 1)
                .unwrap();
        }
        assert_eq!(
            e.request(ip("198.51.100.9"), None, "x", Source::Api, 1),
            Err(Deny::MaxActive(3))
        );
    }

    #[test]
    fn detector_duplicates_are_silent() {
        let (mut e, _rx, sink) = engine();
        e.request(ip("198.51.100.7"), None, "x", Source::Sflow, 1)
            .unwrap();
        assert!(e
            .request(ip("198.51.100.7"), None, "x", Source::Sflow, 2)
            .is_err());
        assert!(e
            .request(ip("198.51.100.7"), None, "x", Source::Detector, 2)
            .is_err());
        assert_eq!(sink.lines().len(), 1);
        assert!(e
            .request(ip("198.51.100.7"), None, "x", Source::Api, 2)
            .is_err());
        assert_eq!(sink.lines().len(), 2);
    }

    #[test]
    fn expiry_withdraws() {
        let (mut e, rx, sink) = engine();
        e.request(ip("198.51.100.7"), Some(300), "x", Source::Api, 0)
            .unwrap();
        assert_eq!(e.expire(299), 0);
        assert_eq!(e.expire(300), 1);
        assert!(rx.borrow().is_empty());
        assert_eq!(sink.lines().last().unwrap()["event"], "expire");
    }

    #[test]
    fn release_only_touches_detector_entries() {
        let (mut e, _rx, _) = engine();
        e.request(ip("198.51.100.7"), None, "x", Source::Api, 0)
            .unwrap();
        e.request(ip("198.51.100.8"), None, "x", Source::Sflow, 0)
            .unwrap();
        e.request(ip("198.51.100.9"), None, "x", Source::Detector, 0)
            .unwrap();
        assert!(e.release(ip("198.51.100.7"), 1).is_none());
        assert!(e.release(ip("198.51.100.8"), 1).is_some());
        assert!(e.release(ip("198.51.100.9"), 1).is_some());
        assert!(e.release(ip("198.51.100.10"), 1).is_none());
        assert_eq!(e.list().len(), 1);
    }

    #[test]
    fn manual_withdraw() {
        let (mut e, rx, _) = engine();
        e.request(ip("2001:db8:100::7"), None, "x", Source::Api, 0)
            .unwrap();
        assert!(e
            .withdraw(ip("2001:db8:100::7"), "done", Source::Api, 5)
            .is_some());
        assert!(e
            .withdraw(ip("2001:db8:100::7"), "done", Source::Api, 5)
            .is_none());
        assert!(rx.borrow().is_empty());
    }

    #[test]
    fn restore_revalidates_everything() {
        let (mut e, rx, sink) = engine();
        let mut scoped = mk("198.51.100.10", 500, false);
        scoped.scope = Some("nowhere".into());
        e.restore(
            vec![
                mk("198.51.100.7", 1_000_000, false), // kept, expiry clamped
                mk("198.51.100.8", 50, false),        // expired
                mk("198.51.100.9", 500, true),        // dry-run entry in live mode
                mk("203.0.113.7", 500, false),        // no longer protected
                mk("198.51.100.1", 500, false),       // now in never list
                mk("198.51.100.7", 500, false),       // duplicate
                scoped,                               // scope no longer exists
            ],
            100,
        );
        let l = e.list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].expires_at, 100 + 21_600);
        assert_eq!(rx.borrow().len(), 1);
        let drops = sink
            .lines()
            .iter()
            .filter(|v| v["event"] == "restore_drop")
            .count();
        assert_eq!(drops, 6);
    }

    #[test]
    fn restore_revalidates_flowspec() {
        let (mut e, rx, _) = engine();
        let f = |dst: &str, exp: u64, dry: bool| FlowEntry {
            id: String::new(),
            rule: rule(dst),
            reason: "r".into(),
            source: Source::Detector,
            created_at: 0,
            expires_at: exp,
            dry_run: dry,
        };
        e.restore_all(
            vec![],
            vec![
                f("198.51.100.7", 1_000_000, false),
                f("198.51.100.8", 50, false),
                f("198.51.100.9", 500, true),
                f("203.0.113.9", 500, false),
                f("198.51.100.7", 500, false),
            ],
            100,
        );
        let l = e.list_flowspec();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].id, rule("198.51.100.7").key());
        assert!(l[0].expires_at <= 100 + 21_600);
        assert_eq!(rx.borrow().flowspec.len(), 1);
    }

    #[test]
    fn state_is_persisted_on_change() {
        let d = crate::state::tests::tmpdir("engine");
        let p = d.join("s.json");
        let audit = Arc::new(Audit::to_writer(Box::new(Sink::default())));
        let (mut e, _rx) = Engine::new(
            policy(),
            Some(p.clone()),
            audit,
            Arc::new(Metrics::default()),
        );
        e.request(ip("198.51.100.7"), None, "x", Source::Api, 0)
            .unwrap();
        e.request_flowspec(rule("198.51.100.8"), None, "x", Source::Api, 0)
            .unwrap();
        let (b, f) = crate::state::load_all(&p).unwrap();
        assert_eq!((b.len(), f.len()), (1, 1));
        e.expire(u64::MAX);
        assert!(crate::state::load(&p).unwrap().is_empty());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn flowspec_goes_through_policy_and_is_published() {
        let (mut e, rx, sink) = engine();
        let f = e
            .request_flowspec(rule("198.51.100.7"), None, "dns amp", Source::Detector, 0)
            .unwrap();
        assert!(rx.borrow().flowspec.contains_key(&f.id));
        assert_eq!(sink.lines()[0]["event"], "flowspec_allow");
        // duplicate from the detector is silent, from the API it is audited
        assert!(e
            .request_flowspec(rule("198.51.100.7"), None, "x", Source::Detector, 1)
            .is_err());
        assert_eq!(sink.lines().len(), 1);
        // policy denials: unprotected, discard not allowed, capacity
        assert_eq!(
            e.request_flowspec(rule("203.0.113.7"), None, "x", Source::Api, 1)
                .unwrap_err()
                .code(),
            "not_protected"
        );
        let mut d = rule("198.51.100.8");
        d.action = FlowAction::Discard;
        assert_eq!(
            e.request_flowspec(d, None, "x", Source::Api, 1)
                .unwrap_err()
                .code(),
            "flowspec_action"
        );
        e.request_flowspec(rule("198.51.100.8"), None, "x", Source::Api, 1)
            .unwrap();
        assert_eq!(
            e.request_flowspec(rule("198.51.100.9"), None, "x", Source::Api, 1),
            Err(Deny::FlowspecMaxActive(2))
        );
        // release removes only detector-owned rules for that destination
        assert_eq!(e.release_flowspec(ip("198.51.100.8"), 2), 0);
        assert_eq!(e.release_flowspec(ip("198.51.100.7"), 2), 1);
        assert_eq!(rx.borrow().flowspec.len(), 1);
        assert!(e
            .withdraw_flowspec(&rule("198.51.100.8").key(), "x", Source::Api, 3)
            .is_some());
        assert!(rx.borrow().flowspec.is_empty());
    }

    #[test]
    fn scoped_blackhole_is_published_with_scope() {
        let (mut e, rx, _) = engine();
        e.request_blackhole(
            ip("198.51.100.7"),
            None,
            Some("eu".into()),
            vec!["transit-a".into()],
            "x",
            Source::Api,
            0,
        )
        .unwrap();
        assert_eq!(
            rx.borrow().blackholes[&ip("198.51.100.7")],
            Scope {
                region: Some("eu".into()),
                upstreams: vec!["transit-a".into()]
            }
        );
        assert_eq!(
            e.request_blackhole(
                ip("198.51.100.8"),
                None,
                Some("eu".into()),
                vec!["transit-b".into()],
                "x",
                Source::Api,
                0
            ),
            Err(Deny::UnknownScope("eu".into()))
        );
        // "global" is the same as no scope
        let g = e
            .request_blackhole(
                ip("198.51.100.9"),
                None,
                Some("global".into()),
                vec![],
                "x",
                Source::Api,
                0,
            )
            .unwrap();
        assert!(g.scope.is_none());
    }

    #[test]
    fn approval_mode_parks_detector_requests() {
        let (mut e, rx, sink) = engine();
        let (tx, mut notes) = mpsc::channel(8);
        e.set_notifier(tx);
        e.set_approval(ApprovalMode::Detector, 60);
        // API requests are not covered by mode = detector.
        assert!(matches!(
            e.submit(
                Target::blackhole(ip("198.51.100.20")),
                None,
                "x",
                Source::Api,
                0
            ),
            Ok(Submitted::Blackhole(_))
        ));
        let Ok(Submitted::Pending(p)) = e.submit(
            Target::blackhole(ip("198.51.100.7")),
            None,
            "x",
            Source::Detector,
            0,
        ) else {
            panic!("expected pending")
        };
        assert_eq!(p.id.len(), 32);
        assert!(!rx.borrow().contains(&ip("198.51.100.7")));
        assert_eq!(notes.try_recv().unwrap().id, p.id);
        // Re-request returns the same pending entry, no new notification.
        let Ok(Submitted::Pending(again)) = e.submit(
            Target::blackhole(ip("198.51.100.7")),
            None,
            "x",
            Source::Detector,
            1,
        ) else {
            panic!("expected pending")
        };
        assert_eq!(again.id, p.id);
        assert!(notes.try_recv().is_err());
        // A request the policy denies is never parked.
        assert_eq!(
            e.submit(
                Target::blackhole(ip("203.0.113.7")),
                None,
                "x",
                Source::Detector,
                1
            )
            .unwrap_err()
            .code(),
            "not_protected"
        );
        // Approval re-runs the policy and publishes.
        assert!(matches!(
            e.approve(&p.id, "api", 2),
            Ok(Submitted::Blackhole(_))
        ));
        assert!(rx.borrow().contains(&ip("198.51.100.7")));
        assert_eq!(e.approve(&p.id, "api", 2), Err(ApproveError::NotFound));
        let events: Vec<String> = sink
            .lines()
            .iter()
            .map(|l| l["event"].as_str().unwrap().to_owned())
            .collect();
        assert!(events.contains(&"approval_pending".to_owned()));
        assert!(events.contains(&"approval_approved".to_owned()));
    }

    #[test]
    fn approval_is_rechecked_against_current_state() {
        let (mut e, rx, _) = engine();
        e.set_approval(ApprovalMode::All, 60);
        let Ok(Submitted::Pending(p)) = e.submit(
            Target::blackhole(ip("198.51.100.7")),
            None,
            "x",
            Source::Api,
            0,
        ) else {
            panic!()
        };
        // Meanwhile the policy is reloaded without that prefix.
        let mut cfg = crate::config::Config::parse(crate::config::tests::EXAMPLE).unwrap();
        cfg.guardrails.protected = vec!["192.0.2.0/24".parse().unwrap()];
        cfg.dry_run = false;
        e.set_policy(Policy::from_config(&cfg), 1);
        assert_eq!(
            e.approve(&p.id, "api", 2).unwrap_err(),
            ApproveError::Denied(Deny::NotProtected(ip("198.51.100.7")))
        );
        assert!(rx.borrow().is_empty());
    }

    #[test]
    fn approval_reject_timeout_and_cancel() {
        let (mut e, rx, sink) = engine();
        e.set_approval(ApprovalMode::Detector, 60);
        let pend = |e: &mut Engine, t: Target| match e.submit(t, None, "x", Source::Detector, 0) {
            Ok(Submitted::Pending(p)) => p,
            other => panic!("{other:?}"),
        };
        let a = pend(&mut e, Target::blackhole(ip("198.51.100.7")));
        let b = pend(&mut e, Target::blackhole(ip("198.51.100.8")));
        let c = pend(
            &mut e,
            Target::Flowspec {
                rule: rule("198.51.100.9"),
            },
        );
        assert!(e.reject(&a.id, "telegram:1", 1).is_some());
        assert!(e.reject(&a.id, "telegram:1", 1).is_none());
        assert_eq!(e.release_flowspec(ip("198.51.100.9"), 2), 0);
        assert_eq!(e.list_pending().len(), 1);
        // Pending capacity is bounded by max_active (3).
        pend(&mut e, Target::blackhole(ip("198.51.100.10")));
        pend(&mut e, Target::blackhole(ip("198.51.100.11")));
        assert_eq!(
            e.submit(
                Target::blackhole(ip("198.51.100.12")),
                None,
                "x",
                Source::Detector,
                0
            ),
            Err(Deny::TooManyPending(3))
        );
        e.expire(59);
        assert_eq!(e.list_pending().len(), 3);
        e.expire(60);
        assert!(e.list_pending().is_empty());
        assert!(rx.borrow().is_empty());
        let events: Vec<String> = sink
            .lines()
            .iter()
            .map(|l| l["event"].as_str().unwrap().to_owned())
            .collect();
        assert!(events.contains(&"approval_denied".to_owned()));
        assert!(events.contains(&"approval_cancelled".to_owned()));
        assert_eq!(
            events.iter().filter(|e| *e == "approval_timeout").count(),
            3
        );
        let _ = (b, c);
    }

    #[test]
    fn reload_withdraws_what_the_new_policy_forbids() {
        let (mut e, rx, _) = engine();
        e.request(ip("198.51.100.7"), None, "x", Source::Api, 0)
            .unwrap();
        e.request_flowspec(rule("198.51.100.8"), None, "x", Source::Api, 0)
            .unwrap();
        let mut cfg = crate::config::Config::parse(crate::config::tests::EXAMPLE).unwrap();
        cfg.dry_run = false;
        cfg.guardrails
            .never
            .push("198.51.100.7/32".parse().unwrap());
        cfg.flowspec = None;
        e.set_policy(Policy::from_config(&cfg), 1);
        assert!(rx.borrow().is_empty());
        assert!(rx.borrow().flowspec.is_empty());
    }

    #[test]
    fn propagation_only_for_active_entries() {
        use crate::propagation::{PropStatus, Propagation};
        let (mut e, _rx, _) = engine();
        let p = Propagation {
            checked_at: 5,
            visible_peers: 0,
            status: PropStatus::NotSeen,
            ripestat_peers: Some(0),
            pathology_peers: None,
        };
        e.set_propagation(ip("198.51.100.7"), p.clone());
        assert!(e.propagation(ip("198.51.100.7")).is_none());
        e.request(ip("198.51.100.7"), None, "x", Source::Api, 0)
            .unwrap();
        e.set_propagation(ip("198.51.100.7"), p);
        assert_eq!(
            e.propagation(ip("198.51.100.7")).unwrap().status,
            PropStatus::NotSeen
        );
        e.withdraw(ip("198.51.100.7"), "x", Source::Api, 1);
        assert!(e.propagation(ip("198.51.100.7")).is_none());
    }
}
