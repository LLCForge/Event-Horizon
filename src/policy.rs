//! Policy engine: the single choke point every routing change passes through.
//!
//! Deny by default. A blackhole is allowed only if the address is a routable
//! unicast host address, lies inside a `protected` prefix, lies outside every
//! `never` prefix, is not already active, fits under `max_active`, the
//! requested TTL is inside `[min, max]`, and its scope (region / upstream
//! subset) names something that exists. A FlowSpec rule must pass the same
//! address and TTL checks plus its own: FlowSpec enabled, a known protocol,
//! ports only for TCP/UDP, an allowed action and the FlowSpec `max_active`.
//! Escalation and manual approval do not bypass anything: they call the same
//! functions again at the moment the route would be announced.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use thiserror::Error;

use crate::bgp::flowspec::{FlowAction, FlowRule, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::config::{fmt_duration, Config};

pub const MAX_SCOPE_UPSTREAMS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowPolicy {
    pub max_active: usize,
    pub allow_discard: bool,
}

#[derive(Debug, Clone)]
pub struct Policy {
    protected: Vec<IpNet>,
    never: Vec<IpNet>,
    max_active: usize,
    ttl_min: u64,
    ttl_default: u64,
    ttl_max: u64,
    dry_run: bool,
    /// upstream name -> region names it supports.
    upstreams: BTreeMap<String, Vec<String>>,
    flowspec: Option<FlowPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approval {
    pub ttl: u64,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Deny {
    #[error("{0} is not a routable unicast host address")]
    SpecialAddress(IpAddr),
    #[error("{0} is inside never-blackhole prefix {1}")]
    Never(IpAddr, IpNet),
    #[error("{0} is not inside any protected prefix")]
    NotProtected(IpAddr),
    #[error("{0} is already blackholed")]
    AlreadyActive(IpAddr),
    #[error("max_active limit of {0} reached")]
    MaxActive(usize),
    #[error("requested TTL {} is below the minimum {}", fmt_duration(*.0), fmt_duration(*.1))]
    TtlTooShort(u64, u64),
    #[error("requested TTL {} is above the maximum {}", fmt_duration(*.0), fmt_duration(*.1))]
    TtlTooLong(u64, u64),
    #[error("unknown upstream {0:?}")]
    UnknownUpstream(String),
    #[error("no selected upstream defines blackhole scope {0:?}")]
    UnknownScope(String),
    #[error("FlowSpec is not enabled")]
    FlowspecDisabled,
    #[error(
        "FlowSpec protocol {0} is not allowed for this address family (tcp, udp, icmp, icmpv6)"
    )]
    FlowspecProtocol(u8),
    #[error("FlowSpec ports must be 1-65535 and only used with tcp or udp")]
    FlowspecPort,
    #[error("FlowSpec action {0} is not allowed by policy")]
    FlowspecAction(String),
    #[error("FlowSpec rule is already active")]
    FlowspecActive,
    #[error("FlowSpec max_active limit of {0} reached")]
    FlowspecMaxActive(usize),
    #[error("{0} requests are already waiting for approval")]
    TooManyPending(usize),
}

impl Deny {
    pub fn code(&self) -> &'static str {
        match self {
            Deny::SpecialAddress(_) => "special_address",
            Deny::Never(..) => "never_list",
            Deny::NotProtected(_) => "not_protected",
            Deny::AlreadyActive(_) | Deny::FlowspecActive => "already_active",
            Deny::MaxActive(_) => "max_active",
            Deny::TtlTooShort(..) => "ttl_too_short",
            Deny::TtlTooLong(..) => "ttl_too_long",
            Deny::UnknownUpstream(_) => "unknown_upstream",
            Deny::UnknownScope(_) => "unknown_scope",
            Deny::FlowspecDisabled => "flowspec_disabled",
            Deny::FlowspecProtocol(_) => "flowspec_protocol",
            Deny::FlowspecPort => "flowspec_port",
            Deny::FlowspecAction(_) => "flowspec_action",
            Deny::FlowspecMaxActive(_) => "flowspec_max_active",
            Deny::TooManyPending(_) => "too_many_pending",
        }
    }

    /// Duplicate requests (already active); detectors repeat these by design.
    pub fn is_duplicate(&self) -> bool {
        matches!(self, Deny::AlreadyActive(_) | Deny::FlowspecActive)
    }
}

/// Addresses that must never be blackholed regardless of configuration.
fn is_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 0
                || o[0] >= 224 // multicast, reserved, broadcast
                || a.is_loopback()
                || a.is_link_local()
        }
        IpAddr::V6(a) => {
            let s0 = a.segments()[0];
            a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || (s0 & 0xffc0) == 0xfe80 // link-local
                || a.to_ipv4_mapped().is_some()
                || a.segments()[..6] == [0; 6] // IPv4-compatible / reserved ::/96
        }
    }
}

impl Policy {
    pub fn from_config(cfg: &Config) -> Self {
        let g = &cfg.guardrails;
        Self {
            protected: g.protected.clone(),
            never: g.never.clone(),
            max_active: g.max_active,
            ttl_min: g.ttl.min.0,
            ttl_default: g.ttl.default.0,
            ttl_max: g.ttl.max.0,
            dry_run: cfg.dry_run,
            upstreams: cfg
                .bgp
                .upstreams
                .iter()
                .map(|u| (u.name.clone(), u.regions.keys().cloned().collect()))
                .collect(),
            flowspec: cfg.flowspec.as_ref().map(|f| FlowPolicy {
                max_active: f.max_active,
                allow_discard: f.allow_discard,
            }),
        }
    }

    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    pub fn max_active(&self) -> usize {
        self.max_active
    }

    pub fn ttl_max(&self) -> u64 {
        self.ttl_max
    }

    pub fn flowspec(&self) -> Option<FlowPolicy> {
        self.flowspec
    }

    /// Address-only checks, reused when reloading persisted state.
    pub fn check_address(&self, ip: IpAddr) -> Result<(), Deny> {
        if is_special(ip) {
            return Err(Deny::SpecialAddress(ip));
        }
        if let Some(n) = self.never.iter().find(|n| n.contains(&ip)) {
            return Err(Deny::Never(ip, *n));
        }
        if !self.protected.iter().any(|p| p.contains(&ip)) {
            return Err(Deny::NotProtected(ip));
        }
        Ok(())
    }

    fn check_ttl(&self, requested: Option<u64>) -> Result<u64, Deny> {
        let ttl = requested.unwrap_or(self.ttl_default);
        if ttl < self.ttl_min {
            return Err(Deny::TtlTooShort(ttl, self.ttl_min));
        }
        if ttl > self.ttl_max {
            return Err(Deny::TtlTooLong(ttl, self.ttl_max));
        }
        Ok(ttl)
    }

    /// Scope checks: every named upstream exists, and a region is defined by
    /// at least one selected upstream. `None` / `"global"` means all.
    pub fn check_scope(&self, scope: Option<&str>, upstreams: &[String]) -> Result<(), Deny> {
        if upstreams.len() > MAX_SCOPE_UPSTREAMS {
            return Err(Deny::UnknownUpstream(format!(
                "more than {MAX_SCOPE_UPSTREAMS} upstreams"
            )));
        }
        for u in upstreams {
            if !self.upstreams.contains_key(u) {
                return Err(Deny::UnknownUpstream(u.clone()));
            }
        }
        let Some(region) = scope.filter(|s| *s != "global") else {
            return Ok(());
        };
        let selected = |name: &String| upstreams.is_empty() || upstreams.contains(name);
        if self
            .upstreams
            .iter()
            .any(|(n, regions)| selected(n) && regions.iter().any(|r| r == region))
        {
            Ok(())
        } else {
            Err(Deny::UnknownScope(region.to_owned()))
        }
    }

    pub fn evaluate(
        &self,
        ip: IpAddr,
        requested_ttl: Option<u64>,
        active_count: usize,
        already_active: bool,
    ) -> Result<Approval, Deny> {
        self.check_address(ip)?;
        if already_active {
            return Err(Deny::AlreadyActive(ip));
        }
        if active_count >= self.max_active {
            return Err(Deny::MaxActive(self.max_active));
        }
        Ok(Approval {
            ttl: self.check_ttl(requested_ttl)?,
            dry_run: self.dry_run,
        })
    }

    /// Blackhole with a scope: address checks, then scope, then capacity and TTL.
    pub fn evaluate_scoped(
        &self,
        ip: IpAddr,
        requested_ttl: Option<u64>,
        scope: Option<&str>,
        upstreams: &[String],
        active_count: usize,
        already_active: bool,
    ) -> Result<Approval, Deny> {
        self.check_address(ip)?;
        self.check_scope(scope, upstreams)?;
        self.evaluate(ip, requested_ttl, active_count, already_active)
    }

    /// FlowSpec rule: same address and TTL rules as a blackhole plus match / action checks.
    pub fn evaluate_flowspec(
        &self,
        rule: &FlowRule,
        requested_ttl: Option<u64>,
        active_count: usize,
        already_active: bool,
    ) -> Result<Approval, Deny> {
        let Some(fp) = self.flowspec else {
            return Err(Deny::FlowspecDisabled);
        };
        self.check_address(rule.dst)?;
        let proto_ok = match rule.protocol {
            PROTO_TCP | PROTO_UDP => true,
            PROTO_ICMP => rule.dst.is_ipv4(),
            PROTO_ICMPV6 => rule.dst.is_ipv6(),
            _ => false,
        };
        if !proto_ok {
            return Err(Deny::FlowspecProtocol(rule.protocol));
        }
        let has_ports = rule.src_port.is_some() || rule.dst_port.is_some();
        let tcp_udp = matches!(rule.protocol, PROTO_TCP | PROTO_UDP);
        if (has_ports && !tcp_udp) || rule.src_port == Some(0) || rule.dst_port == Some(0) {
            return Err(Deny::FlowspecPort);
        }
        match rule.action {
            FlowAction::Discard if !fp.allow_discard => {
                return Err(Deny::FlowspecAction(rule.action.to_string()))
            }
            FlowAction::RateLimit { kbps } if kbps == 0 || kbps > 100_000_000 => {
                return Err(Deny::FlowspecAction(rule.action.to_string()))
            }
            _ => {}
        }
        if already_active {
            return Err(Deny::FlowspecActive);
        }
        if active_count >= fp.max_active {
            return Err(Deny::FlowspecMaxActive(fp.max_active));
        }
        Ok(Approval {
            ttl: self.check_ttl(requested_ttl)?,
            dry_run: self.dry_run,
        })
    }

    /// Bound on requests waiting for manual approval.
    pub fn check_pending(&self, pending: usize) -> Result<(), Deny> {
        if pending >= self.max_active {
            Err(Deny::TooManyPending(pending))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn policy() -> Policy {
        Policy {
            protected: vec![
                "198.51.100.0/24".parse().unwrap(),
                "2001:db8:100::/48".parse().unwrap(),
            ],
            never: vec![
                "198.51.100.1/32".parse().unwrap(),
                "198.51.100.128/26".parse().unwrap(),
                "2001:db8:100::53/128".parse().unwrap(),
            ],
            max_active: 3,
            ttl_min: 300,
            ttl_default: 1800,
            ttl_max: 21_600,
            dry_run: false,
            upstreams: [
                ("transit-a".to_owned(), vec!["eu".to_owned()]),
                ("transit-b".to_owned(), vec![]),
            ]
            .into(),
            flowspec: Some(FlowPolicy {
                max_active: 2,
                allow_discard: false,
            }),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn eval(s: &str) -> Result<Approval, Deny> {
        policy().evaluate(ip(s), None, 0, false)
    }

    #[test]
    fn allows_host_inside_protected() {
        assert_eq!(
            eval("198.51.100.7"),
            Ok(Approval {
                ttl: 1800,
                dry_run: false
            })
        );
        assert!(eval("198.51.100.0").is_ok());
        assert!(eval("198.51.100.255").is_ok()); // just outside the never /26
        assert!(eval("2001:db8:100::7").is_ok());
        assert!(eval("2001:db8:100:ffff:ffff:ffff:ffff:ffff").is_ok());
    }

    #[test]
    fn denies_outside_protected() {
        for s in [
            "198.51.99.255",
            "198.51.101.0",
            "203.0.113.7",
            "192.0.2.1",
            "8.8.8.8",
            "2001:db8:101::1",
            "2001:db8::1",
            "2001:db7:ffff::1",
        ] {
            assert_eq!(eval(s), Err(Deny::NotProtected(ip(s))), "{s}");
        }
    }

    #[test]
    fn never_list_wins_over_protected() {
        assert_eq!(
            eval("198.51.100.1"),
            Err(Deny::Never(
                ip("198.51.100.1"),
                "198.51.100.1/32".parse().unwrap()
            ))
        );
        for s in ["198.51.100.128", "198.51.100.150", "198.51.100.191"] {
            assert!(matches!(eval(s), Err(Deny::Never(..))), "{s}");
        }
        assert!(eval("198.51.100.192").is_ok());
        assert!(eval("198.51.100.127").is_ok());
        assert!(matches!(eval("2001:db8:100::53"), Err(Deny::Never(..))));
    }

    #[test]
    fn denies_special_addresses_even_if_protected() {
        let mut p = policy();
        p.protected = vec![
            "0.0.0.0/1".parse().unwrap(),
            "128.0.0.0/1".parse().unwrap(),
            "::/1".parse().unwrap(),
            "8000::/1".parse().unwrap(),
        ];
        p.never.clear();
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.5",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "::ffff:198.51.100.7",
            "::198.51.100.7",
        ] {
            assert_eq!(
                p.evaluate(ip(s), None, 0, false),
                Err(Deny::SpecialAddress(ip(s))),
                "{s}"
            );
        }
        assert!(p.evaluate(ip("198.51.100.7"), None, 0, false).is_ok());
        assert!(p.evaluate(ip("2001:db8::1"), None, 0, false).is_ok());
    }

    #[test]
    fn mapped_address_cannot_bypass_never_list() {
        // ::ffff:198.51.100.1 would not match the v4 never entry; it must be refused outright.
        assert!(matches!(
            eval("::ffff:198.51.100.1"),
            Err(Deny::SpecialAddress(_))
        ));
    }

    #[test]
    fn denies_when_already_active() {
        let p = policy();
        assert_eq!(
            p.evaluate(ip("198.51.100.7"), None, 1, true),
            Err(Deny::AlreadyActive(ip("198.51.100.7")))
        );
    }

    #[test]
    fn enforces_max_active() {
        let p = policy();
        assert!(p.evaluate(ip("198.51.100.7"), None, 2, false).is_ok());
        assert_eq!(
            p.evaluate(ip("198.51.100.7"), None, 3, false),
            Err(Deny::MaxActive(3))
        );
        assert_eq!(
            p.evaluate(ip("198.51.100.7"), None, 1000, false),
            Err(Deny::MaxActive(3))
        );
    }

    #[test]
    fn address_checks_run_before_capacity_checks() {
        let p = policy();
        assert!(matches!(
            p.evaluate(ip("203.0.113.7"), None, 1000, true),
            Err(Deny::NotProtected(_))
        ));
    }

    #[test]
    fn enforces_ttl_bounds() {
        let p = policy();
        let a = ip("198.51.100.7");
        assert_eq!(p.evaluate(a, Some(300), 0, false).unwrap().ttl, 300);
        assert_eq!(p.evaluate(a, Some(21_600), 0, false).unwrap().ttl, 21_600);
        assert_eq!(
            p.evaluate(a, Some(299), 0, false),
            Err(Deny::TtlTooShort(299, 300))
        );
        assert_eq!(
            p.evaluate(a, Some(0), 0, false),
            Err(Deny::TtlTooShort(0, 300))
        );
        assert_eq!(
            p.evaluate(a, Some(21_601), 0, false),
            Err(Deny::TtlTooLong(21_601, 21_600))
        );
        assert_eq!(
            p.evaluate(a, Some(u64::MAX), 0, false),
            Err(Deny::TtlTooLong(u64::MAX, 21_600))
        );
    }

    #[test]
    fn approval_carries_dry_run() {
        let mut p = policy();
        p.dry_run = true;
        assert!(
            p.evaluate(ip("198.51.100.7"), None, 0, false)
                .unwrap()
                .dry_run
        );
        let r = flow("198.51.100.7", PROTO_UDP, Some(53), RL);
        assert!(p.evaluate_flowspec(&r, None, 0, false).unwrap().dry_run);
    }

    #[test]
    fn empty_protected_denies_everything() {
        let mut p = policy();
        p.protected.clear();
        assert!(matches!(
            eval_with(&p, "198.51.100.7"),
            Err(Deny::NotProtected(_))
        ));
        assert!(matches!(
            eval_with(&p, "2001:db8:100::7"),
            Err(Deny::NotProtected(_))
        ));
        let r = flow("198.51.100.7", PROTO_UDP, Some(53), RL);
        assert!(matches!(
            p.evaluate_flowspec(&r, None, 0, false),
            Err(Deny::NotProtected(_))
        ));
    }

    fn eval_with(p: &Policy, s: &str) -> Result<Approval, Deny> {
        p.evaluate(ip(s), None, 0, false)
    }

    #[test]
    fn deny_codes_and_messages() {
        assert_eq!(Deny::MaxActive(3).code(), "max_active");
        assert_eq!(
            Deny::TtlTooLong(86_400, 21_600).to_string(),
            "requested TTL 1d is above the maximum 6h"
        );
        assert!(Deny::FlowspecActive.is_duplicate());
        assert!(!Deny::FlowspecDisabled.is_duplicate());
    }

    #[test]
    fn policy_from_example_config() {
        let cfg = crate::config::Config::parse(crate::config::tests::EXAMPLE).unwrap();
        let p = Policy::from_config(&cfg);
        assert!(p.dry_run());
        assert!(p.evaluate(ip("198.51.100.7"), None, 0, false).is_ok());
        assert!(p.evaluate(ip("198.51.100.53"), None, 0, false).is_err());
        assert!(p.evaluate(ip("203.0.113.1"), None, 0, false).is_err());
        assert!(p.flowspec().is_some());
        assert!(p.check_scope(Some("eu"), &[]).is_ok());
    }

    fn flow(dst: &str, proto: u8, sport: Option<u16>, action: FlowAction) -> FlowRule {
        FlowRule {
            dst: ip(dst),
            protocol: proto,
            src_port: sport,
            dst_port: None,
            action,
        }
    }

    const RL: FlowAction = FlowAction::RateLimit { kbps: 1000 };

    #[test]
    fn flowspec_allows_valid_rules() {
        let p = policy();
        for r in [
            flow("198.51.100.7", PROTO_UDP, Some(53), RL),
            flow("198.51.100.7", PROTO_TCP, None, RL),
            flow("198.51.100.7", PROTO_ICMP, None, RL),
            flow("2001:db8:100::7", PROTO_ICMPV6, None, RL),
        ] {
            assert_eq!(
                p.evaluate_flowspec(&r, None, 0, false).unwrap().ttl,
                1800,
                "{r}"
            );
        }
    }

    #[test]
    fn flowspec_matrix_denies() {
        let p = policy();
        let cases: Vec<(FlowRule, &str)> = vec![
            (
                flow("203.0.113.7", PROTO_UDP, Some(53), RL),
                "not_protected",
            ),
            (flow("198.51.100.1", PROTO_UDP, Some(53), RL), "never_list"),
            (
                flow("198.51.100.150", PROTO_UDP, Some(53), RL),
                "never_list",
            ),
            (
                flow("127.0.0.1", PROTO_UDP, Some(53), RL),
                "special_address",
            ),
            (
                flow("::ffff:198.51.100.7", PROTO_UDP, Some(53), RL),
                "special_address",
            ),
            (flow("198.51.100.7", 47, None, RL), "flowspec_protocol"),
            (
                flow("198.51.100.7", PROTO_ICMPV6, None, RL),
                "flowspec_protocol",
            ),
            (
                flow("2001:db8:100::7", PROTO_ICMP, None, RL),
                "flowspec_protocol",
            ),
            (
                flow("198.51.100.7", PROTO_ICMP, Some(1), RL),
                "flowspec_port",
            ),
            (
                flow("198.51.100.7", PROTO_UDP, Some(0), RL),
                "flowspec_port",
            ),
            (
                flow("198.51.100.7", PROTO_UDP, Some(53), FlowAction::Discard),
                "flowspec_action",
            ),
            (
                flow(
                    "198.51.100.7",
                    PROTO_UDP,
                    Some(53),
                    FlowAction::RateLimit { kbps: 0 },
                ),
                "flowspec_action",
            ),
        ];
        for (r, code) in cases {
            assert_eq!(
                p.evaluate_flowspec(&r, None, 0, false).unwrap_err().code(),
                code,
                "{r}"
            );
        }
        let ok = flow("198.51.100.7", PROTO_UDP, Some(53), RL);
        assert_eq!(
            p.evaluate_flowspec(&ok, None, 0, true),
            Err(Deny::FlowspecActive)
        );
        assert_eq!(
            p.evaluate_flowspec(&ok, None, 2, false),
            Err(Deny::FlowspecMaxActive(2))
        );
        assert_eq!(
            p.evaluate_flowspec(&ok, Some(10), 0, false),
            Err(Deny::TtlTooShort(10, 300))
        );
        assert_eq!(
            p.evaluate_flowspec(&ok, Some(u64::MAX), 0, false),
            Err(Deny::TtlTooLong(u64::MAX, 21_600))
        );
        // Address checks run before duplicate / capacity checks.
        assert!(matches!(
            p.evaluate_flowspec(&flow("203.0.113.7", PROTO_UDP, None, RL), None, 99, true),
            Err(Deny::NotProtected(_))
        ));
    }

    #[test]
    fn flowspec_disabled_denies_everything() {
        let mut p = policy();
        p.flowspec = None;
        let r = flow("198.51.100.7", PROTO_UDP, Some(53), RL);
        assert_eq!(
            p.evaluate_flowspec(&r, None, 0, false),
            Err(Deny::FlowspecDisabled)
        );
    }

    #[test]
    fn flowspec_discard_needs_allow_discard() {
        let mut p = policy();
        p.flowspec = Some(FlowPolicy {
            max_active: 2,
            allow_discard: true,
        });
        let r = flow("198.51.100.7", PROTO_UDP, Some(123), FlowAction::Discard);
        assert!(p.evaluate_flowspec(&r, None, 0, false).is_ok());
    }

    #[test]
    fn scope_checks() {
        let p = policy();
        let a = ip("198.51.100.7");
        let up = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(p.evaluate_scoped(a, None, None, &[], 0, false).is_ok());
        assert!(p
            .evaluate_scoped(a, None, Some("global"), &[], 0, false)
            .is_ok());
        assert!(p
            .evaluate_scoped(a, None, Some("eu"), &[], 0, false)
            .is_ok());
        assert!(p
            .evaluate_scoped(a, None, Some("eu"), &up(&["transit-a"]), 0, false)
            .is_ok());
        assert!(p
            .evaluate_scoped(a, None, None, &up(&["transit-b"]), 0, false)
            .is_ok());
        assert_eq!(
            p.evaluate_scoped(a, None, Some("eu"), &up(&["transit-b"]), 0, false),
            Err(Deny::UnknownScope("eu".into()))
        );
        assert_eq!(
            p.evaluate_scoped(a, None, Some("us"), &[], 0, false),
            Err(Deny::UnknownScope("us".into()))
        );
        assert_eq!(
            p.evaluate_scoped(a, None, None, &up(&["transit-z"]), 0, false),
            Err(Deny::UnknownUpstream("transit-z".into()))
        );
        let many: Vec<String> = (0..=MAX_SCOPE_UPSTREAMS)
            .map(|_| "transit-a".to_owned())
            .collect();
        assert!(p.evaluate_scoped(a, None, None, &many, 0, false).is_err());
        // Scope never rescues a forbidden address.
        assert!(matches!(
            p.evaluate_scoped(ip("198.51.100.1"), None, Some("eu"), &[], 0, false),
            Err(Deny::Never(..))
        ));
    }

    #[test]
    fn pending_is_bounded() {
        let p = policy();
        assert!(p.check_pending(2).is_ok());
        assert_eq!(p.check_pending(3), Err(Deny::TooManyPending(3)));
    }
}
