//! TOML configuration, defaults and startup validation.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use llcforge_beacon::{AlertsConfig, HealthConfig, LogFormat, SilencesConfig};
use serde::Deserialize;

use crate::bgp::message::{Community, AS_TRANS};

pub const BIN: &str = "event-horizon";

/// Duration written as `"30s"`, `"5m"`, `"6h"`, `"1d"` or plain seconds; stored as seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Secs(pub u64);

impl TryFrom<String> for Secs {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_duration(&s).map(Secs)
    }
}

pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'd') => (&s[..s.len() - 1], 86_400),
        Some(b'0'..=b'9') => (s, 1),
        _ => return Err(format!("invalid duration {s:?} (use e.g. 30s, 5m, 6h, 1d)")),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration {s:?} (use e.g. 30s, 5m, 6h, 1d)"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("duration {s:?} is too large"))
}

pub fn fmt_duration(secs: u64) -> String {
    match secs {
        s if s > 0 && s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s > 0 && s % 3600 == 0 => format!("{}h", s / 3600),
        s if s > 0 && s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// Directory for state, audit log, reports, alert queue and silences.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub state_file: Option<PathBuf>,
    #[serde(default)]
    pub audit_log: Option<PathBuf>,
    #[serde(default)]
    pub log: LogConfig,
    pub bgp: BgpConfig,
    pub guardrails: Guardrails,
    #[serde(default)]
    pub flowspec: Option<FlowspecConfig>,
    #[serde(default)]
    pub approval: Option<ApprovalConfig>,
    #[serde(default)]
    pub api: Option<ApiConfig>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub detect: DetectConfig,
    #[serde(default)]
    pub propagation: Option<PropagationConfig>,
    #[serde(default)]
    pub reports: ReportsConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub silences: SilencesConfig,
    #[serde(default)]
    pub health: HealthConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Optional tracing filter directive, e.g. `"event_horizon=debug,info"`.
    #[serde(default)]
    pub filter: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Text,
            level: default_log_level(),
            filter: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpConfig {
    pub local_asn: u32,
    pub router_id: Ipv4Addr,
    #[serde(default = "default_hold_time")]
    pub hold_time: u16,
    /// Discard next hop for IPv4 blackholes (RFC 5737 TEST-NET-1, null-routed by convention).
    #[serde(default = "default_next_hop_v4")]
    pub next_hop_v4: Ipv4Addr,
    /// Discard next hop for IPv6 blackholes (RFC 6666 discard prefix).
    #[serde(default = "default_next_hop_v6")]
    pub next_hop_v6: Ipv6Addr,
    /// RFC 4724 Graceful Restart; absent = not advertised.
    #[serde(default)]
    pub graceful_restart: Option<GracefulRestartConfig>,
    #[serde(rename = "upstream", default)]
    pub upstreams: Vec<Upstream>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GracefulRestartConfig {
    #[serde(default = "default_restart_time")]
    pub restart_time: Secs,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub neighbor: IpAddr,
    #[serde(default = "default_bgp_port")]
    pub port: u16,
    pub remote_asn: u32,
    #[serde(default)]
    pub communities: Vec<Community>,
    /// RFC 2385 TCP-MD5 password, read from this environment variable (Linux only).
    #[serde(default)]
    pub md5_password_env: Option<String>,
    /// IP TTL / hop limit for multihop eBGP. Unset = operating system default.
    #[serde(default)]
    pub ebgp_multihop: Option<u8>,
    /// Local source address for the session.
    #[serde(default)]
    pub local_address: Option<IpAddr>,
    /// Negotiate and send BGP FlowSpec (RFC 8955 / RFC 8956) on this session.
    #[serde(default)]
    pub flowspec: bool,
    /// Regional / selective blackhole communities: scope name -> communities.
    #[serde(default)]
    pub regions: BTreeMap<String, Vec<Community>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guardrails {
    pub protected: Vec<IpNet>,
    #[serde(default)]
    pub never: Vec<IpNet>,
    pub max_active: usize,
    pub ttl: TtlConfig,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TtlConfig {
    pub min: Secs,
    pub default: Secs,
    pub max: Secs,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlowActionKind {
    #[default]
    RateLimit,
    Discard,
}

/// `[flowspec]`: FlowSpec mitigation (33) and escalation to RTBH (38).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowspecConfig {
    /// Action for detector-generated rules.
    #[serde(default)]
    pub action: FlowActionKind,
    /// Rate for `rate-limit`, in kbit/s.
    #[serde(default = "default_rate_kbps")]
    pub rate_limit_kbps: u64,
    /// Policy: permit `discard` actions at all (detector or API).
    #[serde(default)]
    pub allow_discard: bool,
    #[serde(default = "default_flowspec_max")]
    pub max_active: usize,
    /// Announce an RTBH host route when the attack is still running this long after the FlowSpec rule.
    #[serde(default = "default_escalate_after")]
    pub escalate_after: Secs,
    /// Escalation can be switched off to keep FlowSpec only.
    #[serde(default = "yes")]
    pub escalate: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    #[default]
    Off,
    Detector,
    All,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    #[serde(default)]
    pub mode: ApprovalMode,
    /// Pending requests are denied after this long.
    #[serde(default = "default_approval_timeout")]
    pub timeout: Secs,
    #[serde(default)]
    pub telegram: Option<TelegramApprovalConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramApprovalConfig {
    pub bot_token_env: String,
    pub chat_id: i64,
    /// Telegram user ids allowed to press the buttons.
    pub allowed_user_ids: Vec<i64>,
    #[serde(default = "default_telegram_api")]
    pub api_base: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    #[serde(default = "default_api_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_token_env")]
    pub token_env: String,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    /// When set, clients must present a certificate signed by this CA (mTLS).
    #[serde(default)]
    pub client_ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_listen")]
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectConfig {
    #[serde(default)]
    pub threshold: Option<Rate>,
    #[serde(default)]
    pub release: Option<Rate>,
    #[serde(default)]
    pub window: Option<Secs>,
    #[serde(default)]
    pub trigger_after: Option<Secs>,
    #[serde(default)]
    pub release_after: Option<Secs>,
    #[serde(default)]
    pub baseline: Option<BaselineConfig>,
    #[serde(default)]
    pub sflow: Option<SflowConfig>,
    #[serde(default)]
    pub netflow: Option<NetflowConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SflowConfig {
    pub listen: SocketAddr,
    pub exporters: Vec<IpAddr>,
    /// Legacy location of the detection thresholds (still accepted).
    #[serde(default)]
    pub threshold: Option<Rate>,
    #[serde(default)]
    pub release: Option<Rate>,
    #[serde(default)]
    pub window: Option<Secs>,
    #[serde(default)]
    pub trigger_after: Option<Secs>,
    #[serde(default)]
    pub release_after: Option<Secs>,
}

/// NetFlow v9 and IPFIX on one UDP socket (the version field selects the parser).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetflowConfig {
    pub listen: SocketAddr,
    pub exporters: Vec<IpAddr>,
    /// Packet sampling rate used when a record carries no sampling interval field.
    #[serde(default = "default_sampling")]
    pub sampling_rate: u32,
    #[serde(default = "default_max_templates")]
    pub max_templates: usize,
}

/// Dynamic per-destination thresholds (EWMA of the normal rate).
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfig {
    #[serde(default = "default_alpha")]
    pub alpha: f64,
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,
    #[serde(default)]
    pub min_pps: u64,
    #[serde(default)]
    pub min_mbps: u64,
    #[serde(default = "default_warmup")]
    pub warmup: Secs,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    #[serde(default)]
    pub pps: Option<u64>,
    #[serde(default)]
    pub mbps: Option<u64>,
}

/// Effective detection parameters after merging `[detect]` and the legacy `[detect.sflow]` keys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub threshold: Rate,
    pub release: Rate,
    pub window: u64,
    pub trigger_after: u64,
    pub release_after: u64,
}

impl DetectConfig {
    pub fn any_collector(&self) -> bool {
        self.sflow.is_some() || self.netflow.is_some()
    }

    /// `[detect]` keys win; the legacy `[detect.sflow]` keys fill the gaps.
    pub fn thresholds(&self) -> Option<Thresholds> {
        let s = self.sflow.as_ref();
        let threshold = self.threshold.or(s.and_then(|s| s.threshold))?;
        let r = self
            .release
            .or(s.and_then(|s| s.release))
            .unwrap_or_default();
        // Each missing release value defaults to half of the trigger threshold.
        let release = Rate {
            pps: r.pps.or(threshold.pps.map(|v| v / 2)),
            mbps: r.mbps.or(threshold.mbps.map(|v| v / 2)),
        };
        let pick = |a: Option<Secs>, b: Option<Secs>, d: u64| a.or(b).map_or(d, |x| x.0);
        Some(Thresholds {
            threshold,
            release,
            window: pick(self.window, s.and_then(|s| s.window), 10),
            trigger_after: pick(self.trigger_after, s.and_then(|s| s.trigger_after), 30),
            release_after: pick(self.release_after, s.and_then(|s| s.release_after), 120),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropagationConfig {
    #[serde(default = "yes")]
    pub ripestat: bool,
    #[serde(default = "default_ripestat_url")]
    pub ripestat_url: String,
    #[serde(default)]
    pub pathology_url: Option<String>,
    #[serde(default)]
    pub pathology_token_env: Option<String>,
    /// Wait this long after an announcement before the first check.
    #[serde(default = "default_prop_delay")]
    pub delay: Secs,
    #[serde(default = "default_prop_interval")]
    pub interval: Secs,
    #[serde(default = "default_prop_timeout")]
    pub timeout: Secs,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportsConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub dir: Option<PathBuf>,
    /// Newest reports kept on disk (JSON + Markdown pairs).
    #[serde(default = "default_keep")]
    pub keep: usize,
}

impl Default for ReportsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
            keep: default_keep(),
        }
    }
}

fn yes() -> bool {
    true
}
fn default_log_level() -> String {
    "info".into()
}
fn default_hold_time() -> u16 {
    90
}
fn default_restart_time() -> Secs {
    Secs(120)
}
fn default_next_hop_v4() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 1)
}
fn default_next_hop_v6() -> Ipv6Addr {
    Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 1)
}
fn default_bgp_port() -> u16 {
    179
}
fn default_api_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9179))
}
fn default_metrics_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9180))
}
fn default_token_env() -> String {
    "EVENT_HORIZON_API_TOKEN".into()
}
fn default_max_body() -> usize {
    4096
}
fn default_rate_limit() -> u32 {
    60
}
fn default_rate_kbps() -> u64 {
    10_000
}
fn default_flowspec_max() -> usize {
    32
}
fn default_escalate_after() -> Secs {
    Secs(120)
}
fn default_approval_timeout() -> Secs {
    Secs(300)
}
fn default_telegram_api() -> String {
    "https://api.telegram.org".into()
}
fn default_sampling() -> u32 {
    1
}
fn default_max_templates() -> usize {
    4096
}
fn default_alpha() -> f64 {
    0.02
}
fn default_multiplier() -> f64 {
    5.0
}
fn default_warmup() -> Secs {
    Secs(600)
}
fn default_ripestat_url() -> String {
    "https://stat.ripe.net".into()
}
fn default_prop_delay() -> Secs {
    Secs(120)
}
fn default_prop_interval() -> Secs {
    Secs(600)
}
fn default_prop_timeout() -> Secs {
    Secs(10)
}
fn default_keep() -> usize {
    200
}

pub const MAX_ACTIVE_LIMIT: usize = 10_000;
const MAX_REGIONS: usize = 64;

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

fn valid_http_url(u: &str) -> bool {
    (u.starts_with("https://") || u.starts_with("http://")) && u.len() <= 512 && !u.contains(' ')
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(text)?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn data_dir(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| llcforge_beacon::default_data_dir(BIN))
    }

    pub fn state_path(&self) -> PathBuf {
        self.state_file
            .clone()
            .unwrap_or_else(|| self.data_dir().join("event-horizon.state.json"))
    }

    pub fn audit_path(&self) -> PathBuf {
        self.audit_log
            .clone()
            .unwrap_or_else(|| self.data_dir().join("event-horizon-audit.jsonl"))
    }

    pub fn reports_dir(&self) -> PathBuf {
        self.reports
            .dir
            .clone()
            .unwrap_or_else(|| self.data_dir().join("reports"))
    }

    fn normalize(&mut self) {
        for p in self
            .guardrails
            .protected
            .iter_mut()
            .chain(self.guardrails.never.iter_mut())
        {
            *p = p.trunc();
        }
        if let Some(s) = self.detect.sflow.as_mut() {
            for e in s.exporters.iter_mut() {
                *e = e.to_canonical();
            }
        }
        if let Some(s) = self.detect.netflow.as_mut() {
            for e in s.exporters.iter_mut() {
                *e = e.to_canonical();
            }
        }
    }

    /// Collects every problem instead of stopping at the first one.
    pub fn validate(&self) -> Result<()> {
        let mut errs: Vec<String> = Vec::new();
        let g = &self.guardrails;
        if g.protected.is_empty() {
            errs.push(
                "guardrails.protected must list at least one prefix; refusing to run without it"
                    .into(),
            );
        }
        for p in &g.protected {
            if p.prefix_len() == 0 {
                errs.push(format!(
                    "guardrails.protected must not contain a default route ({p})"
                ));
            }
        }
        if g.max_active == 0 || g.max_active > MAX_ACTIVE_LIMIT {
            errs.push(format!(
                "guardrails.max_active must be between 1 and {MAX_ACTIVE_LIMIT}"
            ));
        }
        let t = g.ttl;
        if t.min.0 == 0 {
            errs.push("guardrails.ttl.min must be greater than zero".into());
        }
        if !(t.min.0 <= t.default.0 && t.default.0 <= t.max.0) {
            errs.push("guardrails.ttl must satisfy min <= default <= max".into());
        }

        let b = &self.bgp;
        if matches!(b.local_asn, 0 | AS_TRANS | 65535 | u32::MAX) {
            errs.push(format!("bgp.local_asn {} is reserved", b.local_asn));
        }
        if b.router_id.is_unspecified() {
            errs.push("bgp.router_id must not be 0.0.0.0".into());
        }
        if b.hold_time == 1 || b.hold_time == 2 {
            errs.push("bgp.hold_time must be 0 or at least 3 seconds".into());
        }
        if let Some(gr) = b.graceful_restart {
            if gr.restart_time.0 == 0 || gr.restart_time.0 > 4095 {
                errs.push("bgp.graceful_restart.restart_time must be between 1s and 4095s".into());
            }
        }
        if b.upstreams.is_empty() {
            errs.push("at least one [[bgp.upstream]] is required".into());
        }
        let mut names = HashSet::new();
        for u in &b.upstreams {
            if !valid_name(&u.name) {
                errs.push(format!(
                    "upstream name {:?} must be 1-64 chars of [A-Za-z0-9-_.]",
                    u.name
                ));
            }
            if !names.insert(u.name.as_str()) {
                errs.push(format!("duplicate upstream name {:?}", u.name));
            }
            if u.remote_asn == 0 || u.remote_asn == AS_TRANS {
                errs.push(format!("upstream {}: invalid remote_asn", u.name));
            }
            if u.remote_asn == b.local_asn {
                errs.push(format!(
                    "upstream {}: remote_asn equals local_asn; only eBGP is supported",
                    u.name
                ));
            }
            if u.port == 0 {
                errs.push(format!("upstream {}: port must not be 0", u.name));
            }
            if u.neighbor.is_unspecified() || u.neighbor.is_multicast() {
                errs.push(format!("upstream {}: invalid neighbor address", u.name));
            }
            if u.ebgp_multihop == Some(0) {
                errs.push(format!(
                    "upstream {}: ebgp_multihop must be between 1 and 255",
                    u.name
                ));
            }
            if let Some(l) = u.local_address {
                if l.is_ipv4() != u.neighbor.is_ipv4() {
                    errs.push(format!(
                        "upstream {}: local_address and neighbor must be the same address family",
                        u.name
                    ));
                }
                if l.is_multicast() {
                    errs.push(format!("upstream {}: invalid local_address", u.name));
                }
            }
            if let Some(v) = &u.md5_password_env {
                if v.trim().is_empty() {
                    errs.push(format!(
                        "upstream {}: md5_password_env must name an environment variable",
                        u.name
                    ));
                }
            }
            if u.flowspec && self.flowspec.is_none() {
                errs.push(format!(
                    "upstream {}: flowspec = true needs a [flowspec] section",
                    u.name
                ));
            }
            if u.regions.len() > MAX_REGIONS {
                errs.push(format!(
                    "upstream {}: at most {MAX_REGIONS} regions",
                    u.name
                ));
            }
            for (r, c) in &u.regions {
                if !valid_name(r) || r == "global" {
                    errs.push(format!(
                        "upstream {}: region name {r:?} must be 1-64 chars of [A-Za-z0-9-_.] and not \"global\"",
                        u.name
                    ));
                }
                if c.is_empty() {
                    errs.push(format!(
                        "upstream {}: region {r} needs at least one community",
                        u.name
                    ));
                }
            }
        }

        if let Some(f) = &self.flowspec {
            if f.max_active == 0 || f.max_active > MAX_ACTIVE_LIMIT {
                errs.push(format!(
                    "flowspec.max_active must be between 1 and {MAX_ACTIVE_LIMIT}"
                ));
            }
            if f.rate_limit_kbps == 0 || f.rate_limit_kbps > 100_000_000 {
                errs.push("flowspec.rate_limit_kbps must be between 1 and 100000000".into());
            }
            if f.action == FlowActionKind::Discard && !f.allow_discard {
                errs.push("flowspec.action = \"discard\" requires allow_discard = true".into());
            }
            if !b.upstreams.iter().any(|u| u.flowspec) {
                errs.push("[flowspec] is set but no upstream has flowspec = true".into());
            }
        }

        if let Some(a) = &self.approval {
            if a.timeout.0 < 10 || a.timeout.0 > 86_400 {
                errs.push("approval.timeout must be between 10s and 1d".into());
            }
            if let Some(t) = &a.telegram {
                if t.bot_token_env.trim().is_empty() {
                    errs.push(
                        "approval.telegram.bot_token_env must name an environment variable".into(),
                    );
                }
                if t.allowed_user_ids.is_empty() {
                    errs.push(
                        "approval.telegram.allowed_user_ids must list at least one user".into(),
                    );
                }
                if !t.api_base.starts_with("https://")
                    && !t.api_base.starts_with("http://127.0.0.1")
                {
                    errs.push("approval.telegram.api_base must be https".into());
                }
            }
            if a.mode != ApprovalMode::Off && a.telegram.is_none() && self.api.is_none() {
                errs.push(
                    "approval mode needs [api] or [approval.telegram] to approve requests".into(),
                );
            }
        }

        if let Some(api) = &self.api {
            if api.token_env.trim().is_empty() {
                errs.push("api.token_env must name an environment variable".into());
            }
            if !(256..=65_536).contains(&api.max_body_bytes) {
                errs.push("api.max_body_bytes must be between 256 and 65536".into());
            }
            if api.rate_limit_per_minute == 0 {
                errs.push("api.rate_limit_per_minute must be at least 1".into());
            }
        }

        let d = &self.detect;
        if let Some(s) = &d.sflow {
            if s.exporters.is_empty() {
                errs.push("detect.sflow.exporters must list the allowed exporter addresses".into());
            }
        }
        if let Some(n) = &d.netflow {
            if n.exporters.is_empty() {
                errs.push(
                    "detect.netflow.exporters must list the allowed exporter addresses".into(),
                );
            }
            if n.sampling_rate == 0 {
                errs.push("detect.netflow.sampling_rate must be at least 1".into());
            }
            if n.max_templates == 0 || n.max_templates > 65_536 {
                errs.push("detect.netflow.max_templates must be between 1 and 65536".into());
            }
        }
        if d.any_collector() {
            match d.thresholds() {
                None => errs.push("detect.threshold needs pps and/or mbps".into()),
                Some(t) => {
                    if t.threshold.pps.is_none() && t.threshold.mbps.is_none() {
                        errs.push("detect.threshold needs pps and/or mbps".into());
                    }
                    if t.threshold.pps == Some(0) || t.threshold.mbps == Some(0) {
                        errs.push("detect.threshold values must be greater than zero".into());
                    }
                    if let (Some(rel), Some(thr)) = (t.release.pps, t.threshold.pps) {
                        if rel >= thr {
                            errs.push("detect.release.pps must be below threshold.pps".into());
                        }
                    }
                    if let (Some(rel), Some(thr)) = (t.release.mbps, t.threshold.mbps) {
                        if rel >= thr {
                            errs.push("detect.release.mbps must be below threshold.mbps".into());
                        }
                    }
                    if t.window == 0 || t.window > 300 {
                        errs.push("detect.window must be between 1s and 5m".into());
                    }
                }
            }
        }
        if let Some(bl) = &d.baseline {
            if !(bl.alpha > 0.0 && bl.alpha <= 1.0) {
                errs.push("detect.baseline.alpha must be in (0, 1]".into());
            }
            if !(bl.multiplier >= 1.0 && bl.multiplier <= 1000.0) {
                errs.push("detect.baseline.multiplier must be between 1 and 1000".into());
            }
            if bl.min_pps == 0 && bl.min_mbps == 0 {
                errs.push("detect.baseline needs min_pps and/or min_mbps as a floor".into());
            }
        }

        if let Some(p) = &self.propagation {
            if !valid_http_url(&p.ripestat_url) {
                errs.push("propagation.ripestat_url must be an http(s) URL".into());
            }
            if let Some(u) = &p.pathology_url {
                if !valid_http_url(u) {
                    errs.push("propagation.pathology_url must be an http(s) URL".into());
                }
            }
            if !p.ripestat && p.pathology_url.is_none() {
                errs.push("propagation needs ripestat = true and/or pathology_url".into());
            }
            if p.interval.0 < 60 {
                errs.push("propagation.interval must be at least 1m".into());
            }
            if p.timeout.0 == 0 || p.timeout.0 > 60 {
                errs.push("propagation.timeout must be between 1s and 60s".into());
            }
        }
        if self.reports.keep == 0 || self.reports.keep > 100_000 {
            errs.push("reports.keep must be between 1 and 100000".into());
        }

        if !["error", "warn", "info", "debug", "trace"].contains(&self.log.level.as_str()) {
            errs.push("log.level must be one of error, warn, info, debug, trace".into());
        }

        if errs.is_empty() {
            Ok(())
        } else {
            bail!("{}", errs.join("\n  - "))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const EXAMPLE: &str = include_str!("../event-horizon.example.toml");

    #[test]
    fn example_config_is_valid() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert!(c.dry_run);
        assert_eq!(c.guardrails.ttl.default, Secs(1800));
        assert!(c.detect.sflow.is_some());
        assert!(c.detect.netflow.is_some());
        assert!(c.flowspec.is_some());
        assert_eq!(c.detect.thresholds().unwrap().window, 10);
    }

    #[test]
    fn readme_configs_are_valid() {
        for (name, doc) in [
            ("README.md", include_str!("../README.md")),
            ("README.tr.md", include_str!("../README.tr.md")),
        ] {
            let block = doc
                .split("```toml")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or_else(|| panic!("{name} has no toml block"));
            Config::parse(block).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s"), Ok(30));
        assert_eq!(parse_duration("5m"), Ok(300));
        assert_eq!(parse_duration("6h"), Ok(21_600));
        assert_eq!(parse_duration("1d"), Ok(86_400));
        assert_eq!(parse_duration("45"), Ok(45));
        for bad in [
            "",
            "m",
            "5x",
            "-5m",
            "5 m",
            "1.5h",
            "é",
            "99999999999999999999d",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
        assert_eq!(fmt_duration(1800), "30m");
        assert_eq!(fmt_duration(21_600), "6h");
        assert_eq!(fmt_duration(90), "90s");
    }

    fn with(replace: &str, by: &str) -> Result<Config> {
        assert!(EXAMPLE.contains(replace), "{replace}");
        Config::parse(&EXAMPLE.replacen(replace, by, 1))
    }

    #[test]
    fn rejects_empty_protected() {
        let e = with(
            r#"protected = ["198.51.100.0/24", "2001:db8:100::/48"]"#,
            "protected = []",
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("refusing to run"));
    }

    #[test]
    fn rejects_default_route_in_protected() {
        assert!(with(r#""198.51.100.0/24", "2001"#, r#""0.0.0.0/0", "2001"#).is_err());
    }

    #[test]
    fn rejects_bad_ttl_order() {
        assert!(with(r#"min = "5m""#, r#"min = "7h""#).is_err());
    }

    #[test]
    fn rejects_ibgp_and_unknown_fields() {
        assert!(with("remote_asn = 64496", "remote_asn = 64500").is_err());
        assert!(with("dry_run = true", "dry_run = true\nsurprise = 1").is_err());
    }

    #[test]
    fn rejects_release_above_threshold() {
        assert!(with("release = { pps = 100000", "release = { pps = 900000").is_err());
    }

    #[test]
    fn normalizes_host_bits() {
        let c = with(r#""198.51.100.0/24", "2001"#, r#""198.51.100.9/24", "2001"#).unwrap();
        assert_eq!(c.guardrails.protected[0].to_string(), "198.51.100.0/24");
    }

    const LEGACY: &str = r#"
[bgp]
local_asn = 64500
router_id = "192.0.2.10"
[[bgp.upstream]]
name = "transit-a"
neighbor = "203.0.113.1"
remote_asn = 64496
[guardrails]
protected = ["198.51.100.0/24"]
max_active = 4
ttl = { min = "5m", default = "30m", max = "6h" }
[detect.sflow]
listen = "127.0.0.1:6343"
exporters = ["192.0.2.21"]
threshold = { pps = 1000 }
window = "20s"
"#;

    #[test]
    fn legacy_sflow_thresholds_still_work() {
        let c = Config::parse(LEGACY).unwrap();
        let t = c.detect.thresholds().unwrap();
        assert_eq!(t.threshold.pps, Some(1000));
        assert_eq!(t.release.pps, Some(500));
        assert_eq!(t.window, 20);
        assert_eq!(t.trigger_after, 30);
        // Without any threshold a collector is refused.
        assert!(Config::parse(&LEGACY.replace("threshold = { pps = 1000 }", "")).is_err());
    }

    #[test]
    fn rejects_bad_feature_settings() {
        // flowspec on an upstream without [flowspec]
        assert!(Config::parse(
            &LEGACY.replace("remote_asn = 64496", "remote_asn = 64496\nflowspec = true")
        )
        .is_err());
        // multihop 0, mixed family local address
        assert!(Config::parse(&LEGACY.replace(
            "remote_asn = 64496",
            "remote_asn = 64496\nebgp_multihop = 0"
        ))
        .is_err());
        assert!(Config::parse(&LEGACY.replace(
            "remote_asn = 64496",
            "remote_asn = 64496\nlocal_address = \"2001:db8::1\""
        ))
        .is_err());
        // region named global, or without communities
        assert!(Config::parse(&LEGACY.replace(
            "remote_asn = 64496",
            "remote_asn = 64496\nregions = { global = [\"64496:1\"] }"
        ))
        .is_err());
        assert!(Config::parse(&LEGACY.replace(
            "remote_asn = 64496",
            "remote_asn = 64496\nregions = { eu = [] }"
        ))
        .is_err());
        // discard without allow_discard
        assert!(with("allow_discard = true", "allow_discard = false")
            .map(|c| c.flowspec.unwrap().action == FlowActionKind::RateLimit)
            .unwrap_or(false));
        assert!(with("action = \"rate-limit\"", "action = \"discard\"").is_ok());
        assert!(with(
            "action = \"rate-limit\"",
            "action = \"discard\"\nallow_discard = false"
        )
        .is_err());
        // graceful restart time out of range
        assert!(with("restart_time = \"2m\"", "restart_time = \"2h\"").is_err());
        // approval with telegram needs users
        assert!(with("allowed_user_ids = [100000001]", "allowed_user_ids = []").is_err());
    }

    #[test]
    fn data_paths_default_into_data_dir() {
        let c = Config::parse(&format!("data_dir = \"/srv/eh\"\n{LEGACY}")).unwrap();
        assert_eq!(
            c.state_path(),
            Path::new("/srv/eh").join("event-horizon.state.json")
        );
        assert_eq!(c.reports_dir(), Path::new("/srv/eh").join("reports"));
        let c = Config::parse(EXAMPLE).unwrap();
        assert_eq!(c.state_path(), PathBuf::from("event-horizon.state.json"));
    }
}
