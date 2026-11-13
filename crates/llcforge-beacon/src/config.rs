//! TOML configuration: `[alerts]`, `[[alerts.sink]]`, `[silences]`, `[health]`.
//!
//! Secrets are never written in config files: every secret field is the *name*
//! of an environment variable (`*_env`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use crate::alert::Severity;
use crate::filter::Filter;

/// Configuration error (bad value, missing secret, unsupported transport).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
    #[error("environment variable {0} is not set or empty")]
    MissingEnv(String),
}

/// Reads a secret from the environment variable named `var`.
pub fn env_secret(var: &str) -> Result<String, ConfigError> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(ConfigError::MissingEnv(var.to_string())),
    }
}

/// `[alerts]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AlertsConfig {
    /// Identical alert ids (same resolved state) inside this window are suppressed.
    pub dedup_window_secs: u64,
    /// Capacity of the non-blocking in-process channel in front of the dispatcher.
    pub channel_capacity: usize,
    pub queue: QueueConfig,
    #[serde(rename = "sink")]
    pub sinks: Vec<SinkConfig>,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        AlertsConfig {
            dedup_window_secs: 300,
            channel_capacity: 1024,
            queue: QueueConfig::default(),
            sinks: Vec::new(),
        }
    }
}

/// `[alerts.queue]`: the persistent on-disk delivery queue.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct QueueConfig {
    /// Disable to keep undelivered alerts in memory only.
    pub persistent: bool,
    /// Defaults to `<data_dir>/alert-queue`.
    pub dir: Option<PathBuf>,
    pub max_entries: usize,
    pub max_bytes: u64,
    pub segment_bytes: u64,
    /// Delay before a sink that exhausted its retries gets the alert again.
    pub redeliver_after_secs: u64,
    /// Undelivered alerts older than this are dropped (counted as failed).
    pub max_age_secs: u64,
}

impl Default for QueueConfig {
    fn default() -> Self {
        QueueConfig {
            persistent: true,
            dir: None,
            max_entries: 10_000,
            max_bytes: 64 * 1024 * 1024,
            segment_bytes: 4 * 1024 * 1024,
            redeliver_after_secs: 60,
            max_age_secs: 86_400,
        }
    }
}

/// `[silences]` section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SilencesConfig {
    /// Defaults to `<data_dir>/silences.json`.
    pub path: Option<PathBuf>,
    /// Bearer token for `/v1/silences`; the API is not mounted when unset.
    pub api_token_env: Option<String>,
}

impl SilencesConfig {
    pub fn path_or(&self, data_dir: &Path) -> PathBuf {
        self.path
            .clone()
            .unwrap_or_else(|| data_dir.join("silences.json"))
    }
}

/// `[health]` section: the admin/health HTTP listener.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthConfig {
    /// e.g. `127.0.0.1:9180`; disabled when unset.
    pub listen: Option<SocketAddr>,
    /// Bearer token for `POST /v1/reload`; the route is not mounted when unset.
    pub admin_token_env: Option<String>,
}

/// One `[[alerts.sink]]` entry: common options plus the `type`-specific table.
#[derive(Debug, Clone)]
pub struct SinkConfig {
    pub common: SinkCommon,
    pub kind: SinkKind,
}

/// Options shared by every sink type.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SinkCommon {
    /// Unique name (metrics label, queue routing). Defaults to `<type>-<index>`.
    pub name: Option<String>,
    pub min_severity: Severity,
    pub tools: Vec<String>,
    pub kinds: Vec<String>,
    /// Resource globs, e.g. `["192.0.2.*", "*.example.org"]`.
    pub resources: Vec<String>,
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
    /// Token-bucket rate; 0 disables limiting.
    pub rate_per_minute: u32,
    pub burst: Option<u32>,
}

impl Default for SinkCommon {
    fn default() -> Self {
        SinkCommon {
            name: None,
            min_severity: Severity::Info,
            tools: Vec::new(),
            kinds: Vec::new(),
            resources: Vec::new(),
            timeout_secs: 10,
            max_retries: 3,
            backoff_base_ms: 500,
            backoff_max_ms: 30_000,
            rate_per_minute: 30,
            burst: None,
        }
    }
}

impl SinkCommon {
    pub fn filter(&self) -> Filter {
        Filter {
            min_severity: self.min_severity,
            tools: self.tools.clone(),
            kinds: self.kinds.clone(),
            resources: self.resources.clone(),
        }
    }
}

const COMMON_KEYS: &[&str] = &[
    "name",
    "min_severity",
    "tools",
    "kinds",
    "resources",
    "timeout_secs",
    "max_retries",
    "backoff_base_ms",
    "backoff_max_ms",
    "rate_per_minute",
    "burst",
];

impl<'de> Deserialize<'de> for SinkConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Split the table so both halves can keep deny_unknown_fields
        // (serde's flatten would silently swallow typos in secret names).
        let mut table = toml::Table::deserialize(d)?;
        let mut common = toml::Table::new();
        for key in COMMON_KEYS {
            if let Some(v) = table.remove(*key) {
                common.insert((*key).to_string(), v);
            }
        }
        let common: SinkCommon = toml::Value::Table(common)
            .try_into()
            .map_err(D::Error::custom)?;
        let kind: SinkKind = toml::Value::Table(table)
            .try_into()
            .map_err(D::Error::custom)?;
        Ok(SinkConfig { common, kind })
    }
}

/// Type-specific sink settings, selected by `type = "..."`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkKind {
    Stdout(StdoutConfig),
    Webhook(WebhookConfig),
    Telegram(TelegramConfig),
    Slack(ChatWebhookConfig),
    Discord(ChatWebhookConfig),
    Teams(ChatWebhookConfig),
    #[serde(alias = "smtp")]
    Email(EmailConfig),
    #[serde(alias = "pager_duty")]
    Pagerduty(PagerDutyConfig),
    Opsgenie(OpsgenieConfig),
    Syslog(SyslogConfig),
}

impl SinkKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            SinkKind::Stdout(_) => "stdout",
            SinkKind::Webhook(_) => "webhook",
            SinkKind::Telegram(_) => "telegram",
            SinkKind::Slack(_) => "slack",
            SinkKind::Discord(_) => "discord",
            SinkKind::Teams(_) => "teams",
            SinkKind::Email(_) => "email",
            SinkKind::Pagerduty(_) => "pagerduty",
            SinkKind::Opsgenie(_) => "opsgenie",
            SinkKind::Syslog(_) => "syslog",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StdoutConfig {
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebhookConfig {
    /// Endpoint URL (use `url_env` instead when the URL itself is a secret).
    pub url: Option<String>,
    pub url_env: Option<String>,
    /// Sent as `Authorization: Bearer <token>`.
    pub bearer_token_env: Option<String>,
    /// Enables `X-LLCForge-Signature: sha256=<hex>` over `"<timestamp>.<body>"`.
    pub hmac_secret_env: Option<String>,
    /// Plain `http://` is refused for non-loopback hosts unless set.
    pub allow_http: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    pub bot_token_env: String,
    #[serde(deserialize_with = "string_or_int")]
    pub chat_id: String,
    #[serde(default)]
    pub message_thread_id: Option<i64>,
    /// Override for tests or a self-hosted Bot API server.
    #[serde(default)]
    pub api_base: Option<String>,
}

/// Slack, Discord and Teams: the webhook URL is a credential, so env only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatWebhookConfig {
    pub url_env: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpTls {
    /// Plain connection upgraded with STARTTLS (port 587). TLS is mandatory.
    #[default]
    Starttls,
    /// Implicit TLS (port 465).
    Tls,
    /// No TLS: only accepted for loopback relays.
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub tls: SmtpTls,
    #[serde(default)]
    pub username_env: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagerDutyConfig {
    pub routing_key_env: String,
    /// Defaults to `https://events.pagerduty.com/v2/enqueue`
    /// (EU: `https://events.eu.pagerduty.com/v2/enqueue`).
    #[serde(default)]
    pub events_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpsgenieConfig {
    pub api_key_env: String,
    /// Defaults to `https://api.opsgenie.com` (EU: `https://api.eu.opsgenie.com`).
    #[serde(default)]
    pub api_base: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogTransport {
    Udp,
    Tcp,
    Tls,
    /// Local datagram socket (`/dev/log`, macOS `/var/run/syslog`). Unix only.
    Unix,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogConfig {
    pub transport: SyslogTransport,
    /// `host:port` for udp/tcp/tls.
    #[serde(default)]
    pub address: Option<String>,
    /// Socket path for `unix`; defaults to the platform's local syslog socket.
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_facility")]
    pub facility: String,
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    /// Extra PEM CA bundle for `tls` (private collectors).
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// TLS server name if it differs from the host in `address`.
    #[serde(default)]
    pub server_name: Option<String>,
}

fn default_facility() -> String {
    "daemon".to_string()
}

fn string_or_int<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        S(String),
        I(i64),
    }
    Ok(match V::deserialize(d)? {
        V::S(s) => s,
        V::I(i) => i.to_string(),
    })
}

/// Accepts `https://` always and `http://` only for loopback hosts or when `allow_http`.
pub(crate) fn check_url(url: &str, allow_http: bool) -> Result<reqwest::Url, ConfigError> {
    let parsed =
        reqwest::Url::parse(url).map_err(|e| ConfigError::Invalid(format!("invalid URL: {e}")))?;
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if allow_http || is_loopback_host(parsed.host_str().unwrap_or("")) => Ok(parsed),
        "http" => Err(ConfigError::Invalid(
            "plain http:// is only allowed for loopback hosts (set allow_http = true to override)"
                .into(),
        )),
        other => Err(ConfigError::Invalid(format!(
            "unsupported URL scheme {other}"
        ))),
    }
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Root {
        alerts: AlertsConfig,
        #[serde(default)]
        silences: SilencesConfig,
        #[serde(default)]
        health: HealthConfig,
    }

    #[test]
    fn parses_full_example() {
        let src = r#"
[alerts]
dedup_window_secs = 600
[alerts.queue]
max_entries = 100

[[alerts.sink]]
type = "stdout"
format = "json"

[[alerts.sink]]
type = "telegram"
name = "noc"
bot_token_env = "TG_TOKEN"
chat_id = -1001234567890
min_severity = "warning"
resources = ["192.0.2.*"]

[[alerts.sink]]
type = "syslog"
transport = "udp"
address = "192.0.2.10:514"

[silences]
api_token_env = "SILENCE_TOKEN"

[health]
listen = "127.0.0.1:9180"
"#;
        let r: Root = toml::from_str(src).unwrap();
        assert_eq!(r.alerts.dedup_window_secs, 600);
        assert_eq!(r.alerts.sinks.len(), 3);
        let tg = &r.alerts.sinks[1];
        assert_eq!(tg.common.name.as_deref(), Some("noc"));
        assert_eq!(tg.common.min_severity, Severity::Warning);
        match &tg.kind {
            SinkKind::Telegram(t) => assert_eq!(t.chat_id, "-1001234567890"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(r.health.listen.is_some());
        assert_eq!(r.silences.api_token_env.as_deref(), Some("SILENCE_TOKEN"));
    }

    #[test]
    fn rejects_typos_in_both_halves() {
        let bad_kind = "[[sink]]\ntype = \"slack\"\nurl_evn = \"X\"\n";
        let bad_common = "[[sink]]\ntype = \"stdout\"\nmin_severty = \"info\"\n";
        let bad_type = "[[sink]]\ntype = \"carrier_pigeon\"\n";
        #[derive(Deserialize, Debug)]
        #[allow(dead_code)]
        struct R {
            sink: Vec<SinkConfig>,
        }
        for src in [bad_kind, bad_common, bad_type] {
            assert!(toml::from_str::<R>(src).is_err(), "{src}");
        }
    }

    #[test]
    fn url_policy() {
        assert!(check_url("https://example.net/x", false).is_ok());
        assert!(check_url("http://127.0.0.1:8080/x", false).is_ok());
        assert!(check_url("http://[::1]/x", false).is_ok());
        assert!(check_url("http://example.net/x", false).is_err());
        assert!(check_url("http://example.net/x", true).is_ok());
        assert!(check_url("file:///etc/passwd", true).is_err());
    }
}
