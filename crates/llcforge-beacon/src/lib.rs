//! Shared alerting and operations plumbing for the LLCForge network tools.
//!
//! * [`Alert`] — the common `llcforge.alert.v1` schema.
//! * [`Dispatcher`] / [`AlertHandle`] — non-blocking intake, dedup, silences,
//!   per-sink routing, persistent queue, redelivery, metrics.
//! * Sinks: stdout, webhook (HMAC), Telegram, Slack, Discord, Teams, e-mail,
//!   PagerDuty, Opsgenie, syslog.
//! * [`SilenceStore`] + [`silences_router`], [`health_router`] + [`Readiness`],
//!   [`ReloadSignal`] + [`reload_router`], [`init_logging`], [`service`].
#![deny(unsafe_code)]

pub mod alert;
pub mod auth;
#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
pub mod dispatcher;
pub mod filter;
pub mod health;
pub mod logging;
pub mod metrics;
pub mod queue;
pub mod reload;
pub mod service;
pub mod silence;
pub mod sink;

pub use alert::{Alert, Field, Link, Severity, SCHEMA_V1};
pub use auth::ApiToken;
pub use config::{
    env_secret, AlertsConfig, ConfigError, HealthConfig, QueueConfig, SilencesConfig, SinkConfig,
};
pub use dispatcher::{AlertHandle, Dispatcher, DispatcherOptions};
pub use filter::{glob_match, Filter};
pub use health::{health_router, serve, Readiness};
pub use logging::{init_logging, LogFormat};
pub use metrics::Metrics;
pub use reload::{reload_router, ReloadReason, ReloadSignal, ReloadTrigger};
pub use service::{run_service_command, ServiceAction, ServiceSpec, Shutdown};
pub use silence::{silences_router, NewSilence, Silence, SilenceStore};
pub use sink::{Sink, SinkError, SinkRunner};

use std::path::PathBuf;

/// Platform default data directory for a tool:
/// `$STATE_DIRECTORY` (systemd) if set; else Linux `$XDG_STATE_HOME/<bin>` or
/// `~/.local/state/<bin>`; macOS `~/Library/Application Support/<bin>`;
/// Windows `%ProgramData%\LLCForge\<bin>`; fallback `./<bin>-data`.
pub fn default_data_dir(bin: &str) -> PathBuf {
    if let Some(d) = std::env::var_os("STATE_DIRECTORY").filter(|v| !v.is_empty()) {
        // systemd may pass several colon-separated dirs; the first is ours.
        let s = d.to_string_lossy().into_owned();
        return PathBuf::from(s.split(':').next().unwrap_or(&s));
    }
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let dir = if cfg!(windows) {
        env("ProgramData").map(|p| p.join("LLCForge").join(bin))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Application Support").join(bin))
    } else {
        env("XDG_STATE_HOME")
            .map(|p| p.join(bin))
            .or_else(|| env("HOME").map(|h| h.join(".local/state").join(bin)))
    };
    dir.unwrap_or_else(|| PathBuf::from(format!("{bin}-data")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn data_dir_ends_with_bin() {
        assert!(super::default_data_dir("demo-tool").ends_with("demo-tool"));
    }
}
