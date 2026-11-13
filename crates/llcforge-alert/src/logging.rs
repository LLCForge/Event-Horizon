//! Uniform `tracing` initialisation for every LLCForge tool.

use std::str::FromStr;

use serde::Deserialize;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl FromStr for LogFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "text" | "pretty" | "plain" => Ok(LogFormat::Text),
            "json" => Ok(LogFormat::Json),
            other => Err(format!("unknown log format {other:?} (text|json)")),
        }
    }
}

/// Builds the filter: explicit `filter` directive > `RUST_LOG` > `level`.
pub fn build_filter(level: &str, filter: Option<&str>) -> Result<EnvFilter, String> {
    if let Some(f) = filter.filter(|f| !f.trim().is_empty()) {
        return EnvFilter::try_new(f).map_err(|e| format!("invalid log filter: {e}"));
    }
    if let Ok(env) = std::env::var("RUST_LOG") {
        if !env.trim().is_empty() {
            return EnvFilter::try_new(env).map_err(|e| format!("invalid RUST_LOG: {e}"));
        }
    }
    EnvFilter::try_new(level).map_err(|e| format!("invalid log level {level:?}: {e}"))
}

/// Installs the global subscriber, logging to stderr (stdout stays free for
/// the stdout sink and CLI output). JSON output is one object per line.
pub fn init_logging(format: LogFormat, level: &str, filter: Option<&str>) -> anyhow::Result<()> {
    let filter = build_filter(level, filter).map_err(anyhow::Error::msg)?;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true);
    let res = match format {
        LogFormat::Text => builder
            .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
            .try_init(),
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .try_init(),
    };
    res.map_err(|e| anyhow::anyhow!("logging already initialised: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_format_and_filter() {
        assert_eq!("JSON".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert!("xml".parse::<LogFormat>().is_err());
        assert!(build_filter("info", Some("llcforge_alert=debug,warn")).is_ok());
        assert!(build_filter("info", Some("[[[")).is_err());
    }

    #[test]
    fn init_once() {
        init_logging(LogFormat::Json, "off", Some("off")).unwrap();
        assert!(init_logging(LogFormat::Text, "off", Some("off")).is_err());
    }
}
