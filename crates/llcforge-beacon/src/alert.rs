//! The common alert schema shared by every LLCForge tool (`llcforge.alert.v1`).

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Schema identifier written into every serialized alert.
pub const SCHEMA_V1: &str = "llcforge.alert.v1";

const MAX_ID: usize = 512;
const MAX_TOOL: usize = 64;
const MAX_KIND: usize = 128;
const MAX_TITLE: usize = 512;
const MAX_SUMMARY: usize = 8192;
const MAX_RESOURCE: usize = 512;
const MAX_FIELDS: usize = 64;
const MAX_FIELD_KEY: usize = 128;
const MAX_FIELD_VALUE: usize = 2048;
const MAX_LINKS: usize = 16;
const MAX_URL: usize = 2048;

/// Alert severity, ordered `Info < Warning < Critical`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "warning" | "warn" => Ok(Severity::Warning),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity {other:?} (info|warning|critical)"
            )),
        }
    }
}

/// One ordered key/value detail line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub key: String,
    pub value: String,
}

/// A related link (looking glass, RPKI validator, CT log entry, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub title: String,
    pub url: String,
}

/// A tool-neutral alert. Build with [`Alert::new`] and the chained setters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alert {
    pub schema: String,
    /// Stable deduplication key: the same condition must always produce the same id.
    pub id: String,
    pub tool: String,
    pub kind: String,
    pub severity: Severity,
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub links: Vec<Link>,
    #[serde(default)]
    pub resolved: bool,
}

fn now_millis() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp_millis(now.timestamp_millis()).unwrap_or(now)
}

impl Alert {
    /// New alert with `id = "{tool}:{kind}"`; [`Alert::resource`] extends it to
    /// `"{tool}:{kind}:{resource}"` unless [`Alert::id`] was set explicitly.
    pub fn new(
        tool: impl Into<String>,
        kind: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
    ) -> Self {
        let tool = tool.into();
        let kind = kind.into();
        let now = now_millis();
        Alert {
            schema: SCHEMA_V1.to_string(),
            id: format!("{tool}:{kind}"),
            tool,
            kind,
            severity,
            title: title.into(),
            summary: String::new(),
            fields: Vec::new(),
            resource: None,
            first_seen: now,
            last_seen: now,
            links: Vec::new(),
            resolved: false,
        }
    }

    fn default_id(&self) -> String {
        format!("{}:{}", self.tool, self.kind)
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.fields.push(Field {
            key: key.into(),
            value: value.to_string(),
        });
        self
    }

    pub fn resource(mut self, r: impl Into<String>) -> Self {
        let r = r.into();
        if self.id == self.default_id() {
            self.id = format!("{}:{r}", self.id);
        }
        self.resource = Some(r);
        self
    }

    pub fn link(mut self, title: impl Into<String>, url: impl Into<String>) -> Self {
        self.links.push(Link {
            title: title.into(),
            url: url.into(),
        });
        self
    }

    pub fn first_seen(mut self, t: DateTime<Utc>) -> Self {
        self.first_seen = t;
        if self.last_seen < t {
            self.last_seen = t;
        }
        self
    }

    pub fn last_seen(mut self, t: DateTime<Utc>) -> Self {
        self.last_seen = t;
        self
    }

    /// Marks the alert as the resolution of a previously raised condition with the same id.
    pub fn resolved(mut self, resolved: bool) -> Self {
        self.resolved = resolved;
        self
    }

    /// Clamps every string to its documented limit, drops excess fields/links and
    /// non-HTTP(S) links. Returns an error only when a mandatory field is empty.
    pub fn normalize(&mut self) -> Result<(), String> {
        self.schema = SCHEMA_V1.to_string();
        truncate(&mut self.id, MAX_ID);
        truncate(&mut self.tool, MAX_TOOL);
        truncate(&mut self.kind, MAX_KIND);
        truncate(&mut self.title, MAX_TITLE);
        truncate(&mut self.summary, MAX_SUMMARY);
        if let Some(r) = &mut self.resource {
            truncate(r, MAX_RESOURCE);
        }
        self.fields.truncate(MAX_FIELDS);
        for f in &mut self.fields {
            truncate(&mut f.key, MAX_FIELD_KEY);
            truncate(&mut f.value, MAX_FIELD_VALUE);
        }
        self.links.retain(|l| {
            l.url.len() <= MAX_URL
                && (l.url.starts_with("https://") || l.url.starts_with("http://"))
        });
        self.links.truncate(MAX_LINKS);
        for l in &mut self.links {
            truncate(&mut l.title, MAX_TITLE);
        }
        if self.last_seen < self.first_seen {
            self.last_seen = self.first_seen;
        }
        for (name, v) in [
            ("id", &self.id),
            ("tool", &self.tool),
            ("kind", &self.kind),
            ("title", &self.title),
        ] {
            if v.trim().is_empty() {
                return Err(format!("alert {name} is empty"));
            }
        }
        Ok(())
    }

    /// Single-line plain text rendering (control characters replaced by spaces).
    pub fn headline(&self) -> String {
        let state = if self.resolved {
            "RESOLVED".to_string()
        } else {
            self.severity.as_str().to_ascii_uppercase()
        };
        let line = match &self.resource {
            Some(r) => format!("[{state}] {}/{} {r}: {}", self.tool, self.kind, self.title),
            None => format!("[{state}] {}/{}: {}", self.tool, self.kind, self.title),
        };
        line.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    }
}

/// Truncates on a char boundary to at most `max` bytes.
pub(crate) fn truncate(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

/// Returns at most `max` chars (not bytes) of `s`, appending `…` when cut.
pub(crate) fn clip_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_follows_resource_unless_explicit() {
        let a =
            Alert::new("vigil", "origin_hijack", Severity::Critical, "t").resource("192.0.2.0/24");
        assert_eq!(a.id, "vigil:origin_hijack:192.0.2.0/24");
        let b = Alert::new("vigil", "k", Severity::Info, "t")
            .id("x")
            .resource("r");
        assert_eq!(b.id, "x");
    }

    #[test]
    fn normalize_clamps_and_rejects_empty() {
        let mut a = Alert::new("t", "k", Severity::Info, "x".repeat(10_000))
            .link("bad", "javascript:alert(1)")
            .link("ok", "https://example.net/");
        a.normalize().unwrap();
        assert_eq!(a.title.len(), MAX_TITLE);
        assert_eq!(a.links.len(), 1);
        let mut e = Alert::new("t", "k", Severity::Info, "  ");
        assert!(e.normalize().is_err());
    }

    #[test]
    fn truncate_respects_char_boundary() {
        let mut s = "ğüşıöç".to_string();
        truncate(&mut s, 3);
        assert_eq!(s, "ğ");
        assert_eq!(clip_chars("abcdef", 4), "abc…");
    }

    #[test]
    fn roundtrip_json() {
        let a = Alert::new(
            "herald",
            "cert_issued",
            Severity::Warning,
            "New certificate",
        )
        .resource("example.org")
        .field("issuer", "Example CA")
        .link("crt", "https://example.net/c/1");
        let s = serde_json::to_string(&a).unwrap();
        let back: Alert = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
        assert!(s.contains("\"schema\":\"llcforge.alert.v1\""));
        assert!(s.contains("Z\""), "timestamps are RFC 3339 UTC: {s}");
    }
}
