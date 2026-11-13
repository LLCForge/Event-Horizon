//! Telegram Bot API sink (`parse_mode = HTML`, every dynamic value escaped).

use super::{capped_retry_after, http_error, SendFuture, Sink, SinkError};
use crate::alert::{clip_chars, Alert};
use crate::config::{check_url, env_secret, ConfigError, TelegramConfig};

const DEFAULT_API: &str = "https://api.telegram.org";
const MAX_MESSAGE: usize = 4096;

/// Not `Debug`: the bot token is a secret (and part of the request URL).
pub struct TelegramSink {
    api_base: String,
    token: String,
    chat_id: String,
    thread_id: Option<i64>,
    client: reqwest::Client,
}

/// Escapes text for Telegram HTML (`&`, `<`, `>`, `"`).
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// Renders the HTML message. Lines are added whole so truncation never cuts a tag.
pub fn render_html(a: &Alert) -> String {
    let state = if a.resolved {
        "RESOLVED".to_string()
    } else {
        a.severity.as_str().to_ascii_uppercase()
    };
    let mut lines = vec![
        format!(
            "<b>[{state}] {}</b>",
            escape_html(&clip_chars(&a.title, 300))
        ),
        format!("<i>{} / {}</i>", escape_html(&a.tool), escape_html(&a.kind)),
    ];
    if let Some(r) = &a.resource {
        lines.push(format!("Resource: <code>{}</code>", escape_html(r)));
    }
    if !a.summary.is_empty() {
        lines.push(escape_html(&clip_chars(&a.summary, 1500)));
    }
    for f in &a.fields {
        lines.push(format!(
            "<b>{}</b>: <code>{}</code>",
            escape_html(&f.key),
            escape_html(&clip_chars(&f.value, 300))
        ));
    }
    lines.push(format!(
        "First seen: {}\nLast seen: {}",
        a.first_seen
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        a.last_seen
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    ));
    for l in &a.links {
        lines.push(format!(
            "<a href=\"{}\">{}</a>",
            escape_html(&l.url),
            escape_html(&l.title)
        ));
    }
    let mut out = String::new();
    for line in lines {
        let extra = line.chars().count() + usize::from(!out.is_empty());
        if out.chars().count() + extra > MAX_MESSAGE {
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&line);
    }
    out
}

impl TelegramSink {
    pub fn new(
        api_base: &str,
        token: String,
        chat_id: String,
        thread_id: Option<i64>,
        client: reqwest::Client,
    ) -> Self {
        TelegramSink {
            api_base: api_base.trim_end_matches('/').to_string(),
            token,
            chat_id,
            thread_id,
            client,
        }
    }

    pub fn from_config(c: &TelegramConfig, client: reqwest::Client) -> Result<Self, ConfigError> {
        let base = c.api_base.as_deref().unwrap_or(DEFAULT_API);
        check_url(base, false)?;
        let token = env_secret(&c.bot_token_env)?;
        if !token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == ':' || ch == '_' || ch == '-')
        {
            return Err(ConfigError::Invalid(
                "telegram bot token has an invalid format".into(),
            ));
        }
        if c.chat_id.trim().is_empty() {
            return Err(ConfigError::Invalid("telegram chat_id is empty".into()));
        }
        Ok(Self::new(
            base,
            token,
            c.chat_id.clone(),
            c.message_thread_id,
            client,
        ))
    }

    pub fn payload(&self, a: &Alert) -> serde_json::Value {
        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": render_html(a),
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        if let Some(t) = self.thread_id {
            body["message_thread_id"] = t.into();
        }
        body
    }
}

impl Sink for TelegramSink {
    fn kind(&self) -> &'static str {
        "telegram"
    }

    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a> {
        Box::pin(async move {
            let url = format!("{}/bot{}/sendMessage", self.api_base, self.token);
            let resp = self
                .client
                .post(url)
                .json(&self.payload(alert))
                .send()
                .await
                .map_err(http_error)?;
            let status = resp.status();
            if status.is_success() {
                return Ok(());
            }
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let desc = body["description"].as_str().unwrap_or("").to_string();
            let message = format!("HTTP {status}: {}", clip_chars(&desc, 200));
            if status.as_u16() == 429 || status.is_server_error() {
                Err(SinkError::Transient {
                    message,
                    retry_after: body["parameters"]["retry_after"]
                        .as_f64()
                        .and_then(capped_retry_after),
                })
            } else {
                Err(SinkError::Permanent(message))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::{HeaderMap, StatusCode};

    use super::super::testutil::*;
    use super::*;
    use crate::alert::Severity;

    fn alert() -> Alert {
        Alert::new("herald", "cert", Severity::Critical, "<script>&\"x\"")
            .resource("evil<b>.example.org")
            .summary("a < b & c > d")
            .field("k<", "v&")
            .link("t\"", "https://example.net/?a=1&b=\"2\"")
    }

    #[test]
    fn escapes_everything() {
        let h = render_html(&alert());
        assert!(h.contains("&lt;script&gt;&amp;&quot;x&quot;"));
        assert!(h.contains("<code>evil&lt;b&gt;.example.org</code>"));
        assert!(h.contains("a &lt; b &amp; c &gt; d"));
        assert!(h.contains("<b>k&lt;</b>: <code>v&amp;</code>"));
        assert!(h.contains("href=\"https://example.net/?a=1&amp;b=&quot;2&quot;\""));
        assert!(!h.contains("<script>"));
    }

    #[test]
    fn message_is_bounded() {
        let mut a = alert();
        for i in 0..64 {
            a = a.field(format!("f{i}"), "x".repeat(300));
        }
        assert!(render_html(&a).chars().count() <= MAX_MESSAGE);
    }

    #[tokio::test]
    async fn sends_and_honours_retry_after() {
        let (url, seen) = mock(Arc::new(|n| {
            if n == 0 {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    HeaderMap::new(),
                    r#"{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":7}}"#.into(),
                )
            } else {
                (StatusCode::OK, HeaderMap::new(), r#"{"ok":true}"#.into())
            }
        }))
        .await;
        let sink = TelegramSink::new(&url, "123:ABC".into(), "-100200".into(), Some(5), client());
        match sink.send(&alert()).await {
            Err(SinkError::Transient { retry_after, .. }) => {
                assert_eq!(retry_after, Some(Duration::from_secs(7)))
            }
            other => panic!("unexpected {other:?}"),
        }
        sink.send(&alert()).await.unwrap();
        let req = seen.lock().unwrap()[1].clone();
        assert_eq!(req.uri.path(), "/bot123:ABC/sendMessage");
        let v = req.json();
        assert_eq!(v["chat_id"], "-100200");
        assert_eq!(v["parse_mode"], "HTML");
        assert_eq!(v["message_thread_id"], 5);
    }

    #[tokio::test]
    async fn bad_request_is_permanent() {
        let (url, _) = mock(Arc::new(|_| {
            (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                r#"{"ok":false,"description":"chat not found"}"#.into(),
            )
        }))
        .await;
        let sink = TelegramSink::new(&url, "1:A".into(), "1".into(), None, client());
        assert!(matches!(
            sink.send(&alert()).await,
            Err(SinkError::Permanent(_))
        ));
    }
}
