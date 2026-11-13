//! Discord webhook sink (one embed; mentions disabled).

use super::{capped_retry_after, http_error, SendFuture, Sink, SinkError};
use crate::alert::{clip_chars, Alert};
use crate::sink::slack::{color, state_label};

/// Not `Debug`: the webhook URL is a credential.
pub struct DiscordSink {
    url: reqwest::Url,
    client: reqwest::Client,
}

impl DiscordSink {
    pub fn new(url: reqwest::Url, client: reqwest::Client) -> Self {
        DiscordSink { url, client }
    }

    pub fn payload(a: &Alert) -> serde_json::Value {
        let fields: Vec<_> = a
            .fields
            .iter()
            .take(25)
            .map(|f| {
                let value = if f.value.is_empty() { "-" } else { &f.value };
                serde_json::json!({
                    "name": clip_chars(&f.key, 256),
                    "value": clip_chars(value, 1024),
                    "inline": f.value.chars().count() <= 40,
                })
            })
            .collect();
        let mut desc = a.summary.clone();
        if let Some(r) = &a.resource {
            desc = format!("Resource: `{}`\n{desc}", r.replace('`', "'"));
        }
        for l in &a.links {
            desc.push_str(&format!(
                "\n[{}]({})",
                l.title.replace(['[', ']'], ""),
                l.url.replace(')', "%29")
            ));
        }
        let mut embed = serde_json::json!({
            "title": clip_chars(&format!("[{}] {}", state_label(a), a.title), 256),
            "description": clip_chars(desc.trim(), 4096),
            "color": color(a),
            "fields": fields,
            "footer": {"text": clip_chars(&format!("{} / {}", a.tool, a.kind), 2048)},
            "timestamp": a.last_seen.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });
        if let Some(l) = a.links.first() {
            embed["url"] = l.url.clone().into();
        }
        serde_json::json!({
            "embeds": [embed],
            // Alert text is untrusted: never ping @everyone/@here/roles/users.
            "allowed_mentions": {"parse": []},
        })
    }
}

impl Sink for DiscordSink {
    fn kind(&self) -> &'static str {
        "discord"
    }

    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a> {
        Box::pin(async move {
            let resp = self
                .client
                .post(self.url.clone())
                .json(&Self::payload(alert))
                .send()
                .await
                .map_err(http_error)?;
            if resp.status().as_u16() == 429 {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                return Err(SinkError::Transient {
                    message: "HTTP 429 rate limited".into(),
                    retry_after: body["retry_after"].as_f64().and_then(capped_retry_after),
                });
            }
            super::check_response(resp).await
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

    #[tokio::test]
    async fn embed_shape_and_rate_limit() {
        let (url, seen) = mock(Arc::new(|n| {
            if n == 0 {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    HeaderMap::new(),
                    r#"{"retry_after":1.5}"#.into(),
                )
            } else {
                (StatusCode::NO_CONTENT, HeaderMap::new(), String::new())
            }
        }))
        .await;
        let sink = DiscordSink::new(reqwest::Url::parse(&url).unwrap(), client());
        let a = Alert::new(
            "pathology",
            "route_leak",
            Severity::Critical,
            "@everyone leak",
        )
        .resource("203.0.113.0/24")
        .field("peer", "AS64496");
        match sink.send(&a).await {
            Err(SinkError::Transient { retry_after, .. }) => {
                assert_eq!(retry_after, Some(Duration::from_millis(1500)))
            }
            other => panic!("{other:?}"),
        }
        sink.send(&a).await.unwrap();
        let v = seen.lock().unwrap()[1].json();
        assert_eq!(v["allowed_mentions"]["parse"].as_array().unwrap().len(), 0);
        assert_eq!(v["embeds"][0]["color"], 0xC62828);
        assert_eq!(v["embeds"][0]["fields"][0]["name"], "peer");
    }
}
