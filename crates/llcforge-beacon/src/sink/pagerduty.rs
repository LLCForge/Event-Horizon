//! PagerDuty Events API v2: `trigger` for active alerts, `resolve` for
//! `resolved = true`, both keyed by `dedup_key = alert.id`.

use super::{check_response, http_error, SendFuture, Sink};
use crate::alert::{clip_chars, Alert, Severity};
use crate::config::{check_url, env_secret, ConfigError, PagerDutyConfig};

const DEFAULT_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// Not `Debug`: holds the routing key.
pub struct PagerDutySink {
    url: reqwest::Url,
    routing_key: String,
    client: reqwest::Client,
}

impl PagerDutySink {
    pub fn new(url: reqwest::Url, routing_key: String, client: reqwest::Client) -> Self {
        PagerDutySink {
            url,
            routing_key,
            client,
        }
    }

    pub fn from_config(c: &PagerDutyConfig, client: reqwest::Client) -> Result<Self, ConfigError> {
        let url = check_url(c.events_url.as_deref().unwrap_or(DEFAULT_URL), false)?;
        Ok(Self::new(url, env_secret(&c.routing_key_env)?, client))
    }

    pub fn payload(&self, a: &Alert) -> serde_json::Value {
        let dedup_key = clip_chars(&a.id, 255);
        if a.resolved {
            return serde_json::json!({
                "routing_key": self.routing_key,
                "event_action": "resolve",
                "dedup_key": dedup_key,
            });
        }
        let severity = match a.severity {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        let details: serde_json::Map<String, serde_json::Value> = a
            .fields
            .iter()
            .map(|f| (f.key.clone(), f.value.clone().into()))
            .chain(
                (!a.summary.is_empty()).then(|| ("summary".to_string(), a.summary.clone().into())),
            )
            .collect();
        let links: Vec<_> = a
            .links
            .iter()
            .map(|l| serde_json::json!({"href": l.url, "text": l.title}))
            .collect();
        serde_json::json!({
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": clip_chars(&a.headline(), 1024),
                "source": a.resource.clone().unwrap_or_else(|| a.tool.clone()),
                "severity": severity,
                "timestamp": a.last_seen.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "component": a.tool,
                "group": a.tool,
                "class": a.kind,
                "custom_details": details,
            },
            "links": links,
            "client": "LLCForge",
        })
    }
}

impl Sink for PagerDutySink {
    fn kind(&self) -> &'static str {
        "pagerduty"
    }

    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a> {
        Box::pin(async move {
            let resp = self
                .client
                .post(self.url.clone())
                .json(&self.payload(alert))
                .send()
                .await
                .map_err(http_error)?;
            check_response(resp).await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::{HeaderMap, StatusCode};

    use super::super::testutil::*;
    use super::*;

    #[tokio::test]
    async fn trigger_then_resolve_share_dedup_key() {
        let (url, seen) = mock(Arc::new(|_| {
            (
                StatusCode::ACCEPTED,
                HeaderMap::new(),
                r#"{"status":"success"}"#.into(),
            )
        }))
        .await;
        let sink = PagerDutySink::new(
            reqwest::Url::parse(&format!("{url}/v2/enqueue")).unwrap(),
            "R0UT1NGKEY".into(),
            client(),
        );
        let a = Alert::new("vigil", "hijack", Severity::Critical, "Hijack")
            .resource("192.0.2.0/24")
            .field("origin", "AS64512");
        sink.send(&a).await.unwrap();
        sink.send(&a.clone().resolved(true)).await.unwrap();
        let reqs = seen.lock().unwrap().clone();
        let t = reqs[0].json();
        let r = reqs[1].json();
        assert_eq!(t["event_action"], "trigger");
        assert_eq!(t["payload"]["severity"], "critical");
        assert_eq!(t["payload"]["source"], "192.0.2.0/24");
        assert_eq!(t["payload"]["custom_details"]["origin"], "AS64512");
        assert_eq!(r["event_action"], "resolve");
        assert_eq!(t["dedup_key"], r["dedup_key"]);
        assert_eq!(r["routing_key"], "R0UT1NGKEY");
    }
}
