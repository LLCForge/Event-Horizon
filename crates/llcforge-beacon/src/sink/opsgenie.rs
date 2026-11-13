//! Opsgenie Alert API: create (`POST /v2/alerts`, `alias = alert.id`) and
//! close by alias (`POST /v2/alerts/{alias}/close?identifierType=alias`).

use super::{check_response, http_error, SendFuture, Sink, SinkError};
use crate::alert::{clip_chars, Alert, Severity};
use crate::config::{check_url, env_secret, ConfigError, OpsgenieConfig};

const DEFAULT_BASE: &str = "https://api.opsgenie.com";

/// Not `Debug`: holds the API key.
pub struct OpsgenieSink {
    base: reqwest::Url,
    api_key: String,
    tags: Vec<String>,
    client: reqwest::Client,
}

impl OpsgenieSink {
    pub fn new(
        base: reqwest::Url,
        api_key: String,
        tags: Vec<String>,
        client: reqwest::Client,
    ) -> Self {
        OpsgenieSink {
            base,
            api_key,
            tags,
            client,
        }
    }

    pub fn from_config(c: &OpsgenieConfig, client: reqwest::Client) -> Result<Self, ConfigError> {
        let base = check_url(c.api_base.as_deref().unwrap_or(DEFAULT_BASE), false)?;
        Ok(Self::new(
            base,
            env_secret(&c.api_key_env)?,
            c.tags.clone(),
            client,
        ))
    }

    fn alias(a: &Alert) -> String {
        clip_chars(&a.id, 512)
    }

    pub fn create_payload(&self, a: &Alert) -> serde_json::Value {
        let priority = match a.severity {
            Severity::Critical => "P1",
            Severity::Warning => "P3",
            Severity::Info => "P5",
        };
        let mut tags: Vec<String> = vec![a.tool.clone(), a.kind.clone(), a.severity.to_string()];
        tags.extend(self.tags.iter().cloned());
        tags.iter_mut().for_each(|t| *t = clip_chars(t, 50));
        tags.truncate(20);
        let mut details: serde_json::Map<String, serde_json::Value> = a
            .fields
            .iter()
            .map(|f| (clip_chars(&f.key, 100), clip_chars(&f.value, 1000).into()))
            .collect();
        for (i, l) in a.links.iter().enumerate() {
            details.insert(format!("link{}", i + 1), l.url.clone().into());
        }
        let mut desc = a.summary.clone();
        if let Some(r) = &a.resource {
            desc = format!("Resource: {r}\n{desc}");
        }
        serde_json::json!({
            "message": clip_chars(&a.title, 130),
            "alias": Self::alias(a),
            "description": clip_chars(desc.trim(), 15_000),
            "priority": priority,
            "source": a.tool,
            "entity": a.resource.as_deref().map(|r| clip_chars(r, 512)).unwrap_or_default(),
            "tags": tags,
            "details": details,
        })
    }

    fn close_url(&self, a: &Alert) -> Result<reqwest::Url, SinkError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| SinkError::Permanent("opsgenie api_base cannot be a base URL".into()))?
            .pop_if_empty()
            .extend(["v2", "alerts", &Self::alias(a), "close"]);
        url.query_pairs_mut().append_pair("identifierType", "alias");
        Ok(url)
    }
}

impl Sink for OpsgenieSink {
    fn kind(&self) -> &'static str {
        "opsgenie"
    }

    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a> {
        Box::pin(async move {
            let (url, body) = if alert.resolved {
                (
                    self.close_url(alert)?,
                    serde_json::json!({"source": alert.tool, "note": "Resolved by LLCForge"}),
                )
            } else {
                let mut url = self.base.clone();
                url.path_segments_mut()
                    .map_err(|()| SinkError::Permanent("invalid opsgenie api_base".into()))?
                    .pop_if_empty()
                    .extend(["v2", "alerts"]);
                (url, self.create_payload(alert))
            };
            let resp = self
                .client
                .post(url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("GenieKey {}", self.api_key),
                )
                .json(&body)
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
    async fn create_and_close_by_alias() {
        let (url, seen) = mock(Arc::new(|_| {
            (
                StatusCode::ACCEPTED,
                HeaderMap::new(),
                r#"{"result":"Request will be processed"}"#.into(),
            )
        }))
        .await;
        let sink = OpsgenieSink::new(
            reqwest::Url::parse(&url).unwrap(),
            "key-1".into(),
            vec!["bgp".into()],
            client(),
        );
        let a = Alert::new("herald", "cert", Severity::Warning, "New cert")
            .resource("www.example.org")
            .id("herald:cert/www example.org");
        sink.send(&a).await.unwrap();
        sink.send(&a.clone().resolved(true)).await.unwrap();
        let reqs = seen.lock().unwrap().clone();
        assert_eq!(reqs[0].uri.path(), "/v2/alerts");
        assert_eq!(reqs[0].headers["authorization"], "GenieKey key-1");
        let c = reqs[0].json();
        assert_eq!(c["alias"], "herald:cert/www example.org");
        assert_eq!(c["priority"], "P3");
        assert_eq!(c["tags"][3], "bgp");
        assert_eq!(
            reqs[1].uri.path(),
            "/v2/alerts/herald:cert%2Fwww%20example.org/close"
        );
        assert_eq!(reqs[1].uri.query(), Some("identifierType=alias"));
    }
}
