//! Microsoft Teams sink: an Adaptive Card message, accepted both by Teams
//! Workflows ("When a Teams webhook request is received") and by legacy
//! incoming webhooks.

use super::{check_response, http_error, SendFuture, Sink};
use crate::alert::{clip_chars, Alert};
use crate::sink::slack::state_label;

/// Not `Debug`: the webhook URL is a credential.
pub struct TeamsSink {
    url: reqwest::Url,
    client: reqwest::Client,
}

impl TeamsSink {
    pub fn new(url: reqwest::Url, client: reqwest::Client) -> Self {
        TeamsSink { url, client }
    }

    pub fn payload(a: &Alert) -> serde_json::Value {
        use crate::alert::Severity::*;
        let color = match (a.resolved, a.severity) {
            (true, _) => "Good",
            (false, Critical) => "Attention",
            (false, Warning) => "Warning",
            (false, Info) => "Accent",
        };
        let mut facts: Vec<_> = a
            .fields
            .iter()
            .take(30)
            .map(|f| {
                serde_json::json!({"title": clip_chars(&f.key, 128), "value": clip_chars(&f.value, 1024)})
            })
            .collect();
        if let Some(r) = &a.resource {
            facts.insert(0, serde_json::json!({"title": "Resource", "value": r}));
        }
        facts.push(
            serde_json::json!({"title": "Source", "value": format!("{} / {}", a.tool, a.kind)}),
        );
        facts.push(serde_json::json!({
            "title": "Last seen",
            "value": a.last_seen.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }));
        let mut body = vec![serde_json::json!({
            "type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": true, "color": color,
            "text": clip_chars(&format!("[{}] {}", state_label(a), a.title), 512),
        })];
        if !a.summary.is_empty() {
            body.push(serde_json::json!({"type": "TextBlock", "wrap": true, "text": clip_chars(&a.summary, 4000)}));
        }
        body.push(serde_json::json!({"type": "FactSet", "facts": facts}));
        let actions: Vec<_> = a
            .links
            .iter()
            .take(5)
            .map(|l| serde_json::json!({"type": "Action.OpenUrl", "title": clip_chars(&l.title, 64), "url": l.url}))
            .collect();
        serde_json::json!({
            "type": "message",
            "summary": clip_chars(&a.headline(), 256),
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": body,
                    "actions": actions,
                }
            }]
        })
    }
}

impl Sink for TeamsSink {
    fn kind(&self) -> &'static str {
        "teams"
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
            check_response(resp).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::alert::Severity;

    #[tokio::test]
    async fn posts_adaptive_card() {
        let (url, seen) = mock(ok()).await;
        let sink = TeamsSink::new(reqwest::Url::parse(&url).unwrap(), client());
        let a = Alert::new("notary", "rpki_invalid", Severity::Critical, "Invalid")
            .resource("192.0.2.0/24")
            .link("Validator", "https://example.net/v");
        sink.send(&a).await.unwrap();
        let v = seen.lock().unwrap()[0].json();
        let card = &v["attachments"][0]["content"];
        assert_eq!(
            v["attachments"][0]["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        assert_eq!(card["type"], "AdaptiveCard");
        assert_eq!(card["body"][0]["color"], "Attention");
        assert_eq!(card["body"][1]["facts"][0]["value"], "192.0.2.0/24");
        assert_eq!(card["actions"][0]["url"], "https://example.net/v");
    }
}
