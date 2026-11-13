//! Slack incoming-webhook sink (Block Kit, mrkdwn-escaped).

use super::{check_response, http_error, SendFuture, Sink};
use crate::alert::{clip_chars, Alert};

/// Not `Debug`: the webhook URL is a credential.
pub struct SlackSink {
    url: reqwest::Url,
    client: reqwest::Client,
}

/// Slack mrkdwn control characters (`&`, `<`, `>`).
pub fn escape_mrkdwn(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub(crate) fn state_label(a: &Alert) -> String {
    if a.resolved {
        "RESOLVED".into()
    } else {
        a.severity.as_str().to_ascii_uppercase()
    }
}

/// RGB colour per state: critical red, warning amber, info blue, resolved green.
pub(crate) fn color(a: &Alert) -> u32 {
    use crate::alert::Severity::*;
    match (a.resolved, a.severity) {
        (true, _) => 0x2E7D32,
        (false, Critical) => 0xC62828,
        (false, Warning) => 0xF9A825,
        (false, Info) => 0x1565C0,
    }
}

impl SlackSink {
    pub fn new(url: reqwest::Url, client: reqwest::Client) -> Self {
        SlackSink { url, client }
    }

    pub fn payload(a: &Alert) -> serde_json::Value {
        let head = clip_chars(&format!("[{}] {}", state_label(a), a.title), 150);
        let mut blocks = vec![serde_json::json!({
            "type": "header",
            "text": {"type": "plain_text", "text": head, "emoji": false}
        })];
        if !a.summary.is_empty() {
            blocks.push(serde_json::json!({
                "type": "section",
                "text": {"type": "mrkdwn", "text": clip_chars(&escape_mrkdwn(&a.summary), 3000)}
            }));
        }
        let fields: Vec<_> = a
            .fields
            .iter()
            .take(10)
            .map(|f| {
                let text = format!("*{}*\n{}", escape_mrkdwn(&f.key), escape_mrkdwn(&f.value));
                serde_json::json!({"type": "mrkdwn", "text": clip_chars(&text, 2000)})
            })
            .collect();
        if !fields.is_empty() {
            blocks.push(serde_json::json!({"type": "section", "fields": fields}));
        }
        let mut ctx = format!("{} / {}", escape_mrkdwn(&a.tool), escape_mrkdwn(&a.kind));
        if let Some(r) = &a.resource {
            ctx.push_str(&format!(" | `{}`", escape_mrkdwn(r)));
        }
        for l in a.links.iter().take(5) {
            ctx.push_str(&format!(
                " | <{}|{}>",
                escape_mrkdwn(&l.url).replace('|', "%7C"),
                escape_mrkdwn(&l.title).replace('|', "/")
            ));
        }
        blocks.push(serde_json::json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": clip_chars(&ctx, 3000)}]
        }));
        serde_json::json!({
            "text": clip_chars(&escape_mrkdwn(&a.headline()), 3000),
            "blocks": blocks,
            "unfurl_links": false,
        })
    }
}

impl Sink for SlackSink {
    fn kind(&self) -> &'static str {
        "slack"
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
    async fn posts_escaped_blocks() {
        let (url, seen) = mock(ok()).await;
        let sink = SlackSink::new(
            reqwest::Url::parse(&format!("{url}/services/T/B/X")).unwrap(),
            client(),
        );
        let a = Alert::new("catchment", "shift", Severity::Warning, "Catchment shift")
            .summary("<!channel> & more")
            .resource("198.51.100.0/24")
            .field("site", "<ams>");
        sink.send(&a).await.unwrap();
        let req = seen.lock().unwrap()[0].clone();
        assert_eq!(req.uri.path(), "/services/T/B/X");
        let v = req.json();
        let s = v.to_string();
        assert!(s.contains("&lt;!channel&gt; &amp; more"));
        assert!(!s.contains("<!channel>"));
        assert_eq!(v["blocks"][0]["type"], "header");
        assert_eq!(v["blocks"][2]["fields"][0]["text"], "*site*\n&lt;ams&gt;");
    }
}
