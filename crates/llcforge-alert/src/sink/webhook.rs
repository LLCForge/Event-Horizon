//! Generic JSON webhook with optional bearer token and HMAC-SHA256 signature.
//!
//! Signature scheme (verify with [`verify_signature`]):
//! `X-LLCForge-Timestamp: <unix seconds>` and
//! `X-LLCForge-Signature: sha256=<hex(HMAC-SHA256(secret, "<timestamp>.<raw body>"))>`.
//! Receivers must reject timestamps outside a small tolerance (replay protection).

use ring::hmac;

use super::{check_response, http_error, SendFuture, Sink, SinkError};
use crate::alert::Alert;
use crate::config::{check_url, env_secret, ConfigError, WebhookConfig};

pub const SIGNATURE_HEADER: &str = "X-LLCForge-Signature";
pub const TIMESTAMP_HEADER: &str = "X-LLCForge-Timestamp";
pub const ALERT_ID_HEADER: &str = "X-LLCForge-Alert-Id";

/// Not `Debug`: holds secrets.
pub struct WebhookSink {
    url: reqwest::Url,
    bearer: Option<String>,
    hmac_key: Option<hmac::Key>,
    client: reqwest::Client,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Returns the header value `sha256=<hex>` for `timestamp` and `body`.
pub fn sign(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    sign_with(&key, timestamp, body)
}

fn sign_with(key: &hmac::Key, timestamp: i64, body: &[u8]) -> String {
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(timestamp.to_string().as_bytes());
    ctx.update(b".");
    ctx.update(body);
    format!("sha256={}", hex(ctx.sign().as_ref()))
}

/// Receiver-side check: constant-time HMAC verification plus a timestamp
/// window of `tolerance_secs` around `now_unix`.
pub fn verify_signature(
    secret: &[u8],
    timestamp: i64,
    body: &[u8],
    header: &str,
    now_unix: i64,
    tolerance_secs: i64,
) -> bool {
    if (now_unix - timestamp).abs() > tolerance_secs {
        return false;
    }
    let Some(hex_sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Some(sig) = unhex(hex_sig) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut msg = timestamp.to_string().into_bytes();
    msg.push(b'.');
    msg.extend_from_slice(body);
    hmac::verify(&key, &msg, &sig).is_ok()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || s.len() > 256 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl WebhookSink {
    pub fn new(
        url: reqwest::Url,
        bearer: Option<String>,
        hmac_secret: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        WebhookSink {
            url,
            bearer,
            hmac_key: hmac_secret.map(|s| hmac::Key::new(hmac::HMAC_SHA256, s.as_bytes())),
            client,
        }
    }

    pub fn from_config(c: &WebhookConfig, client: reqwest::Client) -> Result<Self, ConfigError> {
        let raw = match (&c.url, &c.url_env) {
            (Some(u), None) => u.clone(),
            (None, Some(var)) => env_secret(var)?,
            _ => {
                return Err(ConfigError::Invalid(
                    "webhook needs exactly one of url / url_env".into(),
                ))
            }
        };
        let url = check_url(&raw, c.allow_http)?;
        let bearer = c.bearer_token_env.as_deref().map(env_secret).transpose()?;
        let secret = c.hmac_secret_env.as_deref().map(env_secret).transpose()?;
        if secret.as_ref().is_some_and(|s| s.len() < 16) {
            return Err(ConfigError::Invalid(
                "webhook HMAC secret must be at least 16 bytes".into(),
            ));
        }
        Ok(Self::new(url, bearer, secret, client))
    }
}

impl Sink for WebhookSink {
    fn kind(&self) -> &'static str {
        "webhook"
    }

    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a> {
        Box::pin(async move {
            let body =
                serde_json::to_vec(alert).map_err(|e| SinkError::Permanent(e.to_string()))?;
            let ts = chrono::Utc::now().timestamp();
            let mut req = self
                .client
                .post(self.url.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(TIMESTAMP_HEADER, ts.to_string())
                .header(ALERT_ID_HEADER, header_safe(&alert.id));
            if let Some(key) = &self.hmac_key {
                req = req.header(SIGNATURE_HEADER, sign_with(key, ts, &body));
            }
            if let Some(token) = &self.bearer {
                req = req.bearer_auth(token);
            }
            let resp = req.body(body).send().await.map_err(http_error)?;
            check_response(resp).await
        })
    }
}

/// Header values must be visible ASCII; ids are tool-controlled but be strict anyway.
fn header_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .take(256)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::alert::Severity;

    #[test]
    fn hmac_known_vector_and_verify() {
        // RFC 4231 test case 2 key/data, framed as "<ts>.<body>".
        let sig = sign(b"Jefe", 0, b"what do ya want for nothing?");
        assert!(sig.starts_with("sha256=") && sig.len() == 7 + 64);
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, b"Jefe"));
        ctx.update(b"0.what do ya want for nothing?");
        assert_eq!(sig, format!("sha256={}", hex(ctx.sign().as_ref())));

        let body = br#"{"a":1}"#;
        let s = sign(b"0123456789abcdef", 1_700_000_000, body);
        assert!(verify_signature(
            b"0123456789abcdef",
            1_700_000_000,
            body,
            &s,
            1_700_000_100,
            300
        ));
        assert!(!verify_signature(
            b"0123456789abcdef",
            1_700_000_000,
            body,
            &s,
            1_700_001_000,
            300
        ));
        assert!(!verify_signature(
            b"wrong-secret-xxxxx",
            1_700_000_000,
            body,
            &s,
            1_700_000_000,
            300
        ));
        assert!(!verify_signature(
            b"0123456789abcdef",
            1_700_000_000,
            b"{}",
            &s,
            1_700_000_000,
            300
        ));
        assert!(!verify_signature(b"k", 0, b"", "sha256=zz", 0, 1));
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[tokio::test]
    async fn posts_signed_json_with_bearer() {
        let (url, seen) = mock(ok()).await;
        let secret = "0123456789abcdef0123";
        let sink = WebhookSink::new(
            reqwest::Url::parse(&format!("{url}/hook")).unwrap(),
            Some("tok-123".into()),
            Some(secret.into()),
            client(),
        );
        let a = Alert::new("notary", "vrp_stale", Severity::Warning, "VRPs stale");
        sink.send(&a).await.unwrap();
        let req = seen.lock().unwrap()[0].clone();
        assert_eq!(req.method, axum::http::Method::POST);
        assert_eq!(req.uri.path(), "/hook");
        assert_eq!(req.headers["authorization"], "Bearer tok-123");
        assert_eq!(req.headers["content-type"], "application/json");
        assert_eq!(req.headers[ALERT_ID_HEADER], "notary:vrp_stale");
        let ts: i64 = req.headers[TIMESTAMP_HEADER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let sig = req.headers[SIGNATURE_HEADER].to_str().unwrap();
        assert!(verify_signature(
            secret.as_bytes(),
            ts,
            &req.body,
            sig,
            ts,
            300
        ));
        let back: Alert = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(back, a);
    }
}
