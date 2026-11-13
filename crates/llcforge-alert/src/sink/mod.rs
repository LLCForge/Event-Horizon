//! Delivery sinks behind one [`Sink`] trait, plus the shared retry / rate-limit
//! / timeout wrapper ([`SinkRunner`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::alert::Alert;
use crate::config::{env_secret, AlertsConfig, ConfigError, SinkConfig, SinkKind};
use crate::filter::Filter;
use crate::metrics::SinkMetrics;

#[cfg(feature = "smtp")]
pub mod email;
pub mod opsgenie;
pub mod pagerduty;
pub mod slack;
pub mod stdout;
pub mod syslog;
pub mod teams;
pub mod telegram;
pub mod webhook;

pub mod discord;

/// Boxed future returned by [`Sink::send`].
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SinkError>> + Send + 'a>>;

/// A single delivery destination. Implementations must not log secrets.
pub trait Sink: Send + Sync {
    /// Short type name (`"webhook"`, `"telegram"`, ...).
    fn kind(&self) -> &'static str;
    /// One delivery attempt. Retries, timeouts and rate limits are applied by the caller.
    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a>;
}

/// Outcome of a failed attempt.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// Worth retrying (network error, 429, 5xx). `retry_after` honours server hints.
    #[error("transient delivery failure: {message}")]
    Transient {
        message: String,
        retry_after: Option<Duration>,
    },
    /// Retrying cannot help (4xx, bad credentials, invalid payload).
    #[error("permanent delivery failure: {0}")]
    Permanent(String),
}

impl SinkError {
    pub fn transient(message: impl Into<String>) -> Self {
        SinkError::Transient {
            message: message.into(),
            retry_after: None,
        }
    }
}

const MAX_RETRY_AFTER: Duration = Duration::from_secs(600);
const ERROR_BODY_SNIPPET: usize = 256;

/// Maps a reqwest error; `without_url` keeps tokens embedded in URLs out of logs.
pub(crate) fn http_error(e: reqwest::Error) -> SinkError {
    SinkError::transient(e.without_url().to_string())
}

fn retry_after_header(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|s| s.is_finite() && *s >= 0.0)
        .map(|s| Duration::from_secs_f64(s).min(MAX_RETRY_AFTER))
}

/// Classifies an HTTP response: 2xx ok, 408/429/5xx transient, other 4xx permanent.
pub(crate) async fn check_response(resp: reqwest::Response) -> Result<(), SinkError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let retry_after = retry_after_header(&resp);
    let mut body = resp.text().await.unwrap_or_default();
    crate::alert::truncate(&mut body, ERROR_BODY_SNIPPET);
    let message = format!("HTTP {status}: {}", body.trim());
    if status.as_u16() == 429 || status.as_u16() == 408 || status.is_server_error() {
        Err(SinkError::Transient {
            message,
            retry_after,
        })
    } else {
        Err(SinkError::Permanent(message))
    }
}

pub(crate) fn capped_retry_after(secs: f64) -> Option<Duration> {
    (secs.is_finite() && secs >= 0.0).then(|| Duration::from_secs_f64(secs).min(MAX_RETRY_AFTER))
}

/// Shared HTTP client: no redirects (a redirect would forward signed bodies
/// and bearer tokens to an unexpected host), rustls, bounded connect time.
pub fn http_client() -> Result<reqwest::Client, ConfigError> {
    reqwest::Client::builder()
        .user_agent(concat!("llcforge-alert/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| ConfigError::Invalid(format!("HTTP client: {e}")))
}

/// Token bucket; `rate_per_minute == 0` means unlimited.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    capacity: f64,
    tokens: f64,
    per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub(crate) fn new(rate_per_minute: u32, burst: Option<u32>) -> Self {
        let capacity = f64::from(burst.unwrap_or(rate_per_minute).max(1));
        TokenBucket {
            capacity,
            tokens: capacity,
            per_sec: f64::from(rate_per_minute) / 60.0,
            last: Instant::now(),
        }
    }

    /// Takes a token, or returns how long to wait for the next one.
    pub(crate) fn take(&mut self, now: Instant) -> Result<(), Duration> {
        if self.per_sec <= 0.0 {
            return Ok(());
        }
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - self.tokens) / self.per_sec))
        }
    }
}

/// Exponential backoff with jitter in `[delay/2, delay]`.
pub(crate) fn backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    let exp = base.saturating_mul(2u32.saturating_pow(attempt.min(20)));
    let capped = exp.min(max);
    capped.mul_f64(0.5 + fastrand::f64() * 0.5)
}

/// Terminal result of [`SinkRunner::deliver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// Retries exhausted; the dispatcher redelivers later.
    Failed,
    /// Will never succeed; the dispatcher drops it.
    Rejected,
}

/// A configured sink with its filter, timeout, retry policy, rate limit and counters.
pub struct SinkRunner {
    pub name: String,
    pub filter: Filter,
    sink: Box<dyn Sink>,
    timeout: Duration,
    max_retries: u32,
    backoff_base: Duration,
    backoff_max: Duration,
    bucket: Mutex<TokenBucket>,
    pub metrics: Arc<SinkMetrics>,
}

impl SinkRunner {
    pub fn new(name: impl Into<String>, filter: Filter, sink: Box<dyn Sink>) -> Self {
        let name = name.into();
        let metrics = Arc::new(SinkMetrics::new(&name, sink.kind()));
        SinkRunner {
            name,
            filter,
            sink,
            timeout: Duration::from_secs(10),
            max_retries: 3,
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            bucket: Mutex::new(TokenBucket::new(0, None)),
            metrics,
        }
    }

    /// Overrides timeout / retry / rate settings.
    pub fn with_policy(
        mut self,
        timeout: Duration,
        max_retries: u32,
        backoff_base: Duration,
        backoff_max: Duration,
        rate_per_minute: u32,
        burst: Option<u32>,
    ) -> Self {
        self.timeout = timeout;
        self.max_retries = max_retries;
        self.backoff_base = backoff_base;
        self.backoff_max = backoff_max;
        self.bucket = Mutex::new(TokenBucket::new(rate_per_minute, burst));
        self
    }

    pub fn kind(&self) -> &'static str {
        self.sink.kind()
    }

    async fn wait_for_token(&self) {
        loop {
            let wait = match self.bucket.lock() {
                Ok(mut b) => b.take(Instant::now()),
                Err(poisoned) => poisoned.into_inner().take(Instant::now()),
            };
            match wait {
                Ok(()) => return,
                Err(d) => {
                    self.metrics.inc_rate_limited();
                    tokio::time::sleep(d).await;
                }
            }
        }
    }

    /// Delivers with timeout, retries (exponential backoff + jitter, honouring
    /// `retry_after`) and rate limiting. Updates the sink's counters.
    pub async fn deliver(&self, alert: &Alert) -> Outcome {
        let mut attempt = 0u32;
        loop {
            self.wait_for_token().await;
            let result = match tokio::time::timeout(self.timeout, self.sink.send(alert)).await {
                Ok(r) => r,
                Err(_) => Err(SinkError::transient(format!(
                    "timed out after {:?}",
                    self.timeout
                ))),
            };
            match result {
                Ok(()) => {
                    self.metrics.inc_sent();
                    return Outcome::Delivered;
                }
                Err(SinkError::Permanent(msg)) => {
                    self.metrics.inc_failed();
                    tracing::error!(sink = %self.name, alert_id = %alert.id, error = %msg, "alert rejected by sink");
                    return Outcome::Rejected;
                }
                Err(SinkError::Transient {
                    message,
                    retry_after,
                }) => {
                    if attempt >= self.max_retries {
                        self.metrics.inc_failed();
                        tracing::warn!(sink = %self.name, alert_id = %alert.id, error = %message, attempts = attempt + 1, "alert delivery failed; will redeliver later");
                        return Outcome::Failed;
                    }
                    let delay = retry_after.unwrap_or_default().max(backoff(
                        attempt,
                        self.backoff_base,
                        self.backoff_max,
                    ));
                    tracing::debug!(sink = %self.name, error = %message, ?delay, "retrying alert delivery");
                    self.metrics.inc_retries();
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Builds every `[[alerts.sink]]`, reading secrets from the environment.
/// Fails on the first invalid sink or missing secret (fail closed at startup).
pub fn build_sinks(
    cfg: &AlertsConfig,
    tool: &str,
    client: &reqwest::Client,
) -> Result<Vec<SinkRunner>, ConfigError> {
    let mut out: Vec<SinkRunner> = Vec::with_capacity(cfg.sinks.len());
    for (i, sc) in cfg.sinks.iter().enumerate() {
        let runner = build_one(sc, i, tool, client)
            .map_err(|e| ConfigError::Invalid(format!("alerts.sink[{i}]: {e}")))?;
        if out.iter().any(|r| r.name == runner.name) {
            return Err(ConfigError::Invalid(format!(
                "alerts.sink[{i}]: duplicate sink name {:?}",
                runner.name
            )));
        }
        out.push(runner);
    }
    Ok(out)
}

fn build_one(
    sc: &SinkConfig,
    index: usize,
    tool: &str,
    client: &reqwest::Client,
) -> Result<SinkRunner, ConfigError> {
    let c = &sc.common;
    let filter = c.filter();
    filter.validate().map_err(ConfigError::Invalid)?;
    if c.timeout_secs == 0 || c.timeout_secs > 300 {
        return Err(ConfigError::Invalid("timeout_secs must be 1..=300".into()));
    }
    if c.max_retries > 20 {
        return Err(ConfigError::Invalid("max_retries must be <= 20".into()));
    }
    let name = c
        .name
        .clone()
        .unwrap_or_else(|| format!("{}-{index}", sc.kind.type_name()));
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "-_.".contains(ch))
    {
        return Err(ConfigError::Invalid(
            "name must be 1..=64 chars of [A-Za-z0-9-_.]".into(),
        ));
    }
    let timeout = Duration::from_secs(c.timeout_secs);
    let client = client.clone();
    let sink: Box<dyn Sink> = match &sc.kind {
        SinkKind::Stdout(s) => Box::new(stdout::StdoutSink::new(s.format)),
        SinkKind::Webhook(w) => Box::new(webhook::WebhookSink::from_config(w, client)?),
        SinkKind::Telegram(t) => Box::new(telegram::TelegramSink::from_config(t, client)?),
        SinkKind::Slack(s) => Box::new(slack::SlackSink::new(
            crate::config::check_url(&env_secret(&s.url_env)?, false)?,
            client,
        )),
        SinkKind::Discord(s) => Box::new(discord::DiscordSink::new(
            crate::config::check_url(&env_secret(&s.url_env)?, false)?,
            client,
        )),
        SinkKind::Teams(s) => Box::new(teams::TeamsSink::new(
            crate::config::check_url(&env_secret(&s.url_env)?, false)?,
            client,
        )),
        #[cfg(feature = "smtp")]
        SinkKind::Email(e) => Box::new(email::EmailSink::from_config(e, timeout)?),
        #[cfg(not(feature = "smtp"))]
        SinkKind::Email(_) => {
            return Err(ConfigError::Invalid(
                "email sink requires the `smtp` cargo feature".into(),
            ))
        }
        SinkKind::Pagerduty(p) => Box::new(pagerduty::PagerDutySink::from_config(p, client)?),
        SinkKind::Opsgenie(o) => Box::new(opsgenie::OpsgenieSink::from_config(o, client)?),
        SinkKind::Syslog(s) => Box::new(syslog::SyslogSink::from_config(s, tool)?),
    };
    Ok(SinkRunner::new(name, filter, sink).with_policy(
        timeout,
        c.max_retries,
        Duration::from_millis(c.backoff_base_ms.max(1)),
        Duration::from_millis(c.backoff_max_ms.max(c.backoff_base_ms).max(1)),
        c.rate_per_minute,
        c.burst,
    ))
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Local mock HTTP server capturing requests.
    use std::sync::{Arc, Mutex};

    use axum::body::Bytes;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::IntoResponse;

    #[derive(Debug, Clone)]
    pub struct Captured {
        pub method: Method,
        pub uri: Uri,
        pub headers: HeaderMap,
        pub body: Bytes,
    }

    impl Captured {
        pub fn json(&self) -> serde_json::Value {
            serde_json::from_slice(&self.body).expect("json body")
        }
    }

    pub type Responder = Arc<dyn Fn(usize) -> (StatusCode, HeaderMap, String) + Send + Sync>;

    /// Starts a server on 127.0.0.1:0; `respond(n)` decides the n-th response (0-based).
    pub async fn mock(respond: Responder) -> (String, Arc<Mutex<Vec<Captured>>>) {
        let seen: Arc<Mutex<Vec<Captured>>> = Arc::default();
        let s2 = seen.clone();
        let app = axum::Router::new().fallback(
            move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
                let seen = s2.clone();
                let respond = respond.clone();
                async move {
                    let n = {
                        let mut g = seen.lock().unwrap();
                        g.push(Captured {
                            method,
                            uri,
                            headers,
                            body,
                        });
                        g.len() - 1
                    };
                    respond(n).into_response()
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), seen)
    }

    pub fn ok() -> Responder {
        Arc::new(|_| (StatusCode::OK, HeaderMap::new(), "{\"ok\":true}".into()))
    }

    pub fn client() -> reqwest::Client {
        super::http_client().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use crate::alert::Severity;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    #[test]
    fn bucket_limits_and_refills() {
        let mut b = TokenBucket::new(60, Some(2));
        let t0 = Instant::now();
        assert!(b.take(t0).is_ok());
        assert!(b.take(t0).is_ok());
        let wait = b.take(t0).unwrap_err();
        assert!(wait <= Duration::from_secs(1));
        assert!(b.take(t0 + Duration::from_secs(1)).is_ok());
        let mut unlimited = TokenBucket::new(0, None);
        for _ in 0..1000 {
            assert!(unlimited.take(t0).is_ok());
        }
    }

    #[test]
    fn backoff_grows_and_caps() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(1);
        for a in 0..30 {
            let d = backoff(a, base, max);
            assert!(d <= max);
        }
        assert!(backoff(3, base, max) >= Duration::from_millis(400));
    }

    #[tokio::test]
    async fn runner_retries_transient_then_succeeds_and_honours_retry_after() {
        let (url, seen) = mock(Arc::new(|n| {
            let mut h = HeaderMap::new();
            if n == 0 {
                h.insert("retry-after", HeaderValue::from_static("0"));
                (StatusCode::TOO_MANY_REQUESTS, h, String::new())
            } else {
                (StatusCode::OK, h, String::new())
            }
        }))
        .await;
        let sink =
            webhook::WebhookSink::new(reqwest::Url::parse(&url).unwrap(), None, None, client());
        let r = SinkRunner::new("w", Filter::default(), Box::new(sink)).with_policy(
            Duration::from_secs(5),
            2,
            Duration::from_millis(1),
            Duration::from_millis(5),
            0,
            None,
        );
        let a = Alert::new("t", "k", Severity::Info, "x");
        assert_eq!(r.deliver(&a).await, Outcome::Delivered);
        assert_eq!(seen.lock().unwrap().len(), 2);
        let m = r.metrics.snapshot();
        assert_eq!((m.sent, m.failed, m.retries), (1, 0, 1));
    }

    #[tokio::test]
    async fn runner_stops_on_permanent_and_on_exhaustion() {
        let (url, seen) = mock(Arc::new(|_| {
            (StatusCode::BAD_REQUEST, HeaderMap::new(), "nope".into())
        }))
        .await;
        let sink =
            webhook::WebhookSink::new(reqwest::Url::parse(&url).unwrap(), None, None, client());
        let r = SinkRunner::new("w", Filter::default(), Box::new(sink));
        let a = Alert::new("t", "k", Severity::Info, "x");
        assert_eq!(r.deliver(&a).await, Outcome::Rejected);
        assert_eq!(seen.lock().unwrap().len(), 1);

        let (url, seen) = mock(Arc::new(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                HeaderMap::new(),
                String::new(),
            )
        }))
        .await;
        let sink =
            webhook::WebhookSink::new(reqwest::Url::parse(&url).unwrap(), None, None, client());
        let r = SinkRunner::new("w", Filter::default(), Box::new(sink)).with_policy(
            Duration::from_secs(5),
            2,
            Duration::from_millis(1),
            Duration::from_millis(2),
            0,
            None,
        );
        assert_eq!(r.deliver(&a).await, Outcome::Failed);
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[test]
    fn build_sinks_reads_env_and_rejects_duplicates() {
        std::env::set_var("LLCF_TEST_SLACK_URL", "https://hooks.example.net/x");
        let src = r#"
[[sink]]
type = "slack"
url_env = "LLCF_TEST_SLACK_URL"
[[sink]]
type = "stdout"
"#;
        let cfg: AlertsConfig = toml::from_str(src).unwrap();
        let sinks = build_sinks(&cfg, "t", &client()).unwrap();
        assert_eq!(sinks[0].name, "slack-0");
        assert_eq!(sinks[1].name, "stdout-1");

        let dup = "[[sink]]\ntype = \"stdout\"\nname = \"a\"\n[[sink]]\ntype = \"stdout\"\nname = \"a\"\n";
        let cfg: AlertsConfig = toml::from_str(dup).unwrap();
        assert!(build_sinks(&cfg, "t", &client()).is_err());

        let missing = "[[sink]]\ntype = \"slack\"\nurl_env = \"LLCF_TEST_UNSET_VAR_XYZ\"\n";
        let cfg: AlertsConfig = toml::from_str(missing).unwrap();
        assert!(build_sinks(&cfg, "t", &client()).is_err());
    }
}
