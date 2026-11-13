//! Trigger HTTP API for operators and external detectors.
//!
//! * `POST /v1/blackholes`, `DELETE /v1/blackholes/{ip}`, `GET /v1/blackholes`
//!   (each entry carries `propagation`, item 43).
//! * `POST /v1/flowspec`, `DELETE /v1/flowspec/{id}`, `GET /v1/flowspec`.
//! * `GET /v1/approvals`, `POST /v1/approvals/{id}/approve|deny` (41).
//! * `GET /v1/reports` (44).
//!
//! Every request passes a global rate limit and a constant-time bearer token
//! check before it reaches the policy engine. Plain HTTP on localhost by
//! default; built-in TLS / mTLS is in `tls.rs`.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::alerts::Alerts;
use crate::bgp::flowspec::{FlowAction, FlowRule, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
use crate::config::parse_duration;
use crate::engine::{ApproveError, Engine, Submitted, Target, MAX_REASON_LEN};
use crate::metrics::Metrics;
use crate::policy::{Deny, MAX_SCOPE_UPSTREAMS};
use crate::propagation::Propagation;
use crate::report::ReportStore;
use crate::state::Source;
use crate::unix_now;

pub const MIN_TOKEN_LEN: usize = 32;

struct Bucket {
    tokens: f64,
    capacity: f64,
    per_sec: f64,
    last: Instant,
}

impl Bucket {
    fn new(per_minute: u32) -> Self {
        let cap = f64::from(per_minute.max(1));
        Self {
            tokens: cap,
            capacity: cap,
            per_sec: cap / 60.0,
            last: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct ApiState {
    engine: Arc<Mutex<Engine>>,
    token: Arc<str>,
    bucket: Arc<Mutex<Bucket>>,
    metrics: Arc<Metrics>,
    reports: Option<Arc<ReportStore>>,
}

impl ApiState {
    pub fn new(
        engine: Arc<Mutex<Engine>>,
        token: String,
        rate_per_minute: u32,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            engine,
            token: token.into(),
            bucket: Arc::new(Mutex::new(Bucket::new(rate_per_minute))),
            metrics,
            reports: None,
        }
    }

    pub fn with_reports(mut self, r: Arc<ReportStore>) -> Self {
        self.reports = Some(r);
        self
    }
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

async fn guard(State(s): State<ApiState>, req: Request, next: Next) -> Response {
    let allowed = s.bucket.lock().map(|mut b| b.take()).unwrap_or(false);
    if !allowed {
        Metrics::inc(&s.metrics.api_rate_limited);
        return error(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let ok: bool = presented.as_bytes().ct_eq(s.token.as_bytes()).into();
    if !ok {
        Metrics::inc(&s.metrics.api_unauthorized);
        let mut r = error(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Bearer".parse().expect("static header"),
        );
        return r;
    }
    next.run(req).await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateReq {
    ip: IpAddr,
    #[serde(default)]
    ttl: Option<String>,
    reason: String,
    /// Regional scope name from `[bgp.upstream.regions]`; absent / "global" = everywhere.
    #[serde(default)]
    scope: Option<String>,
    /// Selective blackholing: only these upstreams.
    #[serde(default)]
    upstreams: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowReq {
    dst: IpAddr,
    protocol: String,
    #[serde(default)]
    src_port: Option<u16>,
    #[serde(default)]
    dst_port: Option<u16>,
    /// "discard" or "rate-limit".
    action: String,
    #[serde(default)]
    rate_kbps: Option<u64>,
    #[serde(default)]
    ttl: Option<String>,
    reason: String,
}

fn deny_status(d: &Deny) -> StatusCode {
    match d {
        Deny::AlreadyActive(_) | Deny::FlowspecActive => StatusCode::CONFLICT,
        Deny::TtlTooShort(..)
        | Deny::TtlTooLong(..)
        | Deny::UnknownScope(_)
        | Deny::UnknownUpstream(_)
        | Deny::FlowspecPort
        | Deny::FlowspecProtocol(_) => StatusCode::UNPROCESSABLE_ENTITY,
        Deny::TooManyPending(_) => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::FORBIDDEN,
    }
}

fn denied(d: &Deny) -> Response {
    (
        deny_status(d),
        Json(json!({ "error": "denied", "code": d.code(), "detail": d.to_string() })),
    )
        .into_response()
}

fn check_reason(r: &str) -> Result<&str, String> {
    let reason = r.trim();
    if reason.is_empty()
        || reason.chars().count() > MAX_REASON_LEN
        || reason.chars().any(char::is_control)
    {
        return Err(format!(
            "reason must be 1-{MAX_REASON_LEN} characters without control characters"
        ));
    }
    Ok(reason)
}

fn check_ttl(t: Option<&str>) -> Result<Option<u64>, String> {
    t.map(parse_duration).transpose()
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

fn submitted(r: Result<Submitted, Deny>) -> Response {
    match r {
        Ok(Submitted::Blackhole(e)) => (StatusCode::CREATED, Json(json!(e))).into_response(),
        Ok(Submitted::Flowspec(f)) => (StatusCode::CREATED, Json(json!(f))).into_response(),
        Ok(Submitted::Pending(p)) => (
            StatusCode::ACCEPTED,
            Json(json!({"status": "pending_approval", "pending": p})),
        )
            .into_response(),
        Err(d) => denied(&d),
    }
}

async fn create(
    State(s): State<ApiState>,
    body: Result<Json<CreateReq>, JsonRejection>,
) -> Response {
    let req = match body {
        Ok(Json(r)) => r,
        Err(rej) => return error(rej.status(), rej.body_text()),
    };
    let (reason, ttl) = match (check_reason(&req.reason), check_ttl(req.ttl.as_deref())) {
        (Ok(r), Ok(t)) => (r, t),
        (Err(e), _) | (_, Err(e)) => return error(StatusCode::UNPROCESSABLE_ENTITY, e),
    };
    if req.scope.as_deref().is_some_and(|s| !valid_name(s))
        || req.upstreams.len() > MAX_SCOPE_UPSTREAMS
        || req.upstreams.iter().any(|u| !valid_name(u))
    {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "scope and upstreams must be names of 1-64 chars of [A-Za-z0-9-_.]",
        );
    }
    let Ok(mut eng) = s.engine.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let target = Target::Blackhole {
        ip: req.ip,
        scope: req.scope,
        upstreams: req.upstreams,
    };
    submitted(eng.submit(target, ttl, reason, Source::Api, unix_now()))
}

async fn remove(State(s): State<ApiState>, Path(ip): Path<String>) -> Response {
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return error(StatusCode::BAD_REQUEST, "invalid IP address");
    };
    let Ok(mut eng) = s.engine.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    match eng.withdraw(ip, "withdrawn via API", Source::Api, unix_now()) {
        Some(e) => Json(e).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            "no active blackhole for this address",
        ),
    }
}

async fn list(State(s): State<ApiState>) -> Response {
    match s.engine.lock() {
        Ok(eng) => {
            let items: Vec<serde_json::Value> = eng
                .list()
                .into_iter()
                .map(|e| {
                    let p = eng
                        .propagation(e.ip)
                        .cloned()
                        .unwrap_or_else(Propagation::unknown);
                    let mut v = json!(e);
                    v["propagation"] = json!(p);
                    v
                })
                .collect();
            Json(json!({ "blackholes": items })).into_response()
        }
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn parse_protocol(p: &str) -> Option<u8> {
    match p.to_ascii_lowercase().as_str() {
        "tcp" => Some(PROTO_TCP),
        "udp" => Some(PROTO_UDP),
        "icmp" => Some(PROTO_ICMP),
        "icmpv6" => Some(PROTO_ICMPV6),
        n => n.parse().ok(),
    }
}

async fn create_flow(
    State(s): State<ApiState>,
    body: Result<Json<FlowReq>, JsonRejection>,
) -> Response {
    let req = match body {
        Ok(Json(r)) => r,
        Err(rej) => return error(rej.status(), rej.body_text()),
    };
    let (reason, ttl) = match (check_reason(&req.reason), check_ttl(req.ttl.as_deref())) {
        (Ok(r), Ok(t)) => (r, t),
        (Err(e), _) | (_, Err(e)) => return error(StatusCode::UNPROCESSABLE_ENTITY, e),
    };
    let Some(protocol) = parse_protocol(&req.protocol) else {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "protocol must be tcp, udp, icmp, icmpv6 or a number",
        );
    };
    let action = match (req.action.as_str(), req.rate_kbps) {
        ("discard", None) => FlowAction::Discard,
        ("rate-limit", Some(kbps)) => FlowAction::RateLimit { kbps },
        _ => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "action must be \"discard\" or \"rate-limit\" with rate_kbps",
            )
        }
    };
    let rule = FlowRule {
        dst: req.dst,
        protocol,
        src_port: req.src_port,
        dst_port: req.dst_port,
        action,
    };
    let Ok(mut eng) = s.engine.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    submitted(eng.submit(
        Target::Flowspec { rule },
        ttl,
        reason,
        Source::Api,
        unix_now(),
    ))
}

async fn list_flow(State(s): State<ApiState>) -> Response {
    match s.engine.lock() {
        Ok(eng) => Json(json!({ "flowspec": eng.list_flowspec() })).into_response(),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn remove_flow(State(s): State<ApiState>, Path(id): Path<String>) -> Response {
    if id.len() > 128 {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    }
    let Ok(mut eng) = s.engine.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    match eng.withdraw_flowspec(&id, "withdrawn via API", Source::Api, unix_now()) {
        Some(f) => Json(f).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            "no active FlowSpec rule with this id",
        ),
    }
}

async fn list_approvals(State(s): State<ApiState>) -> Response {
    match s.engine.lock() {
        Ok(eng) => Json(json!({ "pending": eng.list_pending() })).into_response(),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn approval(
    State(s): State<ApiState>,
    Path((id, action)): Path<(String, String)>,
) -> Response {
    if id.len() > 64 {
        return error(StatusCode::BAD_REQUEST, "invalid id");
    }
    let Ok(mut eng) = s.engine.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let now = unix_now();
    match action.as_str() {
        "approve" => match eng.approve(&id, "api", now) {
            Ok(r) => submitted(Ok(r)),
            Err(ApproveError::NotFound) => {
                error(StatusCode::NOT_FOUND, "no pending request with this id")
            }
            Err(ApproveError::Denied(d)) => denied(&d),
        },
        "deny" => match eng.reject(&id, "api", now) {
            Some(p) => Json(json!({"status": "denied", "pending": p})).into_response(),
            None => error(StatusCode::NOT_FOUND, "no pending request with this id"),
        },
        _ => error(StatusCode::NOT_FOUND, "unknown action"),
    }
}

async fn reports(State(s): State<ApiState>) -> Response {
    let r = s.reports.as_ref().map(|r| r.recent()).unwrap_or_default();
    Json(json!({ "reports": r })).into_response()
}

pub fn router(state: ApiState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/v1/blackholes", get(list).post(create))
        .route("/v1/blackholes/{ip}", delete(remove))
        .route("/v1/flowspec", get(list_flow).post(create_flow))
        .route("/v1/flowspec/{id}", delete(remove_flow))
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/{id}/{action}", post(approval))
        .route("/v1/reports", get(reports))
        .layer(from_fn_with_state(state.clone(), guard))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

/// `/metrics`: Event Horizon metrics followed by the llcforge-alert counters.
pub fn metrics_router(metrics: Arc<Metrics>, alerts: Alerts) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            let (m, a) = (metrics.clone(), alerts.clone());
            async move {
                let mut body = m.render();
                if let Some(h) = a.handle() {
                    h.metrics().render_prometheus(&mut body);
                }
                ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApprovalMode;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn app_with(rate: u32, approval: ApprovalMode) -> (Router, crate::engine::Routes) {
        let (mut e, rx, _) = crate::engine::tests::engine();
        e.set_approval(approval, 60);
        let st = ApiState::new(
            Arc::new(Mutex::new(e)),
            TOKEN.into(),
            rate,
            Arc::new(Metrics::default()),
        )
        .with_reports(Arc::new(ReportStore::new(None, 10)));
        (router(st, 512), rx)
    }

    fn app(rate: u32) -> (Router, crate::engine::Routes) {
        app_with(rate, ApprovalMode::Off)
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let resp = app
            .clone()
            .oneshot(b.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn requires_valid_token() {
        let (app, _) = app(100);
        for path in [
            "/v1/blackholes",
            "/v1/flowspec",
            "/v1/approvals",
            "/v1/reports",
        ] {
            assert_eq!(
                call(&app, "GET", path, None, "").await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            call(&app, "GET", "/v1/blackholes", Some("wrong"), "")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let almost = format!("{}x", &TOKEN[..31]);
        assert_eq!(
            call(&app, "GET", "/v1/blackholes", Some(&almost), "")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "GET", "/v1/blackholes", Some(TOKEN), "").await.0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn create_list_delete() {
        let (app, rx) = app(100);
        let (st, v) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"198.51.100.7","ttl":"10m","reason":"test"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        assert_eq!(v["ip"], "198.51.100.7");
        assert!(rx.borrow().contains(&"198.51.100.7".parse().unwrap()));

        let (st, v) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"198.51.100.7","reason":"again"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);
        assert_eq!(v["code"], "already_active");

        let (_, v) = call(&app, "GET", "/v1/blackholes", Some(TOKEN), "").await;
        let list = v["blackholes"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        // Cross-tool contract: base fields plus propagation.
        for k in [
            "ip",
            "reason",
            "source",
            "created_at",
            "expires_at",
            "dry_run",
        ] {
            assert!(list[0].get(k).is_some(), "{k}");
        }
        assert_eq!(list[0]["propagation"]["status"], "unknown");
        assert_eq!(list[0]["propagation"]["visible_peers"], 0);
        assert_eq!(list[0]["propagation"]["checked_at"], 0);

        assert_eq!(
            call(
                &app,
                "DELETE",
                "/v1/blackholes/198.51.100.7",
                Some(TOKEN),
                ""
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "DELETE",
                "/v1/blackholes/198.51.100.7",
                Some(TOKEN),
                ""
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(&app, "DELETE", "/v1/blackholes/not-an-ip", Some(TOKEN), "")
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert!(rx.borrow().is_empty());
    }

    #[tokio::test]
    async fn scoped_blackholes() {
        let (app, rx) = app(100);
        let (st, v) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"198.51.100.7","reason":"x","scope":"eu","upstreams":["transit-a"]}"#,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        assert_eq!(v["scope"], "eu");
        assert_eq!(
            rx.borrow()
                .blackholes
                .values()
                .next()
                .unwrap()
                .region
                .as_deref(),
            Some("eu")
        );
        for (body, code) in [
            (
                r#"{"ip":"198.51.100.8","reason":"x","scope":"mars"}"#,
                "unknown_scope",
            ),
            (
                r#"{"ip":"198.51.100.8","reason":"x","upstreams":["nope"]}"#,
                "unknown_upstream",
            ),
        ] {
            let (st, v) = call(&app, "POST", "/v1/blackholes", Some(TOKEN), body).await;
            assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(v["code"], code);
        }
        let (st, _) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"198.51.100.8","reason":"x","scope":"a b"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn flowspec_endpoints() {
        let (app, rx) = app(100);
        let (st, v) = call(
            &app,
            "POST",
            "/v1/flowspec",
            Some(TOKEN),
            r#"{"dst":"198.51.100.7","protocol":"udp","src_port":53,"action":"rate-limit","rate_kbps":1000,"reason":"dns amp"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let id = v["id"].as_str().unwrap().to_owned();
        assert_eq!(rx.borrow().flowspec.len(), 1);
        let (_, v) = call(&app, "GET", "/v1/flowspec", Some(TOKEN), "").await;
        assert_eq!(v["flowspec"].as_array().unwrap().len(), 1);
        // policy: discard not allowed, unprotected, bad protocol / port, bad action shape
        for (body, status) in [
            (
                r#"{"dst":"198.51.100.8","protocol":"udp","action":"discard","reason":"x"}"#,
                StatusCode::FORBIDDEN,
            ),
            (
                r#"{"dst":"203.0.113.8","protocol":"udp","action":"rate-limit","rate_kbps":1,"reason":"x"}"#,
                StatusCode::FORBIDDEN,
            ),
            (
                r#"{"dst":"198.51.100.8","protocol":"gre","action":"rate-limit","rate_kbps":1,"reason":"x"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                r#"{"dst":"198.51.100.8","protocol":"icmp","dst_port":80,"action":"rate-limit","rate_kbps":1,"reason":"x"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                r#"{"dst":"198.51.100.8","protocol":"udp","action":"rate-limit","reason":"x"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                r#"{"dst":"198.51.100.8","protocol":"udp","action":"discard","reason":"x","extra":1}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let (st, v) = call(&app, "POST", "/v1/flowspec", Some(TOKEN), body).await;
            assert_eq!(st, status, "{body} -> {v}");
        }
        assert_eq!(
            call(
                &app,
                "DELETE",
                &format!("/v1/flowspec/{id}"),
                Some(TOKEN),
                ""
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "DELETE",
                &format!("/v1/flowspec/{id}"),
                Some(TOKEN),
                ""
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert!(rx.borrow().flowspec.is_empty());
    }

    #[tokio::test]
    async fn approval_endpoints() {
        let (app, rx) = app_with(100, ApprovalMode::All);
        let (st, v) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"198.51.100.7","reason":"x"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED, "{v}");
        let id = v["pending"]["id"].as_str().unwrap().to_owned();
        assert_eq!(v["pending"]["kind"], "blackhole");
        assert!(rx.borrow().is_empty());
        let (_, v) = call(&app, "GET", "/v1/approvals", Some(TOKEN), "").await;
        assert_eq!(v["pending"].as_array().unwrap().len(), 1);
        let (st, v) = call(
            &app,
            "POST",
            &format!("/v1/approvals/{id}/approve"),
            Some(TOKEN),
            "",
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        assert!(rx.borrow().contains(&"198.51.100.7".parse().unwrap()));
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/approvals/{id}/approve"),
                Some(TOKEN),
                ""
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        // deny path
        let (_, v) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"198.51.100.8","reason":"x"}"#,
        )
        .await;
        let id = v["pending"]["id"].as_str().unwrap().to_owned();
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/approvals/{id}/deny"),
                Some(TOKEN),
                ""
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/approvals/{id}/explode"),
                Some(TOKEN),
                ""
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert!(!rx.borrow().contains(&"198.51.100.8".parse().unwrap()));
        // a request the policy denies is not parked
        let (st, _) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"203.0.113.7","reason":"x"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn policy_denials_map_to_status_codes() {
        let (app, _) = app(100);
        let (st, v) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"203.0.113.7","reason":"x"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        assert_eq!(v["code"], "not_protected");
        let (st, _) = call(
            &app,
            "POST",
            "/v1/blackholes",
            Some(TOKEN),
            r#"{"ip":"198.51.100.7","ttl":"1d","reason":"x"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn rejects_invalid_bodies() {
        let (app, _) = app(100);
        for body in [
            r#"{"ip":"198.51.100.7"}"#,
            r#"{"ip":"nope","reason":"x"}"#,
            r#"{"ip":"198.51.100.7","reason":"x","extra":1}"#,
            r#"{"ip":"198.51.100.7","reason":""}"#,
            r#"{"ip":"198.51.100.7","reason":"a\nb"}"#,
            r#"{"ip":"198.51.100.7","reason":"x","ttl":"soon"}"#,
            "not json",
        ] {
            let (st, _) = call(&app, "POST", "/v1/blackholes", Some(TOKEN), body).await;
            assert!(st.is_client_error(), "{body} -> {st}");
        }
        let big = format!(r#"{{"ip":"198.51.100.7","reason":"{}"}}"#, "a".repeat(1000));
        let (st, _) = call(&app, "POST", "/v1/blackholes", Some(TOKEN), &big).await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn rate_limit_applies_before_auth() {
        let (app, _) = app(2);
        assert_eq!(
            call(&app, "GET", "/v1/blackholes", None, "").await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "GET", "/v1/blackholes", Some(TOKEN), "").await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&app, "GET", "/v1/blackholes", Some(TOKEN), "").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn reports_endpoint() {
        let (app, _) = app(100);
        let (st, v) = call(&app, "GET", "/v1/reports", Some(TOKEN), "").await;
        assert_eq!(st, StatusCode::OK);
        assert!(v["reports"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn metrics_endpoint() {
        let r = metrics_router(Arc::new(Metrics::default()), Alerts::disabled());
        let resp = r
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let t = String::from_utf8_lossy(&b);
        assert!(t.contains("event_horizon_active_blackholes"));
        assert!(t.contains("llcforge_alert_received_total"));
    }
}
