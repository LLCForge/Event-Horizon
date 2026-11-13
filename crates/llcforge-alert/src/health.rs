//! `/healthz` (liveness) and `/readyz` (readiness from named checks).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Named readiness flags the tool flips (`"bgp_session"`, `"vrp_loaded"`, ...).
/// Ready when every registered check is ok (and trivially when none exist).
#[derive(Debug, Clone, Default)]
pub struct Readiness(Arc<RwLock<BTreeMap<String, Check>>>);

impl Readiness {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `name` as not ready yet.
    pub fn register(&self, name: &str) {
        self.set_detail(name, false, Some("starting".into()));
    }

    pub fn set(&self, name: &str, ok: bool) {
        self.set_detail(name, ok, None);
    }

    pub fn set_detail(&self, name: &str, ok: bool, detail: Option<String>) {
        let mut g = self.0.write().unwrap_or_else(|p| p.into_inner());
        g.insert(name.to_string(), Check { ok, detail });
    }

    pub fn is_ready(&self) -> bool {
        self.snapshot().values().all(|c| c.ok)
    }

    pub fn snapshot(&self) -> BTreeMap<String, Check> {
        self.0.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

async fn readyz(State(r): State<Readiness>) -> impl IntoResponse {
    let checks = r.snapshot();
    let failing: Vec<&String> = checks
        .iter()
        .filter(|(_, c)| !c.ok)
        .map(|(k, _)| k)
        .collect();
    let ready = failing.is_empty();
    let body = Json(serde_json::json!({
        "ready": ready,
        "failing": failing,
        "checks": checks,
    }));
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, body)
}

/// `GET /healthz` and `GET /readyz`. Unauthenticated by design (probes);
/// expose only on a loopback / cluster-internal listener.
pub fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(readiness)
}

/// Serves `router` on `addr` until `shutdown` resolves.
pub async fn serve(
    addr: SocketAddr,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "admin/health listener started");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    async fn get_json(app: &Router, path: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let st = resp.status();
        let b = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (st, serde_json::from_slice(&b).unwrap())
    }

    #[tokio::test]
    async fn liveness_and_readiness() {
        let r = Readiness::new();
        let app = health_router(r.clone());
        assert_eq!(get_json(&app, "/healthz").await.0, StatusCode::OK);
        assert_eq!(get_json(&app, "/readyz").await.0, StatusCode::OK);
        r.register("bgp_session");
        r.set("config", true);
        let (st, v) = get_json(&app, "/readyz").await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["failing"], serde_json::json!(["bgp_session"]));
        assert_eq!(v["checks"]["config"]["ok"], true);
        r.set("bgp_session", true);
        let (st, v) = get_json(&app, "/readyz").await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["ready"], true);
    }
}
