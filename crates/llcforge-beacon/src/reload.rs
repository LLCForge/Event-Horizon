//! Configuration reload triggers: SIGHUP (Unix), config-file change (mtime
//! polling, all OSes) and `POST /v1/reload` (token protected).

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::auth::{require_bearer, ApiToken};

/// Why a reload fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadReason {
    Signal,
    FileChanged,
    Api,
}

/// Cloneable trigger (used by the HTTP route; tools may fire it too).
#[derive(Debug, Clone)]
pub struct ReloadTrigger(mpsc::Sender<ReloadReason>);

impl ReloadTrigger {
    /// Requests a reload; bursts are coalesced. Returns `false` if the receiver is gone.
    pub fn fire(&self, reason: ReloadReason) -> bool {
        !matches!(
            self.0.try_send(reason),
            Err(mpsc::error::TrySendError::Closed(_))
        )
    }
}

/// Stream of reload requests. `recv().await` yields the next reason.
pub struct ReloadSignal {
    rx: mpsc::Receiver<ReloadReason>,
    tx: mpsc::Sender<ReloadReason>,
    tasks: Vec<JoinHandle<()>>,
}

impl Default for ReloadSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ReloadSignal {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn stamp(p: &std::path::Path) -> Option<(SystemTime, u64)> {
    let m = std::fs::metadata(p).ok()?;
    Some((m.modified().ok()?, m.len()))
}

impl ReloadSignal {
    /// Empty signal; add sources with [`watch_file`](Self::watch_file) and
    /// [`listen_sighup`](Self::listen_sighup). Must be used inside a Tokio runtime.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(4);
        ReloadSignal {
            rx,
            tx,
            tasks: Vec::new(),
        }
    }

    /// SIGHUP + config file polling every 5 s: the standard setup for every tool.
    pub fn standard(config_path: Option<PathBuf>) -> std::io::Result<Self> {
        let mut s = Self::new();
        s.listen_sighup()?;
        if let Some(p) = config_path {
            s.watch_file(p, Duration::from_secs(5));
        }
        Ok(s)
    }

    pub fn trigger(&self) -> ReloadTrigger {
        ReloadTrigger(self.tx.clone())
    }

    /// Fires when the file's mtime or size changes (no OS watcher dependency).
    pub fn watch_file(&mut self, path: PathBuf, every: Duration) {
        let tx = self.tx.clone();
        let every = every.max(Duration::from_millis(50));
        self.tasks.push(tokio::spawn(async move {
            let mut last = stamp(&path);
            let mut tick = tokio::time::interval(every);
            tick.tick().await;
            loop {
                tick.tick().await;
                let now = stamp(&path);
                // A vanished file (editor rename dance) is not a change yet.
                if now.is_some() && now != last {
                    last = now;
                    if let Err(mpsc::error::TrySendError::Closed(_)) =
                        tx.try_send(ReloadReason::FileChanged)
                    {
                        break;
                    }
                }
            }
        }));
    }

    /// Fires on SIGHUP. No-op on non-Unix platforms.
    #[cfg(unix)]
    pub fn listen_sighup(&mut self) -> std::io::Result<()> {
        use tokio::signal::unix::{signal, SignalKind};
        let mut hup = signal(SignalKind::hangup())?;
        let tx = self.tx.clone();
        self.tasks.push(tokio::spawn(async move {
            while hup.recv().await.is_some() {
                if let Err(mpsc::error::TrySendError::Closed(_)) = tx.try_send(ReloadReason::Signal)
                {
                    break;
                }
            }
        }));
        Ok(())
    }

    /// Fires on SIGHUP. No-op on non-Unix platforms.
    #[cfg(not(unix))]
    pub fn listen_sighup(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Waits for the next reload request (never `None` while `self` is alive).
    pub async fn recv(&mut self) -> Option<ReloadReason> {
        self.rx.recv().await
    }
}

async fn reload_handler(State(t): State<ReloadTrigger>) -> impl IntoResponse {
    if t.fire(ReloadReason::Api) {
        tracing::info!("configuration reload requested via API");
        (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status": "reload scheduled"})),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "reload unavailable"})),
        )
    }
}

/// `POST /v1/reload` (bearer token, empty body) → 202.
pub fn reload_router(trigger: ReloadTrigger, token: ApiToken) -> Router {
    Router::new()
        .route("/v1/reload", post(reload_handler))
        .with_state(trigger)
        .layer(axum::extract::DefaultBodyLimit::max(1024))
        .layer(axum::middleware::from_fn_with_state(token, require_bearer))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn file_change_fires() {
        let dir = std::env::temp_dir().join(format!("llcf-reload-{}", fastrand::u64(..)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tool.toml");
        std::fs::write(&path, "a = 1\n").unwrap();
        // SIGHUP is not registered here: CI runners can deliver a stray SIGHUP,
        // and this test is only about file polling.
        let mut s = ReloadSignal::new();
        s.watch_file(path.clone(), Duration::from_millis(50));
        tokio::time::sleep(Duration::from_millis(120)).await;
        std::fs::write(&path, "a = 22\n").unwrap();
        let r = tokio::time::timeout(Duration::from_secs(5), s.recv())
            .await
            .unwrap();
        assert_eq!(r, Some(ReloadReason::FileChanged));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn api_route_requires_token_and_fires() {
        let mut s = ReloadSignal::new();
        let app = reload_router(s.trigger(), ApiToken::new("reload-token-0123456").unwrap());
        let resp = app
            .clone()
            .oneshot(Request::post("/v1/reload").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = app
            .oneshot(
                Request::post("/v1/reload")
                    .header("authorization", "Bearer reload-token-0123456")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(s.recv().await, Some(ReloadReason::Api));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sighup_fires() {
        let mut s = ReloadSignal::new();
        s.listen_sighup().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        std::process::Command::new("kill")
            .args(["-HUP", &std::process::id().to_string()])
            .status()
            .unwrap();
        let r = tokio::time::timeout(Duration::from_secs(5), s.recv())
            .await
            .unwrap();
        assert_eq!(r, Some(ReloadReason::Signal));
    }
}
