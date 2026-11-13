//! Maintenance windows / silences: matcher rules persisted to JSON with an
//! atomic write, an HTTP API (`/v1/silences`) and CLI helpers.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{DefaultBodyLimit, Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::alert::Alert;
use crate::auth::{require_bearer, ApiToken};
use crate::filter::{glob_match, validate_glob};

const MAX_SILENCES: usize = 1000;
const MAX_WINDOW: chrono::Duration = chrono::Duration::days(366);
const REFRESH_EVERY: Duration = Duration::from_secs(2);

/// A persisted silence rule. Unset matchers match everything; at least one is required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Silence {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub comment: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

impl Silence {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.starts_at <= now && now < self.ends_at
    }

    pub fn matches(&self, a: &Alert) -> bool {
        let m = |pat: &Option<String>, v: Option<&str>| match pat {
            None => true,
            Some(p) => v.is_some_and(|v| glob_match(p, v)),
        };
        m(&self.resource, a.resource.as_deref())
            && m(&self.kind, Some(&a.kind))
            && m(&self.tool, Some(&a.tool))
    }
}

/// Request body for creating a silence (API and CLI).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewSilence {
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    /// Defaults to now.
    #[serde(default)]
    pub starts_at: Option<DateTime<Utc>>,
    /// Either `ends_at` or `duration` (e.g. `"90m"`, `"2h"`, `"1d12h"`).
    #[serde(default)]
    pub ends_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub duration: Option<String>,
    pub comment: String,
    #[serde(default)]
    pub created_by: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SilenceError {
    #[error("{0}")]
    Invalid(String),
    #[error("too many silences (max {MAX_SILENCES})")]
    Full,
    #[error("silence store I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parses `"30s"`, `"15m"`, `"2h"`, `"7d"`, `"1w"` and concatenations like `"1h30m"`.
pub fn parse_duration(s: &str) -> Result<chrono::Duration, SilenceError> {
    let bad = || SilenceError::Invalid(format!("invalid duration {s:?} (e.g. 30m, 2h, 1d12h)"));
    let s = s.trim();
    if s.is_empty() || s.len() > 32 {
        return Err(bad());
    }
    let mut total: i64 = 0;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: i64 = num.parse().map_err(|_| bad())?;
        num.clear();
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(bad()),
        };
        total = n
            .checked_mul(unit)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(bad)?;
    }
    if !num.is_empty() || total <= 0 {
        return Err(bad());
    }
    chrono::Duration::try_seconds(total).ok_or_else(bad)
}

fn check_matcher(name: &str, v: &Option<String>) -> Result<(), SilenceError> {
    if let Some(p) = v {
        validate_glob(p).map_err(|e| SilenceError::Invalid(format!("{name}: {e}")))?;
    }
    Ok(())
}

impl NewSilence {
    /// Validates and converts into a stored [`Silence`].
    pub fn into_silence(self, now: DateTime<Utc>) -> Result<Silence, SilenceError> {
        check_matcher("resource", &self.resource)?;
        check_matcher("kind", &self.kind)?;
        check_matcher("tool", &self.tool)?;
        if self.resource.is_none() && self.kind.is_none() && self.tool.is_none() {
            return Err(SilenceError::Invalid(
                "at least one of resource, kind, tool is required".into(),
            ));
        }
        let comment = self.comment.trim().to_string();
        if comment.is_empty() || comment.chars().count() > 1024 {
            return Err(SilenceError::Invalid(
                "comment must be 1..=1024 characters".into(),
            ));
        }
        let created_by = self
            .created_by
            .unwrap_or_else(|| "api".into())
            .trim()
            .to_string();
        if created_by.is_empty()
            || created_by.chars().count() > 128
            || created_by.chars().any(char::is_control)
        {
            return Err(SilenceError::Invalid(
                "created_by must be 1..=128 printable characters".into(),
            ));
        }
        let starts_at = self.starts_at.unwrap_or(now);
        let ends_at = match (self.ends_at, self.duration.as_deref()) {
            (Some(e), None) => e,
            (None, Some(d)) => starts_at + parse_duration(d)?,
            _ => {
                return Err(SilenceError::Invalid(
                    "exactly one of ends_at or duration is required".into(),
                ))
            }
        };
        if ends_at <= starts_at {
            return Err(SilenceError::Invalid(
                "ends_at must be after starts_at".into(),
            ));
        }
        if ends_at <= now {
            return Err(SilenceError::Invalid(
                "silence would already be expired".into(),
            ));
        }
        if ends_at - starts_at > MAX_WINDOW {
            return Err(SilenceError::Invalid(
                "silence window longer than 366 days".into(),
            ));
        }
        Ok(Silence {
            id: format!("{:016x}", fastrand::u64(..)),
            resource: self.resource,
            kind: self.kind,
            tool: self.tool,
            starts_at,
            ends_at,
            comment,
            created_by,
            created_at: now,
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    silences: Vec<Silence>,
}

#[derive(Debug)]
struct Inner {
    rules: Vec<Silence>,
    stamp: Option<(SystemTime, u64)>,
    last_check: Option<Instant>,
}

/// Thread-safe silence store. With a path, every change is persisted and
/// external edits (e.g. by the CLI) are picked up within ~2 s.
#[derive(Debug)]
pub struct SilenceStore {
    path: Option<PathBuf>,
    inner: RwLock<Inner>,
}

fn file_stamp(p: &Path) -> Option<(SystemTime, u64)> {
    let m = std::fs::metadata(p).ok()?;
    Some((m.modified().ok()?, m.len()))
}

fn read_file(p: &Path) -> Result<Vec<Silence>, SilenceError> {
    match std::fs::read(p) {
        Ok(b) => {
            let f: FileFormat = serde_json::from_slice(&b)
                .map_err(|e| SilenceError::Invalid(format!("{}: {e}", p.display())))?;
            Ok(f.silences)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// Write to a temp file, fsync, rename over the target (atomic on all three OSes).
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp-{:08x}", fastrand::u32(..)));
    let res = (|| {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

impl SilenceStore {
    pub fn in_memory() -> Self {
        SilenceStore {
            path: None,
            inner: RwLock::new(Inner {
                rules: Vec::new(),
                stamp: None,
                last_check: None,
            }),
        }
    }

    /// Loads `path` (missing file = no silences). Expired rules are dropped on the next write.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SilenceError> {
        let path = path.into();
        let rules = read_file(&path)?;
        Ok(SilenceStore {
            inner: RwLock::new(Inner {
                rules,
                stamp: file_stamp(&path),
                last_check: Some(Instant::now()),
            }),
            path: Some(path),
        })
    }

    fn write_lock(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(|p| p.into_inner())
    }

    fn read_lock(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Reloads from disk if the file changed (checked at most every 2 s unless `force`).
    pub fn refresh(&self, force: bool) {
        let Some(path) = &self.path else { return };
        {
            let g = self.read_lock();
            if !force && g.last_check.is_some_and(|t| t.elapsed() < REFRESH_EVERY) {
                return;
            }
        }
        let mut g = self.write_lock();
        g.last_check = Some(Instant::now());
        let stamp = file_stamp(path);
        if stamp == g.stamp {
            return;
        }
        match read_file(path) {
            Ok(rules) => {
                g.rules = rules;
                g.stamp = stamp;
            }
            Err(e) => {
                tracing::error!(error = %e, "silence file unreadable; keeping previous rules")
            }
        }
    }

    fn persist(&self, g: &mut Inner, now: DateTime<Utc>) -> Result<(), SilenceError> {
        g.rules.retain(|s| s.ends_at > now);
        if let Some(path) = &self.path {
            let body = serde_json::to_vec_pretty(&FileFormat {
                version: 1,
                silences: g.rules.clone(),
            })
            .map_err(|e| SilenceError::Invalid(e.to_string()))?;
            atomic_write(path, &body)?;
            g.stamp = file_stamp(path);
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<Silence> {
        self.refresh(false);
        let now = Utc::now();
        self.read_lock()
            .rules
            .iter()
            .filter(|s| s.ends_at > now)
            .cloned()
            .collect()
    }

    pub fn add(&self, new: NewSilence) -> Result<Silence, SilenceError> {
        let now = Utc::now();
        let s = new.into_silence(now)?;
        self.refresh(true);
        let mut g = self.write_lock();
        g.rules.retain(|r| r.ends_at > now);
        if g.rules.len() >= MAX_SILENCES {
            return Err(SilenceError::Full);
        }
        g.rules.push(s.clone());
        if let Err(e) = self.persist(&mut g, now) {
            g.rules.retain(|r| r.id != s.id);
            return Err(e);
        }
        Ok(s)
    }

    /// Removes by id; returns whether it existed.
    pub fn remove(&self, id: &str) -> Result<bool, SilenceError> {
        self.refresh(true);
        let mut g = self.write_lock();
        let before = g.rules.len();
        let backup = g.rules.clone();
        g.rules.retain(|r| r.id != id);
        if g.rules.len() == before {
            return Ok(false);
        }
        if let Err(e) = self.persist(&mut g, Utc::now()) {
            g.rules = backup;
            return Err(e);
        }
        Ok(true)
    }

    /// Returns the id of the first active silence matching `a`.
    pub fn silenced_by(&self, a: &Alert, now: DateTime<Utc>) -> Option<String> {
        self.refresh(false);
        self.read_lock()
            .rules
            .iter()
            .find(|s| s.is_active(now) && s.matches(a))
            .map(|s| s.id.clone())
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorBody { error: msg.into() })).into_response()
}

async fn list_handler(State(s): State<Arc<SilenceStore>>) -> Response {
    Json(serde_json::json!({ "silences": s.list() })).into_response()
}

async fn add_handler(
    State(s): State<Arc<SilenceStore>>,
    body: Result<Json<NewSilence>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(new) = match body {
        Ok(b) => b,
        Err(e) => return err(e.status(), e.body_text()),
    };
    match s.add(new) {
        Ok(sil) => {
            tracing::info!(silence_id = %sil.id, created_by = %sil.created_by, ends_at = %sil.ends_at, "silence created via API");
            (StatusCode::CREATED, Json(sil)).into_response()
        }
        Err(SilenceError::Invalid(m)) => err(StatusCode::UNPROCESSABLE_ENTITY, m),
        Err(SilenceError::Full) => err(StatusCode::CONFLICT, SilenceError::Full.to_string()),
        Err(SilenceError::Io(e)) => {
            tracing::error!(error = %e, "persisting silence failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

async fn delete_handler(
    State(s): State<Arc<SilenceStore>>,
    UrlPath(id): UrlPath<String>,
) -> Response {
    if id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return err(StatusCode::BAD_REQUEST, "invalid silence id");
    }
    match s.remove(&id) {
        Ok(true) => {
            tracing::info!(silence_id = %id, "silence removed via API");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "no such silence"),
        Err(e) => {
            tracing::error!(error = %e, "removing silence failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// `GET/POST /v1/silences`, `DELETE /v1/silences/{id}`, bearer-token protected,
/// 16 KiB body limit.
pub fn silences_router(store: Arc<SilenceStore>, token: ApiToken) -> Router {
    Router::new()
        .route("/v1/silences", get(list_handler).post(add_handler))
        .route("/v1/silences/{id}", delete(delete_handler))
        .with_state(store)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(axum::middleware::from_fn_with_state(token, require_bearer))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::alert::Severity;

    fn new(resource: &str) -> NewSilence {
        NewSilence {
            resource: Some(resource.into()),
            duration: Some("1h".into()),
            comment: "planned maintenance".into(),
            ..Default::default()
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90m").unwrap().num_seconds(), 5400);
        assert_eq!(parse_duration("1d12h").unwrap().num_seconds(), 129_600);
        for bad in ["", "5", "h", "-1h", "1y", "99999999999999999w"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn validation() {
        let now = Utc::now();
        assert!(new("192.0.2.*").into_silence(now).is_ok());
        let mut n = new("x");
        n.resource = None;
        assert!(n.into_silence(now).is_err());
        let mut n = new("x");
        n.comment = " ".into();
        assert!(n.into_silence(now).is_err());
        let mut n = new("x");
        n.ends_at = Some(now + chrono::Duration::hours(1));
        assert!(n.into_silence(now).is_err(), "both ends_at and duration");
        let mut n = new("x");
        n.duration = Some("400d".into());
        assert!(n.into_silence(now).is_err());
    }

    #[test]
    fn matching_and_windows() {
        let st = SilenceStore::in_memory();
        let s = st.add(new("192.0.2.*")).unwrap();
        let hit = Alert::new("vigil", "hijack", Severity::Critical, "x").resource("192.0.2.0/24");
        let miss =
            Alert::new("vigil", "hijack", Severity::Critical, "x").resource("198.51.100.0/24");
        let now = Utc::now();
        assert_eq!(st.silenced_by(&hit, now), Some(s.id.clone()));
        assert_eq!(st.silenced_by(&miss, now), None);
        assert_eq!(st.silenced_by(&hit, now + chrono::Duration::hours(2)), None);
        let mut future = new("192.0.2.*");
        future.starts_at = Some(now + chrono::Duration::hours(1));
        let f = future.into_silence(now).unwrap();
        assert!(!f.is_active(now));
        assert!(st.remove(&s.id).unwrap());
        assert!(!st.remove(&s.id).unwrap());
    }

    #[test]
    fn persistence_and_external_edits() {
        let dir = std::env::temp_dir().join(format!("llcf-sil-{}", fastrand::u64(..)));
        let path = dir.join("silences.json");
        let a = SilenceStore::open(&path).unwrap();
        let s = a.add(new("*.example.org")).unwrap();
        // A second store (the CLI) sees it and removes it; the first notices on refresh.
        let b = SilenceStore::open(&path).unwrap();
        assert_eq!(b.list().len(), 1);
        assert!(b.remove(&s.id).unwrap());
        a.refresh(true);
        assert!(a.list().is_empty());
        // Corrupt file: refresh keeps the last good rules, open reports an error.
        std::fs::write(&path, b"{not json").unwrap();
        a.refresh(true);
        assert!(SilenceStore::open(&path).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    fn token() -> ApiToken {
        ApiToken::new("0123456789abcdef-test").unwrap()
    }

    async fn call(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn http_api() {
        let store = Arc::new(SilenceStore::in_memory());
        let app = silences_router(store.clone(), token());
        let auth = "Bearer 0123456789abcdef-test";

        let (st, _) = call(
            &app,
            Request::get("/v1/silences").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _) = call(
            &app,
            Request::get("/v1/silences")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        let body =
            r#"{"resource":"192.0.2.*","duration":"2h","comment":"fiber work","created_by":"noc"}"#;
        let (st, v) = call(
            &app,
            Request::post("/v1/silences")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let id = v["id"].as_str().unwrap().to_string();

        let (st, v) = call(
            &app,
            Request::post("/v1/silences")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"comment":"x","duration":"1h"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{v}");

        let (st, _) = call(
            &app,
            Request::post("/v1/silences")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(vec![b' '; 64 * 1024]))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);

        let (st, _) = call(
            &app,
            Request::post("/v1/silences")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"comment":"x","duration":"1h","resource":"a","evil":1}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);

        let (st, v) = call(
            &app,
            Request::get("/v1/silences")
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["silences"].as_array().unwrap().len(), 1);

        let (st, _) = call(
            &app,
            Request::delete(format!("/v1/silences/{id}"))
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, _) = call(
            &app,
            Request::delete(format!("/v1/silences/{id}"))
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        assert!(store.list().is_empty());
    }
}
