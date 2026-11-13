//! Propagation verification (43): is the blackhole host route visible outside?
//!
//! Sources, both optional and time-boxed:
//! * RIPEstat looking-glass (`/data/looking-glass/data.json?resource=<ip>/32`):
//!   counts RIS peers whose `prefix` equals our host prefix.
//! * Pathology (`GET /v1/prefixes/<prefix>/paths`): counts current best paths
//!   seen by your own routers / BMP feeds.
//!
//! A failing source never blocks anything: the status simply stays `unknown`.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info};

use crate::bgp::message::host_prefix;
use crate::config::PropagationConfig;
use crate::engine::Engine;
use crate::metrics::Metrics;
use crate::unix_now;

/// Responses larger than this are refused.
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_PARALLEL: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropStatus {
    Unknown,
    Propagated,
    NotSeen,
}

/// `propagation` field of `GET /v1/blackholes` (cross-tool contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Propagation {
    /// Unix seconds of the last check; 0 = never checked.
    pub checked_at: u64,
    pub visible_peers: usize,
    pub status: PropStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ripestat_peers: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pathology_peers: Option<usize>,
}

impl Propagation {
    pub fn unknown() -> Self {
        Self {
            checked_at: 0,
            visible_peers: 0,
            status: PropStatus::Unknown,
            ripestat_peers: None,
            pathology_peers: None,
        }
    }

    /// Combines source results: any visible peer = propagated; all sources
    /// answered with zero = not_seen; no answer at all = unknown.
    pub fn combine(now: u64, ripestat: Option<usize>, pathology: Option<usize>) -> Self {
        let answered: Vec<usize> = [ripestat, pathology].into_iter().flatten().collect();
        let visible: usize = answered.iter().sum();
        let status = if answered.is_empty() {
            PropStatus::Unknown
        } else if visible > 0 {
            PropStatus::Propagated
        } else {
            PropStatus::NotSeen
        };
        Self {
            checked_at: now,
            visible_peers: visible,
            status,
            ripestat_peers: ripestat,
            pathology_peers: pathology,
        }
    }
}

#[derive(Deserialize)]
struct LgResponse {
    data: LgData,
}
#[derive(Deserialize)]
struct LgData {
    #[serde(default)]
    rrcs: Vec<LgRrc>,
}
#[derive(Deserialize)]
struct LgRrc {
    #[serde(default)]
    peers: Vec<LgPeer>,
}
#[derive(Deserialize)]
struct LgPeer {
    #[serde(default)]
    prefix: String,
}

/// Counts looking-glass peers carrying exactly `prefix`.
pub fn count_ripestat(body: &[u8], prefix: &str) -> Result<usize, String> {
    let r: LgResponse = serde_json::from_slice(body).map_err(|e| format!("RIPEstat: {e}"))?;
    Ok(r.data
        .rrcs
        .iter()
        .flat_map(|r| &r.peers)
        .filter(|p| p.prefix == prefix)
        .count())
}

/// Counts `paths` in a Pathology `/v1/prefixes/<p>/paths` response.
pub fn count_pathology(body: &[u8]) -> Result<usize, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Pathology: {e}"))?;
    v.get("paths")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| "Pathology: response has no paths array".to_owned())
}

async fn get_limited(req: reqwest::RequestBuilder) -> Result<Vec<u8>, String> {
    let mut resp = req.send().await.map_err(|e| e.without_url().to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| e.without_url().to_string())?
    {
        if out.len() + chunk.len() > MAX_BODY {
            return Err("response too large".into());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

#[derive(Clone)]
pub struct Checker {
    client: reqwest::Client,
    ripestat: Option<String>,
    pathology: Option<String>,
    pathology_token: Option<String>,
}

impl Checker {
    pub fn from_config(cfg: &PropagationConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout.0))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("event-horizon/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let pathology_token = match &cfg.pathology_token_env {
            Some(v) => Some(llcforge_beacon::env_secret(v)?),
            None => None,
        };
        Ok(Self {
            client,
            ripestat: cfg
                .ripestat
                .then(|| cfg.ripestat_url.trim_end_matches('/').to_owned()),
            pathology: cfg
                .pathology_url
                .as_ref()
                .map(|u| u.trim_end_matches('/').to_owned()),
            pathology_token,
        })
    }

    async fn ripestat(&self, base: &str, ip: IpAddr) -> Result<usize, String> {
        let prefix = host_prefix(ip).to_string();
        let req = self
            .client
            .get(format!("{base}/data/looking-glass/data.json"))
            .query(&[
                ("resource", prefix.as_str()),
                ("sourceapp", "event-horizon"),
            ]);
        count_ripestat(&get_limited(req).await?, &prefix)
    }

    async fn pathology(&self, base: &str, ip: IpAddr) -> Result<usize, String> {
        let prefix = host_prefix(ip).to_string().replace('/', "%2F");
        let mut req = self
            .client
            .get(format!("{base}/v1/prefixes/{prefix}/paths"));
        if let Some(t) = &self.pathology_token {
            req = req.bearer_auth(t);
        }
        count_pathology(&get_limited(req).await?)
    }

    pub async fn check(&self, ip: IpAddr) -> Propagation {
        let rs = match &self.ripestat {
            Some(b) => self
                .ripestat(b, ip)
                .await
                .map_err(|e| debug!(%ip, error = %e, "RIPEstat check failed"))
                .ok(),
            None => None,
        };
        let pa = match &self.pathology {
            Some(b) => self
                .pathology(b, ip)
                .await
                .map_err(|e| debug!(%ip, error = %e, "Pathology check failed"))
                .ok(),
            None => None,
        };
        Propagation::combine(unix_now(), rs, pa)
    }
}

/// Periodically checks live (non dry-run) blackholes older than `delay`.
pub async fn run(
    cfg: PropagationConfig,
    checker: Checker,
    engine: Arc<Mutex<Engine>>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    let mut running: JoinSet<(IpAddr, Propagation)> = JoinSet::new();
    let mut in_flight = std::collections::HashSet::new();
    info!("propagation checker started");
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let now = unix_now();
                let due: Vec<IpAddr> = match engine.lock() {
                    Ok(e) => e
                        .list()
                        .into_iter()
                        .filter(|x| !x.dry_run && now.saturating_sub(x.created_at) >= cfg.delay.0)
                        .filter(|x| e.propagation(x.ip).is_none_or(|p| now.saturating_sub(p.checked_at) >= cfg.interval.0))
                        .map(|x| x.ip)
                        .collect(),
                    Err(_) => continue,
                };
                for ip in due {
                    if running.len() >= MAX_PARALLEL || !in_flight.insert(ip) {
                        continue;
                    }
                    let c = checker.clone();
                    running.spawn(async move { (ip, c.check(ip).await) });
                }
            }
            Some(r) = running.join_next(), if !running.is_empty() => {
                if let Ok((ip, p)) = r {
                    in_flight.remove(&ip);
                    metrics.propagation(p.status);
                    if let Ok(mut e) = engine.lock() {
                        e.set_propagation(ip, p);
                    }
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_statuses() {
        assert_eq!(
            Propagation::combine(1, None, None).status,
            PropStatus::Unknown
        );
        assert_eq!(
            Propagation::combine(1, Some(0), None).status,
            PropStatus::NotSeen
        );
        assert_eq!(
            Propagation::combine(1, Some(0), Some(0)).status,
            PropStatus::NotSeen
        );
        let p = Propagation::combine(1, Some(3), Some(2));
        assert_eq!((p.status, p.visible_peers), (PropStatus::Propagated, 5));
        assert_eq!(
            serde_json::to_value(Propagation::combine(1, Some(0), None)).unwrap()["status"],
            "not_seen"
        );
    }

    /// Shape verified against the live RIPEstat looking-glass data call.
    const LG: &str = r#"{"status":"ok","data":{"rrcs":[
        {"rrc":"RRC00","location":"Amsterdam, NL","peers":[
            {"asn_origin":"64500","as_path":"64496 64500","community":"65535:666","prefix":"198.51.100.7/32","peer":"192.0.2.1","origin":"IGP","next_hop":"192.0.2.1","latest_time":"2026-11-13T00:00:00"},
            {"asn_origin":"64500","as_path":"64497 64500","prefix":"198.51.100.0/24","peer":"192.0.2.2"}]},
        {"rrc":"RRC01","peers":[{"prefix":"198.51.100.7/32","peer":"192.0.2.3"}]},
        {"rrc":"RRC03"}],"query_time":"2026-11-13T00:00:00"}}"#;

    #[test]
    fn counts_exact_prefix_only() {
        assert_eq!(count_ripestat(LG.as_bytes(), "198.51.100.7/32"), Ok(2));
        assert_eq!(count_ripestat(LG.as_bytes(), "198.51.100.8/32"), Ok(0));
        assert_eq!(
            count_ripestat(br#"{"data":{"rrcs":[]}}"#, "198.51.100.7/32"),
            Ok(0)
        );
        assert!(count_ripestat(b"<html>", "x").is_err());
        assert_eq!(
            count_pathology(br#"{"paths":[{"peer":"192.0.2.1","peer_asn":64496}]}"#),
            Ok(1)
        );
        assert!(count_pathology(b"[]").is_err());
    }

    async fn serve(body: &'static str, expect_path: &'static str) -> String {
        use axum::routing::get;
        let app = axum::Router::new().route(
            expect_path,
            get(move || async move { ([("content-type", "application/json")], body) }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn checks_both_sources_over_http() {
        let rs = serve(LG, "/data/looking-glass/data.json").await;
        let pa = serve(
            r#"{"paths":[{"peer":"192.0.2.9"}]}"#,
            "/v1/prefixes/{p}/paths",
        )
        .await;
        let cfg = PropagationConfig {
            ripestat: true,
            ripestat_url: rs,
            pathology_url: Some(pa),
            pathology_token_env: None,
            delay: crate::config::Secs(0),
            interval: crate::config::Secs(60),
            timeout: crate::config::Secs(5),
        };
        let c = Checker::from_config(&cfg).unwrap();
        let p = c.check("198.51.100.7".parse().unwrap()).await;
        assert_eq!(p.ripestat_peers, Some(2));
        assert_eq!(p.pathology_peers, Some(1));
        assert_eq!(p.status, PropStatus::Propagated);
        // An unreachable source leaves the status unknown instead of failing.
        let dead = PropagationConfig {
            ripestat_url: "http://127.0.0.1:9".into(),
            pathology_url: None,
            ..cfg
        };
        let p = Checker::from_config(&dead)
            .unwrap()
            .check("198.51.100.7".parse().unwrap())
            .await;
        assert_eq!(p.status, PropStatus::Unknown);
    }
}
