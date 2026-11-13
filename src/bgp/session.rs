//! Announce-only eBGP session per upstream.
//!
//! The speaker connects out to each upstream (optionally from a fixed local
//! address, with a multihop TTL and a TCP-MD5 signature), negotiates OPEN,
//! keeps the session alive and mirrors the engine's published set: /32 or
//! /128 blackhole host routes (with global or regional communities, 34) and
//! FlowSpec rules when the session negotiated SAFI 133. Received UPDATEs are
//! parsed for safety and discarded; nothing is ever re-advertised. On session
//! loss it reconnects with exponential backoff and re-announces everything.
//! With Graceful Restart (RFC 4724) it sends End-of-RIB after the initial
//! sync and closes without a Cease on shutdown so upstreams keep the routes for
//! `restart_time`. In dry-run mode no TCP connection is made; the UPDATEs that
//! would be sent are logged instead.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use llcforge_alert::Severity;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, sleep_until, timeout, Instant};
use tracing::{debug, info, warn};

use super::flowspec::{encode_flowspec_announce, encode_flowspec_withdraw, FlowRule};
use super::message::*;
use super::socket::{self, SocketOptions};
use crate::alerts::{alert, Alerts};
use crate::audit::Audit;
use crate::config::{Config, Upstream};
use crate::engine::{Published, Routes, Scope};
use crate::metrics::Metrics;
use crate::unix_now;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Speaker {
    pub local_asn: u32,
    pub router_id: Ipv4Addr,
    pub hold_time: u16,
    pub next_hop_v4: Ipv4Addr,
    pub next_hop_v6: Ipv6Addr,
    /// Graceful Restart time; `None` = capability not advertised.
    pub graceful_restart: Option<u16>,
}

impl Speaker {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            local_asn: cfg.bgp.local_asn,
            router_id: cfg.bgp.router_id,
            hold_time: cfg.bgp.hold_time,
            next_hop_v4: cfg.bgp.next_hop_v4,
            next_hop_v6: cfg.bgp.next_hop_v6,
            graceful_restart: cfg
                .bgp
                .graceful_restart
                .map(|g| u16::try_from(g.restart_time.0).unwrap_or(4095)),
        }
    }

    pub fn announce_params(&self, up: &Upstream, four_octet_as: bool) -> AnnounceParams {
        AnnounceParams {
            local_asn: self.local_asn,
            four_octet_as,
            next_hop_v4: self.next_hop_v4,
            next_hop_v6: self.next_hop_v6,
            communities: blackhole_communities(&up.communities),
        }
    }

    pub fn open_options(&self, up: &Upstream, restarting: bool) -> OpenOptions {
        OpenOptions {
            flowspec: up.flowspec,
            graceful_restart: self.graceful_restart.map(|t| (t, restarting)),
        }
    }
}

/// Communities for a blackhole with `scope` on upstream `up`, or `None` when
/// the scope excludes this upstream.
pub fn communities_for(up: &Upstream, scope: &Scope) -> Option<Vec<Community>> {
    if !scope.upstreams.is_empty() && !scope.upstreams.contains(&up.name) {
        return None;
    }
    match &scope.region {
        None => Some(blackhole_communities(&up.communities)),
        Some(r) => up.regions.get(r).map(|c| regional_communities(c)),
    }
}

/// What this upstream should carry right now.
pub fn desired(
    up: &Upstream,
    p: &Published,
) -> (BTreeMap<IpAddr, Vec<Community>>, BTreeMap<String, FlowRule>) {
    let bh = p
        .blackholes
        .iter()
        .filter_map(|(ip, s)| communities_for(up, s).map(|c| (*ip, c)))
        .collect();
    let fs = if up.flowspec {
        p.flowspec.clone()
    } else {
        BTreeMap::new()
    };
    (bh, fs)
}

/// Keys to withdraw (advertised but no longer wanted) and entries to
/// (re-)announce (new or changed).
pub fn diff<K: Ord + Clone, V: PartialEq + Clone>(
    current: &BTreeMap<K, V>,
    advertised: &BTreeMap<K, V>,
) -> (Vec<K>, Vec<(K, V)>) {
    (
        advertised
            .keys()
            .filter(|k| !current.contains_key(*k))
            .cloned()
            .collect(),
        current
            .iter()
            .filter(|(k, v)| advertised.get(*k) != Some(*v))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

/// Shared context for one upstream task.
pub struct Ctx {
    pub up: Upstream,
    pub speaker: Speaker,
    pub audit: Arc<Audit>,
    pub metrics: Arc<Metrics>,
    pub alerts: Alerts,
    pub socket: SocketOptions,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Ctx {
    fn audit_update(&self, kind: &str, what: &str, dry_run: bool) {
        let c = match kind {
            "announce" => &self.metrics.updates_sent_announce,
            "withdraw" => &self.metrics.updates_sent_withdraw,
            "flowspec_announce" => &self.metrics.flowspec_updates_announce,
            _ => &self.metrics.flowspec_updates_withdraw,
        };
        Metrics::inc(c);
        let key = if kind.starts_with("flowspec") {
            "flowspec"
        } else {
            "ip"
        };
        self.audit.record(
            unix_now(),
            &format!("bgp_{kind}"),
            json!({"upstream": self.up.name, key: what, "dry_run": dry_run}),
        );
    }
}

/// Dry-run stand-in for a session: logs the UPDATEs that would be sent.
pub async fn run_dry(ctx: Ctx, mut routes: Routes, mut shutdown: watch::Receiver<bool>) {
    let params = ctx.speaker.announce_params(&ctx.up, true);
    let mut adv_bh = BTreeMap::new();
    let mut adv_fs: BTreeMap<String, FlowRule> = BTreeMap::new();
    loop {
        let (bh, fs) = desired(&ctx.up, &routes.borrow_and_update());
        let (withdraw, announce) = diff(&bh, &adv_bh);
        for ip in withdraw {
            let msg = encode_withdraw(ip);
            info!(upstream = %ctx.up.name, %ip, update = %hex(&msg), "dry-run: would withdraw");
            ctx.audit_update("withdraw", &ip.to_string(), true);
        }
        for (ip, comms) in announce {
            let p = AnnounceParams {
                communities: comms,
                ..params.clone()
            };
            let msg = encode_announce(ip, &p);
            info!(upstream = %ctx.up.name, %ip, update = %hex(&msg), "dry-run: would announce");
            ctx.audit_update("announce", &ip.to_string(), true);
        }
        let (withdraw, announce) = diff(&fs, &adv_fs);
        for k in withdraw {
            if let Some(r) = adv_fs.get(&k) {
                let msg = encode_flowspec_withdraw(r);
                info!(upstream = %ctx.up.name, rule = %r, update = %hex(&msg), "dry-run: would withdraw FlowSpec");
                ctx.audit_update("flowspec_withdraw", &k, true);
            }
        }
        for (k, r) in announce {
            let msg = encode_flowspec_announce(&r, ctx.speaker.local_asn, true);
            info!(upstream = %ctx.up.name, rule = %r, update = %hex(&msg), "dry-run: would announce FlowSpec");
            ctx.audit_update("flowspec_announce", &k, true);
        }
        adv_bh = bh;
        adv_fs = fs;
        tokio::select! {
            r = routes.changed() => if r.is_err() { return },
            _ = shutdown.changed() => return,
        }
    }
}

/// Live session loop with reconnect and exponential backoff.
pub async fn run(ctx: Ctx, mut routes: Routes, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = BACKOFF_MIN;
    // RFC 4724 Restart State: set on the first session after a process start.
    let mut restarting = true;
    loop {
        let mut established = false;
        let res = session(
            &ctx,
            &mut routes,
            &mut shutdown,
            &mut established,
            restarting,
        )
        .await;
        ctx.metrics.set_session(&ctx.up.name, false);
        if established {
            restarting = false;
        }
        match res {
            Ok(()) => return, // shutdown
            Err(e) => {
                let msg = format!("{e:#}");
                warn!(upstream = %ctx.up.name, error = %msg, "BGP session down");
                if established {
                    ctx.alerts.send(
                        alert(
                            "session_down",
                            Severity::Warning,
                            format!("BGP session to {} down", ctx.up.name),
                        )
                        .resource(ctx.up.name.clone())
                        .summary(msg)
                        .field("neighbor", ctx.up.neighbor),
                    );
                }
            }
        }
        if established {
            backoff = BACKOFF_MIN;
        }
        info!(upstream = %ctx.up.name, retry_in = ?backoff, "reconnecting");
        tokio::select! {
            _ = sleep(backoff) => {}
            _ = shutdown.changed() => return,
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

type Frame = (u8, Vec<u8>);

async fn read_frames(mut rd: OwnedReadHalf, tx: mpsc::Sender<Result<Frame>>) {
    loop {
        let mut hdr = [0u8; HEADER_LEN];
        let res = async {
            rd.read_exact(&mut hdr).await.context("connection closed")?;
            let (len, kind) = decode_header(&hdr)?;
            let mut body = vec![0u8; len - HEADER_LEN];
            rd.read_exact(&mut body)
                .await
                .context("connection closed")?;
            Ok((kind, body))
        }
        .await;
        let stop = res.is_err();
        if tx.send(res).await.is_err() || stop {
            return;
        }
    }
}

async fn send(wr: &mut OwnedWriteHalf, msg: &[u8]) -> Result<()> {
    timeout(WRITE_TIMEOUT, wr.write_all(msg))
        .await
        .map_err(|_| anyhow!("write timed out"))??;
    Ok(())
}

async fn recv(rx: &mut mpsc::Receiver<Result<Frame>>, wait: Duration) -> Result<Frame> {
    match timeout(wait, rx.recv()).await {
        Err(_) => bail!("timed out waiting for peer"),
        Ok(None) => bail!("connection closed"),
        Ok(Some(r)) => r,
    }
}

fn peer_notification(body: &[u8]) -> anyhow::Error {
    match decode_notification(body) {
        Ok(n) => anyhow!("peer sent NOTIFICATION {}/{}", n.code, n.subcode),
        Err(_) => anyhow!("peer sent malformed NOTIFICATION"),
    }
}

/// Checks a received OPEN; returns the NOTIFICATION (code, subcode) to send on failure.
pub fn check_open(open: &Open, up: &Upstream, local_asn: u32) -> Result<(), (u8, u8, String)> {
    if open.version != 4 {
        return Err((2, 1, format!("unsupported BGP version {}", open.version)));
    }
    if open.asn != up.remote_asn {
        return Err((
            2,
            2,
            format!("peer AS {} != configured {}", open.asn, up.remote_asn),
        ));
    }
    if open.router_id.is_unspecified() {
        return Err((2, 3, "peer BGP identifier is 0.0.0.0".into()));
    }
    if open.hold_time == 1 || open.hold_time == 2 {
        return Err((2, 6, format!("unacceptable hold time {}", open.hold_time)));
    }
    if local_asn > 0xFFFF && !open.four_octet_as {
        return Err((
            2,
            7,
            "peer lacks 4-octet AS support required for our ASN".into(),
        ));
    }
    Ok(())
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn session(
    ctx: &Ctx,
    routes: &mut Routes,
    shutdown: &mut watch::Receiver<bool>,
    established: &mut bool,
    restarting: bool,
) -> Result<()> {
    let up = &ctx.up;
    let sp = &ctx.speaker;
    let addr = SocketAddr::new(up.neighbor, up.port);
    let stream = tokio::select! {
        r = timeout(CONNECT_TIMEOUT, socket::connect(addr, &ctx.socket)) => {
            r.map_err(|_| anyhow!("connect to {addr} timed out"))?
                .with_context(|| format!("connect to {addr}"))?
        }
        _ = shutdown.changed() => return Ok(()),
    };
    stream.set_nodelay(true)?;
    let (rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel(16);
    let _reader = AbortOnDrop(tokio::spawn(read_frames(rd, tx)));

    send(
        &mut wr,
        &encode_open_with(
            sp.local_asn,
            sp.hold_time,
            sp.router_id,
            &sp.open_options(up, restarting),
        ),
    )
    .await?;
    let (kind, body) = recv(&mut rx, OPEN_TIMEOUT).await?;
    let open = match kind {
        MSG_OPEN => match decode_open(&body) {
            Ok(o) => o,
            Err(e) => {
                let _ = send(&mut wr, &encode_notification(2, 0, &[])).await;
                bail!("malformed OPEN: {e}");
            }
        },
        MSG_NOTIFICATION => return Err(peer_notification(&body)),
        _ => {
            let _ = send(&mut wr, &encode_notification(5, 1, &[])).await;
            bail!("expected OPEN, got message type {kind}");
        }
    };
    if let Err((code, sub, why)) = check_open(&open, up, sp.local_asn) {
        let _ = send(&mut wr, &encode_notification(code, sub, &[])).await;
        bail!("rejected OPEN: {why}");
    }
    let hold = sp.hold_time.min(open.hold_time);
    let hold_dur = Duration::from_secs(u64::from(hold));
    send(&mut wr, &encode_keepalive()).await?;
    let (kind, body) = recv(&mut rx, if hold > 0 { hold_dur } else { OPEN_TIMEOUT }).await?;
    match kind {
        MSG_KEEPALIVE => {}
        MSG_NOTIFICATION => return Err(peer_notification(&body)),
        _ => {
            let _ = send(&mut wr, &encode_notification(5, 2, &[])).await;
            bail!("expected KEEPALIVE, got message type {kind}");
        }
    }

    *established = true;
    ctx.metrics.set_session(&up.name, true);
    let fs_v4 = up.flowspec && open.ipv4_flowspec;
    let fs_v6 = up.flowspec && open.ipv6_flowspec;
    info!(upstream = %up.name, peer_as = open.asn, hold, four_octet_as = open.four_octet_as,
          ipv6 = open.ipv6_unicast, flowspec_v4 = fs_v4, flowspec_v6 = fs_v6,
          graceful_restart = sp.graceful_restart.is_some(), "BGP session established");
    if up.flowspec && !(fs_v4 || fs_v6) {
        warn!(upstream = %up.name, "peer did not negotiate FlowSpec; FlowSpec rules are not sent to it");
    }
    ctx.alerts.send(
        alert(
            "session_down",
            Severity::Info,
            format!("BGP session to {} established", up.name),
        )
        .resource(up.name.clone())
        .resolved(true),
    );

    let params = sp.announce_params(up, open.four_octet_as);
    let mut adv_bh: BTreeMap<IpAddr, Vec<Community>> = BTreeMap::new();
    let mut adv_fs: BTreeMap<String, FlowRule> = BTreeMap::new();
    let ka = hold_dur / 3;
    let mut next_ka = Instant::now() + ka;
    let mut hold_deadline = Instant::now() + hold_dur;
    let mut sync_needed = true;
    let mut eor_sent = false;

    loop {
        if sync_needed {
            sync_needed = false;
            let (bh, fs) = desired(up, &routes.borrow_and_update());
            let (withdraw, announce) = diff(&bh, &adv_bh);
            for ip in withdraw {
                send(&mut wr, &encode_withdraw(ip)).await?;
                adv_bh.remove(&ip);
                info!(upstream = %up.name, %ip, "withdrawn");
                ctx.audit_update("withdraw", &ip.to_string(), false);
            }
            for (ip, comms) in announce {
                if !open.supports(ip) {
                    warn!(upstream = %up.name, %ip, "peer did not negotiate this address family; not announced");
                    continue;
                }
                let p = AnnounceParams {
                    communities: comms.clone(),
                    ..params.clone()
                };
                send(&mut wr, &encode_announce(ip, &p)).await?;
                adv_bh.insert(ip, comms);
                info!(upstream = %up.name, %ip, "announced");
                ctx.audit_update("announce", &ip.to_string(), false);
            }
            let (withdraw, announce) = diff(&fs, &adv_fs);
            for k in withdraw {
                if let Some(r) = adv_fs.remove(&k) {
                    send(&mut wr, &encode_flowspec_withdraw(&r)).await?;
                    info!(upstream = %up.name, rule = %r, "FlowSpec withdrawn");
                    ctx.audit_update("flowspec_withdraw", &k, false);
                }
            }
            for (k, r) in announce {
                if !open.supports_flowspec(r.dst) {
                    continue;
                }
                send(
                    &mut wr,
                    &encode_flowspec_announce(&r, sp.local_asn, open.four_octet_as),
                )
                .await?;
                info!(upstream = %up.name, rule = %r, "FlowSpec announced");
                ctx.audit_update("flowspec_announce", &k, false);
                adv_fs.insert(k, r);
            }
            if sp.graceful_restart.is_some() && !eor_sent {
                eor_sent = true;
                let mut fams = vec![(AFI_IPV4, SAFI_UNICAST)];
                if open.ipv6_unicast {
                    fams.push((AFI_IPV6, SAFI_UNICAST));
                }
                if fs_v4 {
                    fams.push((AFI_IPV4, SAFI_FLOWSPEC));
                }
                if fs_v6 {
                    fams.push((AFI_IPV6, SAFI_FLOWSPEC));
                }
                for (afi, safi) in fams {
                    send(&mut wr, &encode_end_of_rib(afi, safi)).await?;
                }
                debug!(upstream = %up.name, "End-of-RIB sent");
            }
        }
        tokio::select! {
            msg = rx.recv() => {
                let (kind, body) = msg.ok_or_else(|| anyhow!("connection closed"))??;
                hold_deadline = Instant::now() + hold_dur;
                match kind {
                    MSG_KEEPALIVE => {}
                    MSG_UPDATE => {
                        Metrics::inc(&ctx.metrics.updates_received);
                        match decode_update(&body, open.four_octet_as) {
                            Ok(u) => debug!(upstream = %up.name, nlri = u.nlri.len(), withdrawn = u.withdrawn.len(), "ignoring received UPDATE"),
                            Err(e) => warn!(upstream = %up.name, error = %e, "ignoring malformed UPDATE"),
                        }
                    }
                    MSG_NOTIFICATION => return Err(peer_notification(&body)),
                    _ => {
                        let _ = send(&mut wr, &encode_notification(5, 3, &[])).await;
                        bail!("unexpected OPEN in established state");
                    }
                }
            }
            _ = sleep_until(next_ka), if hold > 0 => {
                send(&mut wr, &encode_keepalive()).await?;
                next_ka += ka;
            }
            _ = sleep_until(hold_deadline), if hold > 0 => {
                let _ = send(&mut wr, &encode_notification(4, 0, &[])).await;
                bail!("hold timer expired");
            }
            r = routes.changed() => {
                if r.is_err() { return Ok(()); }
                sync_needed = true;
            }
            _ = shutdown.changed() => {
                if sp.graceful_restart.is_some() {
                    // No NOTIFICATION: the peer keeps our routes as stale for restart_time.
                    let _ = wr.shutdown().await;
                    info!(upstream = %up.name, "session closed for shutdown (graceful restart, routes retained by peer)");
                } else {
                    // Cease / Administrative Shutdown. The upstream drops our routes with the session.
                    let _ = send(&mut wr, &encode_notification(6, 2, &[])).await;
                    info!(upstream = %up.name, "session closed for shutdown");
                }
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::Sink;
    use crate::bgp::flowspec::decode_flowspec_update;
    use crate::engine::tests::{engine, rule};
    use crate::state::Source;
    use tokio::net::{TcpListener, TcpStream};

    fn upstream(port: u16) -> Upstream {
        Upstream {
            name: "transit-a".into(),
            neighbor: IpAddr::from([127, 0, 0, 1]),
            port,
            remote_asn: 64496,
            communities: vec!["64496:666".parse().unwrap()],
            md5_password_env: None,
            ebgp_multihop: None,
            local_address: None,
            flowspec: false,
            regions: [("eu".to_owned(), vec!["64496:6661".parse().unwrap()])].into(),
        }
    }

    fn speaker() -> Speaker {
        Speaker {
            local_asn: 64500,
            router_id: Ipv4Addr::new(192, 0, 2, 10),
            hold_time: 9,
            next_hop_v4: Ipv4Addr::new(192, 0, 2, 1),
            next_hop_v6: "100::1".parse().unwrap(),
            graceful_restart: None,
        }
    }

    fn ctx(up: Upstream, sp: Speaker, sink: &Sink) -> Ctx {
        Ctx {
            up,
            speaker: sp,
            audit: Arc::new(Audit::to_writer(Box::new(sink.clone()))),
            metrics: Arc::new(Metrics::default()),
            alerts: Alerts::disabled(),
            socket: SocketOptions::default(),
        }
    }

    async fn read_msg(s: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut h = [0u8; HEADER_LEN];
        s.read_exact(&mut h).await.unwrap();
        let (len, kind) = decode_header(&h).unwrap();
        let mut b = vec![0u8; len - HEADER_LEN];
        s.read_exact(&mut b).await.unwrap();
        (kind, b)
    }

    async fn next_update_body(s: &mut TcpStream) -> Vec<u8> {
        loop {
            let (k, b) = read_msg(s).await;
            if k == MSG_UPDATE {
                return b;
            }
        }
    }

    async fn next_update(s: &mut TcpStream) -> Update {
        decode_update(&next_update_body(s).await, true).unwrap()
    }

    #[test]
    fn diff_computes_changes() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let a: BTreeMap<IpAddr, u8> = [(ip("198.51.100.7"), 1), (ip("198.51.100.9"), 2)].into();
        let b: BTreeMap<IpAddr, u8> = [(ip("198.51.100.8"), 1), (ip("198.51.100.9"), 1)].into();
        assert_eq!(
            diff(&a, &b),
            (
                vec![ip("198.51.100.8")],
                vec![(ip("198.51.100.7"), 1), (ip("198.51.100.9"), 2)]
            )
        );
    }

    #[test]
    fn scope_selects_upstreams_and_communities() {
        let up = upstream(179);
        let global = Scope::default();
        assert_eq!(
            communities_for(&up, &global).unwrap()[0],
            Community::BLACKHOLE
        );
        let eu = Scope {
            region: Some("eu".into()),
            upstreams: vec![],
        };
        assert_eq!(
            communities_for(&up, &eu).unwrap(),
            vec![Community::NO_EXPORT, "64496:6661".parse().unwrap()]
        );
        let us = Scope {
            region: Some("us".into()),
            upstreams: vec![],
        };
        assert!(communities_for(&up, &us).is_none());
        let other = Scope {
            region: None,
            upstreams: vec!["transit-b".into()],
        };
        assert!(communities_for(&up, &other).is_none());
        // FlowSpec only on upstreams that enable it.
        let mut p = Published::default();
        p.flowspec.insert("k".into(), rule("198.51.100.7"));
        assert!(desired(&up, &p).1.is_empty());
        let mut fsup = up.clone();
        fsup.flowspec = true;
        assert_eq!(desired(&fsup, &p).1.len(), 1);
    }

    #[test]
    fn open_checks() {
        let up = upstream(179);
        let ok = Open {
            version: 4,
            asn: 64496,
            hold_time: 90,
            router_id: Ipv4Addr::new(203, 0, 113, 1),
            four_octet_as: true,
            any_multiprotocol: true,
            ipv4_unicast: true,
            ipv6_unicast: true,
            ipv4_flowspec: false,
            ipv6_flowspec: false,
            graceful_restart: None,
        };
        assert!(check_open(&ok, &up, 64500).is_ok());
        let code = |o: Open, asn: u32| check_open(&o, &up, asn).unwrap_err().1;
        assert_eq!(
            code(
                Open {
                    asn: 64497,
                    ..ok.clone()
                },
                64500
            ),
            2
        );
        assert_eq!(
            code(
                Open {
                    version: 3,
                    ..ok.clone()
                },
                64500
            ),
            1
        );
        assert_eq!(
            code(
                Open {
                    hold_time: 2,
                    ..ok.clone()
                },
                64500
            ),
            6
        );
        assert_eq!(
            code(
                Open {
                    router_id: Ipv4Addr::UNSPECIFIED,
                    ..ok.clone()
                },
                64500
            ),
            3
        );
        assert!(check_open(
            &Open {
                four_octet_as: false,
                ..ok.clone()
            },
            &up,
            64500
        )
        .is_ok());
        assert!(check_open(
            &Open {
                four_octet_as: false,
                ..ok
            },
            &up,
            4_200_000_000
        )
        .is_err());
    }

    async fn handshake(mut s: TcpStream, opts: OpenOptions) -> (TcpStream, Open) {
        let (k, b) = read_msg(&mut s).await;
        assert_eq!(k, MSG_OPEN);
        let ours = decode_open(&b).unwrap();
        assert_eq!(ours.asn, 64500);
        s.write_all(&encode_open_with(
            64496,
            90,
            Ipv4Addr::new(203, 0, 113, 1),
            &opts,
        ))
        .await
        .unwrap();
        s.write_all(&encode_keepalive()).await.unwrap();
        assert_eq!(read_msg(&mut s).await.0, MSG_KEEPALIVE);
        (s, ours)
    }

    /// End-to-end against a fake upstream on loopback: handshake, initial
    /// announce, live withdraw, ignore a garbage UPDATE, reconnect + re-announce, Cease on shutdown.
    #[tokio::test]
    async fn session_against_fake_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (mut eng, routes, _) = engine();
        eng.request(
            "198.51.100.7".parse().unwrap(),
            None,
            "t",
            Source::Api,
            unix_now(),
        )
        .unwrap();
        let (sd_tx, sd_rx) = watch::channel(false);
        let sink = Sink::default();
        let task = tokio::spawn(run(ctx(upstream(port), speaker(), &sink), routes, sd_rx));

        let (s, _) = listener.accept().await.unwrap();
        let (mut s, ours) = handshake(s, OpenOptions::default()).await;
        assert!(!ours.ipv4_flowspec && ours.graceful_restart.is_none());
        let u = next_update(&mut s).await;
        assert_eq!(u.nlri, vec!["198.51.100.7/32".parse().unwrap()]);
        assert_eq!(u.communities[0], Community::BLACKHOLE);
        assert_eq!(u.as_path, vec![64500]);

        // Garbage UPDATE from the peer is ignored, session stays up.
        s.write_all(&[[0xFFu8; 16].as_slice(), &[0, 25, 2, 0, 9, 1, 2, 3, 4]].concat())
            .await
            .unwrap();

        eng.request(
            "2001:db8:100::7".parse().unwrap(),
            None,
            "t",
            Source::Api,
            unix_now(),
        )
        .unwrap();
        let u = next_update(&mut s).await;
        assert_eq!(u.nlri, vec!["2001:db8:100::7/128".parse().unwrap()]);
        assert_eq!(u.next_hop, Some("100::1".parse().unwrap()));

        // Regional scope: provider community instead of BLACKHOLE.
        eng.request_blackhole(
            "198.51.100.9".parse().unwrap(),
            None,
            Some("eu".into()),
            vec![],
            "t",
            Source::Api,
            unix_now(),
        )
        .unwrap();
        let u = next_update(&mut s).await;
        assert_eq!(u.nlri, vec!["198.51.100.9/32".parse().unwrap()]);
        assert_eq!(
            u.communities,
            vec![Community::NO_EXPORT, "64496:6661".parse().unwrap()]
        );

        eng.withdraw(
            "198.51.100.7".parse().unwrap(),
            "t",
            Source::Api,
            unix_now(),
        )
        .unwrap();
        let u = next_update(&mut s).await;
        assert_eq!(u.withdrawn, vec!["198.51.100.7/32".parse().unwrap()]);

        // Drop the connection: the speaker reconnects and re-announces the active set.
        drop(s);
        let (s, _) = listener.accept().await.unwrap();
        let (mut s, _) = handshake(s, OpenOptions::default()).await;
        let mut seen = vec![
            next_update(&mut s).await.nlri,
            next_update(&mut s).await.nlri,
        ];
        seen.sort();
        assert_eq!(
            seen,
            vec![
                vec!["198.51.100.9/32".parse().unwrap()],
                vec!["2001:db8:100::7/128".parse().unwrap()],
            ]
        );

        sd_tx.send(true).unwrap();
        let (k, b) = read_msg(&mut s).await;
        assert_eq!(k, MSG_NOTIFICATION);
        assert_eq!(
            decode_notification(&b).unwrap(),
            Notification {
                code: 6,
                subcode: 2
            }
        );
        timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(sink.lines().iter().any(|l| l["event"] == "bgp_withdraw"));
    }

    /// FlowSpec over SAFI 133, End-of-RIB with Graceful Restart, and no Cease on shutdown.
    #[tokio::test]
    async fn flowspec_and_graceful_restart_against_fake_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (mut eng, routes, _) = engine();
        eng.request_flowspec(rule("198.51.100.7"), None, "t", Source::Api, unix_now())
            .unwrap();
        let mut up = upstream(port);
        up.flowspec = true;
        let mut sp = speaker();
        sp.graceful_restart = Some(120);
        let (sd_tx, sd_rx) = watch::channel(false);
        let sink = Sink::default();
        let task = tokio::spawn(run(ctx(up, sp, &sink), routes, sd_rx));

        let (s, _) = listener.accept().await.unwrap();
        let peer_opts = OpenOptions {
            flowspec: true,
            graceful_restart: Some((180, false)),
        };
        let (mut s, ours) = handshake(s, peer_opts).await;
        assert!(ours.ipv4_flowspec && ours.ipv6_flowspec);
        assert_eq!(ours.graceful_restart, Some(120));
        // First UPDATE is the FlowSpec rule, then the End-of-RIB markers.
        let f = decode_flowspec_update(&next_update_body(&mut s).await).unwrap();
        assert_eq!(f.announced[0].protocol, Some(17));
        assert_eq!(f.announced[0].src_port, Some(53));
        assert_eq!(f.rates, vec![125_000.0]);
        let eor = next_update_body(&mut s).await;
        assert_eq!(eor, vec![0, 0, 0, 0]); // IPv4 unicast EoR
        for _ in 0..3 {
            let b = next_update_body(&mut s).await;
            assert!(decode_flowspec_update(&b).unwrap().withdrawn.is_empty());
        }
        // Live FlowSpec withdraw.
        eng.withdraw_flowspec(&rule("198.51.100.7").key(), "t", Source::Api, unix_now())
            .unwrap();
        let f = decode_flowspec_update(&next_update_body(&mut s).await).unwrap();
        assert_eq!(f.withdrawn.len(), 1);

        sd_tx.send(true).unwrap();
        // Graceful restart: the speaker closes without a NOTIFICATION.
        let mut rest = Vec::new();
        timeout(Duration::from_secs(5), s.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        let mut i = 0;
        while i + HEADER_LEN <= rest.len() {
            let (len, kind) = decode_header(&rest[i..i + HEADER_LEN]).unwrap();
            assert_ne!(kind, MSG_NOTIFICATION);
            i += len;
        }
        timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(sink
            .lines()
            .iter()
            .any(|l| l["event"] == "bgp_flowspec_announce"));
    }

    #[tokio::test]
    async fn dry_run_sends_nothing_but_audits() {
        let (mut eng, routes, _) = engine();
        let (sd_tx, sd_rx) = watch::channel(false);
        let sink = Sink::default();
        let mut up = upstream(1);
        up.flowspec = true;
        let task = tokio::spawn(run_dry(ctx(up, speaker(), &sink), routes, sd_rx));
        eng.request(
            "198.51.100.7".parse().unwrap(),
            None,
            "t",
            Source::Api,
            unix_now(),
        )
        .unwrap();
        eng.request_flowspec(rule("198.51.100.8"), None, "t", Source::Api, unix_now())
            .unwrap();
        for _ in 0..100 {
            if sink.lines().len() >= 2 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        sd_tx.send(true).unwrap();
        task.await.unwrap();
        let l = sink.lines();
        assert_eq!(l[0]["event"], "bgp_announce");
        assert_eq!(l[0]["dry_run"], true);
        assert!(l.iter().any(|x| x["event"] == "bgp_flowspec_announce"));
    }
}
