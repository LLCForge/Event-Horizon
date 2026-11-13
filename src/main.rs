//! Event Horizon: automated, guard-railed RTBH and FlowSpec mitigation.
#![deny(unsafe_code)]

mod alerts;
mod api;
mod approval;
mod audit;
mod bgp;
mod config;
mod detect;
mod engine;
mod flow;
mod metrics;
mod netflow;
mod policy;
mod propagation;
mod report;
mod sflow;
mod state;
mod tls;
mod wire;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use llcforge_beacon::cli::{run_silence_command, ServiceCommand, SilenceCommand};
use llcforge_beacon::{
    health_router, init_logging, reload_router, run_service_command, silences_router, ApiToken,
    Dispatcher, DispatcherOptions, LogFormat, Readiness, ReloadSignal, ServiceSpec, Severity,
    Shutdown, SilenceStore,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::alerts::{alert, Alerts};
use crate::bgp::flowspec::{
    decode_flowspec_update, encode_flowspec_announce, FlowAction, FlowRule,
};
use crate::bgp::message::{decode_update, encode_announce, encode_withdraw, HEADER_LEN};
use crate::bgp::session::{self, communities_for, Ctx, Speaker};
use crate::bgp::socket::{self as bgp_socket, SocketOptions};
use crate::config::{fmt_duration, parse_duration, ApprovalMode, Config, BIN};
use crate::detect::{Detector, FlowSettings, Mitigator, Params};
use crate::engine::{Engine, Scope};
use crate::metrics::Metrics;
use crate::policy::Policy;
use crate::report::ReportStore;

const SPEC: ServiceSpec = ServiceSpec {
    bin: BIN,
    display_name: "Event Horizon",
    description: "Automated guard-railed RTBH and FlowSpec DDoS mitigation over BGP",
};

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Parser)]
#[command(
    name = "event-horizon",
    version,
    about = "Automated, guard-railed RTBH and FlowSpec (BGP DDoS mitigation)"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, short, global = true, default_value = "event-horizon.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the speaker, detectors, trigger API and metrics endpoint.
    Run,
    /// Validate the configuration and print a summary.
    CheckConfig,
    /// Run the policy engine for one address and print the exact BGP UPDATEs. No network I/O.
    Simulate {
        /// Destination address to evaluate.
        #[arg(long)]
        dst: IpAddr,
        /// Requested TTL (e.g. 30m); defaults to guardrails.ttl.default.
        #[arg(long)]
        ttl: Option<String>,
        /// Pretend this many blackholes are already active.
        #[arg(long, default_value_t = 0)]
        active: usize,
        /// Regional blackhole scope (a key of [bgp.upstream.regions]).
        #[arg(long)]
        scope: Option<String>,
        /// Simulate a FlowSpec rule instead: tcp, udp, icmp, icmpv6 or a number.
        #[arg(long)]
        protocol: Option<String>,
        #[arg(long)]
        src_port: Option<u16>,
        #[arg(long)]
        dst_port: Option<u16>,
        /// FlowSpec action: rate-limit (default, flowspec.rate_limit_kbps) or discard.
        #[arg(long)]
        discard: bool,
    },
    /// Manage alert silences (maintenance windows).
    Silence {
        #[command(subcommand)]
        cmd: SilenceCommand,
    },
    /// Install, remove or run as a system service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCommand,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.command {
        Command::Run => {
            init_logging_from(&cli.config);
            llcforge_beacon::service::run_foreground(cli.config, daemon).map(|_| ExitCode::SUCCESS)
        }
        Command::Service { cmd } => {
            init_logging_from(&cli.config);
            run_service_command(&SPEC, cmd.into_action(cli.config), daemon)
                .map(|_| ExitCode::SUCCESS)
        }
        Command::Silence { cmd } => Config::load(&cli.config).and_then(|cfg| {
            run_silence_command(cmd, &cfg.silences.path_or(&cfg.data_dir()))
                .map(|_| ExitCode::SUCCESS)
        }),
        Command::CheckConfig => {
            Config::load(&cli.config).map(|cfg| check_config(&cli.config, &cfg))
        }
        Command::Simulate {
            dst,
            ttl,
            active,
            scope,
            protocol,
            src_port,
            dst_port,
            discard,
        } => Config::load(&cli.config).and_then(|cfg| {
            let ttl = ttl
                .as_deref()
                .map(parse_duration)
                .transpose()
                .map_err(anyhow::Error::msg)?;
            match protocol {
                Some(p) => simulate_flowspec(&cfg, dst, ttl, &p, src_port, dst_port, discard),
                None => simulate(&cfg, dst, ttl, active, scope),
            }
        }),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Logging from the config when it parses; text/info otherwise (the daemon reports the error).
fn init_logging_from(path: &Path) {
    let (fmt, level, filter) = match Config::load(path) {
        Ok(c) => (c.log.format, c.log.level, c.log.filter),
        Err(_) => (LogFormat::Text, "info".to_owned(), None),
    };
    if let Err(e) = init_logging(fmt, &level, filter.as_deref()) {
        eprintln!("warning: {e:#}");
    }
}

fn daemon(config: PathBuf, shutdown: Shutdown) -> Result<()> {
    let cfg = Config::load(&config)?;
    tokio::runtime::Runtime::new()
        .context("cannot start async runtime")?
        .block_on(run(cfg, config, shutdown))
}

fn check_config(path: &Path, cfg: &Config) -> ExitCode {
    let g = &cfg.guardrails;
    let join = |v: Vec<String>| {
        if v.is_empty() {
            "-".to_owned()
        } else {
            v.join(", ")
        }
    };
    let env_state = |var: &str| {
        if std::env::var_os(var).is_some() {
            "set"
        } else {
            "NOT SET, run will fail"
        }
    };
    println!("config OK: {}", path.display());
    println!(
        "  mode       : {}",
        if cfg.dry_run {
            "dry-run (no BGP sessions are opened)"
        } else {
            "LIVE (BGP sessions will announce routes)"
        }
    );
    println!(
        "  local AS   : {} (router-id {}{})",
        cfg.bgp.local_asn,
        cfg.bgp.router_id,
        match cfg.bgp.graceful_restart {
            Some(gr) => format!(", graceful restart {}", fmt_duration(gr.restart_time.0)),
            None => String::new(),
        }
    );
    println!(
        "  upstreams  : {}",
        join(
            cfg.bgp
                .upstreams
                .iter()
                .map(|u| {
                    let mut s = format!("{} AS{} {}", u.name, u.remote_asn, u.neighbor);
                    if u.flowspec {
                        s.push_str(" +flowspec");
                    }
                    if let Some(h) = u.ebgp_multihop {
                        s.push_str(&format!(" multihop {h}"));
                    }
                    if let Some(v) = &u.md5_password_env {
                        s.push_str(&format!(" md5 ${v}"));
                        if !bgp_socket::md5_supported() {
                            s.push_str(" (UNSUPPORTED on this OS, live run will fail)");
                        }
                    }
                    if !u.regions.is_empty() {
                        s.push_str(&format!(
                            " regions [{}]",
                            u.regions.keys().cloned().collect::<Vec<_>>().join(",")
                        ));
                    }
                    s
                })
                .collect()
        )
    );
    println!(
        "  protected  : {}",
        join(g.protected.iter().map(ToString::to_string).collect())
    );
    println!(
        "  never      : {}",
        join(g.never.iter().map(ToString::to_string).collect())
    );
    println!(
        "  limits     : max_active {}, ttl min {} / default {} / max {}",
        g.max_active,
        fmt_duration(g.ttl.min.0),
        fmt_duration(g.ttl.default.0),
        fmt_duration(g.ttl.max.0)
    );
    match &cfg.flowspec {
        Some(f) => println!(
            "  flowspec   : {}, max_active {}, escalate to RTBH {}",
            match f.action {
                config::FlowActionKind::RateLimit =>
                    format!("rate-limit {} kbit/s", f.rate_limit_kbps),
                config::FlowActionKind::Discard => "discard".to_owned(),
            },
            f.max_active,
            if f.escalate {
                format!("after {}", fmt_duration(f.escalate_after.0))
            } else {
                "never".into()
            }
        ),
        None => println!("  flowspec   : disabled"),
    }
    match &cfg.approval {
        Some(a) if a.mode != ApprovalMode::Off => println!(
            "  approval   : {:?}, timeout {}{}",
            a.mode,
            fmt_duration(a.timeout.0),
            a.telegram
                .as_ref()
                .map(|t| format!(
                    ", telegram chat {} (token ${}: {})",
                    t.chat_id,
                    t.bot_token_env,
                    env_state(&t.bot_token_env)
                ))
                .unwrap_or_default()
        ),
        _ => println!("  approval   : off"),
    }
    match &cfg.api {
        Some(a) => println!(
            "  api        : {}://{} (token from ${}: {}){}",
            if a.tls.is_some() { "https" } else { "http" },
            a.listen,
            a.token_env,
            env_state(&a.token_env),
            match &a.tls {
                Some(t) if t.client_ca_file.is_some() => ", mutual TLS",
                _ => "",
            }
        ),
        None => println!("  api        : disabled"),
    }
    match &cfg.metrics {
        Some(m) => println!(
            "  metrics    : http://{}/metrics (+ /healthz /readyz)",
            m.listen
        ),
        None => println!("  metrics    : disabled"),
    }
    match &cfg.detect.sflow {
        Some(s) => println!(
            "  sflow      : {} from {} exporter(s)",
            s.listen,
            s.exporters.len()
        ),
        None => println!("  sflow      : disabled"),
    }
    match &cfg.detect.netflow {
        Some(s) => println!(
            "  netflow    : {} (v9 + IPFIX) from {} exporter(s)",
            s.listen,
            s.exporters.len()
        ),
        None => println!("  netflow    : disabled"),
    }
    match &cfg.propagation {
        Some(p) => println!(
            "  propagation: {}{}",
            if p.ripestat { "RIPEstat" } else { "" },
            p.pathology_url
                .as_ref()
                .map(|u| format!(" + Pathology {u}"))
                .unwrap_or_default()
        ),
        None => println!("  propagation: disabled"),
    }
    println!("  data dir   : {}", cfg.data_dir().display());
    ExitCode::SUCCESS
}

fn hex_lines(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(16)
        .map(|c| c.chunks(2).map(session::hex).collect::<Vec<_>>().join(" "))
        .collect()
}

fn simulate(
    cfg: &Config,
    dst: IpAddr,
    ttl: Option<u64>,
    active: usize,
    scope: Option<String>,
) -> Result<ExitCode> {
    let policy = Policy::from_config(cfg);
    let prefix = bgp::message::host_prefix(dst);
    let scope = scope.filter(|s| s != "global");
    let approval = match policy.evaluate_scoped(dst, ttl, scope.as_deref(), &[], active, false) {
        Ok(a) => a,
        Err(d) => {
            println!("decision  DENY {prefix} [{}] {d}", d.code());
            return Ok(ExitCode::from(2));
        }
    };
    println!(
        "decision  ALLOW {prefix} ttl={} dry_run={}{}",
        fmt_duration(approval.ttl),
        approval.dry_run,
        scope
            .as_ref()
            .map(|s| format!(" scope={s}"))
            .unwrap_or_default()
    );
    let speaker = Speaker::from_config(cfg);
    let sc = Scope {
        region: scope,
        upstreams: Vec::new(),
    };
    for up in &cfg.bgp.upstreams {
        println!(
            "upstream  {} AS{} {}:{}",
            up.name, up.remote_asn, up.neighbor, up.port
        );
        let Some(comms) = communities_for(up, &sc) else {
            println!("  (scope not defined on this upstream, nothing sent)");
            continue;
        };
        let mut params = speaker.announce_params(up, true);
        params.communities = comms;
        let msg = encode_announce(dst, &params);
        println!("  announce UPDATE, {} bytes", msg.len());
        for l in hex_lines(&msg) {
            println!("    {l}");
        }
        let u = decode_update(&msg[HEADER_LEN..], true).context("self-decode failed")?;
        let comms: Vec<String> = u.communities.iter().map(ToString::to_string).collect();
        let nh = u.next_hop.map(|n| n.to_string()).unwrap_or_default();
        let path: Vec<String> = u.as_path.iter().map(ToString::to_string).collect();
        println!("    ORIGIN IGP  AS_PATH {}  NEXT_HOP {nh}", path.join(" "));
        println!("    COMMUNITIES {}", comms.join(" "));
        println!(
            "    NLRI {}",
            u.nlri
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        );
        let w = encode_withdraw(dst);
        println!(
            "  withdraw UPDATE, {} bytes (sent on expiry or DELETE)",
            w.len()
        );
        for l in hex_lines(&w) {
            println!("    {l}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn simulate_flowspec(
    cfg: &Config,
    dst: IpAddr,
    ttl: Option<u64>,
    protocol: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    discard: bool,
) -> Result<ExitCode> {
    let protocol = match protocol.to_ascii_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" => 58,
        n => n
            .parse()
            .context("protocol must be tcp, udp, icmp, icmpv6 or a number")?,
    };
    let kbps = cfg.flowspec.as_ref().map_or(10_000, |f| f.rate_limit_kbps);
    let rule = FlowRule {
        dst,
        protocol,
        src_port,
        dst_port,
        action: if discard {
            FlowAction::Discard
        } else {
            FlowAction::RateLimit { kbps }
        },
    };
    let policy = Policy::from_config(cfg);
    let approval = match policy.evaluate_flowspec(&rule, ttl, 0, false) {
        Ok(a) => a,
        Err(d) => {
            println!("decision  DENY flowspec {rule} [{}] {d}", d.code());
            return Ok(ExitCode::from(2));
        }
    };
    println!(
        "decision  ALLOW flowspec {rule} ttl={} dry_run={}",
        fmt_duration(approval.ttl),
        approval.dry_run
    );
    for up in &cfg.bgp.upstreams {
        if !up.flowspec {
            println!(
                "upstream  {} AS{}: flowspec not enabled, skipped",
                up.name, up.remote_asn
            );
            continue;
        }
        println!(
            "upstream  {} AS{} {}:{}",
            up.name, up.remote_asn, up.neighbor, up.port
        );
        let msg = encode_flowspec_announce(&rule, cfg.bgp.local_asn, true);
        println!("  flowspec UPDATE (SAFI 133), {} bytes", msg.len());
        for l in hex_lines(&msg) {
            println!("    {l}");
        }
        let f = decode_flowspec_update(&msg[HEADER_LEN..]).context("self-decode failed")?;
        for m in &f.announced {
            let opt = |n: &str, v: Option<u16>| v.map(|p| format!(" {n} {p}")).unwrap_or_default();
            println!(
                "    MATCH dst {} proto {}{}{}",
                m.dst.map(|d| d.to_string()).unwrap_or_default(),
                m.protocol.unwrap_or(0),
                opt("src-port", m.src_port),
                opt("dst-port", m.dst_port)
            );
        }
        for r in &f.rates {
            println!(
                "    ACTION traffic-rate {r} bytes/s{}",
                if *r == 0.0 { " (discard)" } else { "" }
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn api_token(cfg: &Config) -> Result<Option<String>> {
    let Some(a) = &cfg.api else { return Ok(None) };
    let t = std::env::var(&a.token_env).with_context(|| {
        format!(
            "API enabled but environment variable {} is not set",
            a.token_env
        )
    })?;
    if t.len() < api::MIN_TOKEN_LEN {
        bail!(
            "API token in {} must be at least {} characters",
            a.token_env,
            api::MIN_TOKEN_LEN
        );
    }
    Ok(Some(t))
}

/// Per-upstream socket options; TCP-MD5 secrets are read now so a missing
/// variable or an unsupported OS stops the process before anything is announced.
fn socket_options(cfg: &Config) -> Result<Vec<SocketOptions>> {
    cfg.bgp
        .upstreams
        .iter()
        .map(|u| {
            let md5_key = match &u.md5_password_env {
                Some(_) if cfg.dry_run => None,
                Some(var) => {
                    if !bgp_socket::md5_supported() {
                        return Err(anyhow::Error::new(bgp_socket::md5_unsupported_error())
                            .context(format!("upstream {}", u.name)));
                    }
                    let k = llcforge_beacon::env_secret(var)
                        .with_context(|| format!("upstream {}: TCP-MD5 password", u.name))?;
                    if k.len() > bgp_socket::MD5_MAX_KEY {
                        bail!(
                            "upstream {}: TCP-MD5 password must be at most {} bytes",
                            u.name,
                            bgp_socket::MD5_MAX_KEY
                        );
                    }
                    Some(k.into_bytes())
                }
                None => None,
            };
            Ok(SocketOptions {
                local: u.local_address,
                ttl: u.ebgp_multihop,
                md5_key,
            })
        })
        .collect()
}

fn dispatcher_options(data: &Path, silences: &Arc<SilenceStore>) -> DispatcherOptions {
    DispatcherOptions {
        tool: BIN.into(),
        data_dir: Some(data.to_path_buf()),
        silences: Some(silences.clone()),
        http: None,
    }
}

async fn run(mut cfg: Config, config_path: PathBuf, mut shutdown: Shutdown) -> Result<()> {
    // Resolve every fallible resource before touching the network.
    let api_token = api_token(&cfg)?;
    let tls = match cfg.api.as_ref().and_then(|a| a.tls.as_ref()) {
        Some(t) => Some(tls::server_config(t)?),
        None => None,
    };
    let sockets = socket_options(&cfg)?;
    let telegram = match cfg.approval.as_ref() {
        Some(a) if a.mode != ApprovalMode::Off => match &a.telegram {
            Some(t) => Some((
                t.clone(),
                llcforge_beacon::env_secret(&t.bot_token_env)
                    .context("approval.telegram.bot_token_env")?,
            )),
            None => None,
        },
        _ => None,
    };
    let checker = match &cfg.propagation {
        Some(p) => Some(propagation::Checker::from_config(p)?),
        None => None,
    };
    let data = cfg.data_dir();
    std::fs::create_dir_all(&data)
        .with_context(|| format!("cannot create data directory {}", data.display()))?;
    let audit_path = cfg.audit_path();
    if let Some(dir) = audit_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let audit = Arc::new(
        audit::Audit::open(&audit_path)
            .with_context(|| format!("cannot open audit log {}", audit_path.display()))?,
    );
    let (persisted, persisted_flows) = state::load_all(&cfg.state_path())?;

    let silences = Arc::new(SilenceStore::open(cfg.silences.path_or(&data))?);
    let mut dispatcher = Dispatcher::start(&cfg.alerts, dispatcher_options(&data, &silences))?;
    let alerts = Alerts::new(dispatcher.handle());

    let metrics = Arc::new(Metrics::new(
        cfg.bgp.upstreams.iter().map(|u| u.name.as_str()),
    ));
    let (mut eng, routes) = Engine::new(
        Policy::from_config(&cfg),
        Some(cfg.state_path()),
        audit.clone(),
        metrics.clone(),
    );
    eng.set_alerts(alerts.clone());
    if let Some(a) = &cfg.approval {
        eng.set_approval(a.mode, a.timeout.0);
    }
    let (note_tx, note_rx) = mpsc::channel(64);
    if telegram.is_some() {
        eng.set_notifier(note_tx);
    }
    let now = unix_now();
    audit.record(
        now,
        "start",
        serde_json::json!({"dry_run": cfg.dry_run, "version": env!("CARGO_PKG_VERSION")}),
    );
    eng.restore_all(persisted, persisted_flows, now);
    let engine = Arc::new(Mutex::new(eng));
    let reports = cfg
        .reports
        .enabled
        .then(|| Arc::new(ReportStore::new(Some(cfg.reports_dir()), cfg.reports.keep)));

    let api_listener = match &cfg.api {
        Some(a) => {
            if !a.listen.ip().is_loopback() && a.tls.is_none() {
                warn!(listen = %a.listen, "trigger API is plain HTTP on a non-loopback address; enable [api.tls] or put a TLS reverse proxy in front of it");
            }
            Some(
                TcpListener::bind(a.listen)
                    .await
                    .with_context(|| format!("cannot bind API on {}", a.listen))?,
            )
        }
        None => None,
    };
    let metrics_listener = match &cfg.metrics {
        Some(m) => Some(
            TcpListener::bind(m.listen)
                .await
                .with_context(|| format!("cannot bind metrics on {}", m.listen))?,
        ),
        None => None,
    };
    let sflow_sock = match &cfg.detect.sflow {
        Some(s) => Some(
            UdpSocket::bind(s.listen)
                .await
                .with_context(|| format!("cannot bind sFlow on {}", s.listen))?,
        ),
        None => None,
    };
    let netflow_sock = match &cfg.detect.netflow {
        Some(s) => Some(
            UdpSocket::bind(s.listen)
                .await
                .with_context(|| format!("cannot bind NetFlow/IPFIX on {}", s.listen))?,
        ),
        None => None,
    };

    let readiness = Readiness::new();
    readiness.register("bgp");
    let mut reload = ReloadSignal::standard(Some(config_path.clone()))?;

    let (sd_tx, sd_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let speaker = Speaker::from_config(&cfg);

    if cfg.dry_run {
        warn!("dry_run = true: no BGP sessions are opened; UPDATEs are logged instead");
    }
    for (up, socket) in cfg.bgp.upstreams.iter().zip(sockets) {
        let ctx = Ctx {
            up: up.clone(),
            speaker: speaker.clone(),
            audit: audit.clone(),
            metrics: metrics.clone(),
            alerts: alerts.clone(),
            socket,
        };
        if cfg.dry_run {
            tasks.spawn(session::run_dry(ctx, routes.clone(), sd_rx.clone()));
        } else {
            tasks.spawn(session::run(ctx, routes.clone(), sd_rx.clone()));
        }
    }

    {
        let (engine, metrics, readiness) = (engine.clone(), metrics.clone(), readiness.clone());
        let dry = cfg.dry_run;
        let mut sd = sd_rx.clone();
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        if let Ok(mut e) = engine.lock() { e.expire(unix_now()); }
                        readiness.set("bgp", dry || metrics.any_session_up());
                    }
                    _ = sd.changed() => return,
                }
            }
        });
    }

    if let (Some(listener), Some(a), Some(token)) = (api_listener, &cfg.api, api_token) {
        let mut st = api::ApiState::new(
            engine.clone(),
            token,
            a.rate_limit_per_minute,
            metrics.clone(),
        );
        if let Some(r) = &reports {
            st = st.with_reports(r.clone());
        }
        let app = api::router(st, a.max_body_bytes);
        info!(listen = %a.listen, tls = tls.is_some(), "trigger API listening");
        match tls {
            Some(tls) => {
                tasks.spawn(tls::serve(
                    listener,
                    app,
                    tls,
                    metrics.clone(),
                    sd_rx.clone(),
                ));
            }
            None => {
                let mut sd = sd_rx.clone();
                tasks.spawn(async move {
                    let res = axum::serve(listener, app)
                        .with_graceful_shutdown(async move {
                            let _ = sd.changed().await;
                        })
                        .await;
                    if let Err(e) = res {
                        error!(error = %e, "trigger API stopped");
                    }
                });
            }
        }
    }

    // Management router: /metrics, /healthz, /readyz, optional /v1/silences and /v1/reload.
    let mut admin = health_router(readiness.clone());
    if let Some(var) = &cfg.silences.api_token_env {
        admin = admin.merge(silences_router(silences.clone(), ApiToken::from_env(var)?));
    }
    if let Some(var) = &cfg.health.admin_token_env {
        admin = admin.merge(reload_router(reload.trigger(), ApiToken::from_env(var)?));
    }
    let metrics_addr = cfg.metrics.as_ref().map(|m| m.listen);
    if let Some(listener) = metrics_listener {
        let app = api::metrics_router(metrics.clone(), alerts.clone()).merge(admin.clone());
        let mut sd = sd_rx.clone();
        tasks.spawn(async move {
            let res = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = sd.changed().await;
                })
                .await;
            if let Err(e) = res {
                error!(error = %e, "metrics endpoint stopped");
            }
        });
    }
    if let Some(addr) = cfg.health.listen.filter(|a| Some(*a) != metrics_addr) {
        let mut sd = sd_rx.clone();
        tasks.spawn(async move {
            if let Err(e) = llcforge_beacon::serve(addr, admin, async move {
                let _ = sd.changed().await;
            })
            .await
            {
                error!(error = %e, "health listener stopped");
            }
        });
    }

    if cfg.detect.any_collector() {
        let t = cfg
            .detect
            .thresholds()
            .context("detection thresholds missing")?;
        let det = Arc::new(Mutex::new(Detector::new(
            Params::from_thresholds(t, cfg.detect.baseline),
            cfg.guardrails.protected.clone(),
        )));
        if let (Some(sock), Some(s)) = (sflow_sock, &cfg.detect.sflow) {
            tasks.spawn(detect::run_sflow(
                sock,
                s.clone(),
                det.clone(),
                metrics.clone(),
                sd_rx.clone(),
            ));
        }
        if let (Some(sock), Some(n)) = (netflow_sock, &cfg.detect.netflow) {
            tasks.spawn(detect::run_netflow(
                sock,
                n.clone(),
                det.clone(),
                metrics.clone(),
                sd_rx.clone(),
            ));
        }
        let mit = Mitigator::new(
            cfg.flowspec.as_ref().map(FlowSettings::from_config),
            alerts.clone(),
            metrics.clone(),
            reports.clone(),
        );
        tasks.spawn(detect::run_detector(
            det,
            mit,
            engine.clone(),
            sd_rx.clone(),
        ));
    }

    if let (Some(p), Some(c)) = (&cfg.propagation, checker) {
        tasks.spawn(propagation::run(
            p.clone(),
            c,
            engine.clone(),
            metrics.clone(),
            sd_rx.clone(),
        ));
    }

    if let Some((t, token)) = telegram {
        let timeout = cfg.approval.as_ref().map_or(300, |a| a.timeout.0);
        let bot = approval::Bot::new(t, &token)?;
        tasks.spawn(approval::run(
            bot,
            timeout,
            engine.clone(),
            note_rx,
            sd_rx.clone(),
        ));
    }

    alerts.send(
        alert(
            "started",
            Severity::Info,
            format!(
                "Event Horizon started ({})",
                if cfg.dry_run { "dry-run" } else { "live" }
            ),
        )
        .field("version", env!("CARGO_PKG_VERSION"))
        .field("upstreams", cfg.bgp.upstreams.len()),
    );
    info!(
        dry_run = cfg.dry_run,
        upstreams = cfg.bgp.upstreams.len(),
        "event-horizon running"
    );

    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            Some(reason) = reload.recv() => {
                info!(?reason, "reloading configuration");
                let new = match Config::load(&config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        error!(error = %format!("{e:#}"), "invalid configuration; keeping the running one");
                        continue;
                    }
                };
                if new.dry_run != cfg.dry_run {
                    error!("dry_run cannot change on reload; restart the service; keeping the running configuration");
                    continue;
                }
                dispatcher.shutdown(Duration::from_secs(5)).await;
                dispatcher = match Dispatcher::start(&new.alerts, dispatcher_options(&data, &silences)) {
                    Ok(d) => d,
                    Err(e) => {
                        error!(error = %e, "new [alerts] invalid; keeping the old sinks");
                        Dispatcher::start(&cfg.alerts, dispatcher_options(&data, &silences))?
                    }
                };
                alerts.replace(dispatcher.handle());
                if let Ok(mut e) = engine.lock() {
                    e.set_policy(Policy::from_config(&new), unix_now());
                    if let Some(a) = &new.approval {
                        e.set_approval(a.mode, a.timeout.0);
                    } else {
                        e.set_approval(ApprovalMode::Off, 300);
                    }
                }
                audit.record(unix_now(), "reload", serde_json::json!({"reason": format!("{reason:?}")}));
                info!("configuration reloaded: alerts, guardrails, flowspec policy and approval mode applied; BGP, listeners and detectors change on restart");
                cfg = new;
            }
        }
    }

    info!("shutdown requested; closing sessions (routes are dropped by upstreams with the session unless graceful restart is enabled; the active set is kept on disk)");
    let _ = sd_tx.send(true);
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .is_err()
    {
        warn!("some tasks did not stop within 5s");
    }
    audit.record(unix_now(), "stop", serde_json::json!({}));
    dispatcher.shutdown(Duration::from_secs(5)).await;
    Ok(())
}
