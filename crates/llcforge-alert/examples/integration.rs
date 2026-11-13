//! How an LLCForge tool wires llcforge-alert (compiled by `cargo clippy --all-targets`).
//!
//! Run: `cargo run --example integration -- run --config demo.toml`

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use llcforge_alert::cli::{run_silence_command, ServiceCommand, SilenceCommand};
use llcforge_alert::{
    default_data_dir, health_router, init_logging, reload_router, run_service_command,
    silences_router, Alert, AlertsConfig, ApiToken, Dispatcher, DispatcherOptions, HealthConfig,
    LogFormat, Readiness, ReloadSignal, ServiceSpec, Severity, Shutdown, SilenceStore,
    SilencesConfig,
};
use serde::Deserialize;

const SPEC: ServiceSpec = ServiceSpec {
    bin: "demo-tool",
    display_name: "Demo Tool",
    description: "Example integration of llcforge-alert",
};

#[derive(Parser)]
struct Cli {
    #[arg(long, short, global = true, default_value = "demo.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run,
    Silence {
        #[command(subcommand)]
        cmd: SilenceCommand,
    },
    Service {
        #[command(subcommand)]
        cmd: ServiceCommand,
    },
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Config {
    data_dir: Option<PathBuf>,
    alerts: AlertsConfig,
    silences: SilencesConfig,
    health: HealthConfig,
}

fn load(path: &PathBuf) -> anyhow::Result<Config> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(toml::from_str(&s)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e.into()),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(LogFormat::Text, "info", None)?;
    match cli.command {
        Command::Run => llcforge_alert::service::run_foreground(cli.config, daemon),
        Command::Silence { cmd } => {
            let cfg = load(&cli.config)?;
            let data = cfg.data_dir.unwrap_or_else(|| default_data_dir(SPEC.bin));
            run_silence_command(cmd, &cfg.silences.path_or(&data))
        }
        Command::Service { cmd } => run_service_command(&SPEC, cmd.into_action(cli.config), daemon),
    }
}

fn daemon(config: PathBuf, mut shutdown: Shutdown) -> anyhow::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(async move {
        let cfg = load(&config)?;
        let data = cfg.data_dir.clone().unwrap_or_else(|| default_data_dir(SPEC.bin));
        let silences = Arc::new(SilenceStore::open(cfg.silences.path_or(&data))?);
        let readiness = Readiness::new();
        readiness.register("feed");

        let mut dispatcher = Dispatcher::start(
            &cfg.alerts,
            DispatcherOptions {
                tool: SPEC.bin.into(),
                data_dir: Some(data.clone()),
                silences: Some(silences.clone()),
                http: None,
            },
        )?;
        let mut reload = ReloadSignal::standard(Some(config.clone()))?;

        let mut admin = health_router(readiness.clone());
        if let Some(var) = &cfg.silences.api_token_env {
            admin = admin.merge(silences_router(silences.clone(), ApiToken::from_env(var)?));
        }
        if let Some(var) = &cfg.health.admin_token_env {
            admin = admin.merge(reload_router(reload.trigger(), ApiToken::from_env(var)?));
        }
        if let Some(addr) = cfg.health.listen {
            let mut sd = shutdown.clone();
            tokio::spawn(llcforge_alert::serve(addr, admin, async move { sd.wait().await }));
        }

        readiness.set("feed", true);
        dispatcher.handle().send(
            Alert::new(SPEC.bin, "started", Severity::Info, "Demo tool started")
                .resource("192.0.2.0/24")
                .field("version", env!("CARGO_PKG_VERSION")),
        );

        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                Some(reason) = reload.recv() => {
                    tracing::info!(?reason, "reloading configuration");
                    match load(&config) {
                        Ok(new) => {
                            dispatcher.shutdown(Duration::from_secs(5)).await;
                            dispatcher = Dispatcher::start(&new.alerts, DispatcherOptions {
                                tool: SPEC.bin.into(),
                                data_dir: Some(data.clone()),
                                silences: Some(silences.clone()),
                                http: None,
                            })?;
                        }
                        Err(e) => tracing::error!(error = %e, "invalid configuration; keeping the old one"),
                    }
                }
            }
        }
        dispatcher.shutdown(Duration::from_secs(5)).await;
        Ok(())
    })
}
