//! clap subcommands so each tool gets `<tool> silence add|list|remove` and
//! `<tool> service install|uninstall|run` with a few lines of glue.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::service::ServiceAction;
use crate::silence::{NewSilence, SilenceStore};

fn parse_time(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| format!("expected RFC 3339 time (2026-01-31T22:00:00Z): {e}"))
}

#[derive(Debug, Clone, clap::Args)]
pub struct SilenceAddArgs {
    /// Resource glob, e.g. "192.0.2.*" or "*.example.org".
    #[arg(long)]
    pub resource: Option<String>,
    /// Alert kind glob.
    #[arg(long)]
    pub kind: Option<String>,
    /// Tool name glob.
    #[arg(long)]
    pub tool: Option<String>,
    /// Start time (RFC 3339); default now.
    #[arg(long, value_parser = parse_time)]
    pub starts: Option<DateTime<Utc>>,
    /// End time (RFC 3339).
    #[arg(long, value_parser = parse_time, conflicts_with = "duration")]
    pub until: Option<DateTime<Utc>>,
    /// Length, e.g. 30m, 2h, 1d12h (default 1h).
    #[arg(long)]
    pub duration: Option<String>,
    /// Why the silence exists.
    #[arg(long, short = 'm')]
    pub comment: String,
    /// Free-text author label.
    #[arg(long, default_value = "cli")]
    pub created_by: String,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum SilenceCommand {
    /// Create a silence / maintenance window.
    Add(SilenceAddArgs),
    /// List active and scheduled silences.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Remove a silence by id.
    Remove { id: String },
}

/// Executes a silence subcommand against the store file (the running daemon
/// picks up changes within a few seconds).
pub fn run_silence_command(cmd: SilenceCommand, store_path: &Path) -> anyhow::Result<()> {
    let store = SilenceStore::open(store_path)?;
    match cmd {
        SilenceCommand::Add(a) => {
            let duration = if a.until.is_none() && a.duration.is_none() {
                Some("1h".to_string())
            } else {
                a.duration
            };
            let s = store.add(NewSilence {
                resource: a.resource,
                kind: a.kind,
                tool: a.tool,
                starts_at: a.starts,
                ends_at: a.until,
                duration,
                comment: a.comment,
                created_by: Some(a.created_by),
            })?;
            println!("{}  until {}", s.id, s.ends_at.to_rfc3339());
        }
        SilenceCommand::List { json } => {
            let list = store.list();
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!("no silences");
            } else {
                for s in list {
                    println!(
                        "{}  {} -> {}  resource={} kind={} tool={}  by={}  {}",
                        s.id,
                        s.starts_at.to_rfc3339(),
                        s.ends_at.to_rfc3339(),
                        s.resource.as_deref().unwrap_or("*"),
                        s.kind.as_deref().unwrap_or("*"),
                        s.tool.as_deref().unwrap_or("*"),
                        s.created_by,
                        s.comment
                    );
                }
            }
        }
        SilenceCommand::Remove { id } => {
            if store.remove(&id)? {
                println!("removed {id}");
            } else {
                anyhow::bail!("no silence with id {id}");
            }
        }
    }
    Ok(())
}

/// `<tool> service ...`. Takes no `--config` of its own so it composes with
/// the tool's global `--config` flag; pass that path to [`ServiceCommand::into_action`].
#[derive(Debug, Clone, Copy, clap::Subcommand)]
pub enum ServiceCommand {
    /// Register as a system service (Windows SCM; prints systemd/launchd steps on Unix).
    Install,
    /// Remove the system service.
    Uninstall,
    /// Run under the service manager (falls back to foreground on a console).
    Run,
}

impl ServiceCommand {
    pub fn into_action(self, config: PathBuf) -> ServiceAction {
        match self {
            ServiceCommand::Install => ServiceAction::Install { config },
            ServiceCommand::Uninstall => ServiceAction::Uninstall,
            ServiceCommand::Run => ServiceAction::Run { config },
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }

    #[derive(clap::Subcommand)]
    enum Cmd {
        Silence {
            #[command(subcommand)]
            cmd: SilenceCommand,
        },
        Service {
            #[command(subcommand)]
            cmd: ServiceCommand,
        },
    }

    #[test]
    fn add_list_remove_via_cli() {
        let dir = std::env::temp_dir().join(format!("llcf-cli-{}", fastrand::u64(..)));
        let path = dir.join("silences.json");
        let parse = |args: &[&str]| match Cli::parse_from(args).cmd {
            Cmd::Silence { cmd } => cmd,
            Cmd::Service { .. } => unreachable!(),
        };
        run_silence_command(
            parse(&[
                "t",
                "silence",
                "add",
                "--resource",
                "192.0.2.*",
                "-m",
                "fiber cut",
                "--duration",
                "2h",
            ]),
            &path,
        )
        .unwrap();
        let store = SilenceStore::open(&path).unwrap();
        let list = store.list();
        assert_eq!(list.len(), 1);
        run_silence_command(parse(&["t", "silence", "list", "--json"]), &path).unwrap();
        run_silence_command(parse(&["t", "silence", "remove", &list[0].id]), &path).unwrap();
        assert!(run_silence_command(parse(&["t", "silence", "remove", "ffff"]), &path).is_err());
        assert!(SilenceStore::open(&path).unwrap().list().is_empty());
        assert!(
            Cli::try_parse_from(["t", "silence", "add", "-m", "x", "--until", "nope"]).is_err()
        );
        let svc = match Cli::parse_from(["t", "service", "install"]).cmd {
            Cmd::Service { cmd } => cmd.into_action(PathBuf::from("c.toml")),
            Cmd::Silence { .. } => unreachable!(),
        };
        assert!(matches!(svc, ServiceAction::Install { .. }));
        std::fs::remove_dir_all(dir).ok();
    }
}
