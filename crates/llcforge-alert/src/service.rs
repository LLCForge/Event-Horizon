//! Platform service helpers: Windows service entry point / installer (feature
//! `service`), shutdown signalling, and systemd/launchd hints on Unix.

use std::path::{Path, PathBuf};

use tokio::sync::watch;

/// Identity of the tool as a system service.
#[derive(Debug, Clone, Copy)]
pub struct ServiceSpec {
    /// Binary / service name, e.g. `"event-horizon"`.
    pub bin: &'static str,
    /// Display name, e.g. `"Event Horizon"`.
    pub display_name: &'static str,
    pub description: &'static str,
}

/// What `<tool> service ...` should do.
#[derive(Debug, Clone)]
pub enum ServiceAction {
    Install { config: PathBuf },
    Uninstall,
    Run { config: PathBuf },
}

/// Shutdown notification handed to the tool's run function.
#[derive(Debug, Clone)]
pub struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    /// Pair of (trigger, receiver) for tools that manage shutdown themselves.
    pub fn channel() -> (watch::Sender<bool>, Shutdown) {
        let (tx, rx) = watch::channel(false);
        (tx, Shutdown(rx))
    }

    pub fn is_triggered(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once shutdown is requested (or the trigger is dropped).
    pub async fn wait(&mut self) {
        while !*self.0.borrow_and_update() {
            if self.0.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Resolves on Ctrl-C, and on SIGTERM on Unix.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler unavailable; Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Runs `run` in the foreground on a dedicated thread; shutdown fires on
/// Ctrl-C / SIGTERM. Safe to call whether or not a Tokio runtime is active.
pub fn run_foreground<F>(config: PathBuf, run: F) -> anyhow::Result<()>
where
    F: FnOnce(PathBuf, Shutdown) -> anyhow::Result<()> + Send + 'static,
{
    let (tx, rx) = Shutdown::channel();
    std::thread::Builder::new()
        .name("shutdown-signal".into())
        .spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(shutdown_signal()),
                Err(e) => {
                    tracing::error!(error = %e, "cannot start signal runtime");
                    return;
                }
            }
            let _ = tx.send(true);
        })?;
    let worker = std::thread::Builder::new()
        .name("service-main".into())
        .spawn(move || run(config, rx))?;
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("service thread panicked"))?
}

/// Human instructions printed by `service install|uninstall` on Unix.
pub fn unix_instructions(spec: &ServiceSpec, install: bool) -> String {
    let bin = spec.bin;
    if cfg!(target_os = "macos") {
        let plist = format!("net.llcforge.{bin}.plist");
        if install {
            format!(
                "{name} runs under launchd on macOS. Shipped file: packaging/launchd/{plist}\n\
                 sudo install -m 0644 packaging/launchd/{plist} /Library/LaunchDaemons/{plist}\n\
                 sudo launchctl bootstrap system /Library/LaunchDaemons/{plist}",
                name = spec.display_name
            )
        } else {
            format!(
                "sudo launchctl bootout system/net.llcforge.{bin}\n\
                 sudo rm /Library/LaunchDaemons/{plist}"
            )
        }
    } else if install {
        format!(
            "{name} runs under systemd on Linux. Shipped unit: packaging/systemd/{bin}.service\n\
             (.deb/.rpm packages install it as /usr/lib/systemd/system/{bin}.service)\n\
             sudo install -m 0644 packaging/systemd/{bin}.service /etc/systemd/system/{bin}.service\n\
             sudo systemctl daemon-reload && sudo systemctl enable --now {bin}",
            name = spec.display_name
        )
    } else {
        format!(
            "sudo systemctl disable --now {bin}\n\
             sudo rm /etc/systemd/system/{bin}.service && sudo systemctl daemon-reload"
        )
    }
}

fn absolute(p: &Path) -> anyhow::Result<PathBuf> {
    Ok(std::path::absolute(p)?)
}

/// Executes a `service` subcommand. Call it from synchronous code (before or
/// outside any Tokio runtime is fine; `run` executes on its own thread and
/// should build its own runtime).
pub fn run_service_command<F>(
    spec: &ServiceSpec,
    action: ServiceAction,
    run: F,
) -> anyhow::Result<()>
where
    F: FnOnce(PathBuf, Shutdown) -> anyhow::Result<()> + Send + 'static,
{
    match action {
        ServiceAction::Install { config } => {
            let config = absolute(&config)?;
            platform::install(spec, &config)
        }
        ServiceAction::Uninstall => platform::uninstall(spec),
        ServiceAction::Run { config } => platform::run(spec, absolute(&config)?, run),
    }
}

#[cfg(not(all(windows, feature = "service")))]
mod platform {
    use super::*;

    pub fn install(spec: &ServiceSpec, config: &Path) -> anyhow::Result<()> {
        if cfg!(windows) {
            anyhow::bail!(
                "this build lacks the `service` feature; Windows service install is unavailable"
            );
        }
        println!("{}", unix_instructions(spec, true));
        println!("Config file to reference: {}", config.display());
        Ok(())
    }

    pub fn uninstall(spec: &ServiceSpec) -> anyhow::Result<()> {
        if cfg!(windows) {
            anyhow::bail!(
                "this build lacks the `service` feature; Windows service removal is unavailable"
            );
        }
        println!("{}", unix_instructions(spec, false));
        Ok(())
    }

    pub fn run<F>(_spec: &ServiceSpec, config: PathBuf, run: F) -> anyhow::Result<()>
    where
        F: FnOnce(PathBuf, Shutdown) -> anyhow::Result<()> + Send + 'static,
    {
        run_foreground(config, run)
    }
}

#[cfg(all(windows, feature = "service"))]
mod platform {
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use windows_service::service::{
        ServiceAccess, ServiceAction as ScAction, ServiceActionType, ServiceControl,
        ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    use super::*;

    /// Least-privileged built-in account that can still use the network.
    const SERVICE_ACCOUNT: &str = "NT AUTHORITY\\LocalService";
    /// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: not launched by the SCM.
    const NOT_A_SERVICE: i32 = 1063;

    type Job = Box<dyn FnOnce() + Send>;
    static JOB: Mutex<Option<Job>> = Mutex::new(None);

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<OsString>) {
        let job = JOB.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(job) = job {
            job();
        }
    }

    fn status(state: ServiceState, exit: ServiceExitCode) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: exit,
            checkpoint: 0,
            wait_hint: Duration::from_secs(if state == ServiceState::Running {
                0
            } else {
                10
            }),
            process_id: None,
        }
    }

    pub fn run<F>(spec: &ServiceSpec, config: PathBuf, run: F) -> anyhow::Result<()>
    where
        F: FnOnce(PathBuf, Shutdown) -> anyhow::Result<()> + Send + 'static,
    {
        let name = spec.bin;
        // The job may run on the SCM thread (service) or here (console fallback).
        let shared: Arc<Mutex<Option<F>>> = Arc::new(Mutex::new(Some(run)));
        let for_service = shared.clone();
        let cfg = config.clone();
        *JOB.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(move || {
            let Some(run) = for_service
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            else {
                return;
            };
            let (tx, rx) = Shutdown::channel();
            let handler = move |ev| match ev {
                ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                    let _ = tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            };
            let handle = match service_control_handler::register(name, handler) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!(error = %e, "registering service control handler failed");
                    return;
                }
            };
            let _ =
                handle.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)));
            let exit = match run(cfg, rx) {
                Ok(()) => ServiceExitCode::Win32(0),
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "service stopped with an error");
                    ServiceExitCode::ServiceSpecific(1)
                }
            };
            let _ = handle.set_service_status(status(ServiceState::Stopped, exit));
        }));
        match service_dispatcher::start(name, ffi_service_main) {
            Ok(()) => Ok(()),
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(NOT_A_SERVICE) => {
                // Started from a console: run in the foreground instead.
                JOB.lock().unwrap_or_else(PoisonError::into_inner).take();
                let run = shared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("service already ran"))?;
                run_foreground(config, run)
            }
            Err(e) => Err(anyhow::anyhow!("service dispatcher failed: {e}")),
        }
    }

    pub fn install(spec: &ServiceSpec, config: &Path) -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let info = ServiceInfo {
            name: OsString::from(spec.bin),
            display_name: OsString::from(spec.display_name),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec![
                OsString::from("service"),
                OsString::from("run"),
                OsString::from("--config"),
                config.as_os_str().to_owned(),
            ],
            dependencies: vec![],
            account_name: Some(OsString::from(SERVICE_ACCOUNT)),
            account_password: None,
        };
        let svc =
            manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
        svc.set_description(spec.description)?;
        svc.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ScAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                };
                3
            ]),
        })?;
        println!(
            "Installed service {:?} (account {SERVICE_ACCOUNT}, config {}). Start it with: sc.exe start {}",
            spec.bin,
            config.display(),
            spec.bin
        );
        Ok(())
    }

    pub fn uninstall(spec: &ServiceSpec) -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = manager.open_service(
            spec.bin,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )?;
        if svc.query_status()?.current_state != ServiceState::Stopped {
            svc.stop()?;
            for _ in 0..30 {
                if svc.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        svc.delete()?;
        println!("Removed service {:?}.", spec.bin);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: ServiceSpec = ServiceSpec {
        bin: "demo-tool",
        display_name: "Demo Tool",
        description: "test",
    };

    #[test]
    fn unix_hints_name_shipped_files() {
        let i = unix_instructions(&SPEC, true);
        assert!(i.contains("demo-tool"));
        assert!(i.contains("packaging/"));
    }

    #[tokio::test]
    async fn shutdown_wait_resolves() {
        let (tx, mut rx) = Shutdown::channel();
        assert!(!rx.is_triggered());
        tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), rx.wait())
            .await
            .unwrap();
        assert!(rx.is_triggered());
    }

    #[test]
    fn run_foreground_returns_tool_result() {
        let r = run_foreground(PathBuf::from("x.toml"), |cfg, _sd| {
            anyhow::ensure!(cfg.ends_with("x.toml"));
            Ok(())
        });
        assert!(r.is_ok());
        let e = run_foreground(PathBuf::from("x"), |_, _| anyhow::bail!("boom"));
        assert!(e.is_err());
    }
}
