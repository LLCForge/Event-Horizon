//! RFC 5424 syslog to a remote collector over UDP (RFC 5426), TCP (RFC 6587
//! octet counting) or TLS (RFC 5425) on every OS, plus the local datagram
//! socket (`/dev/log`, macOS `/var/run/syslog`) on Unix.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;

use super::{SendFuture, Sink, SinkError};
use crate::alert::{truncate, Alert, Severity};
use crate::config::{ConfigError, SyslogConfig, SyslogTransport};

/// Private Enterprise Number reserved for documentation (RFC 5612).
const SD_ID: &str = "llcforge@32473";
const UDP_MAX: usize = 2048;
const STREAM_MAX: usize = 64 * 1024;

#[derive(Clone)]
enum Target {
    Udp(String),
    Tcp(String),
    Tls {
        addr: String,
        server_name: rustls::pki_types::ServerName<'static>,
        connector: tokio_rustls::TlsConnector,
    },
    #[cfg(unix)]
    Unix(PathBuf),
}

pub struct SyslogSink {
    target: Target,
    facility: u8,
    app_name: String,
    hostname: String,
}

pub(crate) fn facility_code(name: &str) -> Option<u8> {
    let n = name.trim().to_ascii_lowercase();
    let code = match n.as_str() {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "ntp" => 12,
        "audit" => 13,
        "alert" => 14,
        "clock" => 15,
        _ => {
            let d = n.strip_prefix("local")?.parse::<u8>().ok()?;
            if d > 7 {
                return None;
            }
            16 + d
        }
    };
    Some(code)
}

/// PRINTUSASCII header field, `-` when empty.
fn header_field(s: &str, max: usize) -> String {
    let v: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(max)
        .collect();
    if v.is_empty() {
        "-".into()
    } else {
        v
    }
}

fn sd_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(if c.is_control() { ' ' } else { c });
    }
    out
}

fn default_hostname() -> String {
    ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "-".into())
}

fn tls_connector(ca_file: Option<&PathBuf>) -> Result<tokio_rustls::TlsConnector, ConfigError> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let certs = rustls::pki_types::CertificateDer::pem_file_iter(path)
            .map_err(|e| ConfigError::Invalid(format!("syslog ca_file: {e}")))?;
        for cert in certs {
            let cert = cert.map_err(|e| ConfigError::Invalid(format!("syslog ca_file: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| ConfigError::Invalid(format!("syslog ca_file: {e}")))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ConfigError::Invalid(format!("syslog TLS: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
}

fn host_of(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((h, _)) => h.trim_start_matches('[').trim_end_matches(']'),
        None => addr,
    }
}

impl SyslogSink {
    pub fn from_config(c: &SyslogConfig, tool: &str) -> Result<Self, ConfigError> {
        let facility = facility_code(&c.facility).ok_or_else(|| {
            ConfigError::Invalid(format!("unknown syslog facility {:?}", c.facility))
        })?;
        let need_addr = || {
            c.address
                .clone()
                .filter(|a| a.contains(':'))
                .ok_or_else(|| ConfigError::Invalid("syslog address must be host:port".into()))
        };
        let target = match c.transport {
            SyslogTransport::Udp => Target::Udp(need_addr()?),
            SyslogTransport::Tcp => Target::Tcp(need_addr()?),
            SyslogTransport::Tls => {
                let addr = need_addr()?;
                let name = c
                    .server_name
                    .clone()
                    .unwrap_or_else(|| host_of(&addr).to_string());
                let server_name = rustls::pki_types::ServerName::try_from(name)
                    .map_err(|e| ConfigError::Invalid(format!("syslog server_name: {e}")))?;
                Target::Tls {
                    addr,
                    server_name,
                    connector: tls_connector(c.ca_file.as_ref())?,
                }
            }
            #[cfg(unix)]
            SyslogTransport::Unix => Target::Unix(c.path.clone().unwrap_or_else(|| {
                if cfg!(target_os = "macos") {
                    PathBuf::from("/var/run/syslog")
                } else {
                    PathBuf::from("/dev/log")
                }
            })),
            #[cfg(not(unix))]
            SyslogTransport::Unix => {
                let _ = &c.path;
                return Err(ConfigError::Invalid(
                    "syslog transport \"unix\" is not available on this OS; use udp, tcp or tls"
                        .into(),
                ));
            }
        };
        Ok(SyslogSink {
            target,
            facility,
            app_name: c.app_name.clone().unwrap_or_else(|| tool.to_string()),
            hostname: c.hostname.clone().unwrap_or_else(default_hostname),
        })
    }

    /// Builds the RFC 5424 message, truncating only the MSG part to `max` bytes total.
    pub fn format(&self, a: &Alert, max: usize) -> String {
        let sev = match (a.resolved, a.severity) {
            (true, _) => 5,
            (false, Severity::Critical) => 2,
            (false, Severity::Warning) => 4,
            (false, Severity::Info) => 6,
        };
        let pri = u16::from(self.facility) * 8 + sev;
        let ts = a
            .last_seen
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut sd = format!(
            "[{SD_ID} id=\"{}\" tool=\"{}\" kind=\"{}\" severity=\"{}\" resolved=\"{}\"",
            sd_escape(&a.id),
            sd_escape(&a.tool),
            sd_escape(&a.kind),
            a.severity,
            a.resolved
        );
        if let Some(r) = &a.resource {
            sd.push_str(&format!(" resource=\"{}\"", sd_escape(r)));
        }
        sd.push(']');
        let head = format!(
            "<{pri}>1 {ts} {} {} {} {} {sd} \u{feff}",
            header_field(&self.hostname, 255),
            header_field(&self.app_name, 48),
            std::process::id(),
            header_field(&a.kind, 32),
        );
        let mut msg = a.headline();
        if !a.summary.is_empty() {
            msg.push_str(" - ");
            msg.push_str(&a.summary);
        }
        for f in &a.fields {
            msg.push_str(&format!(" {}={:?}", f.key, f.value));
        }
        let mut msg: String = msg
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        truncate(&mut msg, max.saturating_sub(head.len()));
        head + &msg
    }

    async fn send_stream<S: tokio::io::AsyncWrite + Unpin>(
        mut s: S,
        line: &str,
    ) -> Result<(), SinkError> {
        // RFC 6587 / 5425 octet-counting framing.
        let frame = format!("{} {line}", line.len());
        s.write_all(frame.as_bytes())
            .await
            .map_err(|e| SinkError::transient(e.to_string()))?;
        s.flush()
            .await
            .map_err(|e| SinkError::transient(e.to_string()))?;
        s.shutdown().await.ok();
        Ok(())
    }
}

impl Sink for SyslogSink {
    fn kind(&self) -> &'static str {
        "syslog"
    }

    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a> {
        Box::pin(async move {
            let io = |e: std::io::Error| SinkError::transient(e.to_string());
            match &self.target {
                Target::Udp(addr) => {
                    let dest = tokio::net::lookup_host(addr.as_str())
                        .await
                        .map_err(io)?
                        .next()
                        .ok_or_else(|| SinkError::transient("syslog address did not resolve"))?;
                    let bind = if dest.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    };
                    let sock = tokio::net::UdpSocket::bind(bind).await.map_err(io)?;
                    let line = self.format(alert, UDP_MAX);
                    sock.send_to(line.as_bytes(), dest).await.map_err(io)?;
                    Ok(())
                }
                Target::Tcp(addr) => {
                    let s = tokio::net::TcpStream::connect(addr.as_str())
                        .await
                        .map_err(io)?;
                    Self::send_stream(s, &self.format(alert, STREAM_MAX)).await
                }
                Target::Tls {
                    addr,
                    server_name,
                    connector,
                } => {
                    let s = tokio::net::TcpStream::connect(addr.as_str())
                        .await
                        .map_err(io)?;
                    let tls = connector
                        .connect(server_name.clone(), s)
                        .await
                        .map_err(io)?;
                    Self::send_stream(tls, &self.format(alert, STREAM_MAX)).await
                }
                #[cfg(unix)]
                Target::Unix(path) => {
                    let sock = tokio::net::UnixDatagram::unbound().map_err(io)?;
                    let line = self.format(alert, UDP_MAX);
                    sock.send_to(line.as_bytes(), path).await.map_err(io)?;
                    Ok(())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    fn cfg(transport: SyslogTransport, address: &str) -> SyslogConfig {
        SyslogConfig {
            transport,
            address: Some(address.into()),
            path: None,
            facility: "local3".into(),
            app_name: None,
            hostname: Some("probe 01.example.net".into()),
            ca_file: None,
            server_name: None,
        }
    }

    fn alert() -> Alert {
        Alert::new("vigil", "hijack", Severity::Critical, "Hijack")
            .resource("192.0.2.0/24")
            .id("vigil:hijack:\"x\"]")
            .summary("line1\nline2")
    }

    #[test]
    fn rfc5424_format() {
        let s =
            SyslogSink::from_config(&cfg(SyslogTransport::Udp, "192.0.2.1:514"), "vigil").unwrap();
        let line = s.format(&alert(), UDP_MAX);
        // local3 (19) * 8 + crit (2) = 154
        assert!(line.starts_with("<154>1 "), "{line}");
        assert!(line.contains(" probe01.example.net vigil "), "{line}");
        assert!(
            line.contains("[llcforge@32473 id=\"vigil:hijack:\\\"x\\\"\\]\""),
            "{line}"
        );
        assert!(line.contains("resource=\"192.0.2.0/24\"]"));
        assert!(!line.contains('\n'));
        let long = alert().summary("x".repeat(10_000));
        assert!(s.format(&long, UDP_MAX).len() <= UDP_MAX);
        assert_eq!(facility_code("local7"), Some(23));
        assert_eq!(facility_code("local8"), None);
        assert!(SyslogSink::from_config(&cfg(SyslogTransport::Udp, "nohost"), "t").is_err());
    }

    #[tokio::test]
    async fn udp_and_tcp_delivery() {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap().to_string();
        let s = SyslogSink::from_config(&cfg(SyslogTransport::Udp, &addr), "vigil").unwrap();
        s.send(&alert()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = udp.recv(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("<154>1 "));

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap().to_string();
        let s = SyslogSink::from_config(&cfg(SyslogTransport::Tcp, &addr), "vigil").unwrap();
        let recv = tokio::spawn(async move {
            let (mut c, _) = tcp.accept().await.unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).await.unwrap();
            out
        });
        s.send(&alert()).await.unwrap();
        let got = recv.await.unwrap();
        let (len, rest) = got.split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), rest.len());
        assert!(rest.starts_with("<154>1 "));
    }

    #[test]
    fn tls_config_builds() {
        let mut c = cfg(SyslogTransport::Tls, "logs.example.net:6514");
        assert!(SyslogSink::from_config(&c, "t").is_ok());
        c.ca_file = Some(PathBuf::from("does-not-exist.pem"));
        assert!(SyslogSink::from_config(&c, "t").is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_datagram() {
        let dir = std::env::temp_dir().join(format!("llcf-syslog-{}", fastrand::u64(..)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.sock");
        let server = tokio::net::UnixDatagram::bind(&path).unwrap();
        let mut c = cfg(SyslogTransport::Unix, "");
        c.address = None;
        c.path = Some(path);
        let s = SyslogSink::from_config(&c, "vigil").unwrap();
        s.send(&alert()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = server.recv(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("<154>1 "));
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(not(unix))]
    #[test]
    fn unix_rejected_elsewhere() {
        let c = cfg(SyslogTransport::Unix, "");
        assert!(SyslogSink::from_config(&c, "t").is_err());
    }
}
