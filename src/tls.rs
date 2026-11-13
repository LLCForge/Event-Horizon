//! Built-in TLS (rustls, ring provider) and optional mutual TLS for the
//! trigger API (42). The bearer token is still required on top of mTLS.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::config::TlsConfig;
use crate::metrics::Metrics;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 256;

fn certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let v = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("cannot read certificates from {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("invalid PEM in {}", path.display()))?;
    anyhow::ensure!(!v.is_empty(), "no certificate in {}", path.display());
    Ok(v)
}

/// TLS 1.3 / 1.2 server configuration; mTLS when `client_ca_file` is set.
pub fn server_config(cfg: &TlsConfig) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let chain = certs(&cfg.cert_file)?;
    let key = PrivateKeyDer::from_pem_file(&cfg.key_file)
        .with_context(|| format!("cannot read private key from {}", cfg.key_file.display()))?;
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
    let builder = match &cfg.client_ca_file {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in certs(ca)? {
                roots.add(c).context("invalid client CA certificate")?;
            }
            let v = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .context("cannot build client certificate verifier")?;
            builder.with_client_cert_verifier(v)
        }
        None => builder.with_no_client_auth(),
    };
    let mut sc = builder
        .with_single_cert(chain, key)
        .context("certificate and private key do not match")?;
    sc.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(sc))
}

/// Accept loop: bounded connections, handshake and header timeouts, HTTP/1.1.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    tls: Arc<ServerConfig>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    info!("TLS listener started");
    loop {
        tokio::select! {
            r = listener.accept() => {
                let Ok((tcp, peer)) = r else { continue };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    debug!(%peer, "too many TLS connections; closing");
                    continue;
                };
                let (acceptor, app, metrics) = (acceptor.clone(), app.clone(), metrics.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            Metrics::inc(&metrics.api_tls_failed);
                            debug!(%peer, error = %e, "TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            Metrics::inc(&metrics.api_tls_failed);
                            return;
                        }
                    };
                    let conn = hyper::server::conn::http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_TIMEOUT)
                        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app));
                    let _ = tokio::time::timeout(CONNECTION_LIFETIME, conn).await;
                });
            }
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedKey, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    };
    use rustls::ClientConfig;
    use rustls_pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub struct Pki {
        pub dir: std::path::PathBuf,
        pub ca_pem: String,
        pub client: (String, String),
    }

    fn issue(
        names: Vec<String>,
        eku: ExtendedKeyUsagePurpose,
        ca: &CertifiedKey,
    ) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(names).unwrap();
        p.extended_key_usages = vec![eku];
        let c = p.signed_by(&key, &ca.cert, &ca.key_pair).unwrap();
        (c.pem(), key.serialize_pem())
    }

    pub fn pki(name: &str) -> Pki {
        let dir = crate::state::tests::tmpdir(name);
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedKey {
            cert: ca_params.self_signed(&ca_key).unwrap(),
            key_pair: ca_key,
        };
        let (srv, srv_key) = issue(
            vec!["localhost".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca,
        );
        std::fs::write(dir.join("server.pem"), srv).unwrap();
        std::fs::write(dir.join("server.key"), srv_key).unwrap();
        std::fs::write(dir.join("ca.pem"), ca.cert.pem()).unwrap();
        let client = issue(
            vec!["detector.example.net".into()],
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca,
        );
        Pki {
            dir,
            ca_pem: ca.cert.pem(),
            client,
        }
    }

    pub fn tls_cfg(p: &Pki, mtls: bool) -> TlsConfig {
        TlsConfig {
            cert_file: p.dir.join("server.pem"),
            key_file: p.dir.join("server.key"),
            client_ca_file: mtls.then(|| p.dir.join("ca.pem")),
        }
    }

    async fn get(
        addr: std::net::SocketAddr,
        p: &Pki,
        with_client_cert: bool,
    ) -> std::io::Result<String> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(p.ca_pem.as_bytes()).unwrap())
            .unwrap();
        let b =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots);
        let cc = if with_client_cert {
            b.with_client_auth_cert(
                vec![CertificateDer::from_pem_slice(p.client.0.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(p.client.1.as_bytes()).unwrap(),
            )
            .unwrap()
        } else {
            b.with_no_client_auth()
        };
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let mut s = tokio_rustls::TlsConnector::from(Arc::new(cc))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        s.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut out = String::new();
        s.read_to_string(&mut out).await?;
        Ok(out)
    }

    async fn start(cfg: &TlsConfig) -> (std::net::SocketAddr, watch::Sender<bool>, Arc<Metrics>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let app = Router::new().route("/ping", axum::routing::get(|| async { "pong" }));
        let (tx, rx) = watch::channel(false);
        let m = Arc::new(Metrics::default());
        tokio::spawn(serve(l, app, server_config(cfg).unwrap(), m.clone(), rx));
        (addr, tx, m)
    }

    #[tokio::test]
    async fn serves_https_and_enforces_client_certificates() {
        let p = pki("tls");
        let (addr, _tx, _) = start(&tls_cfg(&p, false)).await;
        let r = get(addr, &p, false).await.unwrap();
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.ends_with("pong"));

        let (addr, _tx2, m) = start(&tls_cfg(&p, true)).await;
        assert!(get(addr, &p, true).await.unwrap().ends_with("pong"));
        assert!(get(addr, &p, false).await.is_err(), "no client certificate");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(m.api_tls_failed.load(std::sync::atomic::Ordering::Relaxed) >= 1);
        std::fs::remove_dir_all(&p.dir).unwrap();
    }

    #[test]
    fn bad_files_are_reported() {
        let p = pki("tls-bad");
        let mut cfg = tls_cfg(&p, false);
        cfg.key_file = p.dir.join("missing.key");
        assert!(server_config(&cfg).is_err());
        let mut cfg = tls_cfg(&p, false);
        cfg.cert_file = p.dir.join("server.key"); // a key is not a certificate
        assert!(server_config(&cfg).is_err());
        std::fs::remove_dir_all(&p.dir).unwrap();
    }
}
