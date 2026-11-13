//! SMTP e-mail sink (lettre + rustls). STARTTLS or implicit TLS; plaintext is
//! only accepted towards a loopback relay. Credentials come from env vars.

use std::time::Duration;

use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use super::{SendFuture, Sink, SinkError};
use crate::alert::{clip_chars, Alert};
use crate::config::{env_secret, is_loopback_host, ConfigError, EmailConfig, SmtpTls};

/// Not `Debug`: the transport holds credentials.
pub struct EmailSink {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Vec<Mailbox>,
}

impl EmailSink {
    pub fn from_config(c: &EmailConfig, timeout: Duration) -> Result<Self, ConfigError> {
        let bad = |e: &dyn std::fmt::Display| ConfigError::Invalid(format!("email: {e}"));
        if c.to.is_empty() || c.to.len() > 50 {
            return Err(ConfigError::Invalid(
                "email: `to` needs 1..=50 recipients".into(),
            ));
        }
        let mut builder = match c.tls {
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&c.host)
                .map_err(|e| bad(&e))?,
            SmtpTls::Tls => {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&c.host).map_err(|e| bad(&e))?
            }
            SmtpTls::None if is_loopback_host(&c.host) => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&c.host)
            }
            SmtpTls::None => {
                return Err(ConfigError::Invalid(
                    "email: tls = \"none\" is only allowed for a loopback relay".into(),
                ))
            }
        };
        if let Some(port) = c.port {
            builder = builder.port(port);
        }
        builder = builder.timeout(Some(timeout));
        match (&c.username_env, &c.password_env) {
            (Some(u), Some(p)) => {
                builder = builder.credentials(Credentials::new(env_secret(u)?, env_secret(p)?));
            }
            (None, None) => {}
            _ => {
                return Err(ConfigError::Invalid(
                    "email: set both username_env and password_env or neither".into(),
                ))
            }
        }
        let from: Mailbox = c.from.parse().map_err(|e| bad(&e))?;
        let to =
            c.to.iter()
                .map(|t| t.parse::<Mailbox>().map_err(|e| bad(&e)))
                .collect::<Result<Vec<_>, _>>()?;
        Ok(EmailSink {
            transport: builder.build(),
            from,
            to,
        })
    }

    /// Subject line (no CR/LF: header injection is impossible by construction).
    pub fn subject(a: &Alert) -> String {
        clip_chars(&a.headline(), 200).replace(['\r', '\n'], " ")
    }

    /// Plain-text body.
    pub fn body(a: &Alert) -> String {
        let mut b = format!("{}\n\n", a.headline());
        if !a.summary.is_empty() {
            b.push_str(&a.summary);
            b.push_str("\n\n");
        }
        if let Some(r) = &a.resource {
            b.push_str(&format!("Resource:   {r}\n"));
        }
        b.push_str(&format!("Tool/kind:  {} / {}\n", a.tool, a.kind));
        b.push_str(&format!("Severity:   {}\n", a.severity));
        b.push_str(&format!("First seen: {}\n", a.first_seen.to_rfc3339()));
        b.push_str(&format!("Last seen:  {}\n", a.last_seen.to_rfc3339()));
        b.push_str(&format!("Alert id:   {}\n", a.id));
        if !a.fields.is_empty() {
            b.push('\n');
            for f in &a.fields {
                b.push_str(&format!("{}: {}\n", f.key, f.value));
            }
        }
        if !a.links.is_empty() {
            b.push('\n');
            for l in &a.links {
                b.push_str(&format!("{}: {}\n", l.title, l.url));
            }
        }
        b
    }

    pub fn message(&self, a: &Alert) -> Result<Message, SinkError> {
        let mut m = Message::builder()
            .from(self.from.clone())
            .subject(Self::subject(a))
            .header(ContentType::TEXT_PLAIN);
        for t in &self.to {
            m = m.to(t.clone());
        }
        m.body(Self::body(a))
            .map_err(|e| SinkError::Permanent(format!("building e-mail: {e}")))
    }
}

impl Sink for EmailSink {
    fn kind(&self) -> &'static str {
        "email"
    }

    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a> {
        Box::pin(async move {
            let msg = self.message(alert)?;
            match self.transport.send(msg).await {
                Ok(_) => Ok(()),
                Err(e) if e.is_permanent() => Err(SinkError::Permanent(e.to_string())),
                Err(e) => Err(SinkError::transient(e.to_string())),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;
    use crate::alert::Severity;

    /// Minimal SMTP server: accepts one message and records the DATA section.
    async fn mock_smtp() -> (u16, Arc<Mutex<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let data = Arc::new(Mutex::new(String::new()));
        let d2 = data.clone();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            w.write_all(b"220 localhost ESMTP mock\r\n").await.unwrap();
            let mut in_data = false;
            while let Ok(Some(line)) = lines.next_line().await {
                if in_data {
                    if line == "." {
                        in_data = false;
                        w.write_all(b"250 2.0.0 queued\r\n").await.unwrap();
                    } else {
                        let mut g = d2.lock().unwrap();
                        g.push_str(&line);
                        g.push('\n');
                    }
                    continue;
                }
                let upper = line.to_ascii_uppercase();
                let reply: &[u8] = if upper.starts_with("EHLO") {
                    b"250 localhost\r\n"
                } else if upper.starts_with("DATA") {
                    in_data = true;
                    b"354 go ahead\r\n"
                } else if upper.starts_with("QUIT") {
                    w.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                w.write_all(reply).await.unwrap();
            }
        });
        (port, data)
    }

    #[test]
    fn rejects_plaintext_to_remote_and_half_credentials() {
        let mut c = EmailConfig {
            host: "smtp.example.net".into(),
            port: None,
            tls: SmtpTls::None,
            username_env: None,
            password_env: None,
            from: "alerts@example.net".into(),
            to: vec!["noc@example.org".into()],
        };
        assert!(EmailSink::from_config(&c, Duration::from_secs(5)).is_err());
        c.tls = SmtpTls::Starttls;
        assert!(EmailSink::from_config(&c, Duration::from_secs(5)).is_ok());
        c.username_env = Some("X".into());
        assert!(EmailSink::from_config(&c, Duration::from_secs(5)).is_err());
    }

    #[tokio::test]
    async fn sends_via_smtp() {
        let (port, data) = mock_smtp().await;
        let c = EmailConfig {
            host: "127.0.0.1".into(),
            port: Some(port),
            tls: SmtpTls::None,
            username_env: None,
            password_env: None,
            from: "LLCForge <alerts@example.net>".into(),
            to: vec!["noc@example.org".into()],
        };
        let sink = EmailSink::from_config(&c, Duration::from_secs(5)).unwrap();
        let a = Alert::new(
            "vigil",
            "hijack",
            Severity::Critical,
            "Hijack\r\nBcc: x@example.org",
        )
        .resource("192.0.2.0/24");
        sink.send(&a).await.unwrap();
        let d = data.lock().unwrap().clone();
        assert!(d.contains("To: noc@example.org"), "{d}");
        assert!(
            d.contains("Subject: [CRITICAL] vigil/hijack 192.0.2.0/24: Hijack"),
            "{d}"
        );
        assert!(!d.lines().any(|l| l.starts_with("Bcc:")), "{d}");
        assert!(d.contains("Resource:   192.0.2.0/24"));
    }
}
