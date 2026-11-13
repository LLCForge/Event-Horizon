//! Standard output sink (human text or one JSON object per line).

use std::io::Write;

use super::{SendFuture, Sink, SinkError};
use crate::alert::Alert;
use crate::config::OutputFormat;

pub struct StdoutSink {
    format: OutputFormat,
}

impl StdoutSink {
    pub fn new(format: OutputFormat) -> Self {
        StdoutSink { format }
    }

    /// The exact line written for `alert` (without the trailing newline).
    pub fn render(&self, alert: &Alert) -> Result<String, SinkError> {
        match self.format {
            OutputFormat::Json => {
                serde_json::to_string(alert).map_err(|e| SinkError::Permanent(e.to_string()))
            }
            OutputFormat::Text => {
                let mut line = alert.headline();
                if !alert.summary.is_empty() {
                    line.push_str(" - ");
                    line.push_str(&alert.summary);
                }
                for f in &alert.fields {
                    line.push_str(&format!(" {}={:?}", f.key, f.value));
                }
                // One alert per line: neutralise embedded line breaks.
                Ok(line.replace(['\r', '\n'], " "))
            }
        }
    }
}

impl Sink for StdoutSink {
    fn kind(&self) -> &'static str {
        "stdout"
    }

    fn send<'a>(&'a self, alert: &'a Alert) -> SendFuture<'a> {
        Box::pin(async move {
            let line = self.render(alert)?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{line}")
                .and_then(|()| out.flush())
                .map_err(|e| SinkError::transient(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Severity;

    #[test]
    fn text_is_single_line_and_json_parses() {
        let a = Alert::new("vigil", "hijack", Severity::Critical, "Origin\nchange")
            .resource("192.0.2.0/24")
            .summary("line1\r\nline2")
            .field("origin", "AS64512");
        let t = StdoutSink::new(OutputFormat::Text).render(&a).unwrap();
        assert!(!t.contains('\n') && !t.contains('\r'));
        assert!(t.starts_with("[CRITICAL] vigil/hijack 192.0.2.0/24"));
        assert!(t.contains("origin=\"AS64512\""));
        let j = StdoutSink::new(OutputFormat::Json).render(&a).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["schema"], "llcforge.alert.v1");
    }
}
