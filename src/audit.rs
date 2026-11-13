//! Append-only JSON-lines audit log.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde_json::{Map, Value};
use tracing::error;

pub struct Audit {
    out: Mutex<Box<dyn Write + Send>>,
}

impl Audit {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::to_writer(Box::new(f)))
    }

    pub fn to_writer(out: Box<dyn Write + Send>) -> Self {
        Self {
            out: Mutex::new(out),
        }
    }

    /// Writes one record: `ts` (unix seconds), `event` and the fields of `fields` (a JSON object).
    pub fn record(&self, now: u64, event: &str, fields: Value) {
        let mut obj = Map::new();
        obj.insert("ts".into(), now.into());
        obj.insert("event".into(), event.into());
        if let Value::Object(m) = fields {
            obj.extend(m);
        }
        let mut line = Value::Object(obj).to_string();
        line.push('\n');
        let res = match self.out.lock() {
            Ok(mut w) => w.write_all(line.as_bytes()).and_then(|_| w.flush()),
            Err(_) => Err(std::io::Error::other("audit log lock poisoned")),
        };
        if let Err(e) = res {
            error!(error = %e, record = %line.trim_end(), "audit log write failed");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;

    /// Shared in-memory sink for tests.
    #[derive(Clone, Default)]
    pub struct Sink(pub Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Sink {
        pub fn lines(&self) -> Vec<Value> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    #[test]
    fn writes_one_json_object_per_line() {
        let sink = Sink::default();
        let a = Audit::to_writer(Box::new(sink.clone()));
        a.record(
            10,
            "allow",
            serde_json::json!({"ip": "198.51.100.7", "reason": "line\nbreak"}),
        );
        a.record(11, "deny", serde_json::json!({"ip": "203.0.113.7"}));
        let l = sink.lines();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0]["event"], "allow");
        assert_eq!(l[0]["reason"], "line\nbreak");
        assert_eq!(l[1]["ts"], 11);
    }
}
