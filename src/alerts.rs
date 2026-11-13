//! Swappable llcforge-alert handle (40). Every task holds an `Alerts` clone;
//! a configuration reload restarts the dispatcher and swaps the handle in place.

use std::sync::{Arc, RwLock};

use llcforge_alert::{Alert, AlertHandle, Severity};

use crate::config::BIN;

#[derive(Clone)]
pub struct Alerts(Arc<RwLock<AlertHandle>>);

impl Alerts {
    pub fn new(h: AlertHandle) -> Self {
        Self(Arc::new(RwLock::new(h)))
    }

    /// Logs alerts only (tests, one-shot CLI commands).
    pub fn disabled() -> Self {
        Self::new(AlertHandle::disabled(BIN))
    }

    /// Never blocks; dropped alerts are counted by the dispatcher.
    pub fn send(&self, a: Alert) {
        if let Ok(h) = self.0.read() {
            h.send(a);
        }
    }

    pub fn replace(&self, h: AlertHandle) {
        if let Ok(mut g) = self.0.write() {
            *g = h;
        }
    }

    pub fn handle(&self) -> Option<AlertHandle> {
        self.0.read().ok().map(|h| h.clone())
    }
}

/// `Alert::new` with the tool name filled in.
pub fn alert(kind: &str, severity: Severity, title: impl Into<String>) -> Alert {
    Alert::new(BIN, kind, severity, title)
}
