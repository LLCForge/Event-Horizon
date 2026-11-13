//! Persistence of the active blackhole and FlowSpec sets (JSON, atomic replace).

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::bgp::flowspec::FlowRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Api,
    /// Legacy detector source (sFlow-only builds); treated like `Detector`.
    Sflow,
    /// Built-in detector (sFlow, NetFlow v9, IPFIX), including escalation.
    Detector,
}

impl Source {
    pub fn is_detector(self) -> bool {
        matches!(self, Source::Sflow | Source::Detector)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Source::Api => "api",
            Source::Sflow => "sflow",
            Source::Detector => "detector",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub ip: IpAddr,
    pub reason: String,
    pub source: Source,
    pub created_at: u64,
    pub expires_at: u64,
    pub dry_run: bool,
    /// Regional blackhole scope (34); `None` = global.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Selective blackholing: only these upstreams; empty = all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowEntry {
    pub id: String,
    pub rule: FlowRule,
    pub reason: String,
    pub source: Source,
    pub created_at: u64,
    pub expires_at: u64,
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    version: u32,
    entries: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    flowspec: Vec<FlowEntry>,
}

const VERSION: u32 = 1;

/// A missing file means empty state; a corrupt file is an error so the operator decides.
#[cfg(test)]
pub fn load(path: &Path) -> Result<Vec<Entry>> {
    load_all(path).map(|(e, _)| e)
}

pub fn load_all(path: &Path) -> Result<(Vec<Entry>, Vec<FlowEntry>)> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => {
            return Err(e).with_context(|| format!("cannot read state file {}", path.display()))
        }
    };
    let s: StateFile = serde_json::from_str(&text)
        .with_context(|| format!("state file {} is corrupt; fix or remove it", path.display()))?;
    if s.version != VERSION {
        bail!(
            "state file {} has unsupported version {}",
            path.display(),
            s.version
        );
    }
    Ok((s.entries, s.flowspec))
}

/// Writes to `<path>.tmp`, fsyncs, then renames over `path`.
pub fn save(path: &Path, entries: &[Entry], flows: &[FlowEntry]) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(&StateFile {
        version: VERSION,
        entries: entries.to_vec(),
        flowspec: flows.to_vec(),
    })?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = PathBuf::from(path);
    tmp.as_mut_os_string().push(".tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bgp::flowspec::FlowAction;

    pub fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("eh-test-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    pub fn entry(ip: &str) -> Entry {
        Entry {
            ip: ip.parse().unwrap(),
            reason: "test".into(),
            source: Source::Api,
            created_at: 1,
            expires_at: 2,
            dry_run: true,
            scope: None,
            upstreams: Vec::new(),
        }
    }

    #[test]
    fn roundtrip_and_missing_file() {
        let d = tmpdir("state");
        let p = d.join("sub").join("state.json");
        assert!(load(&p).unwrap().is_empty());
        let e = entry("198.51.100.7");
        let f = FlowEntry {
            id: "198.51.100.7-17-s53-dany".into(),
            rule: FlowRule {
                dst: "198.51.100.7".parse().unwrap(),
                protocol: 17,
                src_port: Some(53),
                dst_port: None,
                action: FlowAction::RateLimit { kbps: 100 },
            },
            reason: "dns amplification".into(),
            source: Source::Detector,
            created_at: 1,
            expires_at: 2,
            dry_run: true,
        };
        save(&p, std::slice::from_ref(&e), &[]).unwrap();
        save(&p, std::slice::from_ref(&e), std::slice::from_ref(&f)).unwrap(); // replacing works
        assert_eq!(load_all(&p).unwrap(), (vec![e], vec![f]));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn reads_files_written_before_flowspec_and_scopes() {
        let d = tmpdir("legacy-state");
        let p = d.join("state.json");
        std::fs::write(
            &p,
            r#"{"version":1,"entries":[{"ip":"198.51.100.7","reason":"r","source":"sflow","created_at":1,"expires_at":2,"dry_run":false}]}"#,
        )
        .unwrap();
        let l = load(&p).unwrap();
        assert_eq!(l[0].source, Source::Sflow);
        assert!(l[0].source.is_detector());
        assert!(l[0].scope.is_none() && l[0].upstreams.is_empty());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn corrupt_or_unknown_version_is_an_error() {
        let d = tmpdir("corrupt");
        let p = d.join("state.json");
        std::fs::write(&p, "{not json").unwrap();
        assert!(load(&p).is_err());
        std::fs::write(&p, r#"{"version":9,"entries":[]}"#).unwrap();
        assert!(load(&p).is_err());
        std::fs::remove_dir_all(d).unwrap();
    }
}
