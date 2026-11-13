//! Per-victim attack reports (44): duration, peak rates, top source ASNs,
//! ports and protocols, mitigation timeline. Written as JSON and Markdown.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::flow::FlowSample;

/// Distinct keys tracked per dimension; the rest is summed as "other".
const TOP_CAP: usize = 128;
const TOP_N: usize = 10;
const RECENT: usize = 100;

#[derive(Debug, Clone, Default)]
pub struct Top {
    map: HashMap<u64, u64>,
    other: u64,
    total: u64,
}

impl Top {
    pub fn add(&mut self, key: u64, v: u64) {
        self.total = self.total.saturating_add(v);
        if let Some(c) = self.map.get_mut(&key) {
            *c = c.saturating_add(v);
        } else if self.map.len() < TOP_CAP {
            self.map.insert(key, v);
        } else {
            self.other = self.other.saturating_add(v);
        }
    }

    pub fn top(&self) -> Vec<Share> {
        let mut v: Vec<(u64, u64)> = self.map.iter().map(|(k, c)| (*k, *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.into_iter()
            .take(TOP_N)
            .map(|(k, c)| Share {
                key: k,
                packets: c,
                percent: if self.total == 0 {
                    0.0
                } else {
                    (c as f64 * 1000.0 / self.total as f64).round() / 10.0
                },
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Share {
    pub key: u64,
    pub packets: u64,
    pub percent: f64,
}

/// Accumulated while an attack on one destination is active.
#[derive(Debug, Clone)]
pub struct AttackStats {
    pub started_at: u64,
    pub class: &'static str,
    pub peak_pps: u64,
    pub peak_bps: u64,
    pub packets: u64,
    pub bytes: u64,
    src_asns: Top,
    src_ports: Top,
    dst_ports: Top,
    protocols: Top,
}

impl AttackStats {
    pub fn new(started_at: u64, class: &'static str) -> Self {
        Self {
            started_at,
            class,
            peak_pps: 0,
            peak_bps: 0,
            packets: 0,
            bytes: 0,
            src_asns: Top::default(),
            src_ports: Top::default(),
            dst_ports: Top::default(),
            protocols: Top::default(),
        }
    }

    pub fn add(&mut self, s: &FlowSample) {
        self.packets = self.packets.saturating_add(s.packets);
        self.bytes = self.bytes.saturating_add(s.bytes);
        if let Some(a) = s.src_asn {
            self.src_asns.add(u64::from(a), s.packets);
        }
        if let Some(p) = s.src_port {
            self.src_ports.add(u64::from(p), s.packets);
        }
        if let Some(p) = s.dst_port {
            self.dst_ports.add(u64::from(p), s.packets);
        }
        if let Some(p) = s.protocol {
            self.protocols.add(u64::from(p), s.packets);
        }
    }

    pub fn peak(&mut self, pps: u64, bps: u64) {
        self.peak_pps = self.peak_pps.max(pps);
        self.peak_bps = self.peak_bps.max(bps);
    }

    pub fn finish(&self, dst: IpAddr, ended_at: u64, mitigation: Vec<String>) -> AttackReport {
        AttackReport {
            id: format!(
                "{:012}-{}",
                self.started_at,
                dst.to_string().replace(':', "_")
            ),
            dst,
            started_at: self.started_at,
            ended_at,
            duration_secs: ended_at.saturating_sub(self.started_at),
            classification: self.class.to_owned(),
            peak_pps: self.peak_pps,
            peak_bps: self.peak_bps,
            sampled_packets: self.packets,
            sampled_bytes: self.bytes,
            top_source_asns: self.src_asns.top(),
            top_source_ports: self.src_ports.top(),
            top_destination_ports: self.dst_ports.top(),
            protocols: self.protocols.top(),
            mitigation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackReport {
    pub id: String,
    pub dst: IpAddr,
    pub started_at: u64,
    pub ended_at: u64,
    pub duration_secs: u64,
    pub classification: String,
    pub peak_pps: u64,
    pub peak_bps: u64,
    /// Scaled packet / byte totals from flow samples (estimates).
    pub sampled_packets: u64,
    pub sampled_bytes: u64,
    pub top_source_asns: Vec<Share>,
    pub top_source_ports: Vec<Share>,
    pub top_destination_ports: Vec<Share>,
    pub protocols: Vec<Share>,
    pub mitigation: Vec<String>,
}

pub fn fmt_time(secs: u64) -> String {
    chrono::DateTime::from_timestamp(i64::try_from(secs).unwrap_or(0), 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| secs.to_string())
}

fn proto_name(p: u64) -> String {
    match p {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        47 => "GRE".into(),
        58 => "ICMPv6".into(),
        n => n.to_string(),
    }
}

pub fn human_bps(bps: u64) -> String {
    let b = bps as f64;
    if b >= 1e9 {
        format!("{:.2} Gbit/s", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} Mbit/s", b / 1e6)
    } else {
        format!("{:.0} kbit/s", b / 1e3)
    }
}

impl AttackReport {
    pub fn to_markdown(&self) -> String {
        let mut o = String::new();
        let table =
            |o: &mut String, title: &str, head: &str, rows: &[Share], f: &dyn Fn(u64) -> String| {
                o.push_str(&format!(
                    "\n## {title}\n\n| {head} | Packets | Share |\n|---|---:|---:|\n"
                ));
                if rows.is_empty() {
                    o.push_str("| (not in flow data) | | |\n");
                }
                for r in rows {
                    o.push_str(&format!(
                        "| {} | {} | {:.1}% |\n",
                        f(r.key),
                        r.packets,
                        r.percent
                    ));
                }
            };
        o.push_str(&format!("# Attack report: {}\n\n", self.dst));
        o.push_str("| | |\n|---|---|\n");
        o.push_str(&format!("| Classification | {} |\n", self.classification));
        o.push_str(&format!("| Started | {} |\n", fmt_time(self.started_at)));
        o.push_str(&format!("| Ended | {} |\n", fmt_time(self.ended_at)));
        o.push_str(&format!("| Duration | {} s |\n", self.duration_secs));
        o.push_str(&format!(
            "| Peak | {} pps, {} |\n",
            self.peak_pps,
            human_bps(self.peak_bps)
        ));
        o.push_str(&format!(
            "| Estimated volume | {} packets, {} bytes |\n",
            self.sampled_packets, self.sampled_bytes
        ));
        table(
            &mut o,
            "Top source ASNs",
            "ASN",
            &self.top_source_asns,
            &|k| format!("AS{k}"),
        );
        table(
            &mut o,
            "Protocols",
            "Protocol",
            &self.protocols,
            &proto_name,
        );
        table(
            &mut o,
            "Top source ports",
            "Port",
            &self.top_source_ports,
            &|k| k.to_string(),
        );
        table(
            &mut o,
            "Top destination ports",
            "Port",
            &self.top_destination_ports,
            &|k| k.to_string(),
        );
        o.push_str("\n## Mitigation\n\n");
        if self.mitigation.is_empty() {
            o.push_str("- none\n");
        }
        for m in &self.mitigation {
            o.push_str(&format!("- {m}\n"));
        }
        o
    }
}

/// Writes reports to disk (bounded) and keeps the newest in memory for the API.
pub struct ReportStore {
    dir: Option<PathBuf>,
    keep: usize,
    recent: Mutex<VecDeque<AttackReport>>,
}

fn write_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.to_path_buf();
    tmp.as_mut_os_string().push(".tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, path)
}

impl ReportStore {
    pub fn new(dir: Option<PathBuf>, keep: usize) -> Self {
        Self {
            dir,
            keep: keep.max(1),
            recent: Mutex::new(VecDeque::new()),
        }
    }

    pub fn save(&self, r: &AttackReport) -> std::io::Result<()> {
        if let Ok(mut q) = self.recent.lock() {
            if q.len() >= RECENT {
                q.pop_front();
            }
            q.push_back(r.clone());
        }
        let Some(dir) = &self.dir else { return Ok(()) };
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_vec_pretty(r)?;
        write_atomic(&dir.join(format!("{}.json", r.id)), &json)?;
        write_atomic(
            &dir.join(format!("{}.md", r.id)),
            r.to_markdown().as_bytes(),
        )?;
        self.prune(dir);
        Ok(())
    }

    fn prune(&self, dir: &Path) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut ids: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(str::to_owned))
            .filter_map(|n| n.strip_suffix(".json").map(str::to_owned))
            .collect();
        ids.sort();
        let excess = ids.len().saturating_sub(self.keep);
        for id in ids.into_iter().take(excess) {
            for ext in ["json", "md"] {
                if let Err(e) = std::fs::remove_file(dir.join(format!("{id}.{ext}"))) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(error = %e, "cannot prune old report");
                    }
                }
            }
        }
    }

    /// Newest first.
    pub fn recent(&self) -> Vec<AttackReport> {
        self.recent
            .lock()
            .map(|q| q.iter().rev().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample(sport: u16, asn: u32, packets: u64) -> FlowSample {
        let mut s = FlowSample::new("198.51.100.7".parse().unwrap(), packets, packets * 500);
        s.protocol = Some(17);
        s.src_port = Some(sport);
        s.dst_port = Some(4444);
        s.src_asn = Some(asn);
        s
    }

    #[test]
    fn top_is_bounded_and_sorted() {
        let mut t = Top::default();
        for k in 0..1000u64 {
            t.add(k, 1);
        }
        t.add(5, 100);
        assert_eq!(t.map.len(), TOP_CAP);
        let top = t.top();
        assert_eq!(top.len(), TOP_N);
        assert_eq!(top[0].key, 5);
        assert_eq!(top[0].packets, 101);
        assert!((top[0].percent - 9.2).abs() < 0.01);
    }

    #[test]
    fn report_json_and_markdown() {
        let mut st = AttackStats::new(1_700_000_000, "udp_amplification_dns");
        st.add(&sample(53, 64511, 900));
        st.add(&sample(53, 64512, 100));
        st.peak(50_000, 400_000_000);
        st.peak(10, 10);
        let r = st.finish(
            "198.51.100.7".parse().unwrap(),
            1_700_000_300,
            vec!["FlowSpec rate-limit".into()],
        );
        assert_eq!(r.duration_secs, 300);
        assert_eq!(r.peak_pps, 50_000);
        assert_eq!(r.top_source_asns[0].key, 64511);
        assert_eq!(r.top_source_asns[0].percent, 90.0);
        let md = r.to_markdown();
        assert!(md.contains("# Attack report: 198.51.100.7"));
        assert!(md.contains("| AS64511 | 900 | 90.0% |"));
        assert!(md.contains("| UDP | 1000 | 100.0% |"));
        assert!(md.contains("400.0 Mbit/s"));
        assert!(md.contains("2023-11-14 22:13:20 UTC"));
        let back: AttackReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn store_writes_and_prunes() {
        let d = crate::state::tests::tmpdir("reports");
        let s = ReportStore::new(Some(d.clone()), 2);
        for i in 0..3u64 {
            let r = AttackStats::new(100 + i, "syn_flood").finish(
                "2001:db8:100::7".parse().unwrap(),
                200,
                vec![],
            );
            s.save(&r).unwrap();
        }
        let mut names: Vec<String> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 4);
        assert!(names[0].starts_with("000000000101-2001_db8_100__7"));
        assert_eq!(s.recent()[0].started_at, 102);
        std::fs::remove_dir_all(d).unwrap();
    }
}
