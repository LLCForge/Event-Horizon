//! Append-only, crash-safe on-disk delivery queue.
//!
//! Layout: `<dir>/seg-<n>.jsonl`, one JSON record per line:
//! `{"op":"enq","seq":7,"targets":["noc"],"alert":{...}}` and
//! `{"op":"ack","seq":7,"sink":"noc"}`. Every append is fsynced. On open, all
//! segments are replayed; a torn final line (crash mid-write) is truncated
//! away, corrupt interior lines are skipped. Compaction rewrites the live set
//! into a new segment (temp file + fsync + rename) and deletes older ones.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::alert::Alert;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Record {
    Enq {
        seq: u64,
        targets: Vec<String>,
        alert: Box<Alert>,
    },
    Ack {
        seq: u64,
        sink: String,
    },
}

/// One undelivered alert and the sinks still owed a delivery.
#[derive(Debug, Clone)]
pub struct QueueEntry {
    pub alert: Alert,
    pub targets: BTreeSet<String>,
    line_bytes: u64,
}

/// Limits for [`DiskQueue`].
#[derive(Debug, Clone, Copy)]
pub struct QueueLimits {
    pub max_entries: usize,
    pub max_bytes: u64,
    pub segment_bytes: u64,
}

/// What [`DiskQueue::open`] found on disk.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub segments: usize,
    pub records: usize,
    pub corrupt_lines: usize,
    pub truncated_bytes: u64,
}

pub struct DiskQueue {
    dir: PathBuf,
    limits: QueueLimits,
    active: File,
    active_idx: u64,
    active_len: u64,
    total_bytes: u64,
    live_bytes: u64,
    next_seq: u64,
    live: BTreeMap<u64, QueueEntry>,
}

fn seg_name(idx: u64) -> String {
    format!("seg-{idx:010}.jsonl")
}

fn list_segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut segs = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".tmp") {
            // Leftover from an interrupted compaction: the originals are intact.
            fs::remove_file(e.path())?;
            continue;
        }
        if let Some(n) = name
            .strip_prefix("seg-")
            .and_then(|r| r.strip_suffix(".jsonl"))
            .and_then(|n| n.parse::<u64>().ok())
        {
            segs.push((n, e.path()));
        }
    }
    segs.sort();
    Ok(segs)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    // Windows cannot fsync a directory handle; NTFS journals the rename.
    Ok(())
}

impl DiskQueue {
    /// Opens (creating if needed) and recovers the queue in `dir`.
    pub fn open(
        dir: impl Into<PathBuf>,
        limits: QueueLimits,
    ) -> io::Result<(Self, RecoveryReport)> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let segs = list_segments(&dir)?;
        let mut report = RecoveryReport {
            segments: segs.len(),
            ..Default::default()
        };
        let mut live: BTreeMap<u64, QueueEntry> = BTreeMap::new();
        let mut max_seq = 0u64;
        let mut total_bytes = 0u64;
        let last_idx = segs.last().map(|(n, _)| *n);
        for (idx, path) in &segs {
            let mut buf = Vec::new();
            File::open(path)?.read_to_end(&mut buf)?;
            let is_last = Some(*idx) == last_idx;
            let mut good_len = 0usize;
            let mut pos = 0usize;
            while pos < buf.len() {
                let Some(nl) = buf[pos..].iter().position(|b| *b == b'\n') else {
                    // Unterminated tail: a torn write. Only possible in the last segment.
                    break;
                };
                let line = &buf[pos..pos + nl];
                let line_bytes = (nl + 1) as u64;
                pos += nl + 1;
                match serde_json::from_slice::<Record>(line) {
                    Ok(Record::Enq {
                        seq,
                        targets,
                        alert,
                    }) => {
                        report.records += 1;
                        max_seq = max_seq.max(seq);
                        live.insert(
                            seq,
                            QueueEntry {
                                alert: *alert,
                                targets: targets.into_iter().collect(),
                                line_bytes,
                            },
                        );
                    }
                    Ok(Record::Ack { seq, sink }) => {
                        report.records += 1;
                        max_seq = max_seq.max(seq);
                        if let Some(e) = live.get_mut(&seq) {
                            e.targets.remove(&sink);
                            if e.targets.is_empty() {
                                live.remove(&seq);
                            }
                        }
                    }
                    Err(_) if line.iter().all(u8::is_ascii_whitespace) => {}
                    Err(e) => {
                        report.corrupt_lines += 1;
                        tracing::warn!(segment = %path.display(), error = %e, "skipping corrupt alert-queue record");
                    }
                }
                good_len = pos;
            }
            if good_len < buf.len() {
                let torn = (buf.len() - good_len) as u64;
                if is_last {
                    let f = OpenOptions::new().write(true).open(path)?;
                    f.set_len(good_len as u64)?;
                    f.sync_all()?;
                    report.truncated_bytes += torn;
                    tracing::warn!(segment = %path.display(), bytes = torn, "truncated torn alert-queue tail");
                } else {
                    report.corrupt_lines += 1;
                }
            }
            total_bytes += good_len as u64;
        }
        let active_idx = last_idx.unwrap_or(1);
        let active_path = dir.join(seg_name(active_idx));
        let active = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)?;
        let active_len = active.metadata()?.len();
        if last_idx.is_none() {
            sync_dir(&dir)?;
        }
        let live_bytes = live.values().map(|e| e.line_bytes).sum();
        let mut q = DiskQueue {
            dir,
            limits,
            active,
            active_idx,
            active_len,
            total_bytes,
            live_bytes,
            next_seq: max_seq + 1,
            live,
        };
        if q.segment_count()? > 1 || q.total_bytes > q.live_bytes.saturating_mul(2).max(4096) {
            q.compact()?;
        }
        Ok((q, report))
    }

    fn segment_count(&self) -> io::Result<usize> {
        Ok(list_segments(&self.dir)?.len())
    }

    fn append(&mut self, rec: &Record) -> io::Result<u64> {
        let mut line = serde_json::to_vec(rec).map_err(io::Error::other)?;
        line.push(b'\n');
        // One write_all + fsync per record: a crash leaves at most one torn tail line.
        self.active.write_all(&line)?;
        self.active.sync_data()?;
        let n = line.len() as u64;
        self.active_len += n;
        self.total_bytes += n;
        Ok(n)
    }

    /// Persists a new entry; returns its sequence number.
    pub fn push(&mut self, alert: &Alert, targets: &[String]) -> io::Result<u64> {
        let seq = self.next_seq;
        let rec = Record::Enq {
            seq,
            targets: targets.to_vec(),
            alert: Box::new(alert.clone()),
        };
        let n = self.append(&rec)?;
        self.next_seq += 1;
        self.live_bytes += n;
        self.live.insert(
            seq,
            QueueEntry {
                alert: alert.clone(),
                targets: targets.iter().cloned().collect(),
                line_bytes: n,
            },
        );
        self.maintain()?;
        Ok(seq)
    }

    /// Records that `sink` no longer needs entry `seq` (delivered, rejected or expired).
    pub fn ack(&mut self, seq: u64, sink: &str) -> io::Result<()> {
        let Some(e) = self.live.get(&seq) else {
            return Ok(());
        };
        if !e.targets.contains(sink) {
            return Ok(());
        }
        self.append(&Record::Ack {
            seq,
            sink: sink.to_string(),
        })?;
        if let Some(e) = self.live.get_mut(&seq) {
            e.targets.remove(sink);
            if e.targets.is_empty() {
                self.live_bytes = self.live_bytes.saturating_sub(e.line_bytes);
                self.live.remove(&seq);
            }
        }
        self.maintain()
    }

    /// Acks every remaining target of `seq`.
    pub fn remove(&mut self, seq: u64) -> io::Result<()> {
        let targets: Vec<String> = self
            .live
            .get(&seq)
            .map(|e| e.targets.iter().cloned().collect())
            .unwrap_or_default();
        for t in targets {
            self.ack(seq, &t)?;
        }
        Ok(())
    }

    /// Live entries, oldest first.
    pub fn entries(&self) -> impl Iterator<Item = (u64, &QueueEntry)> {
        self.live.iter().map(|(k, v)| (*k, v))
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Oldest live sequence number when a size or count bound is exceeded.
    pub fn over_limit(&self) -> Option<u64> {
        if self.live.len() > self.limits.max_entries || self.live_bytes > self.limits.max_bytes {
            self.live.keys().next().copied()
        } else {
            None
        }
    }

    fn maintain(&mut self) -> io::Result<()> {
        if self.active_len < self.limits.segment_bytes {
            return Ok(());
        }
        if self.total_bytes > self.live_bytes.saturating_mul(2) {
            self.compact()
        } else {
            self.roll()
        }
    }

    fn roll(&mut self) -> io::Result<()> {
        self.active_idx += 1;
        let path = self.dir.join(seg_name(self.active_idx));
        self.active = OpenOptions::new().create(true).append(true).open(&path)?;
        self.active_len = 0;
        sync_dir(&self.dir)
    }

    /// Rewrites the live set into a fresh segment and deletes all older segments.
    pub fn compact(&mut self) -> io::Result<()> {
        let old = list_segments(&self.dir)?;
        let idx = self.active_idx + 1;
        let final_path = self.dir.join(seg_name(idx));
        let tmp_path = self.dir.join(format!("{}.tmp", seg_name(idx)));
        let mut written = 0u64;
        {
            let mut f = File::create(&tmp_path)?;
            for (seq, e) in &mut self.live {
                let rec = Record::Enq {
                    seq: *seq,
                    targets: e.targets.iter().cloned().collect(),
                    alert: Box::new(e.alert.clone()),
                };
                let mut line = serde_json::to_vec(&rec).map_err(io::Error::other)?;
                line.push(b'\n');
                f.write_all(&line)?;
                e.line_bytes = line.len() as u64;
                written += e.line_bytes;
            }
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        sync_dir(&self.dir)?;
        // The new segment supersedes everything: replaying it after a crash
        // here is safe because a later `enq` for a seq replaces earlier state.
        self.active = OpenOptions::new().append(true).open(&final_path)?;
        for (_, p) in old {
            fs::remove_file(p)?;
        }
        sync_dir(&self.dir)?;
        self.active_idx = idx;
        self.active_len = written;
        self.total_bytes = written;
        self.live_bytes = written;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Severity;

    pub(crate) fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "llcf-{tag}-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn limits() -> QueueLimits {
        QueueLimits {
            max_entries: 100,
            max_bytes: 1 << 20,
            segment_bytes: 1 << 20,
        }
    }

    fn a(n: u32) -> Alert {
        Alert::new("t", "k", Severity::Warning, format!("alert {n}"))
            .resource(format!("192.0.2.{n}"))
    }

    #[test]
    fn persists_and_acks_across_reopen() {
        let dir = tmpdir("q1");
        {
            let (mut q, _) = DiskQueue::open(&dir, limits()).unwrap();
            let s1 = q.push(&a(1), &["x".into(), "y".into()]).unwrap();
            let s2 = q.push(&a(2), &["x".into()]).unwrap();
            q.ack(s1, "x").unwrap();
            q.ack(s2, "x").unwrap();
            assert_eq!(q.len(), 1);
        }
        let (q, rep) = DiskQueue::open(&dir, limits()).unwrap();
        assert_eq!(rep.corrupt_lines, 0);
        let entries: Vec<_> = q.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.alert.title, "alert 1");
        assert_eq!(entries[0].1.targets.iter().collect::<Vec<_>>(), vec!["y"]);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn recovers_from_torn_last_line() {
        let dir = tmpdir("q2");
        {
            let (mut q, _) = DiskQueue::open(&dir, limits()).unwrap();
            q.push(&a(1), &["x".into()]).unwrap();
            q.push(&a(2), &["x".into()]).unwrap();
        }
        // Simulate a crash in the middle of writing a third record.
        let seg = list_segments(&dir).unwrap().pop().unwrap().1;
        let before = fs::metadata(&seg).unwrap().len();
        {
            let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
            f.write_all(br#"{"op":"enq","seq":3,"targets":["x"],"alert":{"sch"#)
                .unwrap();
        }
        let (mut q, rep) = DiskQueue::open(&dir, limits()).unwrap();
        assert!(rep.truncated_bytes > 0, "{rep:?}");
        assert_eq!(q.len(), 2);
        // Appending after recovery yields a clean file that reopens without loss.
        let s = q.push(&a(3), &["x".into()]).unwrap();
        assert_eq!(s, 3);
        drop(q);
        let (q, rep) = DiskQueue::open(&dir, limits()).unwrap();
        assert_eq!((q.len(), rep.corrupt_lines, rep.truncated_bytes), (3, 0, 0));
        let _ = before;
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn skips_corrupt_interior_line() {
        let dir = tmpdir("q3");
        {
            let (mut q, _) = DiskQueue::open(&dir, limits()).unwrap();
            q.push(&a(1), &["x".into()]).unwrap();
        }
        let seg = list_segments(&dir).unwrap().pop().unwrap().1;
        {
            let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
            f.write_all(b"garbage{{\n").unwrap();
        }
        {
            let (mut q, rep) = DiskQueue::open(&dir, limits()).unwrap();
            assert_eq!(rep.corrupt_lines, 1);
            q.push(&a(2), &["x".into()]).unwrap();
        }
        let (q, _) = DiskQueue::open(&dir, limits()).unwrap();
        assert_eq!(q.len(), 2);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn compaction_bounds_disk_usage_and_keeps_live_set() {
        let dir = tmpdir("q4");
        let lim = QueueLimits {
            max_entries: 100,
            max_bytes: 1 << 20,
            segment_bytes: 4096,
        };
        let (mut q, _) = DiskQueue::open(&dir, lim).unwrap();
        let keep = q.push(&a(0), &["x".into()]).unwrap();
        for i in 1..200 {
            let s = q.push(&a(i), &["x".into()]).unwrap();
            q.ack(s, "x").unwrap();
        }
        assert_eq!(q.len(), 1);
        let on_disk: u64 = list_segments(&dir)
            .unwrap()
            .iter()
            .map(|(_, p)| fs::metadata(p).unwrap().len())
            .sum();
        assert!(on_disk < 3 * 4096, "on disk {on_disk}");
        drop(q);
        let (q, _) = DiskQueue::open(&dir, lim).unwrap();
        assert_eq!(q.entries().next().unwrap().0, keep);
        assert_eq!(list_segments(&dir).unwrap().len(), 1);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn interrupted_compaction_temp_file_is_ignored() {
        let dir = tmpdir("q5");
        {
            let (mut q, _) = DiskQueue::open(&dir, limits()).unwrap();
            q.push(&a(1), &["x".into()]).unwrap();
        }
        fs::write(dir.join("seg-0000000099.jsonl.tmp"), b"partial").unwrap();
        let (q, _) = DiskQueue::open(&dir, limits()).unwrap();
        assert_eq!(q.len(), 1);
        assert!(!dir.join("seg-0000000099.jsonl.tmp").exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn over_limit_reports_oldest() {
        let dir = tmpdir("q6");
        let lim = QueueLimits {
            max_entries: 2,
            max_bytes: 1 << 20,
            segment_bytes: 1 << 20,
        };
        let (mut q, _) = DiskQueue::open(&dir, lim).unwrap();
        let first = q.push(&a(1), &["x".into()]).unwrap();
        q.push(&a(2), &["x".into()]).unwrap();
        assert_eq!(q.over_limit(), None);
        q.push(&a(3), &["x".into()]).unwrap();
        assert_eq!(q.over_limit(), Some(first));
        q.remove(first).unwrap();
        assert_eq!(q.over_limit(), None);
        fs::remove_dir_all(dir).ok();
    }
}
