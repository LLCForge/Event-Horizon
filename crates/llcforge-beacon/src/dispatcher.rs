//! Alert dispatcher: non-blocking intake, silences, deduplication, per-sink
//! routing, persistent queue and redelivery.
//!
//! ```text
//! tool ──try_send──▶ [bounded channel] ──▶ dispatcher task ──▶ per-sink worker ──▶ Sink
//!                                          │  normalize, silence, dedup, filter
//!                                          │  persist (DiskQueue, fsync)
//!                                          ◀── ack (delivered / failed / rejected)
//! ```
//! Each sink has its own worker, so a slow or dead destination never delays
//! the others. Failed deliveries are retried by the runner, then redelivered
//! by the dispatcher every `redeliver_after_secs` until `max_age_secs`.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::alert::Alert;
use crate::config::{AlertsConfig, ConfigError};
use crate::metrics::Metrics;
use crate::queue::{DiskQueue, QueueLimits};
use crate::silence::SilenceStore;
use crate::sink::{build_sinks, http_client, Outcome, SinkRunner};

const DEFAULT_GRACE: Duration = Duration::from_secs(5);
const DEDUP_MAP_MAX: usize = 50_000;

/// Inputs besides `[alerts]` that the dispatcher needs.
#[derive(Default)]
pub struct DispatcherOptions {
    /// Tool name (`"vigil"`); used in metrics and as syslog APP-NAME.
    pub tool: String,
    /// Tool data directory; the queue lives in `<data_dir>/alert-queue` unless
    /// `[alerts.queue] dir` is set. Without either, the queue is memory-only.
    pub data_dir: Option<PathBuf>,
    pub silences: Option<Arc<SilenceStore>>,
    /// Reuse the tool's client; one is built otherwise.
    pub http: Option<reqwest::Client>,
}

/// Cheap, cloneable handle used by tool code to submit alerts.
#[derive(Clone)]
pub struct AlertHandle {
    tx: Option<mpsc::Sender<Alert>>,
    metrics: Arc<Metrics>,
}

impl AlertHandle {
    /// A handle that only logs (CLI one-shots, tests, alerts disabled).
    pub fn disabled(tool: &str) -> Self {
        AlertHandle {
            tx: None,
            metrics: Arc::new(Metrics::new(tool, Vec::new())),
        }
    }

    /// Never blocks. Returns `false` when the alert was dropped (channel full or
    /// dispatcher stopped); this is counted in `llcforge_beacon_dropped_total`.
    pub fn send(&self, alert: Alert) -> bool {
        let Some(tx) = &self.tx else {
            tracing::info!(alert_id = %alert.id, "alert (no sinks configured): {}", alert.headline());
            return true;
        };
        match tx.try_send(alert) {
            Ok(()) => true,
            Err(e) => {
                self.metrics.inc_received();
                self.metrics.inc_dropped();
                let a = match e {
                    mpsc::error::TrySendError::Full(a) | mpsc::error::TrySendError::Closed(a) => a,
                };
                tracing::error!(alert_id = %a.id, "alert channel full or closed; alert dropped");
                false
            }
        }
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }
}

/// Owner of the dispatcher task. Dropping it without [`Dispatcher::shutdown`]
/// stops intake once every [`AlertHandle`] is gone; undelivered alerts stay on disk.
pub struct Dispatcher {
    handle: AlertHandle,
    shutdown: Option<oneshot::Sender<Duration>>,
    join: Option<JoinHandle<()>>,
}

struct Ack {
    seq: u64,
    sink: usize,
    outcome: Outcome,
}

struct Target {
    sink: usize,
    in_flight: bool,
    retry_at: Option<Instant>,
}

struct Pending {
    alert: Arc<Alert>,
    targets: Vec<Target>,
    enqueued: Instant,
}

struct State {
    sinks: Vec<Arc<SinkRunner>>,
    workers: Vec<mpsc::Sender<(u64, Arc<Alert>)>>,
    worker_tasks: Vec<JoinHandle<()>>,
    sink_pending: Vec<u64>,
    queue: Option<DiskQueue>,
    pending: BTreeMap<u64, Pending>,
    mem_seq: u64,
    dedup: HashMap<String, (Instant, bool)>,
    dedup_window: Duration,
    redeliver_after: Duration,
    max_age: Duration,
    max_entries: usize,
    silences: Option<Arc<SilenceStore>>,
    metrics: Arc<Metrics>,
}

impl Dispatcher {
    /// Builds all sinks from `cfg` (secrets from env) and starts the dispatcher.
    /// Must be called inside a Tokio runtime.
    pub fn start(cfg: &AlertsConfig, opts: DispatcherOptions) -> Result<Self, ConfigError> {
        let client = match &opts.http {
            Some(c) => c.clone(),
            None => http_client()?,
        };
        let sinks = build_sinks(cfg, &opts.tool, &client)?;
        Self::start_with_sinks(cfg, opts, sinks)
    }

    /// Starts with pre-built sinks (custom [`crate::Sink`] implementations, tests).
    pub fn start_with_sinks(
        cfg: &AlertsConfig,
        opts: DispatcherOptions,
        sinks: Vec<SinkRunner>,
    ) -> Result<Self, ConfigError> {
        let sinks: Vec<Arc<SinkRunner>> = sinks.into_iter().map(Arc::new).collect();
        let metrics = Arc::new(Metrics::new(
            &opts.tool,
            sinks.iter().map(|s| s.metrics.clone()).collect(),
        ));
        let q = &cfg.queue;
        let queue_dir = q
            .dir
            .clone()
            .or_else(|| opts.data_dir.as_ref().map(|d| d.join("alert-queue")));
        let queue = match (q.persistent, queue_dir) {
            (true, Some(dir)) => {
                let limits = QueueLimits {
                    max_entries: q.max_entries.max(1),
                    max_bytes: q.max_bytes.max(64 * 1024),
                    segment_bytes: q.segment_bytes.max(4096),
                };
                let (dq, report) = DiskQueue::open(&dir, limits).map_err(|e| {
                    ConfigError::Invalid(format!("alert queue {}: {e}", dir.display()))
                })?;
                tracing::info!(dir = %dir.display(), pending = dq.len(), corrupt = report.corrupt_lines, truncated = report.truncated_bytes, "alert queue opened");
                Some(dq)
            }
            (true, None) => {
                tracing::warn!("no data dir for the alert queue; undelivered alerts will not survive a restart");
                None
            }
            (false, _) => None,
        };
        let channel_capacity = cfg.channel_capacity.clamp(1, 1 << 20);
        let (tx, rx) = mpsc::channel(channel_capacity);
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();
        let worker_cap = q.max_entries.clamp(16, 1 << 20);
        let mut workers = Vec::with_capacity(sinks.len());
        let mut worker_tasks = Vec::with_capacity(sinks.len());
        for (i, s) in sinks.iter().enumerate() {
            let (wtx, mut wrx) = mpsc::channel::<(u64, Arc<Alert>)>(worker_cap);
            let runner = s.clone();
            let ack_tx: mpsc::UnboundedSender<Ack> = ack_tx.clone();
            worker_tasks.push(tokio::spawn(async move {
                while let Some((seq, a)) = wrx.recv().await {
                    let outcome = runner.deliver(&a).await;
                    if ack_tx
                        .send(Ack {
                            seq,
                            sink: i,
                            outcome,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }));
            workers.push(wtx);
        }
        let mut state = State {
            sink_pending: vec![0; sinks.len()],
            sinks,
            workers,
            worker_tasks,
            queue,
            pending: BTreeMap::new(),
            mem_seq: 1 << 62,
            dedup: HashMap::new(),
            dedup_window: Duration::from_secs(cfg.dedup_window_secs),
            redeliver_after: Duration::from_secs(q.redeliver_after_secs.max(1)),
            max_age: Duration::from_secs(q.max_age_secs.max(1)),
            max_entries: q.max_entries.max(1),
            silences: opts.silences,
            metrics: metrics.clone(),
        };
        state.recover();
        let (sd_tx, sd_rx) = oneshot::channel();
        let join = tokio::spawn(run(state, rx, ack_rx, sd_rx));
        Ok(Dispatcher {
            handle: AlertHandle {
                tx: Some(tx),
                metrics,
            },
            shutdown: Some(sd_tx),
            join: Some(join),
        })
    }

    pub fn handle(&self) -> AlertHandle {
        self.handle.clone()
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.handle.metrics.clone()
    }

    /// Stops intake, persists anything still in the channel, waits up to
    /// `grace` for in-flight deliveries, then stops. Pending alerts stay on disk.
    pub async fn shutdown(mut self, grace: Duration) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(grace);
        }
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

async fn run(
    mut st: State,
    mut rx: mpsc::Receiver<Alert>,
    mut ack_rx: mpsc::UnboundedReceiver<Ack>,
    mut shutdown: oneshot::Receiver<Duration>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let grace = loop {
        tokio::select! {
            biased;
            g = &mut shutdown => break g.unwrap_or(DEFAULT_GRACE),
            Some(ack) = ack_rx.recv() => st.on_ack(ack),
            msg = rx.recv() => match msg {
                Some(a) => st.on_alert(a),
                None => break DEFAULT_GRACE,
            },
            _ = tick.tick() => st.on_tick(),
        }
    };
    rx.close();
    while let Ok(a) = rx.try_recv() {
        st.on_alert(a);
    }
    let deadline = tokio::time::Instant::now() + grace;
    while st.in_flight() > 0 {
        tokio::select! {
            Some(ack) = ack_rx.recv() => st.on_ack(ack),
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }
    for t in &st.worker_tasks {
        t.abort();
    }
    tracing::info!(pending = st.pending.len(), "alert dispatcher stopped");
}

impl State {
    fn in_flight(&self) -> usize {
        self.pending
            .values()
            .flat_map(|p| &p.targets)
            .filter(|t| t.in_flight)
            .count()
    }

    fn update_gauges(&self) {
        self.metrics.set_queue_depth(self.pending.len() as u64);
        for (s, n) in self.sinks.iter().zip(&self.sink_pending) {
            s.metrics.set_queued(*n);
        }
    }

    /// Re-creates pending deliveries from the on-disk queue after a restart.
    fn recover(&mut self) {
        let Some(q) = &self.queue else { return };
        let now = Instant::now();
        let mut unknown: Vec<(u64, String)> = Vec::new();
        let mut restored = Vec::new();
        for (seq, e) in q.entries() {
            let mut targets = Vec::new();
            for name in &e.targets {
                match self.sinks.iter().position(|s| &s.name == name) {
                    Some(i) => targets.push(Target {
                        sink: i,
                        in_flight: false,
                        retry_at: None,
                    }),
                    None => unknown.push((seq, name.clone())),
                }
            }
            if targets.is_empty() {
                continue;
            }
            let age = (Utc::now() - e.alert.last_seen)
                .to_std()
                .unwrap_or_default();
            restored.push((
                seq,
                Pending {
                    alert: Arc::new(e.alert.clone()),
                    targets,
                    enqueued: now.checked_sub(age).unwrap_or(now),
                },
            ));
        }
        if let Some(q) = &mut self.queue {
            for (seq, sink) in unknown {
                tracing::warn!(seq, sink = %sink, "dropping queued alert for a sink that no longer exists");
                if let Err(e) = q.ack(seq, &sink) {
                    tracing::error!(error = %e, "alert queue write failed");
                }
            }
        }
        if !restored.is_empty() {
            tracing::info!(
                count = restored.len(),
                "redelivering alerts queued before restart"
            );
        }
        for (seq, p) in restored {
            for t in &p.targets {
                self.sink_pending[t.sink] += 1;
            }
            self.pending.insert(seq, p);
            self.dispatch(seq);
        }
        self.update_gauges();
    }

    fn on_alert(&mut self, mut a: Alert) {
        self.metrics.inc_received();
        if let Err(e) = a.normalize() {
            self.metrics.inc_invalid();
            tracing::warn!(error = %e, "invalid alert dropped");
            return;
        }
        if let Some(store) = &self.silences {
            if let Some(id) = store.silenced_by(&a, Utc::now()) {
                self.metrics.inc_silenced();
                tracing::info!(alert_id = %a.id, silence_id = %id, "alert silenced");
                return;
            }
        }
        let now = Instant::now();
        if let Some((t, resolved)) = self.dedup.get(&a.id) {
            if *resolved == a.resolved && now.duration_since(*t) < self.dedup_window {
                self.metrics.inc_deduplicated();
                return;
            }
        }
        if self.dedup.len() >= DEDUP_MAP_MAX {
            let w = self.dedup_window;
            self.dedup.retain(|_, (t, _)| now.duration_since(*t) < w);
            if self.dedup.len() >= DEDUP_MAP_MAX {
                self.dedup.clear();
            }
        }
        self.dedup.insert(a.id.clone(), (now, a.resolved));

        let mut idx = Vec::new();
        for (i, s) in self.sinks.iter().enumerate() {
            if s.filter.matches(&a) {
                idx.push(i);
            } else {
                s.metrics.inc_suppressed();
            }
        }
        if idx.is_empty() {
            return;
        }
        let names: Vec<String> = idx.iter().map(|i| self.sinks[*i].name.clone()).collect();
        let seq = match self.queue.as_mut().map(|q| q.push(&a, &names)) {
            Some(Ok(seq)) => seq,
            other => {
                if let Some(Err(e)) = other {
                    tracing::error!(error = %e, "alert queue write failed; delivering from memory only");
                }
                self.mem_seq += 1;
                self.mem_seq
            }
        };
        for i in &idx {
            self.sink_pending[*i] += 1;
        }
        self.pending.insert(
            seq,
            Pending {
                alert: Arc::new(a),
                targets: idx
                    .into_iter()
                    .map(|sink| Target {
                        sink,
                        in_flight: false,
                        retry_at: None,
                    })
                    .collect(),
                enqueued: now,
            },
        );
        self.enforce_bounds();
        self.dispatch(seq);
        self.update_gauges();
    }

    fn enforce_bounds(&mut self) {
        loop {
            let over_count = self.pending.len() > self.max_entries;
            let over_disk = self.queue.as_ref().and_then(DiskQueue::over_limit);
            let victim = if over_count {
                self.pending.keys().next().copied()
            } else {
                over_disk
            };
            let Some(seq) = victim else { break };
            tracing::warn!(seq, "alert queue full; dropping oldest undelivered alert");
            self.metrics.inc_dropped();
            self.drop_entry(seq);
        }
    }

    fn drop_entry(&mut self, seq: u64) {
        if let Some(p) = self.pending.remove(&seq) {
            for t in p.targets {
                self.sink_pending[t.sink] = self.sink_pending[t.sink].saturating_sub(1);
            }
        }
        if let Some(q) = &mut self.queue {
            if let Err(e) = q.remove(seq) {
                tracing::error!(error = %e, "alert queue write failed");
            }
        }
    }

    fn dispatch(&mut self, seq: u64) {
        let now = Instant::now();
        let Some(p) = self.pending.get_mut(&seq) else {
            return;
        };
        for t in &mut p.targets {
            if t.in_flight || t.retry_at.is_some_and(|r| r > now) {
                continue;
            }
            match self.workers[t.sink].try_send((seq, p.alert.clone())) {
                Ok(()) => {
                    t.in_flight = true;
                    t.retry_at = None;
                }
                Err(_) => t.retry_at = Some(now + Duration::from_secs(1)),
            }
        }
    }

    fn finish_target(&mut self, seq: u64, sink: usize) {
        let Some(p) = self.pending.get_mut(&seq) else {
            return;
        };
        p.targets.retain(|t| t.sink != sink);
        self.sink_pending[sink] = self.sink_pending[sink].saturating_sub(1);
        if p.targets.is_empty() {
            self.pending.remove(&seq);
        }
        if let Some(q) = &mut self.queue {
            if let Err(e) = q.ack(seq, &self.sinks[sink].name) {
                tracing::error!(error = %e, "alert queue write failed");
            }
        }
    }

    fn on_ack(&mut self, ack: Ack) {
        match ack.outcome {
            Outcome::Delivered | Outcome::Rejected => self.finish_target(ack.seq, ack.sink),
            Outcome::Failed => {
                let retry = Instant::now() + self.redeliver_after;
                if let Some(t) = self
                    .pending
                    .get_mut(&ack.seq)
                    .and_then(|p| p.targets.iter_mut().find(|t| t.sink == ack.sink))
                {
                    t.in_flight = false;
                    t.retry_at = Some(retry);
                }
            }
        }
        self.update_gauges();
    }

    fn on_tick(&mut self) {
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut due = Vec::new();
        for (seq, p) in &self.pending {
            let old = now.duration_since(p.enqueued) > self.max_age;
            for t in &p.targets {
                if t.in_flight {
                    continue;
                }
                if old {
                    expired.push((*seq, t.sink));
                } else if t.retry_at.is_some_and(|r| r <= now) {
                    due.push(*seq);
                }
            }
        }
        for (seq, sink) in expired {
            tracing::warn!(seq, sink = %self.sinks[sink].name, "alert expired before delivery");
            self.metrics.inc_dropped();
            self.finish_target(seq, sink);
        }
        due.dedup();
        for seq in due {
            self.dispatch(seq);
        }
        self.update_gauges();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::alert::Severity;
    use crate::filter::Filter;
    use crate::silence::NewSilence;
    use crate::sink::{SendFuture, Sink, SinkError};

    /// Records alerts; fails while `fail` is set.
    #[derive(Clone, Default)]
    struct Probe {
        got: Arc<Mutex<Vec<Alert>>>,
        fail: Arc<std::sync::atomic::AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl Sink for Probe {
        fn kind(&self) -> &'static str {
            "probe"
        }
        fn send<'a>(&'a self, a: &'a Alert) -> SendFuture<'a> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.fail.load(Ordering::SeqCst) {
                    return Err(SinkError::transient("down"));
                }
                self.got.lock().unwrap().push(a.clone());
                Ok(())
            })
        }
    }

    fn runner(name: &str, p: &Probe, filter: Filter) -> SinkRunner {
        SinkRunner::new(name, filter, Box::new(p.clone())).with_policy(
            Duration::from_secs(2),
            0,
            Duration::from_millis(1),
            Duration::from_millis(1),
            0,
            None,
        )
    }

    fn cfg() -> AlertsConfig {
        let mut c = AlertsConfig::default();
        c.queue.redeliver_after_secs = 1;
        c
    }

    fn alert(res: &str) -> Alert {
        Alert::new("vigil", "hijack", Severity::Critical, "Hijack").resource(res)
    }

    async fn wait_for(cond: impl Fn() -> bool) {
        for _ in 0..500 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test]
    async fn routes_dedups_and_filters() {
        let a = Probe::default();
        let b = Probe::default();
        let only_v6 = Filter {
            resources: vec!["2001:db8:*".into()],
            ..Default::default()
        };
        let d = Dispatcher::start_with_sinks(
            &cfg(),
            DispatcherOptions {
                tool: "vigil".into(),
                ..Default::default()
            },
            vec![runner("a", &a, Filter::default()), runner("b", &b, only_v6)],
        )
        .unwrap();
        let h = d.handle();
        assert!(h.send(alert("192.0.2.0/24")));
        assert!(h.send(alert("192.0.2.0/24"))); // duplicate
        assert!(h.send(alert("192.0.2.0/24").resolved(true))); // state change passes
        assert!(h.send(alert("2001:db8::/32")));
        wait_for(|| a.got.lock().unwrap().len() == 3 && b.got.lock().unwrap().len() == 1).await;
        let m = d.metrics();
        let s = m.snapshot();
        assert_eq!((s.received, s.deduplicated), (4, 1));
        assert_eq!(m.sinks[1].snapshot().suppressed, 2);
        let mut out = String::new();
        m.render_prometheus(&mut out);
        assert!(out.contains(
            "llcforge_beacon_sink_sent_total{tool=\"vigil\",sink=\"a\",type=\"probe\"} 3"
        ));
        d.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn silences_are_applied_and_counted() {
        let a = Probe::default();
        let store = Arc::new(SilenceStore::in_memory());
        store
            .add(NewSilence {
                resource: Some("192.0.2.*".into()),
                duration: Some("1h".into()),
                comment: "maintenance".into(),
                ..Default::default()
            })
            .unwrap();
        let d = Dispatcher::start_with_sinks(
            &cfg(),
            DispatcherOptions {
                tool: "vigil".into(),
                silences: Some(store),
                ..Default::default()
            },
            vec![runner("a", &a, Filter::default())],
        )
        .unwrap();
        d.handle().send(alert("192.0.2.0/24"));
        d.handle().send(alert("198.51.100.0/24"));
        wait_for(|| a.got.lock().unwrap().len() == 1).await;
        assert_eq!(d.metrics().snapshot().silenced, 1);
        assert_eq!(
            a.got.lock().unwrap()[0].resource.as_deref(),
            Some("198.51.100.0/24")
        );
        d.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn redelivers_after_failure_without_restart() {
        let a = Probe::default();
        a.fail.store(true, Ordering::SeqCst);
        let d = Dispatcher::start_with_sinks(
            &cfg(),
            DispatcherOptions {
                tool: "t".into(),
                ..Default::default()
            },
            vec![runner("a", &a, Filter::default())],
        )
        .unwrap();
        d.handle().send(alert("192.0.2.0/24"));
        wait_for(|| a.calls.load(Ordering::SeqCst) >= 1).await;
        assert_eq!(d.metrics().snapshot().queue_depth, 1);
        a.fail.store(false, Ordering::SeqCst);
        wait_for(|| a.got.lock().unwrap().len() == 1).await;
        wait_for(|| d.metrics().snapshot().queue_depth == 0).await;
        d.shutdown(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn undelivered_alerts_survive_restart() {
        let dir = std::env::temp_dir().join(format!("llcf-disp-{}", fastrand::u64(..)));
        let opts = || DispatcherOptions {
            tool: "t".into(),
            data_dir: Some(dir.clone()),
            ..Default::default()
        };
        let down = Probe::default();
        down.fail.store(true, Ordering::SeqCst);
        let d = Dispatcher::start_with_sinks(
            &cfg(),
            opts(),
            vec![runner("a", &down, Filter::default())],
        )
        .unwrap();
        d.handle().send(alert("192.0.2.0/24"));
        d.handle().send(alert("198.51.100.0/24"));
        wait_for(|| down.calls.load(Ordering::SeqCst) >= 2).await;
        d.shutdown(Duration::from_millis(200)).await;

        // "Restart" with a working sink: both alerts are redelivered.
        let up = Probe::default();
        let d =
            Dispatcher::start_with_sinks(&cfg(), opts(), vec![runner("a", &up, Filter::default())])
                .unwrap();
        wait_for(|| up.got.lock().unwrap().len() == 2).await;
        wait_for(|| d.metrics().snapshot().queue_depth == 0).await;
        d.shutdown(Duration::from_millis(200)).await;

        // Third start: nothing left to deliver.
        let again = Probe::default();
        let d = Dispatcher::start_with_sinks(
            &cfg(),
            opts(),
            vec![runner("a", &again, Filter::default())],
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(again.got.lock().unwrap().is_empty());
        d.shutdown(Duration::from_millis(100)).await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn invalid_and_overflow_are_counted_not_panicking() {
        let a = Probe::default();
        let mut c = cfg();
        c.channel_capacity = 1;
        let d = Dispatcher::start_with_sinks(
            &c,
            DispatcherOptions {
                tool: "t".into(),
                ..Default::default()
            },
            vec![runner("a", &a, Filter::default())],
        )
        .unwrap();
        let h = d.handle();
        assert!(h.send(Alert::new("t", "k", Severity::Info, "")));
        wait_for(|| d.metrics().snapshot().invalid == 1).await;
        let mut accepted = 0;
        for i in 0..50 {
            if h.send(alert(&format!("192.0.2.{i}"))) {
                accepted += 1;
            }
        }
        let s = d.metrics().snapshot();
        assert_eq!(s.dropped as usize, 50 - accepted);
        d.shutdown(Duration::from_secs(1)).await;
        assert!(AlertHandle::disabled("t").send(alert("x")));
    }
}
