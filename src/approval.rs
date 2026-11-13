//! Manual approval through Telegram inline buttons (41).
//!
//! Every pending request is posted to one chat with Approve / Deny buttons.
//! Button presses are read with `getUpdates` long polling (no inbound
//! webhook, nothing to expose). A press is honoured only when it comes from
//! the configured chat and from a user id in `allowed_user_ids`; approving
//! re-runs the policy engine. Requests that nobody answers are denied when
//! `approval.timeout` expires (handled by the engine). Messages are sent as
//! plain text, so request reasons cannot inject markup.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::config::{fmt_duration, TelegramApprovalConfig};
use crate::engine::{ApproveError, Engine, Pending, Submitted};
use crate::unix_now;

const POLL_SECS: u64 = 25;
const MAX_TEXT: usize = 3500;

#[derive(Debug, Deserialize)]
struct TgResp<T> {
    ok: bool,
    #[serde(default = "Option::default")]
    result: Option<T>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Update {
    update_id: i64,
    #[serde(default)]
    callback_query: Option<Callback>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Callback {
    pub id: String,
    pub from: User,
    #[serde(default)]
    pub message: Option<Msg>,
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Msg {
    pub message_id: i64,
    pub chat: Chat,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Chat {
    pub id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
}

/// Validates a button press: right chat, allowed user, well-formed data.
pub fn decide(
    cb: &Callback,
    chat_id: i64,
    allowed: &[i64],
) -> Result<(Decision, String), &'static str> {
    if cb.message.as_ref().map(|m| m.chat.id) != Some(chat_id) {
        return Err("wrong chat");
    }
    if !allowed.contains(&cb.from.id) {
        return Err("not authorized");
    }
    let data = cb.data.as_deref().ok_or("no data")?;
    let (kind, id) = data.split_once(':').ok_or("bad data")?;
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("bad id");
    }
    let d = match kind {
        "a" => Decision::Approve,
        "d" => Decision::Deny,
        _ => return Err("bad action"),
    };
    Ok((d, id.to_owned()))
}

pub fn message_text(p: &Pending, timeout: u64) -> String {
    let target = serde_json::to_value(&p.target)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .map(|m| {
            m.iter()
                .map(|(k, v)| format!("{k}: {}", v.to_string().trim_matches('"')))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let mut t = format!(
        "Event Horizon: approval needed\n{target}\nreason: {}\nsource: {}\nexpires in {} (no answer = deny)\nid: {}",
        p.reason,
        p.source.as_str(),
        fmt_duration(timeout),
        p.id
    );
    t.truncate(MAX_TEXT.min(t.len()));
    t
}

pub struct Bot {
    client: reqwest::Client,
    base: String,
    cfg: TelegramApprovalConfig,
}

impl Bot {
    pub fn new(cfg: TelegramApprovalConfig, token: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(POLL_SECS + 10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            base: format!("{}/bot{token}", cfg.api_base.trim_end_matches('/')),
            cfg,
        })
    }

    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        body: serde_json::Value,
    ) -> Result<T, String> {
        // The URL contains the bot token: never log reqwest errors with their URL.
        let resp = self
            .client
            .post(format!("{}/{method}", self.base))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let r: TgResp<T> = resp.json().await.map_err(|e| e.without_url().to_string())?;
        match (r.ok, r.result) {
            (true, Some(v)) => Ok(v),
            _ => Err(r.description.unwrap_or_else(|| "telegram error".into())),
        }
    }

    async fn post(&self, p: &Pending, timeout: u64) -> Result<i64, String> {
        #[derive(Deserialize)]
        struct Sent {
            message_id: i64,
        }
        let s: Sent = self
            .call(
                "sendMessage",
                json!({
                    "chat_id": self.cfg.chat_id,
                    "text": message_text(p, timeout),
                    "reply_markup": {"inline_keyboard": [[
                        {"text": "Approve", "callback_data": format!("a:{}", p.id)},
                        {"text": "Deny", "callback_data": format!("d:{}", p.id)}
                    ]]}
                }),
            )
            .await?;
        Ok(s.message_id)
    }

    async fn answer(&self, cb: &Callback, text: &str) {
        let _ = self
            .call::<serde_json::Value>(
                "answerCallbackQuery",
                json!({"callback_query_id": cb.id, "text": text}),
            )
            .await;
    }

    async fn close_message(&self, message_id: i64, text: &str) {
        let _ = self
            .call::<serde_json::Value>(
                "editMessageText",
                json!({"chat_id": self.cfg.chat_id, "message_id": message_id, "text": text}),
            )
            .await;
    }

    async fn handle(&self, cb: Callback, engine: &Mutex<Engine>, msgs: &mut HashMap<String, i64>) {
        let (decision, id) = match decide(&cb, self.cfg.chat_id, &self.cfg.allowed_user_ids) {
            Ok(v) => v,
            Err(why) => {
                warn!(user = cb.from.id, why, "ignored Telegram approval button");
                self.answer(&cb, "Not allowed").await;
                return;
            }
        };
        let actor = format!("telegram:{}", cb.from.id);
        let now = unix_now();
        let outcome = match engine.lock() {
            Ok(mut e) => match decision {
                Decision::Approve => match e.approve(&id, &actor, now) {
                    Ok(Submitted::Pending(_)) | Ok(_) => "approved and announced".to_owned(),
                    Err(ApproveError::NotFound) => "no longer pending".to_owned(),
                    Err(ApproveError::Denied(d)) => format!("approved, but denied by policy: {d}"),
                },
                Decision::Deny => match e.reject(&id, &actor, now) {
                    Some(_) => "denied".to_owned(),
                    None => "no longer pending".to_owned(),
                },
            },
            Err(_) => "internal error".to_owned(),
        };
        info!(%id, %actor, %outcome, "Telegram approval");
        self.answer(&cb, &outcome).await;
        let message_id = msgs
            .remove(&id)
            .or(cb.message.as_ref().map(|m| m.message_id));
        if let Some(m) = message_id {
            self.close_message(
                m,
                &format!("Event Horizon request {id}: {outcome} ({actor})"),
            )
            .await;
        }
    }
}

/// Posts pending requests and processes button presses until shutdown.
pub async fn run(
    bot: Bot,
    timeout: u64,
    engine: Arc<Mutex<Engine>>,
    mut notes: mpsc::Receiver<Pending>,
    mut shutdown: watch::Receiver<bool>,
) {
    let bot = Arc::new(bot);
    let mut msgs: HashMap<String, i64> = HashMap::new();
    let mut offset: i64 = 0;
    info!(chat = bot.cfg.chat_id, "Telegram approval bot started");
    loop {
        let poll = bot.call::<Vec<Update>>(
            "getUpdates",
            json!({"offset": offset, "timeout": POLL_SECS, "allowed_updates": ["callback_query"]}),
        );
        tokio::select! {
            Some(p) = notes.recv() => {
                match bot.post(&p, timeout).await {
                    Ok(m) => {
                        if msgs.len() > 1024 {
                            msgs.clear();
                        }
                        msgs.insert(p.id.clone(), m);
                    }
                    Err(e) => warn!(id = %p.id, error = %e, "cannot post approval request to Telegram"),
                }
            }
            r = poll => match r {
                Ok(updates) => {
                    for u in updates {
                        offset = offset.max(u.update_id + 1);
                        if let Some(cb) = u.callback_query {
                            bot.handle(cb, &engine, &mut msgs).await;
                        }
                    }
                }
                Err(e) => {
                    debug!(error = %e, "Telegram getUpdates failed; retrying");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = shutdown.changed() => return,
                    }
                }
            },
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApprovalMode;
    use crate::engine::Target;
    use crate::state::Source;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn cb(chat: i64, user: i64, data: &str) -> Callback {
        Callback {
            id: "1".into(),
            from: User { id: user },
            message: Some(Msg {
                message_id: 9,
                chat: Chat { id: chat },
            }),
            data: Some(data.into()),
        }
    }

    #[test]
    fn button_presses_are_validated() {
        let ok = decide(&cb(-100, 7, &format!("a:{ID}")), -100, &[7]).unwrap();
        assert_eq!(ok, (Decision::Approve, ID.to_owned()));
        assert_eq!(
            decide(&cb(-100, 7, &format!("d:{ID}")), -100, &[7])
                .unwrap()
                .0,
            Decision::Deny
        );
        assert_eq!(
            decide(&cb(-101, 7, &format!("a:{ID}")), -100, &[7]),
            Err("wrong chat")
        );
        assert_eq!(
            decide(&cb(-100, 8, &format!("a:{ID}")), -100, &[7]),
            Err("not authorized")
        );
        assert_eq!(decide(&cb(-100, 7, "a:short"), -100, &[7]), Err("bad id"));
        assert_eq!(
            decide(&cb(-100, 7, &format!("x:{ID}")), -100, &[7]),
            Err("bad action")
        );
        assert_eq!(decide(&cb(-100, 7, "nodata"), -100, &[7]), Err("bad data"));
        let mut no_msg = cb(-100, 7, &format!("a:{ID}"));
        no_msg.message = None;
        assert_eq!(decide(&no_msg, -100, &[7]), Err("wrong chat"));
    }

    #[test]
    fn message_is_plain_text_with_target() {
        let p = Pending {
            id: ID.into(),
            target: Target::blackhole("198.51.100.7".parse().unwrap()),
            ttl: None,
            reason: "<b>udp</b> flood".into(),
            source: Source::Detector,
            created_at: 0,
            expires_at: 300,
        };
        let t = message_text(&p, 300);
        assert!(t.contains("kind: blackhole"));
        assert!(t.contains("ip: 198.51.100.7"));
        assert!(t.contains("expires in 5m"));
        assert!(
            t.contains("<b>udp</b>"),
            "sent without parse_mode, shown literally"
        );
    }

    /// Fake Bot API: one approval press from an allowed user, then nothing.
    #[tokio::test]
    async fn approves_through_fake_bot_api() {
        let (e, rx, _) = crate::engine::tests::engine();
        let engine = Arc::new(Mutex::new(e));
        engine
            .lock()
            .unwrap()
            .set_approval(ApprovalMode::Detector, 60);
        let (tx, notes) = mpsc::channel(4);
        engine.lock().unwrap().set_notifier(tx);
        let pending_id = Arc::new(Mutex::new(String::new()));
        let polls = Arc::new(AtomicUsize::new(0));
        let edits = Arc::new(AtomicUsize::new(0));
        let (pid, pid2, pl, ed) = (
            pending_id.clone(),
            pending_id.clone(),
            polls.clone(),
            edits.clone(),
        );
        let app = Router::new()
            .route(
                "/bottest-token/sendMessage",
                post(move |Json(v): Json<serde_json::Value>| {
                    let pid = pid.clone();
                    async move {
                        let data = v["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
                            .as_str()
                            .unwrap()
                            .to_owned();
                        *pid.lock().unwrap() = data[2..].to_owned();
                        Json(json!({"ok": true, "result": {"message_id": 41}}))
                    }
                }),
            )
            .route(
                "/bottest-token/getUpdates",
                post(move || {
                    let (pid, pl) = (pid2.clone(), pl.clone());
                    async move {
                        let id = pid.lock().unwrap().clone();
                        if id.is_empty() || pl.fetch_add(1, Ordering::SeqCst) > 0 {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            return Json(json!({"ok": true, "result": []}));
                        }
                        Json(json!({"ok": true, "result": [
                            {"update_id": 5, "callback_query": {"id": "c1", "from": {"id": 99},
                              "message": {"message_id": 41, "chat": {"id": -100}}, "data": format!("a:{id}")}},
                            {"update_id": 6, "callback_query": {"id": "c2", "from": {"id": 7},
                              "message": {"message_id": 41, "chat": {"id": -100}}, "data": format!("a:{id}")}}
                        ]}))
                    }
                }),
            )
            .route(
                "/bottest-token/answerCallbackQuery",
                post(|| async { Json(json!({"ok": true, "result": true})) }),
            )
            .route(
                "/bottest-token/editMessageText",
                post(move || {
                    let ed = ed.clone();
                    async move {
                        ed.fetch_add(1, Ordering::SeqCst);
                        Json(json!({"ok": true, "result": true}))
                    }
                }),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

        let cfg = TelegramApprovalConfig {
            bot_token_env: "UNUSED".into(),
            chat_id: -100,
            allowed_user_ids: vec![7],
            api_base: base,
        };
        let (sd_tx, sd_rx) = watch::channel(false);
        let task = tokio::spawn(run(
            Bot::new(cfg, "test-token").unwrap(),
            60,
            engine.clone(),
            notes,
            sd_rx,
        ));
        let sub = engine.lock().unwrap().submit(
            Target::blackhole("198.51.100.7".parse().unwrap()),
            None,
            "x",
            Source::Detector,
            unix_now(),
        );
        assert!(matches!(sub, Ok(Submitted::Pending(_))));
        for _ in 0..200 {
            if rx.borrow().contains(&"198.51.100.7".parse().unwrap()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(rx.borrow().contains(&"198.51.100.7".parse().unwrap()));
        assert!(edits.load(Ordering::SeqCst) >= 1);
        sd_tx.send(true).unwrap();
        task.await.unwrap();
    }
}
