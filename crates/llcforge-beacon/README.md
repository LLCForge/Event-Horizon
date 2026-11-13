# llcforge-beacon

Shared alerting and operations plumbing for the LLCForge network tools
(Pathology, Event-Horizon, Catchment, Notary, Herald, Vigil): one alert schema,
ten delivery sinks, a crash-safe persistent queue, silences / maintenance
windows, health endpoints, uniform logging, configuration reload and service
integration on Windows, macOS and Linux.

[Türkçe](README.tr.md)

## Contents

| Module | What it gives a tool |
|---|---|
| `alert` | `Alert` — the versioned `llcforge.alert.v1` schema ([JSON Schema](schema/alert.v1.json)) |
| `dispatcher` | `Dispatcher` / `AlertHandle` — non-blocking intake, dedup, silences, per-sink routing, metrics |
| `sink` | stdout, webhook (HMAC-signed), Telegram, Slack, Discord, Microsoft Teams, e-mail (SMTP), PagerDuty, Opsgenie, syslog |
| `queue` | append-only on-disk queue: fsync per record, torn-tail recovery, compaction, bounds |
| `silence` | `SilenceStore`, `/v1/silences` API, `<tool> silence add/list/remove` |
| `health` | `/healthz`, `/readyz` driven by named `Readiness` checks |
| `reload` | `ReloadSignal`: SIGHUP (Unix), config file change (all OSes), `POST /v1/reload` |
| `logging` | `init_logging(text/json, level, filter)` |
| `service` | Windows service run/install/uninstall; systemd/launchd hints on Unix |
| `metrics` | Prometheus counters (`llcforge_beacon_*`) |

## Use in a tool

Each tool vendors the crate with `sync.py` and depends on it by path:

```toml
[dependencies]
llcforge-beacon = { path = "crates/llcforge-beacon" }
```

```rust
use llcforge_beacon::{Alert, Dispatcher, DispatcherOptions, Severity};

let dispatcher = Dispatcher::start(&cfg.alerts, DispatcherOptions {
    tool: "vigil".into(),
    data_dir: Some(data_dir.clone()),
    silences: Some(silences.clone()),
    http: None,
})?;
let alerts = dispatcher.handle(); // Clone + Send; send() never blocks

alerts.send(
    Alert::new("vigil", "origin_hijack", Severity::Critical, "Unexpected origin AS64512")
        .resource("192.0.2.0/24")          // id becomes "vigil:origin_hijack:192.0.2.0/24"
        .summary("Seen by 12 RIS peers")
        .field("expected", "AS64500")
        .field("observed", "AS64512")
        .link("RIPEstat", "https://stat.ripe.net/192.0.2.0/24"),
);
// Later, when the condition clears (same id):
alerts.send(Alert::new("vigil", "origin_hijack", Severity::Critical, "Origin restored")
    .resource("192.0.2.0/24").resolved(true));

dispatcher.shutdown(std::time::Duration::from_secs(5)).await;
```

A complete wiring (CLI subcommands, admin router, reload loop, service mode)
is in [`examples/integration.rs`](examples/integration.rs).

## Configuration

```toml
[alerts]
dedup_window_secs = 300          # same id + same resolved state suppressed inside the window
channel_capacity = 1024          # in-process intake; send() returns false when full

[alerts.queue]
persistent = true                # <data_dir>/alert-queue unless dir is set
max_entries = 10000
max_bytes = 67108864
segment_bytes = 4194304
redeliver_after_secs = 60        # after a sink exhausted its retries
max_age_secs = 86400             # give up afterwards (counted as dropped)

# Options every sink accepts:
#   name, min_severity, tools, kinds, resources (globs), timeout_secs,
#   max_retries, backoff_base_ms, backoff_max_ms, rate_per_minute, burst

[[alerts.sink]]
type = "stdout"
format = "json"                  # or "text"

[[alerts.sink]]
type = "webhook"
url = "https://hooks.example.net/llcforge"
bearer_token_env = "WEBHOOK_TOKEN"
hmac_secret_env = "WEBHOOK_HMAC_SECRET"

[[alerts.sink]]
type = "telegram"
name = "noc-v4"
bot_token_env = "TELEGRAM_BOT_TOKEN"
chat_id = -1001234567890
min_severity = "warning"
resources = ["192.0.2.*", "198.51.100.*"]   # this chat only gets these prefixes

[[alerts.sink]]
type = "slack"                   # also "discord", "teams"
url_env = "SLACK_WEBHOOK_URL"

[[alerts.sink]]
type = "email"
host = "smtp.example.net"
port = 587
tls = "starttls"                 # "tls" (465); "none" only for a loopback relay
username_env = "SMTP_USER"
password_env = "SMTP_PASSWORD"
from = "LLCForge <alerts@example.net>"
to = ["noc@example.org"]

[[alerts.sink]]
type = "pagerduty"
routing_key_env = "PD_ROUTING_KEY"
min_severity = "critical"

[[alerts.sink]]
type = "opsgenie"
api_key_env = "OPSGENIE_API_KEY"
# api_base = "https://api.eu.opsgenie.com"

[[alerts.sink]]
type = "syslog"
transport = "tls"                # udp | tcp | tls | unix (Unix only: /dev/log)
address = "logs.example.net:6514"
facility = "local3"

[silences]
# path = "/var/lib/vigil/silences.json"     # default <data_dir>/silences.json
api_token_env = "VIGIL_ADMIN_TOKEN"          # mounts /v1/silences

[health]
listen = "127.0.0.1:9184"
admin_token_env = "VIGIL_ADMIN_TOKEN"        # mounts POST /v1/reload
```

Secrets are never read from configuration files: every secret is the *name* of
an environment variable (`*_env`). A missing variable fails startup.

## Sinks

| Type | Request | Retry hints |
|---|---|---|
| `webhook` | `POST` alert JSON; `Authorization: Bearer`; `X-LLCForge-Timestamp`, `X-LLCForge-Signature: sha256=<hex>`, `X-LLCForge-Alert-Id` | `Retry-After` |
| `telegram` | `sendMessage`, `parse_mode=HTML`, everything escaped, ≤ 4096 chars | `parameters.retry_after` |
| `slack` | Block Kit, mrkdwn escaped | `Retry-After` |
| `discord` | one embed, `allowed_mentions.parse = []` | JSON `retry_after` |
| `teams` | Adaptive Card 1.4 message (Workflows and legacy webhooks) | `Retry-After` |
| `email` | plain text via lettre + rustls (STARTTLS / TLS) | SMTP transient vs permanent |
| `pagerduty` | Events API v2 `trigger` / `resolve`, `dedup_key = id` | `Retry-After` |
| `opsgenie` | create (`alias = id`) / close by alias | `Retry-After` |
| `syslog` | RFC 5424, SD-ID `llcforge@32473`; UDP (RFC 5426), TCP octet counting (RFC 6587), TLS (RFC 5425) | — |
| `stdout` | one line per alert (text or JSON) | — |

Every sink gets a timeout, retries with exponential backoff and jitter, a token
bucket rate limit and a filter. 4xx responses (except 408/429) are permanent and
not retried. HTTP clients never follow redirects.

### Verifying webhook signatures

The signature is `HMAC-SHA256(secret, "<timestamp>.<raw body>")`, hex encoded.
Reject requests whose timestamp is more than five minutes away from your clock.
In Rust: `llcforge_beacon::sink::webhook::verify_signature(secret, ts, body, header, now, 300)`.
In Python:

```python
import hashlib, hmac, time
def verify(secret: bytes, ts: str, body: bytes, header: str) -> bool:
    if abs(time.time() - int(ts)) > 300:
        return False
    mac = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + mac, header)
```

## Delivery guarantees

* `AlertHandle::send` never blocks; a full channel drops the alert and counts it.
* Accepted alerts are written to the on-disk queue (one fsynced JSON line) before
  delivery. Each sink has its own worker, so a dead endpoint never delays others.
* A sink that exhausts its retries gets the alert again every
  `redeliver_after_secs` until `max_age_secs`.
* After a crash or restart, undelivered alerts are redelivered. A torn final
  line is truncated, corrupt lines are skipped, interrupted compactions are
  discarded. Delivery is at-least-once: receivers should deduplicate by `id`.

## Silences

Silences match on `resource`, `kind` and `tool` globs (`*`, `?`, case-insensitive)
for a time window and are stored as JSON with an atomic write (temp file,
fsync, rename). Silenced alerts are counted, not sent.

```text
GET    /v1/silences                 list
POST   /v1/silences                 {"resource":"192.0.2.*","duration":"2h","comment":"fiber work","created_by":"noc"}
DELETE /v1/silences/{id}
```

All routes require `Authorization: Bearer <token>`; bodies are limited to 16 KiB
and strictly validated. CLI (edits the same file; the daemon notices within 2 s):

```text
vigil silence add --resource '192.0.2.*' --duration 2h -m "fiber work"
vigil silence list [--json]
vigil silence remove <id>
```

## Health, reload, service

* `GET /healthz` → `200 {"status":"ok"}`; `GET /readyz` → `200` or `503` with
  `{"ready":false,"failing":["bgp_session"],"checks":{...}}`.
* `ReloadSignal::standard(Some(config_path))` fires on SIGHUP (Unix) and when the
  config file changes (polled every 5 s); `reload_router` adds `POST /v1/reload`.
* `run_service_command` implements `<tool> service install|uninstall|run`:
  Windows Service Control Manager (account `NT AUTHORITY\LocalService`, restart
  on failure); on Linux/macOS it prints the shipped systemd/launchd steps.

## Metrics

`Metrics::render_prometheus(&mut String)` appends:
`llcforge_beacon_{received,deduplicated,silenced,dropped,invalid}_total{tool}`,
`llcforge_beacon_queue_depth{tool}`,
`llcforge_beacon_sink_{sent,failed,suppressed,retries,rate_limited}_total{tool,sink,type}`,
`llcforge_beacon_sink_queued{tool,sink,type}`.

## Packaging templates and sync

`templates/` holds CI, release (multi-OS binaries, cosign-signed SHA256SUMS,
.deb/.rpm, multi-arch image), Docker, systemd, launchd, Windows, Homebrew,
Scoop, winget, Helm, Grafana and Prometheus templates. `sync.py` vendors the
crate and renders them into a tool repository:

```text
python sync.py ../Vigil --bin vigil --name "Vigil" --repo Vigil \
  --description "Real-time BGP origin hijack detection" --port-metrics 9184
```

It never writes the tool's top-level `README*`, `ARCHITECTURE.md` or `src/`,
skips existing files named with `--keep`, and is idempotent.

## Security notes

* Secrets only from environment variables; sink types holding secrets do not
  implement `Debug`, and HTTP errors are logged without URLs.
* API tokens are compared in constant time over SHA-256 digests.
* Alert text is untrusted: HTML/mrkdwn/syslog escaping per sink, mentions
  disabled on Discord, CR/LF stripped from e-mail subjects.
* Plain `http://` targets are refused for non-loopback hosts unless
  `allow_http = true` is set on a webhook.

## Platforms and MSRV

Windows, macOS and Linux (CI on all three). Rust 1.85+ (required by lettre).
Cargo features: `cli` (clap subcommands), `smtp` (e-mail sink), `service`
(Windows service), all enabled by default.

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
