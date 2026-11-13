# llcforge-beacon

LLCForge ağ araçları (Pathology, Event-Horizon, Catchment, Notary, Herald,
Vigil) için ortak uyarı ve işletim altyapısı: tek bir uyarı şeması, on teslim
kanalı (sink), çökmeye dayanıklı kalıcı kuyruk, susturma / bakım pencereleri,
sağlık uç noktaları, tek tip loglama, yapılandırmanın yeniden yüklenmesi ve
Windows, macOS ile Linux üzerinde servis entegrasyonu.

[English](README.md)

## İçerik

| Modül | Araca kazandırdığı |
|---|---|
| `alert` | `Alert` — sürümlü `llcforge.alert.v1` şeması ([JSON Schema](schema/alert.v1.json)) |
| `dispatcher` | `Dispatcher` / `AlertHandle` — bloklamayan kabul, tekilleştirme, susturma, sink bazlı yönlendirme, metrikler |
| `sink` | stdout, webhook (HMAC imzalı), Telegram, Slack, Discord, Microsoft Teams, e-posta (SMTP), PagerDuty, Opsgenie, syslog |
| `queue` | yalnızca eklemeli disk kuyruğu: her kayıtta fsync, yarım kalan son satırın onarımı, sıkıştırma, sınırlar |
| `silence` | `SilenceStore`, `/v1/silences` API'si, `<araç> silence add/list/remove` |
| `health` | adlandırılmış `Readiness` kontrolleriyle `/healthz` ve `/readyz` |
| `reload` | `ReloadSignal`: SIGHUP (Unix), yapılandırma dosyası değişikliği (tüm işletim sistemleri), `POST /v1/reload` |
| `logging` | `init_logging(text/json, seviye, filtre)` |
| `service` | Windows servisi çalıştırma/kurma/kaldırma; Unix'te systemd/launchd yönergeleri |
| `metrics` | Prometheus sayaçları (`llcforge_beacon_*`) |

## Bir araçta kullanım

Her araç crate'i `sync.py` ile kendi deposuna kopyalar ve yol bağımlılığı olarak kullanır:

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
let alerts = dispatcher.handle(); // Clone + Send; send() hiçbir zaman bloklamaz

alerts.send(
    Alert::new("vigil", "origin_hijack", Severity::Critical, "Beklenmeyen origin AS64512")
        .resource("192.0.2.0/24")          // id: "vigil:origin_hijack:192.0.2.0/24"
        .summary("12 RIS eşi tarafından görüldü")
        .field("beklenen", "AS64500")
        .field("görülen", "AS64512"),
);
// Durum düzeldiğinde (aynı id ile):
alerts.send(Alert::new("vigil", "origin_hijack", Severity::Critical, "Origin düzeldi")
    .resource("192.0.2.0/24").resolved(true));

dispatcher.shutdown(std::time::Duration::from_secs(5)).await;
```

Eksiksiz bir bağlama örneği (CLI alt komutları, yönetim router'ı, yeniden
yükleme döngüsü, servis modu) [`examples/integration.rs`](examples/integration.rs) içindedir.

## Yapılandırma

```toml
[alerts]
dedup_window_secs = 300          # aynı id + aynı resolved durumu bu süre içinde bastırılır
channel_capacity = 1024          # süreç içi kabul kanalı; doluysa send() false döner

[alerts.queue]
persistent = true                # dir verilmezse <data_dir>/alert-queue
max_entries = 10000
max_bytes = 67108864
segment_bytes = 4194304
redeliver_after_secs = 60        # bir sink yeniden denemelerini tükettikten sonra
max_age_secs = 86400             # bu süreden sonra vazgeçilir (dropped olarak sayılır)

# Her sink'in kabul ettiği ortak seçenekler:
#   name, min_severity, tools, kinds, resources (glob), timeout_secs,
#   max_retries, backoff_base_ms, backoff_max_ms, rate_per_minute, burst

[[alerts.sink]]
type = "telegram"
name = "noc-v4"
bot_token_env = "TELEGRAM_BOT_TOKEN"
chat_id = -1001234567890
min_severity = "warning"
resources = ["192.0.2.*", "198.51.100.*"]   # bu sohbet yalnızca bu önekleri alır

[[alerts.sink]]
type = "webhook"
url = "https://hooks.example.net/llcforge"
bearer_token_env = "WEBHOOK_TOKEN"
hmac_secret_env = "WEBHOOK_HMAC_SECRET"

[[alerts.sink]]
type = "syslog"
transport = "udp"                # udp | tcp | tls | unix (yalnızca Unix: /dev/log)
address = "192.0.2.10:514"

[silences]
api_token_env = "VIGIL_ADMIN_TOKEN"          # /v1/silences uç noktasını açar

[health]
listen = "127.0.0.1:9184"
admin_token_env = "VIGIL_ADMIN_TOKEN"        # POST /v1/reload uç noktasını açar
```

Diğer sink türleri (`stdout`, `slack`, `discord`, `teams`, `email`,
`pagerduty`, `opsgenie`) için tüm alanlar [README.md](README.md#configuration)
dosyasında listelenmiştir.

Gizli bilgiler asla yapılandırma dosyasından okunmaz: her gizli değer bir ortam
değişkeninin *adıdır* (`*_env`). Eksik bir değişken açılışta hata verir.

## Teslim garantileri

* `AlertHandle::send` hiçbir zaman bloklamaz; kanal doluysa uyarı düşürülür ve sayılır.
* Kabul edilen uyarılar teslimden önce disk kuyruğuna yazılır (fsync edilmiş
  tek bir JSON satırı). Her sink'in kendi işçisi vardır; çökmüş bir uç nokta
  diğerlerini geciktirmez.
* Yeniden denemelerini tüketen bir sink, `max_age_secs` dolana kadar her
  `redeliver_after_secs` saniyede uyarıyı tekrar alır.
* Çökme ya da yeniden başlatma sonrası teslim edilmemiş uyarılar yeniden
  gönderilir. Yarım yazılmış son satır kesilir, bozuk satırlar atlanır, yarıda
  kalan sıkıştırmalar yok sayılır. Teslim en az bir kezdir (at-least-once):
  alıcılar `id` ile tekilleştirme yapmalıdır.

## Webhook imzasının doğrulanması

İmza `HMAC-SHA256(gizli, "<zaman damgası>.<ham gövde>")` değerinin onaltılık
gösterimidir ve `X-LLCForge-Signature: sha256=<hex>` başlığında gelir. Zaman
damgası (`X-LLCForge-Timestamp`) saatinizden beş dakikadan fazla sapıyorsa
isteği reddedin (tekrar oynatma koruması).

## Susturmalar

Susturmalar `resource`, `kind` ve `tool` glob kalıplarıyla (`*`, `?`, büyük/küçük
harf duyarsız) bir zaman aralığı için eşleşir ve atomik yazımla (geçici dosya,
fsync, yeniden adlandırma) JSON olarak saklanır. Susturulan uyarılar sayılır,
gönderilmez.

```text
GET    /v1/silences
POST   /v1/silences                 {"resource":"192.0.2.*","duration":"2h","comment":"fiber çalışması","created_by":"noc"}
DELETE /v1/silences/{id}
```

Tüm uç noktalar `Authorization: Bearer <token>` ister; gövde 16 KiB ile
sınırlıdır ve sıkı biçimde doğrulanır. CLI aynı dosyayı düzenler, çalışan
servis değişikliği 2 saniye içinde fark eder:

```text
vigil silence add --resource '192.0.2.*' --duration 2h -m "fiber çalışması"
vigil silence list [--json]
vigil silence remove <id>
```

## Sağlık, yeniden yükleme, servis

* `GET /healthz` → `200 {"status":"ok"}`; `GET /readyz` → `200` ya da `503` ve
  `{"ready":false,"failing":["bgp_session"],"checks":{...}}`.
* `ReloadSignal::standard(Some(config_path))` SIGHUP (Unix) ile ve yapılandırma
  dosyası değiştiğinde (5 saniyede bir kontrol) tetiklenir; `reload_router`
  `POST /v1/reload` ekler.
* `run_service_command`, `<araç> service install|uninstall|run` komutlarını
  sağlar: Windows'ta Servis Denetim Yöneticisi (`NT AUTHORITY\LocalService`
  hesabı, hata durumunda yeniden başlatma); Linux/macOS'ta paketle gelen
  systemd/launchd adımlarını yazdırır.

## Metrikler

`Metrics::render_prometheus(&mut String)` şunları ekler:
`llcforge_beacon_{received,deduplicated,silenced,dropped,invalid}_total{tool}`,
`llcforge_beacon_queue_depth{tool}`,
`llcforge_beacon_sink_{sent,failed,suppressed,retries,rate_limited}_total{tool,sink,type}`,
`llcforge_beacon_sink_queued{tool,sink,type}`.

## Paketleme şablonları ve senkronizasyon

`templates/` dizini CI, sürüm (çoklu işletim sistemi ikilileri, cosign ile
imzalanmış SHA256SUMS, .deb/.rpm, çok mimarili imaj), Docker, systemd, launchd,
Windows, Homebrew, Scoop, winget, Helm, Grafana ve Prometheus şablonlarını
içerir. `sync.py` crate'i kopyalar ve şablonları araç deposuna işler:

```text
python sync.py ../Vigil --bin vigil --name "Vigil" --repo Vigil \
  --description "Real-time BGP origin hijack detection" --port-metrics 9184
```

Aracın en üst düzeydeki `README*`, `ARCHITECTURE.md` dosyalarına ve `src/`
dizinine asla dokunmaz, `--keep` ile verilen mevcut dosyaları atlar ve tekrar
çalıştırıldığında aynı sonucu üretir.

## Güvenlik notları

* Gizli bilgiler yalnızca ortam değişkenlerinden okunur; gizli bilgi tutan sink
  türleri `Debug` uygulamaz, HTTP hataları URL'siz loglanır.
* API token'ları SHA-256 özetleri üzerinden sabit zamanda karşılaştırılır.
* Uyarı metni güvenilmez kabul edilir: sink'e göre HTML/mrkdwn/syslog
  kaçışlaması, Discord'da bahsetmeler kapalı, e-posta konularından CR/LF silinir.
* Döngü (loopback) dışındaki adreslere düz `http://` reddedilir; webhook için
  `allow_http = true` ile açıkça izin verilebilir.

## Platformlar ve MSRV

Windows, macOS ve Linux (CI üçünde de çalışır). Rust 1.85+ (lettre gerektirir).
Cargo özellikleri: `cli` (clap alt komutları), `smtp` (e-posta sink'i), `service`
(Windows servisi); hepsi varsayılan olarak açıktır.

## Lisans

MIT — bkz. [LICENSE](LICENSE) ve [NOTICE](NOTICE).
