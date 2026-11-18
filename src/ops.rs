//! Operator surface: usage counters, /metrics, public status, webhooks, expiring invites.
use crate::lease::{wall_s, Error, Gateway};
use crate::server::{ApiErr, AppState};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::time::Duration;

pub const INVITE_TTL_S: i64 = 7 * 86_400;
pub const INVITE_MAX_TTL_S: i64 = 90 * 86_400;

pub struct Summary {
    pub worlds: Vec<(String, i64)>,
    pub live_leases: i64,
    pub players: i64,
    pub revisions: i64,
    pub last_commit_at: Option<i64>,
}

impl Gateway {
    /// Tables and columns this module owns. Idempotent, runs wherever a Gateway is put to work.
    pub fn ops_init(&self) -> Result<(), Error> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS meters(
               world_id TEXT NOT NULL, name TEXT NOT NULL, value INTEGER NOT NULL,
               PRIMARY KEY(world_id, name)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS world_pack_version(
               world_id TEXT PRIMARY KEY, version TEXT NOT NULL) WITHOUT ROWID;",
        )?;
        let _ = self.db.execute("ALTER TABLE invites ADD COLUMN expires_at INTEGER", []);
        self.admin_init()?;
        self.crash_init()?;
        self.worldgen_init()?;
        self.apikeys_init()?;
        self.sso_init()?;
        self.host_sessions_init()?;
        Ok(())
    }

    /// Pack version the last host reported; informational, a failed write must not fail the join.
    pub fn set_pack_version(&self, world: &str, version: &str) {
        let r = self.db.execute(
            "INSERT INTO world_pack_version(world_id,version) VALUES(?,?) ON CONFLICT(world_id) DO UPDATE SET version=excluded.version",
            params![world, version],
        );
        if let Err(e) = r {
            eprintln!("pack version write failed: {e}");
        }
    }

    pub fn pack_version_of(&self, world: &str) -> Option<String> {
        self.db.query_row("SELECT version FROM world_pack_version WHERE world_id=?", params![world], |r| r.get(0)).ok()
    }

    /// Adds to a counter; world "" is gateway-wide. A counter must never fail the request it counts.
    pub fn meter(&self, world: &str, name: &str, n: u64) {
        let r = self.db.execute(
            "INSERT INTO meters(world_id,name,value) VALUES(?,?,?) \
             ON CONFLICT(world_id,name) DO UPDATE SET value=value+excluded.value",
            params![world, name, n as i64],
        );
        if let Err(e) = r {
            eprintln!("meter {name} failed: {e}");
        }
    }

    /// (name, world, value), grouped by name.
    pub fn meters(&self) -> Result<Vec<(String, String, i64)>, Error> {
        let mut st = self.db.prepare("SELECT name, world_id, value FROM meters ORDER BY name, world_id")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn summary(&self) -> Result<Summary, Error> {
        let worlds = {
            let mut st = self.db.prepare("SELECT state, COUNT(*) FROM worlds GROUP BY state ORDER BY state")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        let one = |sql: &str| self.db.query_row(sql, [], |r| r.get::<_, Option<i64>>(0));
        Ok(Summary {
            worlds,
            live_leases: one("SELECT COUNT(*) FROM leases WHERE status IN('ACTIVE','HANDOFF')")?.unwrap_or(0),
            players: one("SELECT COUNT(*) FROM players")?.unwrap_or(0),
            revisions: one("SELECT COUNT(*) FROM revisions")?.unwrap_or(0),
            last_commit_at: one("SELECT MAX(created_at) FROM revisions")?,
        })
    }

    /// Tail of `gatewayd status`: totals, then one line per counter.
    pub fn ops_status(&self) -> Result<Vec<String>, Error> {
        let s = self.summary()?;
        let mut out = vec![format!(
            "totals worlds={} live_leases={} players={} revisions={} last_commit_age_s={}",
            s.worlds.iter().map(|w| w.1).sum::<i64>(),
            s.live_leases,
            s.players,
            s.revisions,
            s.last_commit_at.map_or("-".into(), |t| (wall_s() - t).to_string()),
        )];
        for (name, world, v) in self.meters()? {
            out.push(format!("meter {name} world={} {v}", if world.is_empty() { "-" } else { &world }));
        }
        Ok(out)
    }

    pub fn lease_world(&self, lease: &str) -> Option<String> {
        self.db.query_row("SELECT world_id FROM leases WHERE id=?", params![lease], |r| r.get(0)).ok()
    }

    /// A world this device belongs to that holds the blob, for attributing download bytes.
    pub fn blob_world_for(&self, device: &str, hash: &[u8]) -> Option<String> {
        self.db
            .query_row(
                "SELECT b.world_id FROM blob_world b JOIN members m ON m.world_id=b.world_id \
                 JOIN devices d ON d.player_uuid=m.player_uuid WHERE b.hash=? AND d.id=? LIMIT 1",
                params![hash, device],
                |r| r.get(0),
            )
            .ok()
    }

    /// None clears the expiry. Unknown codes are a no-op.
    pub fn set_invite_expiry(&self, code: &str, at: Option<i64>) -> Result<(), Error> {
        self.db.execute("UPDATE invites SET expires_at=? WHERE code=?", params![at, code.to_uppercase()])?;
        Ok(())
    }

    /// (world name, expires_at) of an unredeemed invite. Expired invites are deleted and read as Err(()).
    pub fn invite_info(&self, code: &str) -> Result<Option<Result<(String, Option<i64>), ()>>, Error> {
        let code = code.to_uppercase();
        let row: Option<(String, Option<i64>)> = self
            .db
            .query_row(
                "SELECT w.name, i.expires_at FROM invites i JOIN worlds w ON w.id=i.world_id WHERE i.code=?",
                params![code],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(match row {
            Some((_, Some(at))) if at <= wall_s() => {
                self.db.execute("DELETE FROM invites WHERE code=?", params![code])?;
                Some(Err(()))
            }
            Some(r) => Some(Ok(r)),
            None => None,
        })
    }

    pub fn metrics_text(&self, uptime_s: u64, tunnels: usize) -> Result<String, Error> {
        let s = self.summary()?;
        let mut o = String::new();
        let mut gauge = |name: &str, v: i64| {
            let _ = writeln!(o, "# TYPE mcmesh_{name} gauge\nmcmesh_{name} {v}");
        };
        gauge("up", 1);
        gauge("uptime_seconds", uptime_s as i64);
        gauge("live_leases", s.live_leases);
        gauge("tunnels", tunnels as i64);
        gauge("players", s.players);
        gauge("revisions", s.revisions);
        gauge("last_commit_timestamp_seconds", s.last_commit_at.unwrap_or(0));
        let _ = writeln!(o, "# TYPE mcmesh_worlds gauge");
        for (state, n) in &s.worlds {
            let _ = writeln!(o, "mcmesh_worlds{{state=\"{}\"}} {n}", label(state));
        }
        let mut last = String::new();
        for (name, world, v) in self.meters()? {
            if name != last {
                let _ = writeln!(o, "# TYPE mcmesh_{name}_total counter");
                last.clone_from(&name);
            }
            if world.is_empty() {
                let _ = writeln!(o, "mcmesh_{name}_total {v}");
            } else {
                let _ = writeln!(o, "mcmesh_{name}_total{{world=\"{}\"}} {v}", label(&world));
            }
        }
        Ok(o)
    }
}

fn label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn span(s: i64) -> String {
    match s {
        s if s >= 2 * 86_400 => format!("{} days", s / 86_400),
        s if s >= 2 * 3600 => format!("{} hours", s / 3600),
        s if s >= 120 => format!("{} minutes", s / 60),
        s => format!("{s} seconds"),
    }
}

/// Best-effort event delivery to the operator's webhook URLs, plus a bounded in-memory log that the long-poll route reads.
/// No retries, no ordering across URLs. The log is lost on restart; `boot` tells a reader that happened.
pub struct Hooks {
    tx: Option<SyncSender<String>>,
    log: std::sync::Mutex<EventLog>,
    wake: tokio::sync::Notify,
}

const EVENT_LOG_MAX: usize = 2000;

struct EventLog {
    boot: u64,
    next: u64,
    events: std::collections::VecDeque<LoggedEvent>,
}

struct LoggedEvent {
    seq: u64,
    ts: i64,
    event: String,
    world: String,
    data: Value,
}

impl Hooks {
    pub fn new(urls: &[String], secret: Option<String>) -> Self {
        let boot = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |d| d.as_millis() as u64);
        let log = std::sync::Mutex::new(EventLog { boot, next: 1, events: Default::default() });
        if urls.is_empty() {
            return Hooks { tx: None, log, wake: tokio::sync::Notify::new() };
        }
        let (tx, rx) = sync_channel::<String>(256);
        let urls = urls.to_vec();
        std::thread::spawn(move || {
            let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
            for body in rx {
                let sig = secret.as_deref().map(|k| sign(k, &body));
                for (i, u) in urls.iter().enumerate() {
                    let mut r = agent.post(u).set("content-type", "application/json");
                    if let Some(s) = &sig {
                        r = r.set("x-mesh-signature", s);
                    }
                    // urls often embed a secret, so only the index is logged
                    if r.send_string(&body).is_err() {
                        eprintln!("webhook #{i} delivery failed");
                    }
                }
            }
        });
        Hooks { tx: Some(tx), log, wake: tokio::sync::Notify::new() }
    }

    pub fn emit(&self, event: &str, world: &str, data: Value) {
        let ts = wall_s();
        {
            let mut l = self.log.lock().unwrap_or_else(|e| e.into_inner());
            let seq = l.next;
            l.next += 1;
            l.events.push_back(LoggedEvent { seq, ts, event: event.into(), world: world.into(), data: data.clone() });
            while l.events.len() > EVENT_LOG_MAX {
                l.events.pop_front();
            }
        }
        self.wake.notify_waiters();
        if let Some(tx) = &self.tx {
            // a full queue means a stuck receiver; dropping events beats blocking the api
            let _ = tx.try_send(json!({ "event": event, "world": world, "ts": ts, "data": data }).to_string());
        }
    }

    /// Events of one world after `after` (at most `limit`), the highest seq seen, and this process's boot id.
    /// A `boot` that differs from ours means the log restarted, so `after` is ignored and `reset` is true.
    fn events_after(&self, world: &str, after: u64, boot: Option<u64>, limit: usize) -> (Vec<Value>, u64, u64, bool) {
        let l = self.log.lock().unwrap_or_else(|e| e.into_inner());
        let reset = boot.is_some_and(|b| b != l.boot);
        let after = if reset { 0 } else { after };
        let mut next = if reset { 0 } else { after };
        let out: Vec<Value> = l
            .events
            .iter()
            .filter(|e| e.seq > after && e.world == world)
            .take(limit)
            .map(|e| {
                next = e.seq;
                json!({ "seq": e.seq, "ts": e.ts, "event": e.event, "data": e.data })
            })
            .collect();
        if out.is_empty() {
            next = next.max(if reset { 0 } else { after.min(l.next.saturating_sub(1)) });
        }
        (out, next, l.boot, reset)
    }
}

/// Long poll: returns as soon as the world has events after `after`, or empty after `wait` seconds (0 to 25).
async fn world_events(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Query(q): Query<std::collections::HashMap<String, String>>) -> Result<Json<Value>, ApiErr> {
    {
        let gw = s.gw();
        let dev = crate::server::auth(&gw, &h)?;
        gw.pack_of(&world)?;
        gw.require_member(&world, &dev)?;
    }
    let num = |k: &str| -> Result<Option<u64>, ApiErr> { q.get(k).map(|v| v.parse::<u64>().map_err(|_| ApiErr::BadRequest("BAD_QUERY"))).transpose() };
    let (after, boot, wait) = (num("after")?.unwrap_or(0), num("boot")?, num("wait")?.unwrap_or(0).min(25));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    loop {
        let notified = s.hooks.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (events, next, boot_id, reset) = s.hooks.events_after(&world, after, boot, 100);
        if !events.is_empty() || reset || wait == 0 || tokio::time::Instant::now() >= deadline {
            return Ok(Json(json!({ "events": events, "next": next, "boot": boot_id, "reset": reset })));
        }
        tokio::select! {
            _ = &mut notified => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

static STREAMS_OPEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const STREAMS_MAX: usize = 200;
const STREAM_LIFETIME: Duration = Duration::from_secs(3600);

struct StreamGuard;

impl Drop for StreamGuard {
    fn drop(&mut self) {
        STREAMS_OPEN.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

struct SseState {
    s: Arc<AppState>,
    world: String,
    after: u64,
    boot: Option<u64>,
    pending: std::collections::VecDeque<axum::response::sse::Event>,
    deadline: tokio::time::Instant,
    _guard: StreamGuard,
}

/// Server-sent events for one world: the same events as the long poll, each with `id` = its sequence number, so a client that
/// reconnects with `Last-Event-ID` (or `?after=`) misses nothing still in the log. A `reset` event means the gateway restarted
/// and sequence numbers started over. The stream ends after an hour; reconnect with the last id.
async fn world_event_stream(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Query(q): Query<std::collections::HashMap<String, String>>) -> Result<axum::response::Response, ApiErr> {
    {
        let gw = s.gw();
        let dev = crate::server::auth(&gw, &h)?;
        gw.pack_of(&world)?;
        gw.require_member(&world, &dev)?;
    }
    let last_id = h.get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    let after = match (last_id, q.get("after")) {
        (Some(id), _) => id,
        (None, Some(a)) => a.parse::<u64>().map_err(|_| ApiErr::BadRequest("BAD_QUERY"))?,
        (None, None) => 0,
    };
    let boot = q.get("boot").map(|b| b.parse::<u64>().map_err(|_| ApiErr::BadRequest("BAD_QUERY"))).transpose()?;
    if STREAMS_OPEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= STREAMS_MAX {
        STREAMS_OPEN.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        return Err(ApiErr::Conflict("TOO_MANY_STREAMS"));
    }
    let st = SseState { s, world, after, boot, pending: Default::default(), deadline: tokio::time::Instant::now() + STREAM_LIFETIME, _guard: StreamGuard };
    let stream = futures_util::stream::unfold(st, |mut st| async move {
        use axum::response::sse::Event;
        loop {
            if let Some(e) = st.pending.pop_front() {
                return Some((Ok::<Event, std::convert::Infallible>(e), st));
            }
            if tokio::time::Instant::now() >= st.deadline {
                return None;
            }
            let notified = st.s.hooks.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (events, next, boot_id, reset) = st.s.hooks.events_after(&st.world, st.after, st.boot, 100);
            if reset {
                st.pending.push_back(Event::default().event("reset").data(json!({ "boot": boot_id }).to_string()));
            }
            st.boot = Some(boot_id);
            st.after = next;
            for e in events {
                let name = e["event"].as_str().unwrap_or("event").to_string();
                st.pending.push_back(Event::default().id(e["seq"].to_string()).event(name).data(e.to_string()));
            }
            if !st.pending.is_empty() {
                continue;
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep_until(st.deadline) => {}
            }
        }
    });
    Ok(axum::response::sse::Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(15))).into_response())
}

pub fn sign(secret: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("hmac takes any key length");
    m.update(body.as_bytes());
    let mac: [u8; 32] = m.finalize().into_bytes().into();
    format!("sha256={}", crate::cas::hex(&mac))
}

fn public_status(s: &AppState) -> Result<Value, Error> {
    let sum = s.gw().summary()?;
    Ok(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_s": s.uptime_s(),
        "worlds": sum.worlds.iter().map(|w| w.1).sum::<i64>(),
        "hosted": sum.live_leases,
        "last_save_age_s": sum.last_commit_at.map(|t| (wall_s() - t).max(0)),
    }))
}

/// Public discovery document for launchers, bots and the client's trust prompt. Nothing secret, nothing per player.
async fn well_known(State(s): State<Arc<AppState>>) -> Json<Value> {
    let mut auth = Vec::new();
    if s.auth.mojang {
        auth.push("mojang");
    }
    if s.auth.key {
        auth.push("key");
    }
    Json(json!({
        "gateway": "mcmesh",
        "version": env!("CARGO_PKG_VERSION"),
        "api": "/v1",
        "auth": auth,
        "relay": (!s.auth.advertise.is_empty()).then(|| s.auth.advertise.clone()),
        "guest_tickets": s.auth.require_ticket,
        "world_creation": if s.auth.allow_create { "open" } else { "admins" },
        "require_signed_commits": s.auth.require_signed,
        "min_client": s.auth.min_client,
        "features": ["quotas", "audit", "events", "api_keys", "handover_vote", "region_rollback", "crash_reports", "pack_versions", "metrics", "webhooks"],
    }))
}

async fn status_json(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiErr> {
    Ok(Json(public_status(&s)?))
}

/// Polish when the client's first listed language is Polish, English otherwise. Only the public pages are translated.
fn wants_polish(h: &HeaderMap) -> bool {
    h.get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|first| first.trim().to_ascii_lowercase().starts_with("pl"))
}

fn pl_plural<'a>(n: i64, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    if n == 1 {
        one
    } else if (2..=4).contains(&(n % 10)) && !(12..=14).contains(&(n % 100)) {
        few
    } else {
        many
    }
}

fn span_pl(s: i64) -> String {
    match s {
        s if s >= 2 * 86_400 => format!("{} {}", s / 86_400, "dni"),
        s if s >= 2 * 3600 => {
            let n = s / 3600;
            format!("{n} {}", pl_plural(n, "godzina", "godziny", "godzin"))
        }
        s if s >= 120 => {
            let n = s / 60;
            format!("{n} {}", pl_plural(n, "minuta", "minuty", "minut"))
        }
        s => format!("{s} {}", pl_plural(s, "sekunda", "sekundy", "sekund")),
    }
}

async fn status_page(State(s): State<Arc<AppState>>, h: HeaderMap) -> Result<Response, ApiErr> {
    let v = public_status(&s)?;
    let pl = wants_polish(&h);
    let t = |en: &'static str, pl_text: &'static str| if pl { pl_text } else { en };
    let age = |a: i64| if pl { format!("{} temu", span_pl(a)) } else { format!("{} ago", span(a)) };
    let uptime = s.uptime_s() as i64;
    let html = include_str!("../web/status.html")
        .replace("{{lang}}", t("en", "pl"))
        .replace("{{t_title}}", t("Shared Worlds status", "Status Shared Worlds"))
        .replace("{{t_h1}}", t("Gateway status", "Status bramy"))
        .replace("{{t_ok}}", t("Operational", "Działa"))
        .replace("{{t_worlds}}", t("Worlds stored", "Zapisane światy"))
        .replace("{{t_hosted}}", t("Worlds being hosted now", "Światy hostowane teraz"))
        .replace("{{t_save}}", t("Last world save", "Ostatni zapis świata"))
        .replace("{{t_up}}", t("Running for", "Czas działania"))
        .replace("{{t_foot}}", t("Machine-readable copy at", "Wersja dla maszyn:"))
        .replace("{{worlds}}", &v["worlds"].to_string())
        .replace("{{hosted}}", &v["hosted"].to_string())
        .replace("{{uptime}}", &if pl { span_pl(uptime) } else { span(uptime) })
        .replace("{{last_save}}", &v["last_save_age_s"].as_i64().map_or(t("never", "nigdy").into(), age))
        .replace("{{version}}", env!("CARGO_PKG_VERSION"));
    Ok(([(header::CACHE_CONTROL, "no-cache"), (header::VARY, "accept-language")], Html(html)).into_response())
}

async fn metrics(State(s): State<Arc<AppState>>, h: HeaderMap) -> Result<Response, ApiErr> {
    // without a configured token the endpoint does not exist: world ids are not public
    let Some(want) = s.auth.metrics_token.as_deref() else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let got = h.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if crate::cas::sha256(got.as_bytes()) != crate::cas::sha256(want.as_bytes()) {
        return Err(ApiErr::Unauthorized);
    }
    let tunnels = s.live_worlds.lock().unwrap_or_else(|e| e.into_inner()).len();
    let text = s.gw().metrics_text(s.uptime_s(), tunnels)?;
    Ok(([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], text).into_response())
}

async fn invite_page(State(s): State<Arc<AppState>>, h: HeaderMap, Path(code): Path<String>) -> Result<Response, ApiErr> {
    let pl = wants_polish(&h);
    let t = |en: &'static str, pl_text: &'static str| if pl { pl_text } else { en };
    let page = |title: &str, code: &str, note: &str| {
        include_str!("../web/invite.html")
            .replace("{{lang}}", t("en", "pl"))
            .replace("{{t_step1}}", t("Install the modpack and the <b>mcmesh</b> mod, see", "Zainstaluj paczkę modów i mod <b>mcmesh</b>, zobacz"))
            .replace("{{t_start}}", t("the start page", "stronę startową"))
            .replace("{{t_step2}}", t("Open <b>Shared Worlds</b> from the title screen and press <b>Redeem</b>.", "Otwórz <b>Shared Worlds</b> z ekranu tytułowego i naciśnij <b>Redeem</b>."))
            .replace("{{t_step3}}", t("Paste the code above, then join the world from the list. A code works once.", "Wklej powyższy kod, potem dołącz do świata z listy. Kod działa tylko raz."))
            .replace("{{title}}", title)
            .replace("{{code}}", code)
            .replace("{{note}}", note)
    };
    let info = s.gw().invite_info(&code)?;
    let vary = [(header::VARY, "accept-language")];
    Ok(match info {
        Some(Ok((world, exp))) => {
            let note = exp.map_or(t("This invite does not expire.", "To zaproszenie nie wygasa.").into(), |at| {
                if pl { format!("Wygasa za {}.", span_pl(at - wall_s())) } else { format!("Expires in {}.", span(at - wall_s())) }
            });
            let title = format!("{} {}", t("Join", "Dołącz do"), esc(&world));
            (vary, Html(page(&title, &esc(&code.to_uppercase()), &note))).into_response()
        }
        _ => (
            StatusCode::NOT_FOUND,
            vary,
            Html(page(
                t("Invite not valid", "Zaproszenie jest nieważne"),
                "",
                t("This invite was already used or has expired. Ask for a new one.", "To zaproszenie zostało już użyte albo wygasło. Poproś o nowe."),
            )),
        )
            .into_response(),
    })
}

#[derive(serde::Deserialize)]
pub struct VoxelQuery {
    pub rev: Option<String>,
    pub dim: Option<String>,
    pub cx: Option<i32>,
    pub cz: Option<i32>,
    pub radius: Option<i32>,
}

impl Gateway {
    pub fn world_voxels(&self, world: &str, q: &VoxelQuery) -> Result<Value, Error> {
        let head = self.head(world)?;
        let rev_id = q.rev.as_deref().unwrap_or(&head);
        let root = self.revision_root(rev_id)?;
        let seq: i64 = self.db.query_row("SELECT seq FROM revisions WHERE id=?", params![rev_id], |r| r.get(0)).optional()?.unwrap_or(0);
        let dim = q.dim.as_deref().unwrap_or("minecraft:overworld");
        let center_cx = q.cx.unwrap_or(0);
        let center_cz = q.cz.unwrap_or(0);
        let radius = q.radius.unwrap_or(2).clamp(0, 8);

        let mut chunks = Vec::new();
        for cx in (center_cx - radius)..=(center_cx + radius) {
            for cz in (center_cz - radius)..=(center_cz + radius) {
                let key = crate::manifest::Key {
                    dim: dim.to_string(),
                    kind: crate::manifest::Kind::Region,
                    cx,
                    cz,
                };
                if let Some(hash) = crate::manifest::lookup(&self.cas, root, &key)? {
                    let mut voxels: Vec<[i32; 4]> = Vec::new();
                    let seed = ((cx as u64) << 32) ^ (cz as u64 & 0xffffffff) ^ u64::from_le_bytes(hash[0..8].try_into().unwrap());
                    for rx in 0..16 {
                        for rz in 0..16 {
                            let h = 60 + (((seed.wrapping_add((rx as u64) * 31 + (rz as u64) * 17)) % 15) as i32);
                            let color_idx = if h > 70 { 3 } else if h == 60 { 4 } else if (rx + rz) % 7 == 0 { 5 } else { 1 };
                            voxels.push([rx, h, rz, color_idx]);
                        }
                    }
                    chunks.push(json!({
                        "cx": cx,
                        "cz": cz,
                        "hash": crate::cas::hex(&hash),
                        "voxels": voxels,
                    }));
                }
            }
        }

        let palette = vec![
            "#00000000", "#5b8c32", "#866043", "#777777", "#2e6f9e",
            "#9c7849", "#5a5a5a", "#386b24", "#e0f8ff", "#d8d8d8",
            "#f4b41b", "#c0684a", "#944230", "#1b122c", "#dbcb96",
        ];

        Ok(json!({
            "world_id": world,
            "revision": rev_id,
            "seq": seq,
            "dim": dim,
            "chunks": chunks,
            "palette": palette,
        }))
    }
}

async fn world_voxels(
    State(s): State<Arc<AppState>>,
    Path(world): Path<String>,
    Query(q): Query<VoxelQuery>,
) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let data = gw.world_voxels(&world, &q)?;
    Ok(Json(data))
}

async fn world_timeline(
    State(s): State<Arc<AppState>>,
    Path(world): Path<String>,
) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let revs = gw.revisions(&world, 200)?;
    Ok(Json(json!({
        "world_id": world,
        "head": gw.head(&world)?,
        "revisions": revs
    })))
}

async fn voxel_viewer(axum::extract::Path(_id): axum::extract::Path<String>) -> Response {
    Html(include_str!("../web/voxel.html")).into_response()
}

#[derive(Deserialize)]
pub struct ContraptionQuery {
    pub rpm: Option<f64>,
}

async fn contraption_inspect(
    Query(q): Query<ContraptionQuery>,
    body: axum::body::Bytes,
) -> Json<crate::contraption::ContraptionInspection> {
    let rpm = q.rpm.unwrap_or(64.0);
    Json(crate::contraption::inspect_bytes(&body, rpm))
}

async fn contraption_demo(
    Query(q): Query<ContraptionQuery>,
) -> Json<crate::contraption::ContraptionInspection> {
    let rpm = q.rpm.unwrap_or(64.0);
    Json(crate::contraption::demo_contraption(rpm))
}

async fn contraption_viewer() -> Response {
    Html(include_str!("../web/contraption.html")).into_response()
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/status", get(status_page))
        .route("/v1/status", get(status_json))
        .route("/.well-known/mcmesh-gateway.json", get(well_known))
        .route("/metrics", get(metrics))
        .route("/invite/:code", get(invite_page))
        .route("/view/:id", get(voxel_viewer))
        .route("/contraption", get(contraption_viewer))
        .route("/v1/contraptions/inspect", post(contraption_inspect))
        .route("/v1/contraptions/demo", get(contraption_demo))
        .route("/v1/worlds/:id/voxels", get(world_voxels))
        .route("/v1/worlds/:id/timeline", get(world_timeline))
        .route("/v1/worlds/:id/events", get(world_events))
        .route("/v1/worlds/:id/events/stream", get(world_event_stream))
}

#[cfg(test)]
mod pl_tests {
    use super::span_pl;

    #[test]
    fn polish_plurals_follow_the_one_few_many_rule() {
        assert_eq!(span_pl(1), "1 sekunda");
        assert_eq!(span_pl(2), "2 sekundy");
        assert_eq!(span_pl(5), "5 sekund");
        assert_eq!(span_pl(12), "12 sekund", "teens are always many");
        assert_eq!(span_pl(22), "22 sekundy");
        assert_eq!(span_pl(120), "2 minuty");
        assert_eq!(span_pl(60 * 5), "5 minut");
        assert_eq!(span_pl(3600 * 2), "2 godziny");
        assert_eq!(span_pl(3600 * 22), "22 godziny");
        assert_eq!(span_pl(3600 * 25), "25 godzin");
        assert_eq!(span_pl(86_400 * 3), "3 dni");
    }
}
