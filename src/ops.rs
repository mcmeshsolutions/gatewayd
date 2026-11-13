//! Operator surface: usage counters, /metrics, public status, webhooks, expiring invites.
use crate::lease::{wall_s, Error, Gateway};
use crate::server::{ApiErr, AppState};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rusqlite::{params, OptionalExtension};
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
        self.apikeys_init()?;
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

async fn status_page(State(s): State<Arc<AppState>>) -> Result<Response, ApiErr> {
    let v = public_status(&s)?;
    let html = include_str!("../web/status.html")
        .replace("{{worlds}}", &v["worlds"].to_string())
        .replace("{{hosted}}", &v["hosted"].to_string())
        .replace("{{uptime}}", &span(s.uptime_s() as i64))
        .replace("{{last_save}}", &v["last_save_age_s"].as_i64().map_or("never".into(), |a| format!("{} ago", span(a))))
        .replace("{{version}}", env!("CARGO_PKG_VERSION"));
    Ok(([(header::CACHE_CONTROL, "no-cache")], Html(html)).into_response())
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

async fn invite_page(State(s): State<Arc<AppState>>, Path(code): Path<String>) -> Result<Response, ApiErr> {
    let page = |title: &str, code: &str, note: &str| {
        include_str!("../web/invite.html").replace("{{title}}", title).replace("{{code}}", code).replace("{{note}}", note)
    };
    let info = s.gw().invite_info(&code)?;
    Ok(match info {
        Some(Ok((world, exp))) => {
            let note = exp.map_or("This invite does not expire.".into(), |at| format!("Expires in {}.", span(at - wall_s())));
            Html(page(&format!("Join {}", esc(&world)), &esc(&code.to_uppercase()), &note)).into_response()
        }
        _ => (StatusCode::NOT_FOUND, Html(page("Invite not valid", "", "This invite was already used or has expired. Ask for a new one."))).into_response(),
    })
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/status", get(status_page))
        .route("/v1/status", get(status_json))
        .route("/.well-known/mcmesh-gateway.json", get(well_known))
        .route("/metrics", get(metrics))
        .route("/invite/:code", get(invite_page))
        .route("/v1/worlds/:id/events", get(world_events))
}
