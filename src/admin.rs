//! Audit log, account suspension, maintenance mode, gateway roles and per-world host policy.
//! Tables are created at runtime by `admin_init` (called from `ops_init`), schema.sql is core's.
use crate::lease::{wall_s, Error, Gateway};
use crate::server::{auth, ApiErr, AppState};
use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, Method},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

type R = Result<Json<Value>, ApiErr>;

pub const DEFAULT_RETRY_AFTER_S: u64 = 300;
pub const MAX_RETRY_AFTER_S: u64 = 86_400;
const PAGE_DEFAULT: i64 = 50;
const PAGE_MAX: i64 = 200;

impl Gateway {
    pub fn admin_init(&self) -> Result<(), Error> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log(
               id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
               actor TEXT NOT NULL, actor_name TEXT NOT NULL,
               action TEXT NOT NULL, world_id TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
               detail TEXT NOT NULL DEFAULT '{}');
             CREATE INDEX IF NOT EXISTS audit_world ON audit_log(world_id, id);
             CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
               BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
             CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
               BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
             CREATE TABLE IF NOT EXISTS user_status(
               player_uuid TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN('SUSPENDED','BANNED')),
               reason TEXT NOT NULL DEFAULT '', set_by TEXT NOT NULL, set_at INTEGER NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS gateway_admins(
               player_uuid TEXT PRIMARY KEY, granted_by TEXT NOT NULL, granted_at INTEGER NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS admin_settings(
               key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS world_policy(
               world_id TEXT PRIMARY KEY, owner_uuid TEXT,
               host_policy TEXT NOT NULL DEFAULT 'MEMBERS' CHECK(host_policy IN('OWNER','ALLOWLIST','MEMBERS'))) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS world_aux(
               world_id TEXT NOT NULL, ns TEXT NOT NULL, key TEXT NOT NULL, value BLOB NOT NULL, updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL,
               PRIMARY KEY(world_id, ns, key)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS world_reports(
               id INTEGER PRIMARY KEY AUTOINCREMENT, world_id TEXT NOT NULL, reporter TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL,
               created_at INTEGER NOT NULL, resolved_at INTEGER, note TEXT NOT NULL DEFAULT '');
             CREATE TABLE IF NOT EXISTS world_appeals(
               id INTEGER PRIMARY KEY AUTOINCREMENT, world_id TEXT NOT NULL, player_uuid TEXT NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL,
               resolved_at INTEGER, decision TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '');
             CREATE TABLE IF NOT EXISTS world_bans(
               world_id TEXT NOT NULL, player_uuid TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', banned_by TEXT NOT NULL, banned_at INTEGER NOT NULL,
               PRIMARY KEY(world_id, player_uuid)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS world_templates(
               world_id TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '', set_by TEXT NOT NULL, set_at INTEGER NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS world_host_allow(
               world_id TEXT NOT NULL, player_uuid TEXT NOT NULL, PRIMARY KEY(world_id, player_uuid)) WITHOUT ROWID;",
        )?;
        let _ = self.db.execute("ALTER TABLE world_policy ADD COLUMN require_signed INTEGER NOT NULL DEFAULT 0", []);
        let _ = self.db.execute("ALTER TABLE world_policy ADD COLUMN handover_vote INTEGER NOT NULL DEFAULT 0", []);
        Ok(())
    }

    /// Best effort like `meter`: the audit trail must not turn a successful action into an error.
    pub fn audit_as(&self, uuid: &str, name: &str, action: &str, world: &str, target: &str, detail: Value) {
        let r = self.db.execute(
            "INSERT INTO audit_log(ts,actor,actor_name,action,world_id,target,detail) VALUES(?,?,?,?,?,?,?)",
            params![wall_s(), uuid, name, action, world, target, detail.to_string()],
        );
        if let Err(e) = r {
            eprintln!("audit {action} failed: {e}");
        }
    }

    pub fn audit(&self, device: &str, action: &str, world: &str, target: &str, detail: Value) {
        let (uuid, name) = self.device_player(device).ok().flatten().unwrap_or_default();
        self.audit_as(&uuid, &name, action, world, target, detail);
    }

    /// Newest first. `before` is the id of the last row of the previous page.
    pub fn audit_page(&self, world: Option<&str>, actor: Option<&str>, action: Option<&str>, before: Option<i64>, limit: i64) -> Result<Vec<Value>, Error> {
        let mut st = self.db.prepare(
            "SELECT id,ts,actor,actor_name,action,world_id,target,detail FROM audit_log \
             WHERE (?1 IS NULL OR world_id=?1) AND (?2 IS NULL OR actor=?2) AND (?3 IS NULL OR action=?3) AND (?4 IS NULL OR id<?4) \
             ORDER BY id DESC LIMIT ?5",
        )?;
        let rows = st.query_map(params![world, actor, action, before, limit], |r| {
            let detail: String = r.get(7)?;
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "actor": r.get::<_, String>(2)?, "actor_name": r.get::<_, String>(3)?,
                "action": r.get::<_, String>(4)?, "world": r.get::<_, String>(5)?, "target": r.get::<_, String>(6)?,
                "detail": serde_json::from_str::<Value>(&detail).unwrap_or(Value::Null),
            }))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// (status, reason, set_at)
    pub fn user_status(&self, uuid: &str) -> Result<Option<(String, String, i64)>, Error> {
        Ok(self
            .db
            .query_row("SELECT status, reason, set_at FROM user_status WHERE player_uuid=?", params![uuid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?)
    }

    /// None restores the account.
    pub fn set_user_status(&self, uuid: &str, status: Option<&str>, reason: &str, by: &str) -> Result<(), Error> {
        match status {
            Some(s) => self.db.execute(
                "INSERT INTO user_status(player_uuid,status,reason,set_by,set_at) VALUES(?,?,?,?,?) \
                 ON CONFLICT(player_uuid) DO UPDATE SET status=excluded.status, reason=excluded.reason, set_by=excluded.set_by, set_at=excluded.set_at",
                params![uuid, s, reason, by, wall_s()],
            )?,
            None => self.db.execute("DELETE FROM user_status WHERE player_uuid=?", params![uuid])?,
        };
        Ok(())
    }

    pub fn is_admin(&self, uuid: &str, from_config: &[String]) -> bool {
        from_config.iter().any(|a| a == uuid)
            || self.db.query_row("SELECT 1 FROM gateway_admins WHERE player_uuid=?", params![uuid], |_| Ok(())).is_ok()
    }

    pub fn set_gateway_admin(&self, uuid: &str, admin: bool, by: &str) -> Result<(), Error> {
        if admin {
            self.db.execute(
                "INSERT OR IGNORE INTO gateway_admins(player_uuid,granted_by,granted_at) VALUES(?,?,?)",
                params![uuid, by, wall_s()],
            )?;
        } else {
            self.db.execute("DELETE FROM gateway_admins WHERE player_uuid=?", params![uuid])?;
        }
        Ok(())
    }

    pub fn player_by_name(&self, name: &str) -> Result<Option<(String, String)>, Error> {
        Ok(self
            .db
            .query_row("SELECT uuid, name FROM players WHERE name=? COLLATE NOCASE", params![name], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }

    /// (retry_after_s, message) while maintenance mode is on.
    pub fn maintenance(&self) -> Option<(u64, String)> {
        let v: String = self.db.query_row("SELECT value FROM admin_settings WHERE key='maintenance'", [], |r| r.get(0)).ok()?;
        let v: Value = serde_json::from_str(&v).ok()?;
        Some((v["retry_after_s"].as_u64().unwrap_or(DEFAULT_RETRY_AFTER_S), v["message"].as_str().unwrap_or("").to_string()))
    }

    pub fn set_maintenance(&self, on: Option<(u64, &str)>) -> Result<(), Error> {
        match on {
            Some((retry, msg)) => self.db.execute(
                "INSERT OR REPLACE INTO admin_settings(key,value) VALUES('maintenance',?)",
                params![json!({ "retry_after_s": retry, "message": msg }).to_string()],
            )?,
            None => self.db.execute("DELETE FROM admin_settings WHERE key='maintenance'", [])?,
        };
        Ok(())
    }

    pub fn world_exists(&self, world: &str) -> bool {
        self.db.query_row("SELECT 1 FROM worlds WHERE id=?", params![world], |_| Ok(())).is_ok()
    }

    pub fn set_world_owner(&self, world: &str, uuid: &str) -> Result<(), Error> {
        self.db.execute(
            "INSERT INTO world_policy(world_id, owner_uuid) VALUES(?,?) ON CONFLICT(world_id) DO UPDATE SET owner_uuid=excluded.owner_uuid",
            params![world, uuid],
        )?;
        Ok(())
    }

    /// The recorded owner, else the oldest ADMIN member (worlds that predate this table).
    pub fn world_owner(&self, world: &str) -> Result<Option<String>, Error> {
        let rec: Option<String> = self
            .db
            .query_row("SELECT owner_uuid FROM world_policy WHERE world_id=?", params![world], |r| r.get(0))
            .optional()?
            .flatten();
        if rec.is_some() {
            return Ok(rec);
        }
        Ok(self
            .db
            .query_row("SELECT player_uuid FROM members WHERE world_id=? AND role='ADMIN' ORDER BY rowid LIMIT 1", params![world], |r| r.get(0))
            .optional()?)
    }

    pub fn host_policy(&self, world: &str) -> Result<String, Error> {
        Ok(self
            .db
            .query_row("SELECT host_policy FROM world_policy WHERE world_id=?", params![world], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| "MEMBERS".into()))
    }

    pub fn host_allowlist(&self, world: &str) -> Result<Vec<String>, Error> {
        let mut st = self.db.prepare(
            "SELECT p.name FROM world_host_allow a JOIN players p ON p.uuid=a.player_uuid WHERE a.world_id=? ORDER BY p.name COLLATE NOCASE",
        )?;
        let rows = st.query_map(params![world], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn world_requires_signed(&self, world: &str) -> bool {
        self.db.query_row("SELECT require_signed FROM world_policy WHERE world_id=?", params![world], |r| r.get::<_, bool>(0)).unwrap_or(false)
    }

    pub fn set_require_signed(&mut self, world: &str, on: bool) -> Result<(), Error> {
        self.db.execute(
            "INSERT INTO world_policy(world_id, require_signed) VALUES(?,?) ON CONFLICT(world_id) DO UPDATE SET require_signed=excluded.require_signed",
            params![world, on],
        )?;
        Ok(())
    }

    /// `allow` None keeps the current list.
    pub fn set_host_policy(&mut self, world: &str, policy: &str, allow: Option<&[String]>) -> Result<(), Error> {
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO world_policy(world_id, host_policy) VALUES(?,?) ON CONFLICT(world_id) DO UPDATE SET host_policy=excluded.host_policy",
            params![world, policy],
        )?;
        if let Some(allow) = allow {
            tx.execute("DELETE FROM world_host_allow WHERE world_id=?", params![world])?;
            for uuid in allow {
                tx.execute("INSERT OR IGNORE INTO world_host_allow(world_id,player_uuid) VALUES(?,?)", params![world, uuid])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether the device's player may bid for or take the host lease under the world's policy.
    /// Role checks (CLIENT_ONLY) stay in core; this only narrows them.
    pub fn may_host(&self, world: &str, device: &str) -> bool {
        let Ok(policy) = self.host_policy(world) else { return false };
        if policy == "MEMBERS" {
            return true;
        }
        let Ok(Some((uuid, _))) = self.device_player(device) else { return false };
        if self.world_owner(world).ok().flatten().as_deref() == Some(uuid.as_str()) {
            return true;
        }
        policy == "ALLOWLIST"
            && self
                .db
                .query_row("SELECT 1 FROM world_host_allow WHERE world_id=? AND player_uuid=?", params![world, uuid], |_| Ok(()))
                .is_ok()
    }

    pub(crate) fn is_member_uuid(&self, world: &str, uuid: &str) -> bool {
        self.db.query_row("SELECT 1 FROM members WHERE world_id=? AND player_uuid=?", params![world, uuid], |_| Ok(())).is_ok()
    }
}

fn restriction_code(status: &str) -> &'static str {
    if status == "BANNED" {
        "ACCOUNT_BANNED"
    } else {
        "ACCOUNT_SUSPENDED"
    }
}

fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "))
}

/// Lease-scoped traffic that lets a host wind down. Returns the last path segment.
fn lease_action(method: &Method, path: &str) -> Option<&'static str> {
    if method == Method::PUT && path.starts_with("/v1/blobs/") {
        return Some("blob");
    }
    let rest = path.strip_prefix("/v1/leases/")?;
    match rest.rsplit('/').next()? {
        "commit" => Some("commit"),
        "release" => Some("release"),
        "heartbeat" => Some("heartbeat"),
        "wal" => Some("wal"),
        "host-ready" => Some("host-ready"),
        _ => None,
    }
}

/// Per-request gate for suspended or banned accounts and maintenance mode. Requests without a valid
/// session pass through: the handler answers 401, and public pages stay public.
pub(crate) async fn gate(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if let Some(err) = judge(&s, req.headers(), req.method(), req.uri().path()) {
        return err.into_response();
    }
    next.run(req).await
}

fn judge(s: &AppState, h: &HeaderMap, method: &Method, path: &str) -> Option<ApiErr> {
    let tok = bearer(h)?;
    let gw = s.gw();
    let dev = gw.device_for_token(tok).ok()??;
    let (uuid, _) = gw.device_player(&dev).ok()??;
    let lease = lease_action(method, path);
    if let Some((status, _, since)) = gw.user_status(&uuid).ok()? {
        // the final commit decision needs the body, so the handler makes it
        let open = match lease {
            Some("commit" | "release") => true,
            Some(_) => (wall_s() - since).max(0) as u64 <= s.auth.ban_grace_s,
            None => false,
        };
        return (!open).then(|| ApiErr::Forbidden(restriction_code(&status)));
    }
    let (retry, msg) = gw.maintenance()?;
    let mutating = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let exempt = lease.is_some() || path.starts_with("/v1/auth/") || path == "/v1/logs";
    if mutating && !exempt && !gw.is_admin(&uuid, &s.auth.admins) {
        return Some(ApiErr::Maintenance(retry, msg));
    }
    None
}

impl AppState {
    /// A commit that is not final stops for restricted accounts and, outside admins, in maintenance.
    pub(crate) fn check_commit(&self, gw: &Gateway, device: &str, last: bool) -> Result<(), ApiErr> {
        if last {
            return Ok(());
        }
        let Some((uuid, _)) = gw.device_player(device)? else { return Ok(()) };
        if let Some((status, _, _)) = gw.user_status(&uuid)? {
            return Err(ApiErr::Forbidden(restriction_code(&status)));
        }
        if let Some((retry, msg)) = gw.maintenance() {
            if !gw.is_admin(&uuid, &self.auth.admins) {
                return Err(ApiErr::Maintenance(retry, msg));
            }
        }
        Ok(())
    }
}

/// (uuid, name) of the caller when they are a gateway admin.
/// Who is calling an admin route that a scoped API key may also use.
pub(crate) enum Actor {
    Admin(String),
    Key(i64, String),
}

impl Actor {
    fn record(&self, gw: &Gateway, action: &str, world: &str, target: &str, detail: Value) {
        match self {
            Actor::Admin(dev) => gw.audit(dev, action, world, target, detail),
            Actor::Key(id, name) => gw.audit_as(&format!("apikey:{id}"), name, action, world, target, detail),
        }
    }
}

/// A real admin, or an API key that carries `scope`. 401 for an unknown key, 403 `SCOPE_DENIED` for a key without the scope.
fn admin_or_key(s: &AppState, gw: &Gateway, h: &HeaderMap, scope: &str) -> Result<Actor, ApiErr> {
    if let Some(t) = bearer(h).filter(|t| t.starts_with(crate::apikeys::PREFIX)) {
        return match gw.check_api_key(t, scope)? {
            crate::apikeys::KeyCheck::Valid(id, name) => Ok(Actor::Key(id, name)),
            crate::apikeys::KeyCheck::Denied => Err(ApiErr::Forbidden("SCOPE_DENIED")),
            crate::apikeys::KeyCheck::Unknown => Err(ApiErr::Unauthorized),
        };
    }
    let dev = auth(gw, h)?;
    require_admin(s, gw, &dev)?;
    Ok(Actor::Admin(dev))
}

fn require_admin(s: &AppState, gw: &Gateway, dev: &str) -> Result<(String, String), ApiErr> {
    let (uuid, name) = gw.device_player(dev)?.ok_or(ApiErr::Unauthorized)?;
    if gw.is_admin(&uuid, &s.auth.admins) {
        Ok((uuid, name))
    } else {
        Err(ApiErr::Forbidden("ADMIN_ONLY"))
    }
}

/// Owner of the world or a gateway admin. Unknown worlds look like non-ownership to everyone else.
pub(crate) fn require_owner_or_admin(s: &AppState, gw: &Gateway, dev: &str, world: &str) -> Result<(String, String), ApiErr> {
    let (uuid, name) = gw.device_player(dev)?.ok_or(ApiErr::Unauthorized)?;
    if gw.is_admin(&uuid, &s.auth.admins) {
        return if gw.world_exists(world) { Ok((uuid, name)) } else { Err(ApiErr::Domain(Error::NoSuchWorld)) };
    }
    if gw.world_owner(world)?.as_deref() == Some(uuid.as_str()) {
        Ok((uuid, name))
    } else {
        Err(ApiErr::Forbidden("OWNER_ONLY"))
    }
}

fn page_args(q: &HashMap<String, String>) -> Result<(i64, Option<i64>), ApiErr> {
    let limit = match q.get("limit") {
        None => PAGE_DEFAULT,
        Some(v) => v.parse::<i64>().ok().filter(|n| (1..=PAGE_MAX).contains(n)).ok_or(ApiErr::BadRequest("BAD_PAGE"))?,
    };
    let before = match q.get("before") {
        None => None,
        Some(v) => Some(v.parse::<i64>().map_err(|_| ApiErr::BadRequest("BAD_PAGE"))?),
    };
    Ok((limit, before))
}

fn page_json(rows: Vec<Value>, limit: i64) -> Value {
    let next = (rows.len() as i64 == limit).then(|| rows.last().and_then(|r| r["id"].as_i64())).flatten();
    json!({ "entries": rows, "next_before": next })
}

async fn admin_audit(State(s): State<Arc<AppState>>, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> R {
    let gw = s.gw();
    admin_or_key(&s, &gw, &h, "read:status")?;
    let (limit, before) = page_args(&q)?;
    let rows = gw.audit_page(q.get("world").map(String::as_str), q.get("actor").map(String::as_str), q.get("action").map(String::as_str), before, limit)?;
    Ok(Json(page_json(rows, limit)))
}

async fn world_audit(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Query(q): Query<HashMap<String, String>>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    let (limit, before) = page_args(&q)?;
    let rows = gw.audit_page(Some(&world), q.get("actor").map(String::as_str), q.get("action").map(String::as_str), before, limit)?;
    Ok(Json(page_json(rows, limit)))
}

async fn get_user(State(s): State<Arc<AppState>>, h: HeaderMap, Path(name): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_admin(&s, &gw, &dev)?;
    let (uuid, name) = gw.player_by_name(&name)?.ok_or(ApiErr::NotFound("NO_SUCH_USER"))?;
    let st = gw.user_status(&uuid)?;
    Ok(Json(json!({
        "uuid": uuid, "name": name,
        "role": if gw.is_admin(&uuid, &s.auth.admins) { "admin" } else { "user" },
        "status": st.as_ref().map_or("ACTIVE", |x| x.0.as_str()),
        "reason": st.as_ref().map(|x| x.1.clone()),
    })))
}

#[derive(Deserialize)]
struct StatusReq {
    status: String,
    #[serde(default)]
    reason: String,
}

async fn put_status(State(s): State<Arc<AppState>>, h: HeaderMap, Path(name): Path<String>, Json(b): Json<StatusReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let (actor, _) = require_admin(&s, &gw, &dev)?;
    let status = match b.status.as_str() {
        "ACTIVE" => None,
        "SUSPENDED" | "BANNED" => Some(b.status.as_str()),
        _ => return Err(ApiErr::BadRequest("BAD_STATUS")),
    };
    if b.reason.len() > 256 {
        return Err(ApiErr::BadRequest("BAD_REASON"));
    }
    let (uuid, name) = gw.player_by_name(&name)?.ok_or(ApiErr::NotFound("NO_SUCH_USER"))?;
    if uuid == actor {
        return Err(ApiErr::Conflict("CANNOT_TARGET_SELF"));
    }
    gw.set_user_status(&uuid, status, &b.reason, &actor)?;
    let action = match status {
        Some("BANNED") => "user.ban",
        Some(_) => "user.suspend",
        None => "user.restore",
    };
    gw.audit(&dev, action, "", &name, json!({ "reason": b.reason }));
    Ok(Json(json!({ "ok": true, "status": b.status })))
}

#[derive(Deserialize)]
struct RoleReq {
    role: String,
}

async fn put_gateway_role(State(s): State<Arc<AppState>>, h: HeaderMap, Path(name): Path<String>, Json(b): Json<RoleReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let (actor, _) = require_admin(&s, &gw, &dev)?;
    let admin = match b.role.as_str() {
        "admin" => true,
        "user" => false,
        _ => return Err(ApiErr::BadRequest("BAD_ROLE")),
    };
    let (uuid, name) = gw.player_by_name(&name)?.ok_or(ApiErr::NotFound("NO_SUCH_USER"))?;
    if !admin {
        if uuid == actor {
            return Err(ApiErr::Conflict("CANNOT_TARGET_SELF"));
        }
        if s.auth.admins.contains(&uuid) {
            return Err(ApiErr::Conflict("ADMIN_FROM_CONFIG"));
        }
    }
    gw.set_gateway_admin(&uuid, admin, &actor)?;
    gw.audit(&dev, "role.gateway", "", &name, json!({ "role": b.role }));
    Ok(Json(json!({ "ok": true, "role": b.role })))
}

async fn get_maintenance(State(s): State<Arc<AppState>>, h: HeaderMap) -> R {
    let gw = s.gw();
    admin_or_key(&s, &gw, &h, "read:status")?;
    Ok(Json(match gw.maintenance() {
        Some((retry, msg)) => json!({ "on": true, "retry_after_s": retry, "message": msg }),
        None => json!({ "on": false }),
    }))
}

#[derive(Deserialize)]
struct MaintReq {
    on: bool,
    retry_after_s: Option<u64>,
    #[serde(default)]
    message: String,
}

async fn put_maintenance(State(s): State<Arc<AppState>>, h: HeaderMap, Json(b): Json<MaintReq>) -> R {
    let gw = s.gw();
    let actor = admin_or_key(&s, &gw, &h, "op:lifecycle")?;
    let retry = b.retry_after_s.unwrap_or(DEFAULT_RETRY_AFTER_S);
    if !(1..=MAX_RETRY_AFTER_S).contains(&retry) || b.message.len() > 256 {
        return Err(ApiErr::BadRequest("BAD_MAINTENANCE"));
    }
    gw.set_maintenance(b.on.then_some((retry, b.message.as_str())))?;
    actor.record(&gw, if b.on { "maintenance.on" } else { "maintenance.off" }, "", "", json!({ "retry_after_s": retry, "message": b.message }));
    Ok(Json(json!({ "ok": true, "on": b.on })))
}

async fn get_policy(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    let owner = gw.world_owner(&world)?.and_then(|u| gw.db.query_row("SELECT name FROM players WHERE uuid=?", params![u], |r| r.get::<_, String>(0)).ok());
    Ok(Json(json!({ "policy": gw.host_policy(&world)?, "owner": owner, "allow": gw.host_allowlist(&world)?, "require_signed": gw.world_requires_signed(&world), "handover_vote": gw.vote_enabled(&world) })))
}

#[derive(Deserialize)]
struct PolicyReq {
    policy: String,
    allow: Option<Vec<String>>,
}

async fn put_policy(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<PolicyReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    if !matches!(b.policy.as_str(), "OWNER" | "ALLOWLIST" | "MEMBERS") {
        return Err(ApiErr::BadRequest("BAD_POLICY"));
    }
    let mut uuids = None;
    if let Some(names) = &b.allow {
        if names.len() > 256 {
            return Err(ApiErr::BadRequest("BAD_POLICY"));
        }
        let mut v = Vec::new();
        for n in names {
            let (uuid, _) = gw.player_by_name(n)?.filter(|(u, _)| gw.is_member_uuid(&world, u)).ok_or(ApiErr::NotFound("NO_SUCH_MEMBER"))?;
            v.push(uuid);
        }
        uuids = Some(v);
    }
    gw.set_host_policy(&world, &b.policy, uuids.as_deref())?;
    gw.audit(&dev, "policy.host", &world, "", json!({ "policy": b.policy, "allow": b.allow }));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct SigningReq {
    require_signed: bool,
}

/// Owner switch: from now on commits to this world need a valid host signature (403 SIGNATURE_REQUIRED otherwise).
async fn put_signing(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<SigningReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    gw.set_require_signed(&world, b.require_signed)?;
    gw.audit(&dev, "policy.signing", &world, "", json!({ "require_signed": b.require_signed }));
    Ok(Json(json!({ "ok": true, "require_signed": b.require_signed })))
}

fn limit_json(l: &crate::quota::Limits) -> Value {
    json!({
        "storage_bytes": l.storage_bytes, "world_count": l.world_count, "keep_revisions": l.keep_revisions,
        "keep_days": l.keep_days, "max_guests": l.max_guests, "relay_bytes_month": l.relay_bytes_month,
    })
}

const USAGE_MAX_WORLDS: usize = 500;

/// Usage against limits for every world and every world owner, biggest storage first. Admin only.
async fn admin_usage(State(s): State<Arc<AppState>>, h: HeaderMap) -> R {
    use crate::quota::{month_meter, Scope};
    let gw = s.gw();
    admin_or_key(&s, &gw, &h, "read:status")?;
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let month = month_meter(wall_s());
    let ids: Vec<(String, String)> = {
        let mut st = gw.db.prepare("SELECT id, name FROM worlds").map_err(db)?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(db)?;
        rows.collect::<rusqlite::Result<_>>().map_err(db)?
    };
    let mut worlds = Vec::with_capacity(ids.len());
    let mut owner_set = std::collections::BTreeSet::new();
    for (id, name) in ids {
        let revisions: i64 = gw.db.query_row("SELECT COUNT(*) FROM revisions WHERE world_id=? AND pruned=0", params![id], |r| r.get(0)).map_err(db)?;
        let owner_uuid = gw.world_owner(&id)?;
        let owner = owner_uuid.as_ref().and_then(|u| gw.db.query_row("SELECT name FROM players WHERE uuid=?", params![u], |r| r.get::<_, String>(0)).ok());
        if let Some(u) = owner_uuid {
            owner_set.insert(u);
        }
        worlds.push(json!({
            "id": id, "name": name, "owner": owner,
            "storage_bytes": gw.world_usage(&id)?, "revisions": revisions,
            "relay_bytes_month": gw.meter_value(&id, &month),
            "commits": gw.meter_value(&id, "commits"),
            "limits": limit_json(&gw.limits(Scope::World, &id)?),
        }));
    }
    worlds.sort_by_key(|w| std::cmp::Reverse(w["storage_bytes"].as_u64().unwrap_or(0)));
    let total_worlds = worlds.len();
    worlds.truncate(USAGE_MAX_WORLDS);
    let mut owners: Vec<(String, String)> = Vec::new();
    for uuid in owner_set {
        if let Ok(name) = gw.db.query_row("SELECT name FROM players WHERE uuid=?", params![uuid], |r| r.get::<_, String>(0)) {
            owners.push((uuid, name));
        }
    }
    let mut users = Vec::with_capacity(owners.len());
    for (uuid, name) in owners {
        let (bytes, worlds_owned) = gw.user_usage(&uuid)?;
        users.push(json!({ "uuid": uuid, "name": name, "storage_bytes": bytes, "worlds": worlds_owned, "relay_bytes_month": gw.user_relay_month(&uuid, &month), "limits": limit_json(&gw.limits(Scope::User, &uuid)?) }));
    }
    users.sort_by_key(|u| std::cmp::Reverse(u["storage_bytes"].as_u64().unwrap_or(0)));
    Ok(Json(json!({
        "month": month.trim_start_matches("relay_month_"),
        "total_worlds": total_worlds, "worlds": worlds, "users": users,
    })))
}

#[derive(Deserialize)]
struct VoteSwitch {
    enabled: bool,
}

async fn put_vote_policy(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<VoteSwitch>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    gw.set_vote_enabled(&world, b.enabled)?;
    gw.audit(&dev, "policy.vote", &world, "", json!({ "enabled": b.enabled }));
    Ok(Json(json!({ "ok": true, "handover_vote": b.enabled })))
}

fn vote_error(e: crate::lease::VoteError) -> ApiErr {
    use crate::lease::VoteError::*;
    match e {
        Disabled => ApiErr::Forbidden("VOTE_DISABLED"),
        NotGuest => ApiErr::Forbidden("NOT_A_GUEST"),
        NoLiveHost => ApiErr::Conflict("NO_LIVE_HOST"),
        NotBetter => ApiErr::Conflict("NOT_BETTER"),
        TooEarly => ApiErr::Conflict("TOO_EARLY"),
        RoundOpen => ApiErr::Conflict("ROUND_OPEN"),
        Cooldown => ApiErr::Conflict("COOLDOWN"),
        NoRound => ApiErr::NotFound("NO_ROUND"),
    }
}

fn round_json(r: Option<&crate::lease::RoundView>) -> Value {
    match r {
        None => Value::Null,
        Some(r) => json!({
            "candidate": r.candidate_name, "improvement_pct": r.improvement_pct, "yes": r.yes, "no": r.no, "needed": r.needed,
            "my_vote": r.my_vote, "approved": r.approved, "expires_in_s": r.expires_in_s,
        }),
    }
}

async fn get_handover_vote(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    let now = s.now();
    let round = gw.handover_round(&world, &dev, now)?;
    Ok(Json(json!({ "enabled": gw.vote_enabled(&world), "round": round_json(round.as_ref()) })))
}

#[derive(Deserialize)]
struct ProposeReq {
    #[serde(default = "one")]
    tier: u8,
    score: f64,
}

fn one() -> u8 {
    1
}

async fn propose_handover(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<ProposeReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    if !b.score.is_finite() || b.score < 0.0 {
        return Err(ApiErr::BadRequest("BAD_SCORE"));
    }
    let now = s.now();
    let round = gw.propose_handover(&world, &dev, b.tier, b.score, now)?.map_err(vote_error)?;
    gw.audit(&dev, "vote.propose", &world, "", json!({ "improvement_pct": round.improvement_pct }));
    Ok(Json(json!({ "round": round_json(Some(&round)) })))
}

#[derive(Deserialize)]
struct VoteReq {
    yes: bool,
}

async fn cast_handover_vote(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<VoteReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    let now = s.now();
    let round = gw.cast_handover_vote(&world, &dev, b.yes, now)?.map_err(vote_error)?;
    Ok(Json(json!({ "round": round_json(Some(&round)) })))
}

#[derive(Deserialize)]
struct RollbackReq {
    revision: String,
    #[serde(default = "overworld")]
    dim: String,
    min_cx: i32,
    min_cz: i32,
    max_cx: i32,
    max_cz: i32,
}

fn overworld() -> String {
    "minecraft:overworld".into()
}

/// Restores the chunks inside a rectangle to an older revision, leaving the rest of the world as it is. Owner or admin, idle world only.
async fn rollback_region(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<RollbackReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    match gw.rollback_region(&world, &b.revision, &b.dim, b.min_cx, b.min_cz, b.max_cx, b.max_cz)? {
        Ok(r) => {
            gw.audit(&dev, "world.rollback_region", &world, &r.revision, json!({ "from": b.revision, "dim": b.dim, "restored": r.restored, "removed": r.removed }));
            Ok(Json(json!({ "revision": r.revision, "restored": r.restored, "removed": r.removed })))
        }
        Err("BAD_REGION") => Err(ApiErr::BadRequest("BAD_REGION")),
        Err("NO_SUCH_REVISION") => Err(ApiErr::NotFound("NO_SUCH_REVISION")),
        Err("REVISION_PRUNED") => Err(ApiErr::Gone("REVISION_PRUNED")),
        Err("WORLD_RUNNING") => Err(ApiErr::Conflict("WORLD_RUNNING")),
        Err(code) => Err(ApiErr::Conflict(code)),
    }
}

#[derive(Deserialize)]
struct KeyReq {
    name: String,
    scopes: Vec<String>,
}

async fn create_key(State(s): State<Arc<AppState>>, h: HeaderMap, Json(b): Json<KeyReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    let (_, admin) = require_admin(&s, &gw, &dev)?;
    match gw.create_api_key(&b.name, &b.scopes, &admin)? {
        Ok((id, secret)) => {
            gw.audit(&dev, "apikey.create", "", &id.to_string(), json!({ "name": b.name, "scopes": b.scopes }));
            Ok(Json(json!({ "id": id, "name": b.name, "scopes": b.scopes, "key": secret, "note": "shown once, store it now" })))
        }
        Err(code) => Err(ApiErr::BadRequest(code)),
    }
}

async fn list_keys(State(s): State<Arc<AppState>>, h: HeaderMap) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_admin(&s, &gw, &dev)?;
    Ok(Json(json!({ "keys": gw.list_api_keys()? })))
}

async fn revoke_key(State(s): State<Arc<AppState>>, h: HeaderMap, Path(id): Path<i64>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_admin(&s, &gw, &dev)?;
    if !gw.revoke_api_key(id)? {
        return Err(ApiErr::NotFound("NO_SUCH_KEY"));
    }
    gw.audit(&dev, "apikey.revoke", "", &id.to_string(), json!({}));
    Ok(Json(json!({ "ok": true })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/admin/api-keys", get(list_keys).post(create_key))
        .route("/v1/admin/api-keys/:id", axum::routing::delete(revoke_key))
        .route("/v1/worlds/:id/rollback", post(rollback_region))
        .route("/v1/worlds/:id/vote-policy", put(put_vote_policy))
        .route("/v1/worlds/:id/handover-vote", get(get_handover_vote).post(cast_handover_vote))
        .route("/v1/worlds/:id/handover-vote/propose", post(propose_handover))
        .route("/v1/admin/usage", get(admin_usage))
        .route("/v1/worlds/:id/transfer", post(post_transfer))
        .route("/v1/worlds/:id/fork", post(post_fork))
        .route("/v1/worlds/:id/template", put(put_template))
        .route("/v1/worlds/:id/aux/:ns/:key", get(aux_get).put(aux_put))
        .route("/v1/worlds/:id/reports", get(list_reports).post(world_report))
        .route("/v1/worlds/:id/reports/:rid/resolve", post(resolve_report))
        .route("/v1/worlds/:id/bans", get(world_bans).post(world_ban))
        .route("/v1/worlds/:id/banned", get(world_banned))
        .route("/v1/worlds/:id/appeals", get(list_appeals).post(world_appeal))
        .route("/v1/worlds/:id/appeals/:aid/decide", post(decide_appeal))
        .route("/v1/worlds/:id/moderation", get(moderation_log))
        .route("/v1/worlds/:id/bans/:name", axum::routing::delete(world_unban))
        .route("/v1/templates", get(list_templates))
        .route("/v1/templates/:id/fork", post(fork_template))
        .route("/v1/admin/blobs/batch", post(cas_blob_batch))
        .route("/v1/admin/blobs/:hash", get(cas_blob))
        .route("/v1/admin/worlds/:id/revisions", get(cas_revisions))
        .route("/v1/admin/worlds/:id/revisions/:rev/manifest", get(cas_manifest))
        .route("/v1/worlds/:id/signing", put(put_signing))
        .route("/v1/admin/audit", get(admin_audit))
        .route("/v1/admin/maintenance", get(get_maintenance).put(put_maintenance))
        .route("/v1/admin/users/:name", get(get_user))
        .route("/v1/admin/users/:name/status", put(put_status))
        .route("/v1/admin/users/:name/role", put(put_gateway_role))
        .route("/v1/worlds/:id/audit", get(world_audit))
        .route("/v1/worlds/:id/policy", get(get_policy).put(put_policy))
}

#[derive(Deserialize)]
struct ListQ {
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Revision list for external tools. Needs `read:cas` or an admin login.
async fn cas_revisions(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Query(q): Query<ListQ>) -> R {
    let gw = s.gw();
    admin_or_key(&s, &gw, &h, "read:cas")?;
    let head = gw.head(&world).map_err(|_| ApiErr::NotFound("NO_SUCH_WORLD"))?;
    let revisions = gw.revisions(&world, q.limit.unwrap_or(50).clamp(1, 200))?;
    Ok(Json(json!({ "head": head, "revisions": revisions })))
}

const MANIFEST_PAGE_MAX: usize = 5000;

/// Every leaf of one revision (aux files, then chunks) with its blob hash, paged. Blobs themselves are not served here.
async fn cas_manifest(State(s): State<Arc<AppState>>, h: HeaderMap, Path((world, rev)): Path<(String, String)>, Query(q): Query<ListQ>) -> R {
    let gw = s.gw();
    admin_or_key(&s, &gw, &h, "read:cas")?;
    let owned: Option<String> = gw
        .db
        .query_row("SELECT world_id FROM revisions WHERE id=?", params![rev], |r| r.get(0))
        .ok();
    if owned.as_deref() != Some(world.as_str()) {
        return Err(ApiErr::NotFound("NO_SUCH_REVISION"));
    }
    let root = gw.revision_root(&rev)?;
    let (offset, limit) = (q.offset.unwrap_or(0), q.limit.unwrap_or(1000).clamp(1, MANIFEST_PAGE_MAX));
    let (mut total, mut leaves) = (0usize, Vec::new());
    crate::manifest::for_each_leaf(&gw.cas, root, &mut |item, hash| {
        if total >= offset && leaves.len() < limit {
            let hash = crate::cas::hex(&hash);
            leaves.push(match item {
                crate::manifest::Item::Aux(path) => json!({ "type": "aux", "path": path, "hash": hash }),
                crate::manifest::Item::Chunk(k) => json!({ "type": "chunk", "dim": k.dim, "kind": format!("{:?}", k.kind).to_lowercase(), "cx": k.cx, "cz": k.cz, "hash": hash }),
            });
        }
        total += 1;
        Ok(())
    })
    .map_err(|e| ApiErr::Domain(Error::Store(format!("{e:?}"))))?;
    Ok(Json(json!({ "revision": rev, "total": total, "offset": offset, "leaves": leaves })))
}

/// Raw bytes of one stored blob for external tools. Needs `read:cas` or an admin login; the hash comes from a manifest leaf.
async fn cas_blob(State(s): State<Arc<AppState>>, h: HeaderMap, Path(hash): Path<String>) -> Result<Vec<u8>, ApiErr> {
    let gw = s.gw();
    admin_or_key(&s, &gw, &h, "read:cas")?;
    let want = crate::cas::parse_hex(&hash).ok_or(ApiErr::BadRequest("BAD_HASH"))?;
    if !gw.cas().has(&want) {
        return Err(ApiErr::NotFound("NO_SUCH_BLOB"));
    }
    gw.cas().get(&want).map_err(|e| ApiErr::Domain(Error::Store(e.to_string())))
}

impl Gateway {
    /// Hands the world to another member by name: they become ADMIN and the owner in both owner records.
    /// The previous owner keeps their ADMIN seat. The new owner's world-count limit still applies.
    pub fn transfer_world(&mut self, world: &str, to: &str) -> Result<std::result::Result<String, &'static str>, Error> {
        let uuid: Option<String> = self.db.query_row("SELECT uuid FROM players WHERE name=? COLLATE NOCASE", params![to], |r| r.get(0)).optional()?;
        let Some(uuid) = uuid else { return Ok(Err("NO_SUCH_PLAYER")) };
        let is_member: bool = self.db.query_row("SELECT 1 FROM members WHERE world_id=? AND player_uuid=?", params![world, uuid], |_| Ok(())).optional()?.is_some();
        if !is_member {
            return Ok(Err("NOT_A_MEMBER"));
        }
        if self.world_owner(world)?.as_deref() == Some(uuid.as_str()) {
            return Ok(Err("ALREADY_OWNER"));
        }
        self.check_world_count(&uuid)?;
        self.db.execute("UPDATE members SET role='ADMIN' WHERE world_id=? AND player_uuid=?", params![world, uuid])?;
        self.db.execute("UPDATE worlds SET owner_uuid=? WHERE id=?", params![uuid, world])?;
        self.set_world_owner(world, &uuid)?;
        Ok(Ok(uuid))
    }
}

#[derive(Deserialize)]
struct TransferReq {
    to: String,
}

async fn post_transfer(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<TransferReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    match gw.transfer_world(&world, &b.to)? {
        Ok(uuid) => {
            gw.audit(&dev, "world.transfer", &world, &uuid, json!({ "to": b.to }));
            Ok(Json(json!({ "ok": true, "owner": b.to })))
        }
        Err(code @ "NO_SUCH_PLAYER") => Err(ApiErr::NotFound(code)),
        Err(code) => Err(ApiErr::Conflict(code)),
    }
}

impl Gateway {
    /// New world, owned by the device's player, whose first revision is a copy of `rev` from `src`. Blobs are shared, not copied;
    /// they are tagged for the new world so its owner's usage and blob visibility are right. The source is never touched.
    pub fn fork_world(&mut self, device: &str, src: &str, rev: &str, name: &str) -> Result<std::result::Result<String, &'static str>, Error> {
        let in_src: Option<String> = self.db.query_row("SELECT world_id FROM revisions WHERE id=?", params![rev], |r| r.get(0)).optional()?;
        if in_src.as_deref() != Some(src) {
            return Ok(Err("NO_SUCH_REVISION"));
        }
        let root = match self.revision_root(rev) {
            Ok(r) => r,
            Err(Error::Pruned) => return Ok(Err("REVISION_PRUNED")),
            Err(e) => return Err(e),
        };
        let mut reach = std::collections::HashSet::new();
        crate::manifest::reachable(&self.cas, root, &mut reach)?;
        if reach.iter().any(|h| !self.cas.has(h)) {
            return Ok(Err("REVISION_INCOMPLETE"));
        }
        let (mc, loader, pack): (String, String, String) =
            self.db.query_row("SELECT mc_version, loader, pack_id FROM worlds WHERE id=?", params![src], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        let id = self.create_world_for(device, name, &mc, &loader)?;
        self.db.execute("UPDATE worlds SET pack_id=? WHERE id=?", params![pack, id])?;
        let first = format!("{id}:R_0000");
        self.db.execute("UPDATE revisions SET root_hash=? WHERE id=?", params![root.as_slice(), first])?;
        crate::lease::seal(&self.db, &first)?;
        for h in &reach {
            self.tag_blob(&id, h)?;
        }
        Ok(Ok(id))
    }
}

#[derive(Deserialize)]
struct ForkReq {
    rev: String,
    name: String,
}

async fn post_fork(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<ForkReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    if gw.role(&world, &dev).is_err() {
        return Err(ApiErr::NotFound("NO_SUCH_WORLD"));
    }
    if b.name.is_empty() || b.name.len() > 64 {
        return Err(ApiErr::BadRequest("BAD_NAME"));
    }
    match gw.fork_world(&dev, &world, &b.rev, &b.name)? {
        Ok(id) => {
            gw.audit(&dev, "world.fork", &world, &id, json!({ "rev": b.rev }));
            Ok(Json(json!({ "id": id })))
        }
        Err("REVISION_PRUNED") => Err(ApiErr::Gone("REVISION_PRUNED")),
        Err(code @ "NO_SUCH_REVISION") => Err(ApiErr::NotFound(code)),
        Err(code) => Err(ApiErr::Conflict(code)),
    }
}

#[derive(Deserialize)]
struct TemplateReq {
    on: bool,
    #[serde(default)]
    description: String,
}

/// Owner or admin lists a world as a template that any logged-in player can fork, or takes it off the list.
async fn put_template(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<TemplateReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    if b.description.len() > 280 {
        return Err(ApiErr::BadRequest("BAD_DESCRIPTION"));
    }
    if b.on {
        let (uuid, _) = gw.device_player(&dev)?.ok_or(ApiErr::Unauthorized)?;
        gw.db
            .execute(
                "INSERT OR REPLACE INTO world_templates(world_id, description, set_by, set_at) VALUES(?,?,?,?)",
                params![world, b.description, uuid, wall_s()],
            )
            .map_err(|e| ApiErr::Domain(Error::Db(e)))?;
    } else {
        gw.db.execute("DELETE FROM world_templates WHERE world_id=?", params![world]).map_err(|e| ApiErr::Domain(Error::Db(e)))?;
    }
    gw.audit(&dev, if b.on { "world.template.on" } else { "world.template.off" }, &world, &world, json!({}));
    Ok(Json(json!({ "ok": true })))
}

async fn list_templates(State(s): State<Arc<AppState>>, h: HeaderMap) -> R {
    let gw = s.gw();
    auth(&gw, &h)?;
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let mut st = gw
        .db
        .prepare("SELECT w.id, w.name, w.mc_version, w.loader, t.description FROM world_templates t JOIN worlds w ON w.id=t.world_id ORDER BY w.name")
        .map_err(db)?;
    let rows = st
        .query_map([], |r| Ok(json!({ "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "mc_version": r.get::<_, String>(2)?, "loader": r.get::<_, String>(3)?, "description": r.get::<_, String>(4)? })))
        .map_err(db)?;
    Ok(Json(json!({ "templates": rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)? })))
}

#[derive(Deserialize)]
struct TemplateForkReq {
    name: String,
}

/// Forks the template's current head into a new world owned by the caller; the caller does not need to be a member.
async fn fork_template(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<TemplateForkReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    let listed = gw.db.query_row("SELECT 1 FROM world_templates WHERE world_id=?", params![world], |_| Ok(())).optional().map_err(|e| ApiErr::Domain(Error::Db(e)))?.is_some();
    if !listed {
        return Err(ApiErr::NotFound("NO_SUCH_TEMPLATE"));
    }
    if b.name.is_empty() || b.name.len() > 64 {
        return Err(ApiErr::BadRequest("BAD_NAME"));
    }
    let head = gw.head(&world)?;
    match gw.fork_world(&dev, &world, &head, &b.name)? {
        Ok(id) => {
            gw.audit(&dev, "world.fork", &world, &id, json!({ "rev": head, "template": true }));
            Ok(Json(json!({ "id": id })))
        }
        Err("REVISION_PRUNED") => Err(ApiErr::Gone("REVISION_PRUNED")),
        Err(code) => Err(ApiErr::Conflict(code)),
    }
}

#[derive(Deserialize)]
struct BatchReq {
    hashes: Vec<String>,
}

const BATCH_MAX_HASHES: usize = 256;
const BATCH_MAX_BYTES: usize = 16 << 20;

/// Frames per requested hash, in order: 32 raw hash bytes, a status byte (0 missing, 1 present, 2 deferred
/// because the response is full, ask again), and for 1 a u32 big-endian length plus the decompressed bytes.
async fn cas_blob_batch(State(s): State<Arc<AppState>>, h: HeaderMap, Json(b): Json<BatchReq>) -> Result<Vec<u8>, ApiErr> {
    let gw = s.gw();
    admin_or_key(&s, &gw, &h, "read:cas")?;
    if b.hashes.len() > BATCH_MAX_HASHES {
        return Err(ApiErr::BadRequest("TOO_MANY_HASHES"));
    }
    let mut out = Vec::new();
    for hex in &b.hashes {
        let want = crate::cas::parse_hex(hex).ok_or(ApiErr::BadRequest("BAD_HASH"))?;
        out.extend_from_slice(&want);
        if !gw.cas().has(&want) {
            out.push(0);
        } else if out.len() >= BATCH_MAX_BYTES {
            out.push(2);
        } else {
            let data = gw.cas().get(&want).map_err(|e| ApiErr::Domain(Error::Store(e.to_string())))?;
            out.push(1);
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

const AUX_MAX_VALUE: usize = 64 << 10;
const AUX_MAX_KEYS: i64 = 256;

fn aux_name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

/// Small per-world key-value store for tools and mods: any member reads, the owner or an admin writes.
async fn aux_get(State(s): State<Arc<AppState>>, h: HeaderMap, Path((world, ns, key)): Path<(String, String, String)>) -> Result<Vec<u8>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let (uuid, _) = gw.device_player(&dev)?.ok_or(ApiErr::Unauthorized)?;
    if !gw.is_member_uuid(&world, &uuid) && !gw.is_admin(&uuid, &s.auth.admins) {
        return Err(ApiErr::Forbidden("NOT_A_MEMBER"));
    }
    let v: Option<Vec<u8>> = gw
        .db
        .query_row("SELECT value FROM world_aux WHERE world_id=? AND ns=? AND key=?", params![world, ns, key], |r| r.get(0))
        .optional()
        .map_err(|e| ApiErr::Domain(Error::Db(e)))?;
    v.ok_or(ApiErr::NotFound("NO_SUCH_KEY"))
}

async fn aux_put(State(s): State<Arc<AppState>>, h: HeaderMap, Path((world, ns, key)): Path<(String, String, String)>, body: axum::body::Bytes) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    if !aux_name_ok(&ns) || !aux_name_ok(&key) {
        return Err(ApiErr::BadRequest("BAD_KEY"));
    }
    if body.len() > AUX_MAX_VALUE {
        return Err(ApiErr::BadRequest("VALUE_TOO_LARGE"));
    }
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let exists = gw.db.query_row("SELECT 1 FROM world_aux WHERE world_id=? AND ns=? AND key=?", params![world, ns, key], |_| Ok(())).optional().map_err(db)?.is_some();
    if !exists {
        let n: i64 = gw.db.query_row("SELECT COUNT(*) FROM world_aux WHERE world_id=?", params![world], |r| r.get(0)).map_err(db)?;
        if n >= AUX_MAX_KEYS {
            return Err(ApiErr::Conflict("TOO_MANY_KEYS"));
        }
    }
    let (uuid, _) = gw.device_player(&dev)?.ok_or(ApiErr::Unauthorized)?;
    gw.db
        .execute(
            "INSERT OR REPLACE INTO world_aux(world_id, ns, key, value, updated_by, updated_at) VALUES(?,?,?,?,?,?)",
            params![world, ns, key, body.to_vec(), uuid, wall_s()],
        )
        .map_err(db)?;
    Ok(Json(json!({ "ok": true })))
}

impl Gateway {
    pub(crate) fn is_world_banned(&self, world: &str, uuid: &str) -> bool {
        self.db.query_row("SELECT 1 FROM world_bans WHERE world_id=? AND player_uuid=?", params![world, uuid], |_| Ok(())).is_ok()
    }

    pub(crate) fn invite_world(&self, code: &str) -> Option<String> {
        self.db.query_row("SELECT world_id FROM invites WHERE code=?", params![code.to_uppercase()], |r| r.get(0)).ok()
    }
}

#[derive(Deserialize)]
struct BanReq {
    name: String,
    #[serde(default)]
    reason: String,
}

/// Owner or admin bans a player from one world: they lose their seat and cannot redeem an invite for it again.
async fn world_ban(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<BanReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    let (actor, _) = require_owner_or_admin(&s, &gw, &dev, &world)?;
    if b.reason.len() > 256 {
        return Err(ApiErr::BadRequest("BAD_REASON"));
    }
    let (uuid, name) = gw.player_by_name(&b.name)?.ok_or(ApiErr::NotFound("NO_SUCH_USER"))?;
    if uuid == actor {
        return Err(ApiErr::Conflict("CANNOT_TARGET_SELF"));
    }
    if gw.world_owner(&world)?.as_deref() == Some(uuid.as_str()) {
        return Err(ApiErr::Conflict("CANNOT_BAN_OWNER"));
    }
    gw.db
        .execute(
            "INSERT OR REPLACE INTO world_bans(world_id, player_uuid, reason, banned_by, banned_at) VALUES(?,?,?,?,?)",
            params![world, uuid, b.reason, actor, wall_s()],
        )
        .map_err(|e| ApiErr::Domain(Error::Db(e)))?;
    gw.set_member_unchecked(&world, &name, None)?;
    gw.audit(&dev, "world.ban", &world, &name, json!({ "reason": b.reason }));
    s.hooks.emit("member.banned", &world, json!({ "player": name }));
    Ok(Json(json!({ "ok": true })))
}

async fn world_unban(State(s): State<Arc<AppState>>, h: HeaderMap, Path((world, name)): Path<(String, String)>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    let (uuid, name) = gw.player_by_name(&name)?.ok_or(ApiErr::NotFound("NO_SUCH_USER"))?;
    let n = gw.db.execute("DELETE FROM world_bans WHERE world_id=? AND player_uuid=?", params![world, uuid]).map_err(|e| ApiErr::Domain(Error::Db(e)))?;
    if n == 0 {
        return Err(ApiErr::NotFound("NOT_BANNED"));
    }
    gw.audit(&dev, "world.unban", &world, &name, json!({}));
    Ok(Json(json!({ "ok": true })))
}

async fn world_bans(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let mut st = gw
        .db
        .prepare("SELECT p.name, b.reason, b.banned_at FROM world_bans b JOIN players p ON p.uuid=b.player_uuid WHERE b.world_id=? ORDER BY b.banned_at DESC")
        .map_err(db)?;
    let rows = st.query_map(params![world], |r| Ok(json!({ "name": r.get::<_, String>(0)?, "reason": r.get::<_, String>(1)?, "banned_at": r.get::<_, i64>(2)? }))).map_err(db)?;
    Ok(Json(json!({ "bans": rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)? })))
}

/// Any member of the world can read who is banned (names and ids, no reasons): the host applies it to its own ban list.
async fn world_banned(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let mut st = gw.db.prepare("SELECT p.uuid, p.name FROM world_bans b JOIN players p ON p.uuid=b.player_uuid WHERE b.world_id=? ORDER BY p.name").map_err(db)?;
    let rows = st.query_map(params![world], |r| Ok(json!({ "uuid": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)? }))).map_err(db)?;
    Ok(Json(json!({ "banned": rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)? })))
}

#[derive(Deserialize)]
struct AppealReq {
    text: String,
}

/// A banned player says why the ban should be lifted. One open appeal per player and world; the owner or an admin decides.
async fn world_appeal(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<AppealReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let (me, _) = gw.device_player(&dev)?.ok_or(ApiErr::Unauthorized)?;
    if !gw.is_world_banned(&world, &me) {
        return Err(ApiErr::Conflict("NOT_BANNED"));
    }
    if b.text.trim().is_empty() || b.text.len() > 1000 {
        return Err(ApiErr::BadRequest("BAD_TEXT"));
    }
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let open: i64 = gw.db.query_row("SELECT COUNT(*) FROM world_appeals WHERE world_id=? AND player_uuid=? AND resolved_at IS NULL", params![world, me], |r| r.get(0)).map_err(db)?;
    if open > 0 {
        return Err(ApiErr::Conflict("APPEAL_ALREADY_OPEN"));
    }
    gw.db.execute("INSERT INTO world_appeals(world_id, player_uuid, text, created_at) VALUES(?,?,?,?)", params![world, me, b.text, wall_s()]).map_err(db)?;
    let id = gw.db.last_insert_rowid();
    gw.audit(&dev, "world.appeal", &world, &id.to_string(), json!({}));
    s.hooks.emit("member.appealed", &world, json!({ "appeal": id }));
    Ok(Json(json!({ "id": id })))
}

async fn list_appeals(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Query(q): Query<HashMap<String, String>>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    let all = q.get("all").is_some_and(|v| v == "1");
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let mut st = gw
        .db
        .prepare(
            "SELECT a.id, p.name, a.text, a.created_at, a.resolved_at, a.decision, a.note FROM world_appeals a JOIN players p ON p.uuid=a.player_uuid \
             WHERE a.world_id=? AND (?2 OR a.resolved_at IS NULL) ORDER BY a.id DESC LIMIT 200",
        )
        .map_err(db)?;
    let rows = st
        .query_map(params![world, all], |r| {
            Ok(json!({ "id": r.get::<_, i64>(0)?, "player": r.get::<_, String>(1)?, "text": r.get::<_, String>(2)?, "created_at": r.get::<_, i64>(3)?,
                       "resolved_at": r.get::<_, Option<i64>>(4)?, "decision": r.get::<_, String>(5)?, "note": r.get::<_, String>(6)? }))
        })
        .map_err(db)?;
    Ok(Json(json!({ "appeals": rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)? })))
}

#[derive(Deserialize)]
struct DecideReq {
    decision: String,
    #[serde(default)]
    note: String,
}

/// `lift` removes the ban (the seat is not given back: invite the player again), `keep` closes the appeal and leaves the ban.
async fn decide_appeal(State(s): State<Arc<AppState>>, h: HeaderMap, Path((world, id)): Path<(String, i64)>, Json(b): Json<DecideReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    if b.decision != "lift" && b.decision != "keep" {
        return Err(ApiErr::BadRequest("BAD_DECISION"));
    }
    if b.note.len() > 1000 {
        return Err(ApiErr::BadRequest("BAD_NOTE"));
    }
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let who: String = gw
        .db
        .query_row("SELECT player_uuid FROM world_appeals WHERE id=? AND world_id=? AND resolved_at IS NULL", params![id, world], |r| r.get(0))
        .map_err(|_| ApiErr::NotFound("NO_SUCH_APPEAL"))?;
    gw.db.execute("UPDATE world_appeals SET resolved_at=?, decision=?, note=? WHERE id=?", params![wall_s(), b.decision, b.note, id]).map_err(db)?;
    if b.decision == "lift" {
        gw.db.execute("DELETE FROM world_bans WHERE world_id=? AND player_uuid=?", params![world, who]).map_err(db)?;
    }
    gw.audit(&dev, "world.appeal.decide", &world, &id.to_string(), json!({ "decision": b.decision }));
    Ok(Json(json!({ "ok": true })))
}

/// The dispute log: every ban, unban, report, appeal and decision for the world, newest first, from the append-only audit log.
async fn moderation_log(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    let rows = gw.audit_page(Some(&world), None, None, None, 1000)?;
    let keep: Vec<Value> = rows
        .into_iter()
        .filter(|r| r["action"].as_str().is_some_and(|a| matches!(a, "world.ban" | "world.unban" | "world.report" | "world.report.resolve" | "world.appeal" | "world.appeal.decide")))
        .take(200)
        .collect();
    Ok(Json(json!({ "events": keep })))
}

impl Gateway {
    /// Human-readable difference between two revisions: totals, every changed extra file, and the first `chunk_lines` chunks.
    pub fn diff_report(&self, a: &str, b: &str, chunk_lines: usize) -> Result<Vec<String>, Error> {
        use crate::manifest::{self, Item};
        let diffs = manifest::diff(self.cas(), Some(self.revision_root(a)?), Some(self.revision_root(b)?)).map_err(|e| Error::Store(e.to_string()))?;
        let sign = |d: &manifest::Diff| match (d.old, d.new) {
            (None, _) => '+',
            (_, None) => '-',
            _ => '~',
        };
        let (mut add, mut chg, mut del) = (0, 0, 0);
        let (mut aux, mut chunks) = (Vec::new(), Vec::new());
        for d in &diffs {
            match &d.item {
                Item::Aux(p) => aux.push(format!("  {} {p}", sign(d))),
                Item::Chunk(k) => {
                    match sign(d) {
                        '+' => add += 1,
                        '-' => del += 1,
                        _ => chg += 1,
                    }
                    chunks.push(format!("  {} {} {:?} {},{}", sign(d), k.dim, k.kind, k.cx, k.cz));
                }
            }
        }
        let mut out = vec![format!("{a} -> {b}: chunks {add} added, {chg} changed, {del} removed; {} extra files changed", aux.len())];
        out.extend(aux);
        let more = chunks.len().saturating_sub(chunk_lines);
        out.extend(chunks.into_iter().take(chunk_lines));
        if more > 0 {
            out.push(format!("  ... {more} more chunks"));
        }
        Ok(out)
    }
}

const REPORTS_OPEN_PER_REPORTER: i64 = 5;

#[derive(Deserialize)]
struct ReportReq {
    name: String,
    reason: String,
}

/// Any member can flag another member to the world owner; the target is never told.
async fn world_report(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<ReportReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    if b.reason.trim().is_empty() || b.reason.len() > 1000 {
        return Err(ApiErr::BadRequest("BAD_REASON"));
    }
    let (me, _) = gw.device_player(&dev)?.ok_or(ApiErr::Unauthorized)?;
    let (target, name) = gw.player_by_name(&b.name)?.ok_or(ApiErr::NotFound("NO_SUCH_USER"))?;
    if target == me {
        return Err(ApiErr::Conflict("CANNOT_TARGET_SELF"));
    }
    if !gw.is_member_uuid(&world, &target) {
        return Err(ApiErr::NotFound("NOT_A_MEMBER"));
    }
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let open: i64 = gw.db.query_row("SELECT COUNT(*) FROM world_reports WHERE world_id=? AND reporter=? AND resolved_at IS NULL", params![world, me], |r| r.get(0)).map_err(db)?;
    if open >= REPORTS_OPEN_PER_REPORTER {
        return Err(ApiErr::Conflict("TOO_MANY_OPEN_REPORTS"));
    }
    gw.db
        .execute("INSERT INTO world_reports(world_id, reporter, target, reason, created_at) VALUES(?,?,?,?,?)", params![world, me, target, b.reason, wall_s()])
        .map_err(db)?;
    let id = gw.db.last_insert_rowid();
    gw.audit(&dev, "world.report", &world, &name, json!({ "report": id }));
    s.hooks.emit("member.reported", &world, json!({ "report": id }));
    Ok(Json(json!({ "id": id })))
}

async fn list_reports(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Query(q): Query<HashMap<String, String>>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    let all = q.get("all").is_some_and(|v| v == "1");
    let db = |e: rusqlite::Error| ApiErr::Domain(Error::Db(e));
    let mut st = gw
        .db
        .prepare(
            "SELECT r.id, rp.name, tp.name, r.reason, r.created_at, r.resolved_at, r.note FROM world_reports r \
             JOIN players rp ON rp.uuid=r.reporter JOIN players tp ON tp.uuid=r.target \
             WHERE r.world_id=? AND (?2 OR r.resolved_at IS NULL) ORDER BY r.id DESC LIMIT 200",
        )
        .map_err(db)?;
    let rows = st
        .query_map(params![world, all], |r| {
            Ok(json!({ "id": r.get::<_, i64>(0)?, "reporter": r.get::<_, String>(1)?, "target": r.get::<_, String>(2)?, "reason": r.get::<_, String>(3)?,
                       "created_at": r.get::<_, i64>(4)?, "resolved_at": r.get::<_, Option<i64>>(5)?, "note": r.get::<_, String>(6)? }))
        })
        .map_err(db)?;
    Ok(Json(json!({ "reports": rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db)? })))
}

#[derive(Deserialize)]
struct ResolveReq {
    #[serde(default)]
    note: String,
}

async fn resolve_report(State(s): State<Arc<AppState>>, h: HeaderMap, Path((world, id)): Path<(String, i64)>, Json(b): Json<ResolveReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_owner_or_admin(&s, &gw, &dev, &world)?;
    if b.note.len() > 1000 {
        return Err(ApiErr::BadRequest("BAD_NOTE"));
    }
    let n = gw
        .db
        .execute("UPDATE world_reports SET resolved_at=?, note=? WHERE id=? AND world_id=? AND resolved_at IS NULL", params![wall_s(), b.note, id, world])
        .map_err(|e| ApiErr::Domain(Error::Db(e)))?;
    if n == 0 {
        return Err(ApiErr::NotFound("NO_SUCH_REPORT"));
    }
    gw.audit(&dev, "world.report.resolve", &world, &id.to_string(), json!({}));
    Ok(Json(json!({ "ok": true })))
}
