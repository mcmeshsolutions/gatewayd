//! Web panel and the admin-only APIs behind it. Gateway permissions are managed here, never in game.
use crate::lease::{Error, Gateway, Role};
use crate::server::{auth, ApiErr, AppState};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CODE_TTL: Duration = Duration::from_secs(300);
type R = Result<Json<Value>, ApiErr>;

impl Gateway {
    /// Allowlist document: {"allow":[{"id","hash"}],"ignore":["id"]}. Empty object means no restriction.
    pub fn world_mods(&self, world: &str) -> Result<Value, Error> {
        let s: Option<String> = self
            .db
            .query_row("SELECT mods_json FROM worlds WHERE id=?", params![world], |r| r.get(0))
            .optional()?
            .ok_or(Error::NoSuchWorld)?;
        Ok(s.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| json!({})))
    }

    pub fn set_world_mods(&mut self, device: &str, world: &str, doc: &Value) -> Result<(), Error> {
        if self.role(world, device)? != Role::Admin {
            return Err(Error::NotMember);
        }
        self.db.execute("UPDATE worlds SET mods_json=? WHERE id=?", params![doc.to_string(), world])?;
        Ok(())
    }

    pub fn record_bench(&mut self, device: &str, bench: &Value) -> Result<(), Error> {
        self.db.execute(
            "UPDATE devices SET hw_json=?, last_seen=? WHERE id=?",
            params![bench.to_string(), crate::lease::wall_s(), device],
        )?;
        Ok(())
    }

    /// Latest reported hardware of each member's most recently seen device.
    pub fn members_hw(&self, world: &str) -> Result<Vec<Value>, Error> {
        let mut st = self.db.prepare(
            "SELECT p.name, m.role,
               (SELECT d.hw_json FROM devices d WHERE d.player_uuid=p.uuid AND d.hw_json IS NOT NULL ORDER BY d.last_seen DESC LIMIT 1),
               (SELECT MAX(d.last_seen) FROM devices d WHERE d.player_uuid=p.uuid AND d.hw_json IS NOT NULL)
             FROM members m JOIN players p ON p.uuid=m.player_uuid WHERE m.world_id=? ORDER BY p.name COLLATE NOCASE",
        )?;
        let rows = st.query_map(params![world], |r| {
            let hw: Option<String> = r.get(2)?;
            Ok(json!({
                "name": r.get::<_, String>(0)?, "role": r.get::<_, String>(1)?,
                "hw": hw.and_then(|h| serde_json::from_str::<Value>(&h).ok()), "seen": r.get::<_, Option<i64>>(3)?,
            }))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn add_mod_requests(&mut self, device: &str, world: &str, mods: &[(String, String)]) -> Result<(), Error> {
        self.require_member(world, device)?;
        let uuid: String = self.db.query_row("SELECT player_uuid FROM devices WHERE id=?", params![device], |r| r.get(0))?;
        for (id, hash) in mods.iter().take(64) {
            self.db.execute(
                "INSERT OR REPLACE INTO mod_requests(world_id,mod_id,hash,player_uuid,created_at) VALUES(?,?,?,?,?)",
                params![world, id, hash, uuid, crate::lease::wall_s()],
            )?;
        }
        Ok(())
    }

    pub fn mod_requests(&self, world: &str) -> Result<Vec<Value>, Error> {
        let mut st = self.db.prepare(
            "SELECT r.mod_id, r.hash, p.name, r.created_at FROM mod_requests r JOIN players p ON p.uuid=r.player_uuid
             WHERE r.world_id=? ORDER BY r.created_at DESC",
        )?;
        let rows = st.query_map(params![world], |r| {
            Ok(json!({ "id": r.get::<_, String>(0)?, "hash": r.get::<_, String>(1)?, "player": r.get::<_, String>(2)?, "at": r.get::<_, i64>(3)? }))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Approving swaps the allowlist entry for that mod id. Returns false when the world has no allowlist to extend.
    pub fn resolve_mod_request(&mut self, device: &str, world: &str, id: &str, hash: &str, approve: bool) -> Result<bool, Error> {
        if self.role(world, device)? != Role::Admin {
            return Err(Error::NotMember);
        }
        if approve {
            let mut doc = self.world_mods(world)?;
            let allow = doc.get("allow").and_then(|a| a.as_array()).cloned().unwrap_or_default();
            if allow.is_empty() {
                return Ok(false);
            }
            let mut allow: Vec<Value> = allow.into_iter().filter(|e| e.get("id").and_then(|v| v.as_str()) != Some(id)).collect();
            allow.push(json!({ "id": id, "hash": hash }));
            doc["allow"] = Value::Array(allow);
            self.db.execute("UPDATE worlds SET mods_json=? WHERE id=?", params![doc.to_string(), world])?;
            self.db.execute("DELETE FROM mod_requests WHERE world_id=? AND mod_id=?", params![world, id])?;
        } else {
            self.db.execute("DELETE FROM mod_requests WHERE world_id=? AND mod_id=? AND hash=?", params![world, id, hash])?;
        }
        Ok(true)
    }

    pub fn members(&self, world: &str) -> Result<Vec<(String, String)>, Error> {
        let mut st = self.db.prepare(
            "SELECT p.name, m.role FROM members m JOIN players p ON p.uuid=m.player_uuid WHERE m.world_id=? ORDER BY p.name COLLATE NOCASE",
        )?;
        let rows = st.query_map(params![world], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// `role` None removes the member. The last admin cannot be demoted or removed.
    pub fn set_member(&mut self, device: &str, world: &str, name: &str, role: Option<Role>) -> Result<bool, Error> {
        if self.role(world, device)? != Role::Admin {
            return Err(Error::NotMember);
        }
        let uuid: Option<String> = self
            .db
            .query_row("SELECT uuid FROM players WHERE name=? COLLATE NOCASE", params![name], |r| r.get(0))
            .optional()?;
        let Some(uuid) = uuid else { return Ok(false) };
        let admins: i64 = self.db.query_row("SELECT COUNT(*) FROM members WHERE world_id=? AND role='ADMIN'", params![world], |r| r.get(0))?;
        let cur: Option<String> =
            self.db.query_row("SELECT role FROM members WHERE world_id=? AND player_uuid=?", params![world, uuid], |r| r.get(0)).optional()?;
        if cur.as_deref() == Some("ADMIN") && admins <= 1 && role != Some(Role::Admin) {
            return Ok(false);
        }
        match role {
            Some(r) => self.db.execute(
                "INSERT OR REPLACE INTO members(world_id,player_uuid,role) VALUES(?,?,?)",
                params![world, uuid, r.as_str()],
            )?,
            None => self.db.execute("DELETE FROM members WHERE world_id=? AND player_uuid=?", params![world, uuid])?,
        };
        Ok(true)
    }

    /// Newest first. Each entry is a commit: who hosted it, what kind, and how many chunks and files it touched.
    pub fn revisions(&self, world: &str, limit: usize) -> Result<Vec<Value>, Error> {
        let mut st = self.db.prepare(
            "SELECT r.id, r.parent_id, r.seq, r.kind, r.created_at, r.root_hash, \
               (SELECT p.name FROM leases l JOIN devices d ON d.id=l.device_id JOIN players p ON p.uuid=d.player_uuid WHERE l.id=r.lease_id) \
             FROM revisions r WHERE r.world_id=? ORDER BY r.seq DESC LIMIT ?",
        )?;
        let rows: Vec<(String, Option<String>, i64, String, i64, Vec<u8>, Option<String>)> = st
            .query_map(params![world, limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for (id, parent, seq, kind, at, root, by) in rows {
            let to = <[u8; 32]>::try_from(root.as_slice()).ok();
            let from = match &parent {
                Some(p) => Some(self.revision_root(p)?),
                None => None,
            };
            let (chunks, files) = crate::manifest::diff(&self.cas, from, to)?.iter().fold((0, 0), |(c, f), d| match d.item {
                crate::manifest::Item::Chunk(_) => (c + 1, f),
                crate::manifest::Item::Aux(_) => (c, f + 1),
            });
            out.push(json!({ "id": id, "seq": seq, "kind": kind, "at": at, "by": by, "chunks": chunks, "files": files }));
        }
        Ok(out)
    }

    /// Adds a new revision whose content equals `rev`. History is kept, so a revert can itself be reverted.
    /// Only an idle world can be reverted, otherwise the running host would overwrite it on its next commit.
    pub fn revert(&mut self, device: &str, world: &str, rev: &str) -> Result<Result<String, &'static str>, Error> {
        if self.role(world, device)? != Role::Admin {
            return Err(Error::NotMember);
        }
        if self.revision_world(rev)?.as_deref() != Some(world) {
            return Ok(Err("NO_SUCH_REVISION"));
        }
        if self.world_state(world)?.0 != "IDLE" {
            return Ok(Err("WORLD_RUNNING"));
        }
        let head = self.head(world)?;
        let root = self.revision_root(rev)?;
        let tx = self.db.transaction()?;
        let seq: i64 = tx.query_row("SELECT MAX(seq)+1 FROM revisions WHERE world_id=?", params![world], |r| r.get(0))?;
        let id = format!("{world}:R_{seq:04}");
        tx.execute(
            "INSERT INTO revisions(id,world_id,parent_id,root_hash,seq,kind,created_at) VALUES(?,?,?,?,?,'ROLLBACK',?)",
            params![id, world, head, root.as_slice(), seq, crate::lease::wall_s()],
        )?;
        crate::lease::seal(&tx, &id)?;
        tx.execute("UPDATE refs SET rev_id=? WHERE world_id=? AND name='main'", params![id, world])?;
        tx.commit()?;
        Ok(Ok(id))
    }
}

async fn get_mods(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    Ok(Json(gw.world_mods(&world)?))
}

async fn put_mods(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(doc): Json<Value>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    if !doc.is_object() {
        return Err(ApiErr::BadRequest("BAD_DOC"));
    }
    gw.set_world_mods(&dev, &world, &doc)?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_members(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    Ok(Json(json!({ "members": gw.members_hw(&world)? })))
}

#[derive(Deserialize)]
struct MemberReq {
    name: String,
    role: Option<String>,
}

async fn put_member(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<MemberReq>) -> R {
    let role = match b.role.as_deref() {
        None => None,
        Some("ADMIN") => Some(Role::Admin),
        Some("HOST_ELIGIBLE") => Some(Role::HostEligible),
        Some("CLIENT_ONLY") => Some(Role::ClientOnly),
        _ => return Err(ApiErr::BadRequest("BAD_ROLE")),
    };
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    if gw.set_member(&dev, &world, &b.name, role)? {
        Ok(Json(json!({ "ok": true })))
    } else {
        Err(ApiErr::Conflict("NO_SUCH_PLAYER_OR_LAST_ADMIN"))
    }
}

#[derive(Deserialize)]
struct ModReq {
    mods: Vec<ModRef>,
}

#[derive(Deserialize)]
struct ModRef {
    id: String,
    hash: String,
}

fn clean(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
}

async fn post_mod_requests(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<ModReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    if b.mods.iter().any(|m| !clean(&m.id) || !(m.hash.is_empty() || clean(&m.hash))) {
        return Err(ApiErr::BadRequest("BAD_MOD"));
    }
    let mods: Vec<(String, String)> = b.mods.into_iter().map(|m| (m.id, m.hash)).collect();
    gw.add_mod_requests(&dev, &world, &mods)?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_mod_requests(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    Ok(Json(json!({ "requests": gw.mod_requests(&world)? })))
}

#[derive(Deserialize)]
struct ResolveReq {
    id: String,
    hash: String,
    approve: bool,
}

async fn post_mod_resolve(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<ResolveReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    if gw.resolve_mod_request(&dev, &world, &b.id, &b.hash, b.approve)? {
        Ok(Json(json!({ "ok": true })))
    } else {
        Err(ApiErr::Conflict("NO_ALLOWLIST"))
    }
}

async fn get_revisions(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    Ok(Json(json!({ "head": gw.head(&world)?, "revisions": gw.revisions(&world, 100)? })))
}

#[derive(Deserialize)]
struct RevertReq {
    rev: String,
}

async fn post_revert(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<RevertReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    match gw.revert(&dev, &world, &b.rev)? {
        Ok(id) => Ok(Json(json!({ "ok": true, "revision": id }))),
        Err(code) => Err(ApiErr::Conflict(code)),
    }
}

async fn panel_code(State(s): State<Arc<AppState>>, h: HeaderMap) -> R {
    let dev = auth(&s.gw(), &h)?;
    let mut raw = [0u8; 6];
    getrandom::getrandom(&mut raw).map_err(|_| ApiErr::Domain(Error::Rand))?;
    let code: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let mut m = s.panel_codes.lock().unwrap_or_else(|e| e.into_inner());
    m.retain(|_, (_, t)| t.elapsed() < CODE_TTL);
    m.insert(code.clone(), (dev, Instant::now()));
    Ok(Json(json!({ "code": code })))
}

#[derive(Deserialize)]
struct LoginReq {
    code: String,
}

async fn panel_login(State(s): State<Arc<AppState>>, Json(b): Json<LoginReq>) -> R {
    let dev = {
        let mut m = s.panel_codes.lock().unwrap_or_else(|e| e.into_inner());
        match m.remove(b.code.trim()) {
            Some((d, t)) if t.elapsed() < CODE_TTL => d,
            _ => return Err(ApiErr::Unauthorized),
        }
    };
    let mut raw = [0u8; 24];
    getrandom::getrandom(&mut raw).map_err(|_| ApiErr::Domain(Error::Rand))?;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let token = URL_SAFE_NO_PAD.encode(raw);
    s.gw().add_token(&dev, &token)?;
    Ok(Json(json!({ "token": token })))
}

async fn page() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-cache")], Html(include_str!("../web/panel.html")))
}

async fn landing() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-cache")], Html(include_str!("../web/index.html")))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(landing))
        .route("/panel", get(page))
        .route("/v1/worlds/:id/mods", get(get_mods).put(put_mods))
        .route("/v1/worlds/:id/members", get(get_members).put(put_member))
        .route("/v1/worlds/:id/mod-requests", get(get_mod_requests).post(post_mod_requests))
        .route("/v1/worlds/:id/mod-requests/resolve", post(post_mod_resolve))
        .route("/v1/worlds/:id/revisions", get(get_revisions))
        .route("/v1/worlds/:id/revert", post(post_revert))
        .route("/v1/panel/code", post(panel_code))
        .route("/v1/panel/login", post(panel_login))
}
