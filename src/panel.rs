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
        self.set_member_unchecked(world, name, role)
    }

    /// Caller has already been authorised (world owner or gateway admin).
    pub fn set_member_unchecked(&mut self, world: &str, name: &str, role: Option<Role>) -> Result<bool, Error> {
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
        self.rollback_to(world, rev).map(Ok)
    }

    /// New head with the content of `rev`, kept as a ROLLBACK revision so nothing is lost. The caller checks the world is idle.
    pub(crate) fn rollback_to(&mut self, world: &str, rev: &str) -> Result<String, Error> {
        let root = self.revision_root(rev)?;
        self.rollback_root(world, root)
    }

    /// Makes `root` the head as a new ROLLBACK revision on top of the current head.
    pub(crate) fn rollback_root(&mut self, world: &str, root: crate::cas::Hash) -> Result<String, Error> {
        let head = self.head(world)?;
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
        Ok(id)
    }
}

fn require_member_or_admin(s: &AppState, gw: &Gateway, dev: &str, world: &str) -> Result<(), ApiErr> {
    if gw.require_member(world, dev).is_ok() {
        return Ok(());
    }
    crate::admin::require_owner_or_admin(s, gw, dev, world).map(|_| ())
}

fn require_world_or_gw_admin(s: &AppState, gw: &Gateway, dev: &str, world: &str) -> Result<(), ApiErr> {
    if gw.role(world, dev).ok() == Some(Role::Admin) {
        return Ok(());
    }
    crate::admin::require_owner_or_admin(s, gw, dev, world).map(|_| ())
}

async fn get_mods(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_member_or_admin(&s, &gw, &dev, &world)?;
    Ok(Json(gw.world_mods(&world)?))
}

async fn put_mods(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(doc): Json<Value>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    if !doc.is_object() {
        return Err(ApiErr::BadRequest("BAD_DOC"));
    }
    require_world_or_gw_admin(&s, &gw, &dev, &world)?;
    gw.db.execute("UPDATE worlds SET mods_json=? WHERE id=?", params![doc.to_string(), world]).map_err(Error::Db)?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_members(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_member_or_admin(&s, &gw, &dev, &world)?;
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
    crate::admin::require_owner_or_admin(&s, &gw, &dev, &world)?;
    let target = gw.player_by_name(&b.name)?;
    if target.as_ref().is_some_and(|(u, _)| gw.world_owner(&world).ok().flatten().as_deref() == Some(u.as_str()))
        && role != Some(Role::Admin)
    {
        return Err(ApiErr::Conflict("OWNER_IMMUTABLE"));
    }
    if gw.set_member_unchecked(&world, &b.name, role)? {
        let name = target.map_or(b.name.clone(), |t| t.1);
        gw.audit(&dev, "role.world", &world, &name, json!({ "role": b.role }));
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
    require_member_or_admin(&s, &gw, &dev, &world)?;
    Ok(Json(json!({ "requests": gw.mod_requests(&world)? })))
}

#[derive(Deserialize)]
struct ResolveReq {
    id: String,
    hash: String,
    approve: bool,
}

async fn post_mod_resolve(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<ResolveReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    if gw.role(&world, &dev).ok() != Some(Role::Admin) {
        crate::admin::require_owner_or_admin(&s, &gw, &dev, &world)?;
    }
    let ok = if b.approve {
        let mut doc = gw.world_mods(&world)?;
        let allow = doc.get("allow").and_then(|a| a.as_array()).cloned().unwrap_or_default();
        if allow.is_empty() {
            false
        } else {
            let mut allow: Vec<Value> = allow.into_iter().filter(|e| e.get("id").and_then(|v| v.as_str()) != Some(&b.id)).collect();
            allow.push(json!({ "id": b.id, "hash": b.hash }));
            doc["allow"] = Value::Array(allow);
            gw.db.execute("UPDATE worlds SET mods_json=? WHERE id=?", params![doc.to_string(), world]).map_err(Error::Db)?;
            gw.db.execute("DELETE FROM mod_requests WHERE world_id=? AND mod_id=?", params![world, b.id]).map_err(Error::Db)?;
            true
        }
    } else {
        gw.db.execute("DELETE FROM mod_requests WHERE world_id=? AND mod_id=? AND hash=?", params![world, b.id, b.hash]).map_err(Error::Db)?;
        true
    };
    if ok {
        Ok(Json(json!({ "ok": true })))
    } else {
        Err(ApiErr::Conflict("NO_ALLOWLIST"))
    }
}

async fn get_revisions(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_member_or_admin(&s, &gw, &dev, &world)?;
    Ok(Json(json!({ "head": gw.head(&world)?, "revisions": gw.revisions(&world, 100)? })))
}

#[derive(Deserialize)]
struct RevertReq {
    rev: String,
}

async fn post_revert(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<RevertReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_world_or_gw_admin(&s, &gw, &dev, &world)?;
    if gw.revision_world(&b.rev)?.as_deref() != Some(world.as_str()) {
        return Err(ApiErr::Conflict("NO_SUCH_REVISION"));
    }
    if gw.world_state(&world)?.0 != "IDLE" {
        return Err(ApiErr::Conflict("WORLD_RUNNING"));
    }
    let id = gw.rollback_to(&world, &b.rev)?;
    Ok(Json(json!({ "ok": true, "revision": id })))
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

#[derive(Deserialize)]
struct SetupPayload {
    admin_name: String,
    community_name: Option<String>,
    pack_name: Option<String>,
    motd: Option<String>,
    initial_world_id: Option<String>,
    initial_world_name: Option<String>,
}

async fn setup_page() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-cache")], Html(include_str!("../web/setup.html")))
}

async fn get_setup_status(State(s): State<Arc<AppState>>) -> R {
    let gw = s.gw();
    let admin_count: i64 = gw.db.query_row(
        "SELECT COUNT(*) FROM gateway_admins",
        [],
        |r| r.get(0)
    ).unwrap_or(0);
    let worlds_count: i64 = gw.db.query_row(
        "SELECT COUNT(*) FROM worlds",
        [],
        |r| r.get(0)
    ).unwrap_or(0);
    let community_name = gw.db.query_row(
        "SELECT value FROM admin_settings WHERE key='community_name'",
        [],
        |r| r.get(0)
    ).unwrap_or_else(|_| std::env::var("MCMESH_COMMUNITY_NAME").unwrap_or_else(|_| "MCMesh Community".into()));
    let pack_name = gw.db.query_row(
        "SELECT value FROM admin_settings WHERE key='pack_name'",
        [],
        |r| r.get(0)
    ).unwrap_or_else(|_| std::env::var("MCMESH_PACK_NAME").unwrap_or_else(|_| "MCMesh Pack".into()));

    Ok(Json(json!({
        "configured": admin_count > 0,
        "admin_count": admin_count,
        "community_name": community_name,
        "pack_name": pack_name,
        "worlds_count": worlds_count,
    })))
}

async fn post_setup(State(s): State<Arc<AppState>>, Json(b): Json<SetupPayload>) -> R {
    let admin_name = b.admin_name.trim();
    if admin_name.is_empty() {
        return Err(ApiErr::BadRequest("admin_name required"));
    }

    let mut gw = s.gw();
    let _ = gw.admin_init();
    let now = crate::lease::wall_s();

    // 1. Ensure player exists
    let player_uuid: String = match gw.db.query_row(
        "SELECT uuid FROM players WHERE name=? COLLATE NOCASE",
        params![admin_name],
        |r| r.get(0),
    ) {
        Ok(u) => u,
        Err(_) => {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(format!("player:{}", admin_name.to_lowercase()).as_bytes());
            let u = hash[..16].iter().map(|b| format!("{b:02x}")).collect::<String>();
            gw.db.execute(
                "INSERT INTO players(uuid, name, created_at) VALUES(?, ?, ?)",
                params![u, admin_name, now],
            ).map_err(Error::Db)?;
            u
        }
    };

    // 2. Grant gateway_admin
    gw.db.execute(
        "INSERT OR IGNORE INTO gateway_admins(player_uuid, granted_by, granted_at) VALUES(?, 'setup', ?)",
        params![player_uuid, now],
    ).map_err(Error::Db)?;

    // 3. Create device and admin session token
    let dev_id = format!("dev-admin-{}", &player_uuid[..std::cmp::min(8, player_uuid.len())]);
    let _ = gw.db.execute(
        "INSERT OR IGNORE INTO devices(id, player_uuid, label, last_seen) VALUES(?, ?, 'Web Admin', ?)",
        params![dev_id, player_uuid, now],
    );

    let mut raw = [0u8; 24];
    getrandom::getrandom(&mut raw).map_err(|_| ApiErr::Domain(Error::Rand))?;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let token = URL_SAFE_NO_PAD.encode(raw);
    gw.add_token(&dev_id, &token)?;

    // 4. Save branding
    let comm_name = b.community_name.unwrap_or_else(|| "MCMesh Community".into());
    let pack_name = b.pack_name.unwrap_or_else(|| "MCMesh Modpack".into());
    gw.db.execute("INSERT OR REPLACE INTO admin_settings(key, value) VALUES('community_name', ?)", params![comm_name]).map_err(Error::Db)?;
    gw.db.execute("INSERT OR REPLACE INTO admin_settings(key, value) VALUES('pack_name', ?)", params![pack_name]).map_err(Error::Db)?;
    if let Some(motd) = b.motd {
        gw.db.execute("INSERT OR REPLACE INTO admin_settings(key, value) VALUES('motd', ?)", params![motd]).map_err(Error::Db)?;
    }

    // 5. Initial world
    let mut invite_code = String::new();
    let mut world_id = String::new();
    if let Some(w_id_raw) = b.initial_world_id {
        let w_id = w_id_raw.trim();
        if !w_id.is_empty() {
            world_id = w_id.to_string();
            let w_name = b.initial_world_name.unwrap_or_else(|| w_id.to_string());
            let _ = gw.db.execute(
                "INSERT OR IGNORE INTO worlds(id, name, mc_version, loader, created_at) VALUES(?, ?, '1.21.1', 'neoforge', ?)",
                params![w_id, w_name, now],
            );
            let _ = gw.db.execute(
                "INSERT OR IGNORE INTO members(world_id, player_uuid, role) VALUES(?, ?, 'ADMIN')",
                params![w_id, player_uuid],
            );
            let mut c_raw = [0u8; 6];
            let _ = getrandom::getrandom(&mut c_raw);
            invite_code = URL_SAFE_NO_PAD.encode(c_raw);
            let _ = gw.db.execute(
                "INSERT INTO invites(code, world_id, role, created_at) VALUES(?, ?, 'CLIENT_ONLY', ?)",
                params![invite_code, w_id, now],
            );
        }
    }

    let invite_url = if !invite_code.is_empty() {
        format!("/join/{invite_code}")
    } else {
        String::new()
    };

    Ok(Json(json!({
        "ok": true,
        "admin_name": admin_name,
        "admin_token": token,
        "device_id": dev_id,
        "community_name": comm_name,
        "pack_name": pack_name,
        "world_id": world_id,
        "invite_code": invite_code,
        "invite_url": invite_url,
        "discord_card_url": "/v1/setup/discord-card"
    })))
}

async fn get_discord_card(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let gw = s.gw();
    let comm_name: String = gw.db.query_row(
        "SELECT value FROM admin_settings WHERE key='community_name'",
        [],
        |r| r.get(0)
    ).unwrap_or_else(|_| "MCMesh Community".into());
    let pack_name: String = gw.db.query_row(
        "SELECT value FROM admin_settings WHERE key='pack_name'",
        [],
        |r| r.get(0)
    ).unwrap_or_else(|_| "MCMesh Modpack".into());
    let motd: String = gw.db.query_row(
        "SELECT value FROM admin_settings WHERE key='motd'",
        [],
        |r| r.get(0)
    ).unwrap_or_else(|_| "Cooperative Decentralized Multiplayer".into());

    let svg = format!(r##"<svg xmlns="http://www.w3.org/2000/svg" width="560" height="280" viewBox="0 0 560 280">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#1e222d"/>
      <stop offset="100%" stop-color="#141720"/>
    </linearGradient>
    <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#10b981"/>
      <stop offset="100%" stop-color="#06b6d4"/>
    </linearGradient>
  </defs>
  <rect width="560" height="280" rx="14" fill="url(#bg)" stroke="#2b3142" stroke-width="2"/>
  <rect x="0" y="0" width="8" height="280" rx="4" fill="url(#accent)"/>
  
  <text x="36" y="48" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="12" font-weight="700" fill="#10b981" letter-spacing="1">YOU'VE BEEN INVITED TO JOIN</text>
  <text x="36" y="86" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="24" font-weight="800" fill="#ffffff">{}</text>
  <text x="36" y="118" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="14" font-weight="500" fill="#949ba4">{}</text>

  <rect x="36" y="146" width="488" height="1" fill="#2b3142"/>

  <circle cx="48" cy="178" r="5" fill="#22c55e"/>
  <text x="64" y="182" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="13" font-weight="600" fill="#f1f5f9">Mesh Gateway Online</text>

  <text x="36" y="224" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="12" font-weight="600" fill="#64748b">MODPACK</text>
  <text x="36" y="246" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="14" font-weight="700" fill="#e2e8f0">{} (NeoForge 1.21.1)</text>

  <rect x="360" y="206" width="164" height="42" rx="6" fill="#10b981"/>
  <text x="442" y="232" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif" font-size="14" font-weight="700" fill="#ffffff" text-anchor="middle">Join World</text>
</svg>"##, html_escape(&comm_name), html_escape(&motd), html_escape(&pack_name));

    ([(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "no-cache")], svg)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

async fn page() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-cache")], Html(include_str!("../web/panel.html")))
}

async fn landing() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-cache")], Html(include_str!("../web/index.html")))
}

#[derive(Deserialize)]
struct HandoverReq {
    target_device: Option<String>,
}

#[derive(Deserialize)]
struct FreezeReq {
    frozen: bool,
}

async fn get_world_pulse(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_member_or_admin(&s, &gw, &dev, &world)?;
    let pulse = gw.world_pulse(&world, s.now())?;
    Ok(Json(pulse))
}

async fn post_pulse_handover(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<HandoverReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_world_or_gw_admin(&s, &gw, &dev, &world)?;
    if gw.active_lease(&world)?.is_none() {
        return Err(ApiErr::Conflict("NO_ACTIVE_HOST"));
    }
    let target = gw.trigger_handover(&world, b.target_device.as_deref(), s.now())?;
    if target.is_none() && b.target_device.is_some() {
        return Err(ApiErr::Conflict("TARGET_NOT_BIDDING"));
    }
    gw.audit(&dev, "pulse.handover", &world, target.as_deref().unwrap_or(""), json!({ "target": target }));
    Ok(Json(json!({ "ok": true, "target_device": target, "handover_initiated": true })))
}

async fn post_pulse_flush(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_world_or_gw_admin(&s, &gw, &dev, &world)?;
    if gw.active_lease(&world)?.is_none() {
        return Err(ApiErr::Conflict("NO_ACTIVE_HOST"));
    }
    let queued = gw.trigger_flush_barrier(&world)?;
    gw.audit(&dev, "pulse.flush_barrier", &world, "", json!({}));
    Ok(Json(json!({ "ok": true, "barrier_pending": queued })))
}

async fn post_pulse_freeze(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<FreezeReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_world_or_gw_admin(&s, &gw, &dev, &world)?;
    gw.set_world_frozen(&world, b.frozen)?;
    gw.audit(&dev, "pulse.lag_freeze", &world, "", json!({ "frozen": b.frozen }));
    Ok(Json(json!({ "ok": true, "frozen": b.frozen })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(landing))
        .route("/panel", get(page))
        .route("/setup", get(setup_page))
        .route("/v1/setup/status", get(get_setup_status))
        .route("/v1/setup", post(post_setup))
        .route("/v1/setup/discord-card", get(get_discord_card))
        .route("/v1/worlds/:id/mods", get(get_mods).put(put_mods).layer(axum::extract::DefaultBodyLimit::max(256 << 10)))
        .route("/v1/worlds/:id/members", get(get_members).put(put_member))
        .route("/v1/worlds/:id/mod-requests", get(get_mod_requests).post(post_mod_requests).layer(axum::extract::DefaultBodyLimit::max(256 << 10)))
        .route("/v1/worlds/:id/mod-requests/resolve", post(post_mod_resolve))
        .route("/v1/worlds/:id/revisions", get(get_revisions))
        .route("/v1/worlds/:id/revert", post(post_revert))
        .route("/v1/worlds/:id/pulse", get(get_world_pulse))
        .route("/v1/worlds/:id/pulse/handover", post(post_pulse_handover))
        .route("/v1/worlds/:id/pulse/flush", post(post_pulse_flush))
        .route("/v1/worlds/:id/pulse/freeze", post(post_pulse_freeze))
        .route("/v1/panel/code", post(panel_code))
        .route("/v1/panel/login", post(panel_login))
}

/// What a region rollback changed.
#[derive(Debug, PartialEq, Eq)]
pub struct RegionRollback {
    pub revision: String,
    pub restored: usize,
    pub removed: usize,
}

impl Gateway {
    /// Puts the chunks inside the rectangle (chunk coordinates, inclusive, one dimension; region, entity and poi data alike)
    /// back to how they were in `rev`, and leaves everything else as it is now. A new ROLLBACK revision records it, so it can
    /// be undone like any other. Only while the world is idle. Err carries a short code for the API.
    #[allow(clippy::too_many_arguments)]
    pub fn rollback_region(&mut self, world: &str, rev: &str, dim: &str, min_cx: i32, min_cz: i32, max_cx: i32, max_cz: i32) -> Result<Result<RegionRollback, &'static str>, Error> {
        use crate::manifest::{self, Change, Item};
        if min_cx > max_cx || min_cz > max_cz {
            return Ok(Err("BAD_REGION"));
        }
        if self.revision_world(rev)?.as_deref() != Some(world) {
            return Ok(Err("NO_SUCH_REVISION"));
        }
        if self.world_state(world)?.0 != "IDLE" {
            return Ok(Err("WORLD_RUNNING"));
        }
        let old_root = match self.revision_root(rev) {
            Ok(r) => r,
            Err(Error::Pruned) => return Ok(Err("REVISION_PRUNED")),
            Err(e) => return Err(e),
        };
        let head_root = self.revision_root(&self.head(world)?)?;
        let inside = |k: &manifest::Key| k.dim == dim && (min_cx..=max_cx).contains(&k.cx) && (min_cz..=max_cz).contains(&k.cz);
        let (mut changes, mut restored, mut removed) = (Vec::new(), 0, 0);
        for d in manifest::diff(&self.cas, Some(head_root), Some(old_root))? {
            let Item::Chunk(k) = d.item else { continue };
            if !inside(&k) {
                continue;
            }
            match d.new {
                Some(h) => {
                    restored += 1;
                    changes.push(Change::Put(k, h));
                }
                None => {
                    removed += 1;
                    changes.push(Change::Delete(k));
                }
            }
        }
        if changes.is_empty() {
            return Ok(Err("NOTHING_TO_ROLLBACK"));
        }
        let root = manifest::apply(&self.cas, Some(head_root), &changes)?;
        let revision = self.rollback_root(world, root)?;
        Ok(Ok(RegionRollback { revision, restored, removed }))
    }
}
