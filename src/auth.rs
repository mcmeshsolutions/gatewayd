//! Player identity. Mojang session proof is the primary path; an Ed25519 key bound to a claimed
//! name is the independent fallback for offline-mode (unofficial) clients.
use crate::lease::{Error, Gateway, Role};
use crate::server::{ApiErr, AppState};
use axum::{extract::State, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHALLENGE_TTL: Duration = Duration::from_secs(120);
const LINK_CODE_TTL: Duration = Duration::from_secs(300);
const CHALLENGE_CAP: usize = 4096;
const SIG_DOMAIN: &[u8] = b"mcmesh-auth-v1\0";

#[derive(Clone)]
pub struct AuthCfg {
    pub session_url: String,
    pub mojang: bool,
    pub key: bool,
    /// Guests must present a gateway ticket in the handshake before their connection is forwarded.
    pub require_ticket: bool,
    /// Any logged-in player may create a world and become its admin.
    pub allow_create: bool,
    /// host:port guests should connect to; empty when the gateway has no relay.
    pub advertise: String,
    /// Bearer token for /metrics; the route answers 404 while unset.
    pub metrics_token: Option<String>,
    pub webhooks: Vec<String>,
    /// Signs webhook bodies (x-mesh-signature) when set.
    pub webhook_secret: Option<String>,
    /// Player uuids that are gateway admins regardless of the database.
    pub admins: Vec<String>,
    /// How long a suspended or banned host may still wind down its lease (heartbeat, wal, blobs).
    pub ban_grace_s: u64,
    /// MCMESH_REQUIRE_SIGNED=1: commits without a valid host signature are refused with 403 SIGNATURE_REQUIRED.
    pub require_signed: bool,
    /// MCMESH_MIN_CLIENT: requests from mods below this protocol level (no header counts as 0) get 426 CLIENT_TOO_OLD. 0 = off.
    pub min_client: u32,
}

impl Default for AuthCfg {
    fn default() -> Self {
        AuthCfg { session_url: "https://sessionserver.mojang.com".into(), mojang: true, key: true, require_ticket: true, allow_create: false, advertise: String::new(), metrics_token: None, webhooks: Vec::new(), webhook_secret: None, admins: Vec::new(), ban_grace_s: 120, require_signed: false, min_client: 0 }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    Mojang,
    Key,
}

pub struct LoginOk {
    pub token: String,
    pub uuid: String,
    pub name: String,
}

fn valid_name(n: &str) -> bool {
    (3..=16).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Moves everything that belongs to the placeholder player `old` to `new` and removes the placeholder. Tables are found by their column
/// names (`player_uuid`, `owner_uuid`) so one added later is moved too; `new` has no rows of its own yet.
fn adopt_placeholder(tx: &rusqlite::Transaction, old: &str, new: &str, name: &str) -> Result<(), Error> {
    // the new player first (foreign keys), so the placeholder steps aside under a name nobody can have
    tx.execute("UPDATE players SET name=name||'~adopted' WHERE uuid=?", params![old])?;
    tx.execute("INSERT INTO players(uuid,name,created_at) SELECT ?1, ?2, created_at FROM players WHERE uuid=?3", params![new, name, old])?;
    let tables: Vec<String> = {
        let mut st = tx.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for t in tables {
        if t == "players" {
            continue;
        }
        let cols: Vec<String> = {
            let mut st = tx.prepare(&format!("PRAGMA table_info(\"{t}\")"))?;
            let rows = st.query_map([], |r| r.get::<_, String>(1))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for c in cols.iter().filter(|c| *c == "player_uuid" || *c == "owner_uuid") {
            tx.execute(&format!("UPDATE \"{t}\" SET \"{c}\"=?1 WHERE \"{c}\"=?2"), params![new, old])?;
        }
    }
    tx.execute("DELETE FROM players WHERE uuid=?", params![old])?;
    Ok(())
}

fn rand_b64(n: usize) -> Result<String, Error> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).map_err(|_| Error::Rand)?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

fn fmt_uuid(b: &[u8]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn key_uuid(pubkey: &[u8]) -> String {
    let mut d: [u8; 32] = Sha256::new().chain_update(b"mcmesh-key-v1").chain_update(pubkey).finalize().into();
    d[6] = (d[6] & 0x0f) | 0x40;
    d[8] = (d[8] & 0x3f) | 0x80;
    fmt_uuid(&d[..16])
}

impl Gateway {
    /// Ok(Err(code)) is a policy refusal; Err is an internal failure.
    pub fn login_identity(
        &mut self,
        kind: IdKind,
        uuid: &str,
        name: &str,
        pubkey: Option<&[u8]>,
    ) -> Result<Result<LoginOk, &'static str>, Error> {
        let tx = self.db.transaction()?;
        let holder: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT p.uuid, i.kind FROM players p LEFT JOIN identities i ON i.player_uuid=p.uuid \
                 WHERE p.name=? COLLATE NOCASE",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((hu, hk)) = holder {
            if hu != uuid {
                // premium proof outranks an unverified claim on the same name
                if kind == IdKind::Mojang && hk.as_deref() == Some("KEY") {
                    let renamed = format!("{}_{}", &name[..name.len().min(11)], &hu[..4]);
                    tx.execute("UPDATE players SET name=? WHERE uuid=?", params![renamed, hu])?;
                } else if hk.is_none() {
                    // a name an operator put on a member list (an offline uuid, no identity, never logged in): the first login under it,
                    // verified or by key, becomes that player, and everything the placeholder was (memberships, roles, devices) moves along
                    adopt_placeholder(&tx, &hu, uuid, name)?;
                } else {
                    return Ok(Err("NAME_TAKEN"));
                }
            }
        }
        let known: Option<String> = tx.query_row("SELECT name FROM players WHERE uuid=?", params![uuid], |r| r.get(0)).optional()?;
        match known {
            Some(n) if n != name => {
                tx.execute("UPDATE players SET name=? WHERE uuid=?", params![name, uuid])?;
            }
            Some(_) => {}
            None => {
                tx.execute("INSERT INTO players(uuid,name,created_at) VALUES(?,?,strftime('%s','now'))", params![uuid, name])?;
            }
        }
        let kind_s = if kind == IdKind::Mojang { "MOJANG" } else { "KEY" };
        tx.execute(
            "INSERT OR IGNORE INTO identities(player_uuid,kind,pubkey) VALUES(?,?,?)",
            params![uuid, kind_s, pubkey],
        )?;
        if kind == IdKind::Key {
            if let Some(pk) = pubkey {
                tx.execute(
                    "INSERT OR IGNORE INTO identity_keys(player_uuid,pubkey,added_at) VALUES(?,?,strftime('%s','now'))",
                    params![uuid, pk],
                )?;
            }
        }
        let dev = format!("d_{}", &crate::cas::hex(&Sha256::digest(uuid.as_bytes()).into())[..16]);
        tx.execute("INSERT OR IGNORE INTO devices(id,player_uuid) VALUES(?,?)", params![dev, uuid])?;
        let token = rand_b64(32)?;
        tx.execute(
            "INSERT INTO sessions(token_hash, device_id, last_used) VALUES(?,?,strftime('%s','now'))",
            params![Sha256::digest(token.as_bytes()).as_slice(), dev],
        )?;
        tx.commit()?;
        Ok(Ok(LoginOk { token, uuid: uuid.into(), name: name.into() }))
    }

    /// The player an already-linked key belongs to, so a second (or third...) machine logs in as that player
    /// instead of racing it for the name.
    pub fn key_owner(&self, pubkey: &[u8]) -> Result<Option<String>, Error> {
        Ok(self.db.query_row("SELECT player_uuid FROM identity_keys WHERE pubkey=?", params![pubkey], |r| r.get(0)).optional()?)
    }

    /// The player a device belongs to, to mint a link code tied to the right player.
    pub fn player_of_device(&self, device: &str) -> Result<Option<String>, Error> {
        Ok(self.db.query_row("SELECT player_uuid FROM devices WHERE id=?", params![device], |r| r.get(0)).optional()?)
    }

    /// Links an additional key to an existing player (a second machine), from a one-time code minted by a device
    /// that is already that player.
    pub fn link_key(&mut self, player_uuid: &str, pubkey: &[u8]) -> Result<(), Error> {
        self.db.execute(
            "INSERT OR IGNORE INTO identity_keys(player_uuid,pubkey,added_at) VALUES(?,?,strftime('%s','now'))",
            params![player_uuid, pubkey],
        )?;
        Ok(())
    }

    pub fn player_name(&self, player_uuid: &str) -> Result<String, Error> {
        Ok(self.db.query_row("SELECT name FROM players WHERE uuid=?", params![player_uuid], |r| r.get(0))?)
    }

    pub fn grant_role(&mut self, world: &str, name: &str, role: Role) -> Result<bool, Error> {
        let uuid: Option<String> = self
            .db
            .query_row("SELECT uuid FROM players WHERE name=? COLLATE NOCASE", params![name], |r| r.get(0))
            .optional()?;
        let Some(uuid) = uuid else { return Ok(false) };
        self.db.execute(
            "INSERT OR REPLACE INTO members(world_id,player_uuid,role) VALUES(?,?,?)",
            params![world, uuid, role.as_str()],
        )?;
        Ok(true)
    }
}

fn take_challenge(s: &AppState, c: &str) -> Result<(), ApiErr> {
    let mut m = s.challenges.lock().unwrap_or_else(|e| e.into_inner());
    match m.remove(c) {
        Some(t) if t.elapsed() < CHALLENGE_TTL => Ok(()),
        _ => Err(ApiErr::Forbidden("BAD_CHALLENGE")),
    }
}

pub(crate) async fn challenge(State(s): State<Arc<AppState>>) -> Result<Json<Value>, ApiErr> {
    // mojang's session server rejects some serverIds (seen with '_' and leading '-'), so stay alphanumeric
    let c = rand_b64(24).map_err(ApiErr::from)?.chars().map(|ch| if ch.is_ascii_alphanumeric() { ch } else { 'x' }).collect::<String>();
    let mut m = s.challenges.lock().unwrap_or_else(|e| e.into_inner());
    if m.len() >= CHALLENGE_CAP {
        m.retain(|_, t| t.elapsed() < CHALLENGE_TTL);
        if m.len() >= CHALLENGE_CAP {
            return Err(ApiErr::Conflict("BUSY"));
        }
    }
    m.insert(c.clone(), Instant::now());
    Ok(Json(json!({ "challenge": c, "mojang": s.auth.mojang, "key": s.auth.key })))
}

#[derive(Deserialize)]
pub(crate) struct MojangReq {
    challenge: String,
    name: String,
}

fn finish(s: &AppState, method: &str, r: Result<Result<LoginOk, &'static str>, Error>) -> Result<Json<Value>, ApiErr> {
    match r? {
        Ok(ok) => {
            let mut gw = s.gw();
            if let Some((status, _, _)) = gw.user_status(&ok.uuid)? {
                gw.drop_token(&ok.token)?;
                return Err(ApiErr::Forbidden(if status == "BANNED" { "ACCOUNT_BANNED" } else { "ACCOUNT_SUSPENDED" }));
            }
            gw.meter("", "logins", 1);
            gw.audit_as(&ok.uuid, &ok.name, "login", "", "", json!({ "method": method }));
            Ok(Json(json!({ "token": ok.token, "uuid": ok.uuid, "name": ok.name })))
        }
        Err(code) => Err(ApiErr::Conflict(code)),
    }
}

pub(crate) async fn mojang(State(s): State<Arc<AppState>>, Json(req): Json<MojangReq>) -> Result<Json<Value>, ApiErr> {
    if !s.auth.mojang {
        return Err(ApiErr::Forbidden("AUTH_DISABLED"));
    }
    if !valid_name(&req.name) {
        return Err(ApiErr::BadRequest("BAD_NAME"));
    }
    take_challenge(&s, &req.challenge)?;
    let url = format!("{}/session/minecraft/hasJoined", s.auth.session_url);
    let (name, challenge) = (req.name.clone(), req.challenge.clone());
    let resp = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(5)).build();
        match agent.get(&url).query("username", &name).query("serverId", &challenge).call() {
            Ok(r) if r.status() == 200 => r.into_json::<Value>().ok(),
            _ => None,
        }
    })
    .await
    .map_err(|_| ApiErr::BadRequest("UPSTREAM"))?;
    let v = resp.ok_or(ApiErr::Unauthorized)?;
    let id = v["id"].as_str().filter(|i| i.len() == 32 && i.bytes().all(|b| b.is_ascii_hexdigit())).ok_or(ApiErr::Unauthorized)?;
    let real = v["name"].as_str().filter(|n| n.eq_ignore_ascii_case(&req.name)).ok_or(ApiErr::Unauthorized)?;
    let raw: Vec<u8> = (0..16).map(|i| u8::from_str_radix(&id[i * 2..i * 2 + 2], 16).unwrap_or(0)).collect();
    let uuid = fmt_uuid(&raw);
    let r = s.gw().login_identity(IdKind::Mojang, &uuid, real, None);
    finish(&s, "mojang", r)
}

#[derive(Deserialize)]
pub(crate) struct KeyReq {
    challenge: String,
    name: String,
    pubkey: String,
    sig: String,
}

pub(crate) async fn key(State(s): State<Arc<AppState>>, Json(req): Json<KeyReq>) -> Result<Json<Value>, ApiErr> {
    if !s.auth.key {
        return Err(ApiErr::Forbidden("AUTH_DISABLED"));
    }
    if !valid_name(&req.name) {
        return Err(ApiErr::BadRequest("BAD_NAME"));
    }
    let pk: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&req.pubkey)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(ApiErr::BadRequest("BAD_KEY"))?;
    let sig = URL_SAFE_NO_PAD.decode(&req.sig).ok().ok_or(ApiErr::BadRequest("BAD_SIG"))?;
    take_challenge(&s, &req.challenge)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| ApiErr::BadRequest("BAD_KEY"))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| ApiErr::BadRequest("BAD_SIG"))?;
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(req.challenge.as_bytes());
    vk.verify_strict(&msg, &sig).map_err(|_| ApiErr::Unauthorized)?;
    let mut gw = s.gw();
    // a key already linked to a player (this machine, or another one it was linked to) resolves straight to that
    // player instead of deriving a fresh uuid from the key and racing an existing login for the name
    let uuid = gw.key_owner(&pk)?.unwrap_or_else(|| key_uuid(&pk));
    let r = gw.login_identity(IdKind::Key, &uuid, &req.name, Some(&pk));
    drop(gw);
    finish(&s, "key", r)
}

#[derive(Deserialize)]
pub(crate) struct LinkKeyReq {
    challenge: String,
    code: String,
    pubkey: String,
    sig: String,
}

/// One-time code for linking a second machine's key to this (already logged in) player. Call with the existing
/// device's bearer token; the code is then given to the mod on the new machine.
pub(crate) async fn link_code(State(s): State<Arc<AppState>>, h: axum::http::HeaderMap) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = crate::server::auth(&gw, &h)?;
    let player = gw.player_of_device(&dev)?.ok_or(ApiErr::Unauthorized)?;
    drop(gw);
    let mut raw = [0u8; 6];
    getrandom::getrandom(&mut raw).map_err(|_| ApiErr::Domain(Error::Rand))?;
    let code: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let mut m = s.link_codes.lock().unwrap_or_else(|e| e.into_inner());
    m.retain(|_, (_, t)| t.elapsed() < LINK_CODE_TTL);
    m.insert(code.clone(), (player, Instant::now()));
    Ok(Json(json!({ "code": code })))
}

/// Proves possession of a new key (same challenge/sig scheme as a normal key login) and, if the one-time code is
/// still good, links that key to the code's player and logs in as them straight away.
pub(crate) async fn link_key(State(s): State<Arc<AppState>>, Json(req): Json<LinkKeyReq>) -> Result<Json<Value>, ApiErr> {
    if !s.auth.key {
        return Err(ApiErr::Forbidden("AUTH_DISABLED"));
    }
    let pk: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&req.pubkey)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(ApiErr::BadRequest("BAD_KEY"))?;
    let sig = URL_SAFE_NO_PAD.decode(&req.sig).ok().ok_or(ApiErr::BadRequest("BAD_SIG"))?;
    take_challenge(&s, &req.challenge)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| ApiErr::BadRequest("BAD_KEY"))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| ApiErr::BadRequest("BAD_SIG"))?;
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(req.challenge.as_bytes());
    vk.verify_strict(&msg, &sig).map_err(|_| ApiErr::Unauthorized)?;
    let player = {
        let mut m = s.link_codes.lock().unwrap_or_else(|e| e.into_inner());
        match m.remove(req.code.trim()) {
            Some((p, t)) if t.elapsed() < LINK_CODE_TTL => p,
            _ => return Err(ApiErr::Unauthorized),
        }
    };
    let mut gw = s.gw();
    gw.link_key(&player, &pk)?;
    let name = gw.player_name(&player)?;
    let r = gw.login_identity(IdKind::Key, &player, &name, Some(&pk));
    drop(gw);
    finish(&s, "link", r)
}

const TICKET_TTL: Duration = Duration::from_secs(60);

pub struct Ticket {
    pub uuid: String,
    pub name: String,
    pub world: String,
    pub issued: Instant,
}

impl AppState {
    /// One-time, for a relay serving several worlds: the ticket names its own world.
    pub fn take_ticket_any(&self, ticket: &str) -> Option<Ticket> {
        let t = self.tickets.lock().unwrap_or_else(|e| e.into_inner()).remove(ticket)?;
        (t.issued.elapsed() < TICKET_TTL).then_some(t)
    }

    /// One-time: a second use, an expired ticket or another world's ticket yields None.
    pub fn take_ticket(&self, ticket: &str, world: &str) -> Option<Ticket> {
        let t = self.tickets.lock().unwrap_or_else(|e| e.into_inner()).remove(ticket)?;
        (t.issued.elapsed() < TICKET_TTL && t.world == world).then_some(t)
    }
}

pub(crate) async fn ticket(
    State(s): State<Arc<AppState>>,
    h: axum::http::HeaderMap,
    axum::extract::Path(world): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiErr> {
    let (uuid, name) = {
        let gw = s.gw();
        let dev = crate::server::auth(&gw, &h)?;
        gw.require_member(&world, &dev)?;
        gw.require_pack(&world, &crate::server::req_pack(&h)?)?;
        gw.meter(&world, "tickets", 1);
        gw.device_player(&dev)?.ok_or(ApiErr::Unauthorized)?
    };
    let t = rand_b64(24).map_err(ApiErr::from)?;
    let mut m = s.tickets.lock().unwrap_or_else(|e| e.into_inner());
    if m.len() >= CHALLENGE_CAP {
        m.retain(|_, t| t.issued.elapsed() < TICKET_TTL);
        if m.len() >= CHALLENGE_CAP {
            return Err(ApiErr::Conflict("BUSY"));
        }
    }
    m.insert(t.clone(), Ticket { uuid, name, world, issued: Instant::now() });
    Ok(Json(json!({ "ticket": t, "ttl_s": TICKET_TTL.as_secs() })))
}

impl Gateway {
    pub fn device_player(&self, device: &str) -> Result<Option<(String, String)>, Error> {
        Ok(self
            .db
            .query_row(
                "SELECT p.uuid, p.name FROM devices d JOIN players p ON p.uuid=d.player_uuid WHERE d.id=?",
                params![device],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn require_member(&self, world: &str, device: &str) -> Result<(), Error> {
        self.role(world, device).map(|_| ())
    }
}

#[cfg(test)]
mod placeholder_tests {
    use super::*;
    use crate::cas::Cas;
    use crate::lease::Role;
    use rusqlite::Connection;

    fn gw() -> Gateway {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let k = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cas = Cas::open(std::env::temp_dir().join(format!("mcmesh-adopt-{}-{k}", std::process::id()))).unwrap();
        let mut g = Gateway::open(Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.create_world("w", "w", "1.21.1", "neoforge").unwrap();
        g.add_member("w", "u-a", "alice", "dev-a", Role::Admin).unwrap();
        // what `add-member` leaves for a friend who has not logged in yet: a player and a device, no identity
        g.add_member("w", "42ab389a-offline", "janmclovin", "d_placeholder", Role::HostEligible).unwrap();
        g
    }

    fn role(g: &Gateway, uuid: &str) -> Option<String> {
        g.db().query_row("SELECT role FROM members WHERE world_id='w' AND player_uuid=?", params![uuid], |r| r.get(0)).optional().unwrap()
    }

    #[test]
    fn the_first_key_login_under_a_name_an_operator_added_becomes_that_player_and_keeps_the_membership() {
        let mut g = gw();
        let ok = g.login_identity(IdKind::Key, "key-uuid-1", "janmclovin", Some(&[7u8; 32])).unwrap().expect("not refused");
        assert_eq!(ok.uuid, "key-uuid-1");
        assert_eq!(role(&g, "key-uuid-1"), Some("HOST_ELIGIBLE".to_string()));
        assert_eq!(role(&g, "42ab389a-offline"), None, "the placeholder is gone");
        // a second client under the same name with another key is a stranger and is still refused
        assert_eq!(g.login_identity(IdKind::Key, "key-uuid-2", "janmclovin", Some(&[8u8; 32])).unwrap().err(), Some("NAME_TAKEN"));
        // the same player logging in again is fine
        assert!(g.login_identity(IdKind::Key, "key-uuid-1", "janmclovin", Some(&[7u8; 32])).unwrap().is_ok());
    }

    #[test]
    fn a_name_that_already_belongs_to_a_logged_in_player_is_still_taken() {
        let mut g = gw();
        g.login_identity(IdKind::Key, "key-uuid-1", "bobby", Some(&[1u8; 32])).unwrap().unwrap();
        assert_eq!(g.login_identity(IdKind::Key, "key-uuid-9", "bobby", Some(&[2u8; 32])).unwrap().err(), Some("NAME_TAKEN"));
    }

    #[test]
    fn a_linked_second_key_logs_in_as_the_same_player_instead_of_racing_for_the_name() {
        let mut g = gw();
        let first = g.login_identity(IdKind::Key, "key-uuid-1", "bobby", Some(&[1u8; 32])).unwrap().unwrap();
        // the second machine's own key is a stranger until it is linked
        assert_eq!(g.login_identity(IdKind::Key, "key-uuid-9", "bobby", Some(&[2u8; 32])).unwrap().err(), Some("NAME_TAKEN"));
        assert_eq!(g.key_owner(&[2u8; 32]).unwrap(), None);
        g.link_key(&first.uuid, &[2u8; 32]).unwrap();
        assert_eq!(g.key_owner(&[2u8; 32]).unwrap(), Some(first.uuid.clone()));
        // logging in with the now-linked key resolves straight to the same player, no collision
        let ok = g.login_identity(IdKind::Key, &first.uuid, "bobby", Some(&[2u8; 32])).unwrap().expect("not refused");
        assert_eq!(ok.uuid, first.uuid);
        assert_eq!(ok.name, "bobby");
    }
}
