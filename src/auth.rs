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
}

impl Default for AuthCfg {
    fn default() -> Self {
        AuthCfg { session_url: "https://sessionserver.mojang.com".into(), mojang: true, key: true, require_ticket: true, allow_create: false, advertise: String::new(), metrics_token: None, webhooks: Vec::new(), webhook_secret: None }
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

fn finish(s: &AppState, r: Result<Result<LoginOk, &'static str>, Error>) -> Result<Json<Value>, ApiErr> {
    match r? {
        Ok(ok) => {
            s.gw().meter("", "logins", 1);
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
    finish(&s, r)
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
    let uuid = key_uuid(&pk);
    let r = s.gw().login_identity(IdKind::Key, &uuid, &req.name, Some(&pk));
    finish(&s, r)
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
