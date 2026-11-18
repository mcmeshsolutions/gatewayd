use crate::cas::{hex, parse_hex};
use crate::wal::Frame;
use crate::lease::{CommitKind, Directive, Error, Gateway, Grant, Hw, Join, EXPIRY_MS, FENCE_MS, HEARTBEAT_MS};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub struct AppState {
    gw: Mutex<Gateway>,
    start: Instant,
    pub(crate) auth: crate::auth::AuthCfg,
    pub(crate) challenges: Mutex<std::collections::HashMap<String, Instant>>,
    pub(crate) tickets: Mutex<std::collections::HashMap<String, crate::auth::Ticket>>,
    pub(crate) panel_codes: Mutex<std::collections::HashMap<String, (String, Instant)>>,
    /// Device-link codes: one-time code -> the player uuid to link a second machine's key to. A different id space
    /// from panel_codes (device id, not player uuid), kept separate so the two can never be confused.
    pub(crate) link_codes: Mutex<std::collections::HashMap<String, (String, Instant)>>,
    /// Worlds whose host has a live relay tunnel, i.e. guests can actually get in.
    pub(crate) live_worlds: Mutex<std::collections::HashSet<String>>,
    /// Host's world download progress by lease id: (done, total, when reported).
    pub(crate) sync: Mutex<std::collections::HashMap<String, (u64, u64, Instant)>>,
    /// Last `world.wanted` event per world, so a retrying joiner does not flood the event log.
    wanted: Mutex<std::collections::HashMap<String, Instant>>,
    pub(crate) hooks: crate::ops::Hooks,
    /// Relayed bytes by world since the last tick: (to host, to guests).
    relay_bytes: Mutex<std::collections::HashMap<String, (u64, u64)>>,
    pub(crate) limiter: crate::ratelimit::Limiter,
}

impl AppState {
    pub fn new(gw: Gateway) -> Arc<Self> {
        Self::with_auth(gw, crate::auth::AuthCfg::default())
    }

    pub fn with_auth(gw: Gateway, auth: crate::auth::AuthCfg) -> Arc<Self> {
        if let Err(e) = gw.ops_init() {
            eprintln!("ops init failed: {e:?}");
        }
        let hooks = crate::ops::Hooks::new(&auth.webhooks, auth.webhook_secret.clone());
        Arc::new(AppState { gw: Mutex::new(gw), start: Instant::now(), auth, challenges: Mutex::new(Default::default()), tickets: Mutex::new(Default::default()), panel_codes: Mutex::new(Default::default()), link_codes: Mutex::new(Default::default()), live_worlds: Mutex::new(Default::default()), sync: Mutex::new(Default::default()), wanted: Mutex::new(Default::default()), hooks, relay_bytes: Mutex::new(Default::default()), limiter: crate::ratelimit::Limiter::from_env() })
    }
    /// Seconds since this world was last asked for by someone who could not get in, or None if never.
    fn wanted_age_s(&self, world: &str) -> Option<u64> {
        let m = self.wanted.lock().unwrap_or_else(|e| e.into_inner());
        m.get(world).map(|t| t.elapsed().as_secs())
    }
    /// True at most once per 30 s per world.
    fn wanted_due(&self, world: &str) -> bool {
        let mut m = self.wanted.lock().unwrap_or_else(|e| e.into_inner());
        let due = m.get(world).is_none_or(|t| t.elapsed() >= Duration::from_secs(30));
        if due {
            m.insert(world.to_string(), Instant::now());
        }
        due
    }
    pub(crate) fn uptime_s(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
    /// Called per relayed frame, so it only touches memory; tick() writes the sums out.
    pub fn relay_meter(&self, world: &str, to_host: u64, to_guests: u64) {
        let mut m = self.relay_bytes.lock().unwrap_or_else(|e| e.into_inner());
        match m.get_mut(world) {
            Some(e) => *e = (e.0 + to_host, e.1 + to_guests),
            None => {
                m.insert(world.to_string(), (to_host, to_guests));
            }
        }
    }
    pub(crate) fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
    pub(crate) fn gw(&self) -> MutexGuard<'_, Gateway> {
        self.gw.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// World name when the token's device holds this live lease epoch.
    pub fn tunnel_auth(&self, token: &str, lease: &str, epoch: i64) -> Option<String> {
        let gw = self.gw();
        let dev = gw.device_for_token(token).ok()??;
        if gw.lease_device(lease).ok()?? != dev {
            return None;
        }
        gw.require_live(lease, epoch).ok().map(|(world, _)| world).or_else(|| gw.shard_live(lease, epoch).ok().map(|(world, _, _)| world))
    }

    pub fn tunnel_auth_proof(&self, lease: &str, epoch: i64, ts: u64, proof: &str) -> Option<String> {
        let now = crate::lease::wall_s() as u64;
        if now.abs_diff(ts) > 60 {
            return None;
        }
        let gw = self.gw();
        if !gw.verify_tunnel_proof(lease, epoch, ts, proof) {
            return None;
        }
        gw.require_live(lease, epoch).ok().map(|(world, _)| world).or_else(|| gw.shard_live(lease, epoch).ok().map(|(world, _, _)| world))
    }

    pub fn lease_live(&self, lease: &str, epoch: i64) -> bool {
        self.gw().require_live(lease, epoch).is_ok()
    }

    pub fn tick(&self) {
        let now = self.now();
        let relayed = std::mem::take(&mut *self.relay_bytes.lock().unwrap_or_else(|e| e.into_inner()));
        let mut gw = self.gw();
        for (world, (up, down)) in relayed {
            gw.meter(&world, "relay_to_host_bytes", up);
            gw.meter(&world, "relay_to_guest_bytes", down);
            gw.meter(&world, &crate::quota::month_meter(crate::lease::wall_s()), up + down);
        }
        if let Err(e) = gw.tick(now) {
            eprintln!("tick failed: {e:?}");
        }
        sweep_if_due(&mut gw);
        meter_anchor_time(&gw);
        self.limiter.sweep();
    }
}

/// Client protocol level a request declares: the x-mesh-client header, 0 when absent or unreadable.
fn client_level(h: &HeaderMap) -> u32 {
    h.get("x-mesh-client").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok()).unwrap_or(0)
}

/// Routes that stay open to builds below the minimum: the public status, operators (admin, panel, SSO) and API keys.
fn exempt_from_client_gate(path: &str, h: &HeaderMap) -> bool {
    !path.starts_with("/v1/")
        || path == "/v1/status"
        || path == "/v1/motd"
        || path.starts_with("/v1/admin/")
        || path.starts_with("/v1/panel/")
        || path.starts_with("/v1/sso/")
        || path.starts_with("/v1/auth/sso/")
        || h.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("mcmesh_sso="))
        || h.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).is_some_and(|v| v.trim_start_matches("Bearer ").starts_with(crate::apikeys::PREFIX))
}

async fn client_gate(State(s): State<Arc<AppState>>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let min = s.auth.min_client;
    if min > 0 && !exempt_from_client_gate(req.uri().path(), req.headers()) && client_level(req.headers()) < min {
        let body = Json(json!({
            "error": "CLIENT_TOO_OLD", "min_client": min,
            "message": "This gateway needs a newer version of the mcmesh mod. Update the mod (or the modpack) and start the game again.",
        }));
        return (StatusCode::UPGRADE_REQUIRED, body).into_response();
    }
    next.run(req).await
}

static LAST_ANCHOR_METER_S: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Adds a minute to `anchor_seconds` of every world an anchor device is hosting, once a minute. Feeds per-minute anchor billing later.
fn meter_anchor_time(gw: &Gateway) {
    let now = crate::lease::wall_s() as u64;
    let last = LAST_ANCHOR_METER_S.load(std::sync::atomic::Ordering::Relaxed);
    if last == 0 {
        LAST_ANCHOR_METER_S.store(now, std::sync::atomic::Ordering::Relaxed);
        return;
    }
    if now < last + 60 {
        return;
    }
    LAST_ANCHOR_METER_S.store(now, std::sync::atomic::Ordering::Relaxed);
    for (w, ram) in gw.anchor_hosted_profiles().unwrap_or_default() {
        gw.meter(&w, "anchor_seconds", now - last);
        gw.meter(&w, &format!("anchor_seconds_{}", crate::admin::anchor_profile(ram)), now - last);
    }
}

static LAST_SWEEP_S: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Runs in the serving process under the gateway mutex only: a sweep from a second process could race a revert.
fn sweep_if_due(gw: &mut Gateway) {
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let every = env("MCMESH_SWEEP_INTERVAL_S", 3600);
    let now = crate::lease::wall_s() as u64;
    let last = LAST_SWEEP_S.load(std::sync::atomic::Ordering::Relaxed);
    if every == 0 || now < last + every {
        return;
    }
    LAST_SWEEP_S.store(now, std::sync::atomic::Ordering::Relaxed);
    if !gw.quotas_configured().unwrap_or(false) {
        return;
    }
    match gw.retention_sweep(env("MCMESH_SWEEP_GRACE_S", 3600)) {
        Ok(r) if !r.pruned.is_empty() || r.blobs_removed > 0 => {
            eprintln!("retention sweep: pruned {} revisions, removed {} blobs, freed {} bytes", r.pruned.len(), r.blobs_removed, r.bytes_freed)
        }
        Ok(_) => {}
        Err(e) => eprintln!("retention sweep failed: {e:?}"),
    }
}

pub(crate) enum ApiErr {
    Unauthorized,
    Forbidden(&'static str),
    Conflict(&'static str),
    Gone(&'static str),
    NotFound(&'static str),
    Maintenance(u64, String),
    BadRequest(&'static str),
    Domain(Error),
}

impl From<Error> for ApiErr {
    fn from(e: Error) -> Self {
        ApiErr::Domain(e)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            ApiErr::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            ApiErr::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApiErr::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiErr::Gone(m) => (StatusCode::GONE, m),
            ApiErr::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiErr::Maintenance(retry, message) => {
                let body = Json(json!({ "error": "MAINTENANCE", "retry_after_s": retry, "message": message }));
                return (StatusCode::SERVICE_UNAVAILABLE, [(axum::http::header::RETRY_AFTER, retry.to_string())], body).into_response();
            }
            ApiErr::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiErr::Domain(Error::NotMember) => (StatusCode::FORBIDDEN, "NOT_MEMBER"),
            ApiErr::Domain(Error::NoSuchWorld) => (StatusCode::NOT_FOUND, "NO_SUCH_WORLD"),
            ApiErr::Domain(Error::StaleEpoch) => (StatusCode::CONFLICT, "STALE_EPOCH"),
            ApiErr::Domain(Error::HeadMoved) => (StatusCode::CONFLICT, "HEAD_MOVED"),
            ApiErr::Domain(Error::MissingBlob) => (StatusCode::CONFLICT, "MISSING_BLOB"),
            ApiErr::Domain(Error::Rejected(m)) => {
                eprintln!("sanity gate rejected a commit: {m}");
                (StatusCode::UNPROCESSABLE_ENTITY, "REJECTED_BY_SANITY_GATE")
            }
            ApiErr::Domain(Error::PackMismatch) => (StatusCode::FORBIDDEN, "PACK_MISMATCH"),
            ApiErr::Domain(Error::BadMac) => (StatusCode::FORBIDDEN, "BAD_MAC"),
            ApiErr::Domain(Error::BadFrame(m)) => (StatusCode::BAD_REQUEST, m),
            ApiErr::Domain(Error::Quota(h)) => {
                let status = if h.code == "QUOTA_WORLD_COUNT" { StatusCode::FORBIDDEN } else { StatusCode::INSUFFICIENT_STORAGE };
                return (status, Json(json!({ "error": h.code, "limit": h.limit, "used": h.used }))).into_response();
            }
            ApiErr::Domain(Error::Pruned) => (StatusCode::GONE, "REVISION_PRUNED"),
            ApiErr::Domain(Error::BadSignature) => (StatusCode::FORBIDDEN, "BAD_SIGNATURE"),
            ApiErr::Domain(Error::NoDeviceKey) => (StatusCode::FORBIDDEN, "NO_DEVICE_KEY"),
            ApiErr::Domain(Error::DeviceKeySet) => (StatusCode::CONFLICT, "DEVICE_KEY_SET"),
            ApiErr::Domain(e) => {
                eprintln!("internal error: {e:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
            }
        };
        (code, Json(json!({ "error": msg }))).into_response()
    }
}

type R = Result<Json<Value>, ApiErr>;

/// Modpack the caller was built for; clients that predate packs belong to "default".
pub(crate) fn req_pack(h: &HeaderMap) -> Result<String, ApiErr> {
    let p = h.get("x-mesh-pack").and_then(|v| v.to_str().ok()).unwrap_or("default");
    if p.is_empty() || p.len() > 64 || !p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err(ApiErr::BadRequest("BAD_PACK"));
    }
    Ok(p.to_string())
}

/// Pack version the caller runs. Anything malformed counts as absent so odd clients keep working.
pub(crate) fn req_pack_version(h: &HeaderMap) -> Option<String> {
    let v = h.get("x-mesh-pack-version")?.to_str().ok()?;
    let parts: Vec<&str> = v.split('.').collect();
    let ok = v.len() <= 32 && parts.len() <= 4 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    ok.then(|| v.to_string())
}

pub(crate) fn auth_bearer(gw: &Gateway, h: &HeaderMap) -> Result<String, ApiErr> {
    let tok = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiErr::Unauthorized)?;
    gw.device_for_token(tok)?.ok_or(ApiErr::Unauthorized)
}

pub(crate) fn auth(gw: &Gateway, h: &HeaderMap) -> Result<String, ApiErr> {
    if let Ok(dev) = auth_bearer(gw, h) {
        return Ok(dev);
    }
    let user = crate::sso::sso_auth(gw, h)?;
    Ok(gw.sso_device(&user)?)
}

fn own_lease(gw: &Gateway, device: &str, lease: &str) -> Result<(), ApiErr> {
    match gw.lease_device(lease)? {
        Some(d) if d == device => Ok(()),
        Some(_) => Err(ApiErr::Forbidden("NOT_LEASE_HOLDER")),
        None => Err(ApiErr::Domain(Error::StaleEpoch)),
    }
}

fn lease_json(g: &Grant) -> Value {
    json!({
        "id": g.lease_id, "epoch": g.epoch, "ttl_s": EXPIRY_MS / 1000,
        "heartbeat_s": HEARTBEAT_MS / 1000, "fence_after_s": FENCE_MS / 1000,
        "ref": "main", "base_rev": g.base_rev,
        "hmac_key": URL_SAFE_NO_PAD.encode(g.hmac_key),
    })
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct HwReq {
    tier: u8,
    score: f64,
    #[serde(default = "yes")]
    wants_host: bool,
    #[serde(default)]
    takeover: bool,
    #[serde(default)]
    bench: Option<Value>,
}

#[derive(Deserialize)]
struct JoinReq {
    hw: HwReq,
    /// The client process has just started and holds no lease state.
    #[serde(default)]
    fresh: bool,
}

#[derive(Deserialize)]
struct CreateWorld {
    name: String,
    mc_version: String,
    loader: String,
}

async fn create_world(State(s): State<Arc<AppState>>, h: HeaderMap, Json(b): Json<CreateWorld>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    if !s.auth.allow_create {
        return Err(ApiErr::Forbidden("CREATE_DISABLED"));
    }
    let ok = |t: &str, max: usize| !t.is_empty() && t.len() <= max && t.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    if !ok(&b.name, 64) || !ok(&b.mc_version, 16) || !ok(&b.loader, 16) {
        return Err(ApiErr::BadRequest("BAD_WORLD"));
    }
    let pack = req_pack(&h)?;
    let id = gw.create_world_for(&dev, &b.name, &b.mc_version, &b.loader)?;
    gw.set_pack(&id, &pack)?;
    if let Some((uuid, _)) = gw.device_player(&dev)? {
        gw.set_world_owner(&id, &uuid)?;
    }
    gw.audit(&dev, "world.create", &id, &id, json!({ "name": b.name }));
    s.hooks.emit("world.created", &id, json!({ "name": b.name }));
    Ok(Json(json!({ "id": id, "base_rev": format!("{id}:R_0000") })))
}

async fn device_me(State(s): State<Arc<AppState>>, h: HeaderMap) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    Ok(Json(json!({ "device": dev })))
}

async fn list_worlds(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let now = s.now();
    let pack = req_pack(&h)?;
    let all = q.get("all").is_some_and(|v| v == "1");
    let is_admin = gw.device_player(&dev).ok().flatten().is_some_and(|(u, _)| gw.is_admin(&u, &s.auth.admins));
    let hw = q.get("score").and_then(|v| v.parse::<f64>().ok()).map(|sc| (q.get("tier").and_then(|v| v.parse::<u8>().ok()).unwrap_or(1), sc));
    let raw = if all && is_admin { gw.all_worlds()? } else { gw.worlds_of(&dev)? };
    let worlds: Vec<Value> = raw
        .into_iter()
        .filter(|w| all || gw.pack_of(&w.0).map(|p| p == pack).unwrap_or(false))
        .map(|(id, name, mc, role, state, host)| {
            let pack_version = gw.pack_version_of(&id);
            let ready = host.is_none() || s.live_worlds.lock().unwrap_or_else(|e| e.into_inner()).contains(&id);
            let takeover = hw.filter(|_| ready && gw.may_host(&id, &dev)).and_then(|(tier, score)| gw.takeover_in(&id, &dev, tier, score, now));
            let sync = if ready {
                None
            } else {
                gw.lease_of_world(&id).and_then(|l| s.sync.lock().unwrap_or_else(|e| e.into_inner()).get(&l).copied())
                    .filter(|(_, t, at)| *t > 0 && at.elapsed().as_secs() < 30)
                    .map(|(d, t, _)| json!({ "done": d, "total": t }))
            };
            let mut v = json!({ "id": id, "name": name, "mc_version": mc, "role": role, "state": state, "host": host, "takeover_in_s": takeover, "host_ready": ready, "sync": sync, "pack_version": pack_version, "host_load": gw.lease_load(&id).ok().flatten(), "host_players": gw.lease_players(&id).ok().flatten() });
            if all {
                v["pack"] = json!(gw.pack_of(&id).ok());
                v["owner"] = json!(gw.world_owner(&id).ok().flatten().and_then(|u| gw.player_name(&u).ok()));
            }
            v
        })
        .collect();
    Ok(Json(json!({ "worlds": worlds, "relay": s.auth.advertise, "tunnel_proof": true })))
}

#[derive(Deserialize)]
struct InviteReq {
    role: Option<String>,
    /// Seconds until the code stops working. Omitted: 7 days. 0: never.
    expires_in_s: Option<i64>,
}

async fn create_invite(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<InviteReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    let role = match b.role.as_deref() {
        None | Some("CLIENT_ONLY") => crate::lease::Role::ClientOnly,
        Some("HOST_ELIGIBLE") => crate::lease::Role::HostEligible,
        _ => return Err(ApiErr::BadRequest("BAD_ROLE")),
    };
    let ttl = b.expires_in_s.unwrap_or(crate::ops::INVITE_TTL_S);
    if !(0..=crate::ops::INVITE_MAX_TTL_S).contains(&ttl) {
        return Err(ApiErr::BadRequest("BAD_EXPIRY"));
    }
    let code = gw.create_invite(&dev, &world, role)?;
    let expires_at = (ttl > 0).then(|| crate::lease::wall_s() + ttl);
    gw.set_invite_expiry(&code, expires_at)?;
    gw.audit(&dev, "invite.create", &world, &code, json!({ "expires_at": expires_at }));
    Ok(Json(json!({ "code": code, "expires_at": expires_at, "link": format!("/invite/{code}") })))
}

#[derive(Deserialize)]
struct RedeemReq {
    code: String,
}

async fn redeem_invite(State(s): State<Arc<AppState>>, h: HeaderMap, Json(b): Json<RedeemReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    if let Some(Err(())) = gw.invite_info(b.code.trim())? {
        return Err(ApiErr::Gone("INVITE_EXPIRED"));
    }
    if let (Some(w), Some((uuid, _))) = (gw.invite_world(b.code.trim()), gw.device_player(&dev)?) {
        if gw.is_world_banned(&w, &uuid) {
            return Err(ApiErr::Forbidden("BANNED_FROM_WORLD"));
        }
    }
    let world = gw.redeem_invite(&dev, b.code.trim())?;
    gw.meter(&world, "invites_redeemed", 1);
    gw.audit(&dev, "invite.redeem", &world, &b.code.trim().to_uppercase(), json!({}));
    let player = gw.device_player(&dev)?.map(|p| p.1);
    s.hooks.emit("member.joined", &world, json!({ "player": player }));
    Ok(Json(json!({ "world_id": world })))
}

async fn join(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<JoinReq>) -> R {
    let now = s.now();
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    gw.require_pack(&world, &req_pack(&h)?)?;
    let host_allowed = gw.may_host(&world, &dev);
    let hw = Hw { tier: b.hw.tier, score: b.hw.score, wants_host: b.hw.wants_host && host_allowed, takeover: b.hw.takeover };
    if let Some(b) = b.hw.bench.as_ref().filter(|v| v.is_object() && v.to_string().len() <= 2048) {
        gw.record_bench(&dev, b)?;
    }
    gw.meter(&world, "joins", 1);
    if b.fresh && host_allowed && b.hw.wants_host {
        gw.drop_own_lease(&world, &dev)?;
    }
    let before = gw.lease_of_world(&world);
    let unhosted = before.is_none();
    let mut out = match gw.join(&world, &dev, hw, now)? {
        Join::Host(g) => {
            if before.as_deref() != Some(g.lease_id.as_str()) {
                gw.audit(&dev, "host.grant", &world, &g.lease_id, json!({ "epoch": g.epoch }));
            }
            gw.meter(&world, "host_grants", 1);
            if let Some(v) = req_pack_version(&h) {
                gw.set_pack_version(&world, &v);
            }
            let player = gw.device_player(&dev)?.map(|p| p.1);
            s.hooks.emit("host.started", &world, json!({ "player": player, "epoch": g.epoch }));
            json!({ "decision": "HOST", "lease": lease_json(&g) })
        }
        Join::Guest { epoch, host_device } => json!({ "decision": "GUEST", "epoch": epoch, "host": { "device": host_device } }),
        Join::Wait { phase } => json!({ "decision": "WAIT", "phase": phase, "retry_ms": 1500 }),
    };
    // the mark goes down only for demand that stayed unmet: the client that becomes the host is not waiting for one
    if unhosted && out["decision"] != "HOST" && s.wanted_due(&world) {
        let player = gw.device_player(&dev)?.map(|p| p.1);
        s.hooks.emit("world.wanted", &world, json!({ "player": player, "decision": out["decision"] }));
    }
    out["host_allowed"] = json!(host_allowed);
    Ok(Json(out))
}

#[derive(Deserialize)]
struct EpochReq {
    epoch: i64,
    #[serde(default)]
    sync_done: u64,
    #[serde(default)]
    sync_total: u64,
    #[serde(default)]
    players: Option<u32>,
    #[serde(default)]
    load: Option<u32>,
    #[serde(default)]
    tps: Option<f64>,
    #[serde(default)]
    p2p_direct_bytes: Option<u64>,
}

async fn heartbeat(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<EpochReq>) -> R {
    let now = s.now();
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    own_lease(&gw, &dev, &lease)?;
    let pending = gw.heartbeat_full(&lease, b.epoch, b.players, b.load, b.tps, now)?;
    if let Some(p2p) = b.p2p_direct_bytes {
        if p2p > 0 {
            if let Some(world) = gw.lease_world(&lease) {
                gw.meter(&world, "p2p_direct_bytes", p2p);
            }
        }
    }
    if b.sync_total > 0 {
        s.sync.lock().unwrap_or_else(|e| e.into_inner()).insert(lease.clone(), (b.sync_done, b.sync_total, Instant::now()));
    }
    let dirs: Vec<Value> = pending
        .into_iter()
        .map(|d| match d {
            Directive::MigratePrepare { target_device, deadline_ms } => {
                let name = target_device.as_deref().and_then(|d| gw.device_player(d).ok().flatten()).map(|(_, n)| n);
                json!({ "type": "MIGRATE_PREPARE", "target_device": target_device, "target_name": name, "deadline_ms": deadline_ms })
            }
            Directive::FlushBarrier => json!({ "type": "FLUSH_BARRIER" }),
            Directive::LagFreeze { frozen } => json!({ "type": "LAG_FREEZE", "frozen": frozen }),
        })
        .collect();
    Ok(Json(json!({ "ok": true, "expires_in": EXPIRY_MS / 1000, "directives": dirs })))
}


#[derive(Deserialize)]
struct LockReq {
    epoch: i64,
    name: String,
    owner: String,
    #[serde(default)]
    ttl_s: Option<i64>,
}

fn lock_name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-')
}

/// Mods take named locks through the host's lease. A lock from an older epoch is void, the token only grows (see locks.rs).
async fn lock_take(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<LockReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    own_lease(&gw, &dev, &lease)?;
    if !lock_name_ok(&b.name) || !lock_name_ok(&b.owner) {
        return Err(ApiErr::BadRequest("BAD_LOCK_NAME"));
    }
    let (world, _) = gw.require_live(&lease, b.epoch)?;
    match gw.lock_take(&world, &b.name, &b.owner, b.epoch, b.ttl_s.unwrap_or(60), crate::lease::wall_s())? {
        crate::locks::Taken::Granted { token } => Ok(Json(json!({ "granted": true, "token": token }))),
        crate::locks::Taken::HeldBy { owner, until } => Ok(Json(json!({ "granted": false, "held_by": owner, "until": until }))),
    }
}

async fn lock_release(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<LockReq>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    own_lease(&gw, &dev, &lease)?;
    let (world, _) = gw.require_live(&lease, b.epoch)?;
    Ok(Json(json!({ "released": gw.lock_release(&world, &b.name, &b.owner, b.epoch)? })))
}

/// Does anyone want this world right now? An anchor that only hosts on demand polls this instead of holding the
/// lease all day. `wanted_s_ago` is from the in-memory rate limiter for the `world.wanted` event, so it is reset by
/// a gateway restart and is a hint, never a promise.
async fn world_demand(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    let hosted = gw.lease_of_world(&world).is_some();
    let live = s.live_worlds.lock().unwrap_or_else(|e| e.into_inner()).contains(&world);
    Ok(Json(json!({
        "wanted_s_ago": s.wanted_age_s(&world),
        "hosted": hosted,
        "live": live,
    })))
}

async fn locks_list(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> R {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    let rows = gw.locks_list(&world, crate::lease::wall_s())?;
    let locks: Vec<Value> = rows.into_iter().map(|(name, owner, epoch, token, until)| json!({ "name": name, "owner": owner, "epoch": epoch, "token": token, "until": until })).collect();
    Ok(Json(json!({ "locks": locks })))
}
#[derive(Deserialize)]
struct CommitReq {
    epoch: i64,
    base_rev: String,
    kind: String,
    #[serde(default, rename = "final")]
    last: bool,
    #[serde(default)]
    sig: Option<String>,
}

pub(crate) fn b64_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()?.try_into().ok()
}

pub(crate) fn parse_hash(s: &str) -> Option<[u8; 32]> {
    parse_hex(s.strip_prefix("sha256:")?)
}

#[derive(Deserialize)]
struct DeviceKeyReq {
    pubkey: String,
    sig: String,
}

/// Registers the key the host signs commits with. The proof of possession is a signature over the device id and the key.
async fn device_key(State(s): State<Arc<AppState>>, h: HeaderMap, Json(b): Json<DeviceKeyReq>) -> R {
    let pk: [u8; 32] = b64_fixed(&b.pubkey).ok_or(ApiErr::BadRequest("BAD_KEY"))?;
    let sig: [u8; 64] = b64_fixed(&b.sig).ok_or(ApiErr::BadRequest("BAD_SIG"))?;
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    if !crate::devsig::verify(&pk, &crate::devsig::device_key_message(&dev, &pk), &sig) {
        return Err(ApiErr::Domain(Error::BadSignature));
    }
    gw.set_device_key(&dev, &pk)?;
    gw.audit(&dev, "device.key", "", &dev, json!({}));
    Ok(Json(json!({ "ok": true })))
}

/// Swallows a probe body so the host can time its own upload speed. Authenticated, small, rate limited like any other route.
async fn bandwidth_sink(State(s): State<Arc<AppState>>, h: HeaderMap, body: Bytes) -> R {
    {
        let gw = s.gw();
        auth(&gw, &h)?;
    }
    Ok(Json(json!({ "bytes": body.len() })))
}

async fn commit(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<CommitReq>) -> R {
    let now = s.now();
    let kind = match b.kind.as_str() {
        "AUTOSAVE" => CommitKind::Autosave,
        "MIGRATE" => CommitKind::Migrate,
        "SHUTDOWN" => CommitKind::Shutdown,
        _ => return Err(ApiErr::BadRequest("BAD_KIND")),
    };
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    own_lease(&gw, &dev, &lease)?;
    s.check_commit(&gw, &dev, b.last)?;
    let world = gw.lease_world(&lease).unwrap_or_default();
    let sig: Option<[u8; 64]> = match &b.sig {
        Some(v) => Some(b64_fixed(v).ok_or(ApiErr::BadRequest("BAD_SIG"))?),
        None => None,
    };
    if sig.is_none() && (s.auth.require_signed || gw.world_requires_signed(&world)) {
        return Err(ApiErr::Forbidden("SIGNATURE_REQUIRED"));
    }
    let r = match gw.commit_signed(&lease, b.epoch, &b.base_rev, kind, b.last, sig.as_ref(), now) {
        Ok(r) => r,
        Err(e) => {
            if matches!(e, Error::Rejected(_)) {
                gw.meter(&world, "commits_rejected", 1);
                let player = gw.device_player(&dev)?.map(|p| p.1);
                s.hooks.emit("commit.rejected", &world, json!({ "player": player }));
            }
            return Err(e.into());
        }
    };
    gw.meter(&world, "commits", 1);
    if b.kind != "AUTOSAVE" {
        s.hooks.emit("revision.committed", &world, json!({ "rev": r.id, "seq": r.seq, "kind": b.kind }));
    }
    Ok(Json(json!({ "rev_id": r.id, "parent": r.parent, "seq": r.seq })))
}

#[derive(Deserialize)]
struct ReleaseReq {
    epoch: i64,
    #[serde(default)]
    guests_present: bool,
}

async fn release(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<ReleaseReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    own_lease(&gw, &dev, &lease)?;
    gw.release(&lease, b.epoch, b.guests_present)?;
    gw.audit(&dev, "host.release", &gw.lease_world(&lease).unwrap_or_default(), &lease, json!({}));
    let player = gw.device_player(&dev)?.map(|p| p.1);
    s.hooks.emit("host.released", &gw.lease_world(&lease).unwrap_or_default(), json!({ "player": player }));
    Ok(Json(json!({ "ok": true })))
}

async fn host_ready(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<EpochReq>) -> R {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    own_lease(&gw, &dev, &lease)?;
    gw.host_ready(&lease, b.epoch)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub(crate) struct FrameReq {
    seq: u64,
    op: String,
    #[serde(default)]
    dim: String,
    #[serde(default)]
    cx: i32,
    #[serde(default)]
    cz: i32,
    hash: String,
    mac: String,
}

#[derive(Deserialize)]
pub(crate) struct WalReq {
    pub(crate) epoch: i64,
    pub(crate) frames: Vec<FrameReq>,
}

pub(crate) fn frames_of(b: WalReq) -> Result<Vec<Frame>, ApiErr> {
    let mut frames = Vec::with_capacity(b.frames.len());
    for f in b.frames {
        frames.push(Frame {
            seq: f.seq,
            op: f.op,
            dim: f.dim,
            cx: f.cx,
            cz: f.cz,
            hash: parse_hash(&f.hash).ok_or(ApiErr::BadRequest("BAD_HASH"))?,
            mac: parse_hex(&f.mac).ok_or(ApiErr::BadRequest("BAD_MAC_ENCODING"))?.to_vec(),
        });
    }
    Ok(frames)
}

async fn wal_append(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<WalReq>) -> R {
    let epoch = b.epoch;
    let frames = frames_of(b)?;
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    own_lease(&gw, &dev, &lease)?;
    let next = gw.wal_append(&lease, epoch, &frames)?;
    Ok(Json(json!({ "next_seq": next })))
}

pub(crate) const MAX_BLOB: usize = 16 << 20;
/// Everything that is not a blob, a WAL batch or a log chunk is a small JSON document.
const MAX_JSON: usize = 64 << 10;
const MAX_WAL: usize = 4 << 20;
const MAX_BANDWIDTH_PROBE: usize = 1 << 20;
const MAX_LOG_CHUNK: usize = 1 << 20;

/// Client log lines: appended to MCMESH_LOGS/<player>.log, or stderr when unset.
async fn client_logs(State(s): State<Arc<AppState>>, h: HeaderMap, body: Bytes) -> R {
    use std::io::Write;
    let name = {
        let gw = s.gw();
        let dev = auth(&gw, &h)?;
        gw.device_player(&dev)?.map(|(_, n)| n).unwrap_or_default()
    };
    if body.len() > 1 << 20 || name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ApiErr::BadRequest("BAD_LOG"));
    }
    let text = String::from_utf8_lossy(&body);
    match std::env::var("MCMESH_LOGS") {
        Ok(dir) => {
            let path = std::path::Path::new(&dir).join(format!("{name}.log"));
            rotate_log(&path, std::env::var("MCMESH_LOG_MAX_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(5 << 20));
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).map_err(|_| ApiErr::BadRequest("LOG_IO"))?;
            let _ = f.write_all(text.as_bytes());
        }
        Err(_) => text.lines().for_each(|l| eprintln!("[{name}] {l}")),
    }
    Ok(Json(json!({ "ok": true })))
}

/// One previous file is kept, so a player never takes more than twice `max` on disk.
pub(crate) fn rotate_log(path: &std::path::Path, max: u64) {
    if std::fs::metadata(path).is_ok_and(|m| m.len() >= max) {
        let _ = std::fs::rename(path, path.with_extension("log.1"));
    }
}

async fn blob_put(State(s): State<Arc<AppState>>, h: HeaderMap, Path(hash): Path<String>, body: Bytes) -> R {
    let want = parse_hex(&hash).ok_or(ApiErr::BadRequest("BAD_HASH"))?;
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let world = match gw.hosted_world(&dev)? {
        Some(w) => w,
        None => match gw.shard_world_of(&dev)? {
            Some(w) => w,
            None => gw.worldgen_claim_world(&dev, crate::lease::wall_s())?.ok_or(ApiErr::Forbidden("NOT_LEASE_HOLDER"))?,
        },
    };
    if crate::cas::sha256(&body) != want {
        return Err(ApiErr::BadRequest("HASH_MISMATCH"));
    }
    gw.check_upload_headroom(&world)?;
    gw.cas().put(&body).map_err(|e| ApiErr::Domain(e.into()))?;
    gw.tag_blob(&world, &want)?;
    gw.meter(&world, "blob_put_bytes", body.len() as u64);
    Ok(Json(json!({ "ok": true })))
}

async fn blob_get(State(s): State<Arc<AppState>>, h: HeaderMap, Path(hash): Path<String>) -> Result<Vec<u8>, ApiErr> {
    let want = parse_hex(&hash).ok_or(ApiErr::BadRequest("BAD_HASH"))?;
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let world = gw.blob_accessible_world(&dev, &want)?.ok_or(ApiErr::BadRequest("NO_SUCH_BLOB"))?;
    if !gw.cas().has(&want) {
        return Err(ApiErr::BadRequest("NO_SUCH_BLOB"));
    }
    let data = gw.cas().get(&want).map_err(|e| ApiErr::Domain(e.into()))?;
    gw.meter(&world, "blob_get_bytes", data.len() as u64);
    Ok(data)
}

async fn blob_head(State(s): State<Arc<AppState>>, h: HeaderMap, Path(hash): Path<String>) -> R {
    let want = parse_hex(&hash).ok_or(ApiErr::BadRequest("BAD_HASH"))?;
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let present = gw.blob_visible(&dev, &want)? && gw.cas().has(&want);
    gw.meter("", "blob_checks", 1);
    if present {
        gw.meter("", "blob_check_hits", 1);
    }
    Ok(Json(json!({ "hash": hex(&want), "present": present })))
}

async fn revision_files(State(s): State<Arc<AppState>>, h: HeaderMap, Path(rev): Path<String>) -> R {
    use crate::manifest::{self, Item, Kind};
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let world = gw.revision_world(&rev)?.ok_or(ApiErr::Domain(Error::NoSuchWorld))?;
    gw.require_member(&world, &dev)?;
    let root = gw.revision_root(&rev)?;
    let empty = manifest::empty_root(gw.cas()).map_err(|e| ApiErr::Domain(e.into()))?;
    let diff = manifest::diff(gw.cas(), Some(empty), Some(root)).map_err(|e| ApiErr::Domain(e.into()))?;
    let (mut chunks, mut aux) = (Vec::new(), Vec::new());
    for d in diff {
        let Some(hash) = d.new else { continue };
        match d.item {
            Item::Chunk(k) => chunks.push(json!({
                "dim": k.dim, "cx": k.cx, "cz": k.cz, "hash": hex(&hash),
                "kind": match k.kind { Kind::Region => "region", Kind::Entities => "entities", Kind::Poi => "poi" },
            })),
            Item::Aux(path) => aux.push(json!({ "path": path, "hash": hex(&hash) })),
        }
    }
    Ok(Json(json!({ "rev": rev, "root": hex(&root), "chunks": chunks, "aux": aux })))
}

/// Owner-only world download. Streams zip directly without buffering the whole archive in memory.
async fn world_export(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> Result<Response, ApiErr> {
    let (root, cas) = {
        let gw = s.gw();
        let dev = auth(&gw, &h)?;
        gw.pack_of(&world)?;
        crate::admin::require_owner_or_admin(&s, &gw, &dev, &world)?;
        gw.require_pack(&world, &req_pack(&h)?)?;
        let root = gw.revision_root(&gw.head(&world)?)?;
        (root, gw.cas().clone())
    };
    let name = if world.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        format!("{world}.zip")
    } else {
        "world.zip".to_string()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::io::Result<Bytes>>(16);
    tokio::task::spawn_blocking(move || {
        struct Pipe(tokio::sync::mpsc::Sender<std::io::Result<Bytes>>);
        impl std::io::Write for Pipe {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.blocking_send(Ok(Bytes::copy_from_slice(buf)))
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client disconnected"))?;
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        if let Err(e) = crate::maintenance::export_zip(&cas, root, Pipe(tx.clone())) {
            let _ = tx.blocking_send(Err(e));
        }
    });
    let first = match rx.recv().await {
        Some(Ok(b)) => b,
        Some(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => return Err(ApiErr::Conflict("EXPORT_CORRUPT")),
        Some(Err(e)) => return Err(ApiErr::Domain(e.into())),
        None => Bytes::new(),
    };
    use futures_util::StreamExt;
    let rest = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    let stream = futures_util::stream::once(async move { Ok::<_, std::io::Error>(first) }).chain(rest);
    let body = axum::body::Body::from_stream(stream);
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/zip".to_string()),
            (axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        body,
    )
        .into_response())
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/auth/challenge", post(crate::auth::challenge))
        .route("/v1/auth/mojang", post(crate::auth::mojang))
        .route("/v1/auth/key", post(crate::auth::key))
        .route("/v1/auth/link-code", post(crate::auth::link_code))
        .route("/v1/auth/link", post(crate::auth::link_key))
        .route("/v1/revisions/:rev/files", get(revision_files))
        .route("/v1/worlds/:id/export.zip", get(world_export))
        .route("/v1/worlds/:id/ticket", post(crate::auth::ticket))
        .route("/v1/devices/me", get(device_me))
        .route("/v1/devices/key", post(device_key))
        .route("/v1/bandwidth", post(bandwidth_sink).layer(DefaultBodyLimit::max(MAX_BANDWIDTH_PROBE)))
        .route("/v1/worlds", post(create_world).get(list_worlds))
        .route("/v1/worlds/:id/invite", post(create_invite))
        .route("/v1/invites/redeem", post(redeem_invite))
        .route("/v1/worlds/:id/join", post(join))
        .route("/v1/leases/:id/heartbeat", post(heartbeat))
        .route("/v1/leases/:id/commit", post(commit))
        .route("/v1/leases/:id/lock", post(lock_take))
        .route("/v1/leases/:id/report", post(crate::admin::host_report))
        .route("/v1/leases/:id/unlock", post(lock_release))
        .route("/v1/worlds/:id/locks", get(locks_list))
        .route("/v1/worlds/:id/demand", get(world_demand))
        .route("/v1/leases/:id/release", post(release))
        .route("/v1/leases/:id/host-ready", post(host_ready))
        .route("/v1/leases/:id/wal", post(wal_append).layer(DefaultBodyLimit::max(MAX_WAL)))
        .route("/v1/logs", post(client_logs).layer(DefaultBodyLimit::max(MAX_LOG_CHUNK)))
        .route("/v1/blobs/:hash", put(blob_put).layer(DefaultBodyLimit::max(MAX_BLOB)).get(blob_get))
        .route("/v1/blobs/:hash/exists", get(blob_head))
        .merge(crate::panel::routes())
        .merge(crate::ops::routes())
        .merge(crate::admin::routes())
        .merge(crate::sso::routes())
        .merge(crate::crash::routes())
        .merge(crate::worldgen::routes())
        .merge(crate::shard::routes())
        .merge(crate::skin::routes())
        .layer(axum::middleware::from_fn_with_state(state.clone(), crate::admin::gate))
        .layer(DefaultBodyLimit::max(MAX_JSON))
        .layer(axum::middleware::from_fn_with_state(state.clone(), client_gate))
        .layer(axum::middleware::from_fn_with_state(state.clone(), crate::ratelimit::layer))
        .with_state(state)
}

#[cfg(test)]
mod core_wiring_tests {
    use super::*;
    use crate::lease::Role;
    use crate::quota::QuotaHit;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn body_of(e: ApiErr) -> (u16, Value) {
        let r = e.into_response();
        let code = r.status().as_u16();
        let bytes = r.into_body().collect().await.unwrap().to_bytes();
        (code, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn quota_and_pruned_errors_follow_the_contract() {
        let hit = |code| ApiErr::Domain(Error::Quota(QuotaHit { code, limit: 10, used: 12 }));
        let (c, v) = body_of(hit("QUOTA_WORLD_COUNT")).await;
        assert_eq!((c, v["error"].as_str(), v["limit"].as_u64(), v["used"].as_u64()), (403, Some("QUOTA_WORLD_COUNT"), Some(10), Some(12)));
        let (c, v) = body_of(hit("QUOTA_STORAGE_WORLD")).await;
        assert_eq!((c, v["error"].as_str()), (507, Some("QUOTA_STORAGE_WORLD")));
        let (c, v) = body_of(hit("QUOTA_STORAGE_USER")).await;
        assert_eq!((c, v["error"].as_str()), (507, Some("QUOTA_STORAGE_USER")));
        let (c, v) = body_of(ApiErr::Domain(Error::Pruned)).await;
        assert_eq!((c, v["error"].as_str()), (410, Some("REVISION_PRUNED")));
    }

    #[tokio::test]
    async fn heartbeat_stores_the_players_field_and_old_clients_keep_it() {
        let cas = crate::cas::Cas::open(std::env::temp_dir().join(format!("mcmesh-hbp-{}", std::process::id()))).unwrap();
        let mut g = Gateway::open(rusqlite::Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
        g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
        g.add_token("dev-a", "tok-a").unwrap();
        let state = AppState::new(g);
        let app = router(state.clone());
        let post = |path: String, body: Value| {
            let app = app.clone();
            async move {
                let r = Request::post(path).header("content-type", "application/json").header("authorization", "Bearer tok-a").body(Body::from(body.to_string())).unwrap();
                let resp = app.oneshot(r).await.unwrap();
                let code = resp.status().as_u16();
                let bytes = resp.into_body().collect().await.unwrap().to_bytes();
                (code, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
            }
        };
        let (_, v) = post("/v1/worlds/w1/join".into(), json!({ "hw": { "tier": 2, "score": 5.0 } })).await;
        let lease = v["lease"]["id"].as_str().unwrap().to_string();
        assert_eq!(state.gw().lease_players("w1").unwrap(), None);
        let (c, _) = post(format!("/v1/leases/{lease}/heartbeat"), json!({ "epoch": 1, "players": 3 })).await;
        assert_eq!(c, 200);
        assert_eq!(state.gw().lease_players("w1").unwrap(), Some(3));
        let (c, _) = post(format!("/v1/leases/{lease}/heartbeat"), json!({ "epoch": 1 })).await;
        assert_eq!(c, 200);
        assert_eq!(state.gw().lease_players("w1").unwrap(), Some(3));
    }

    #[tokio::test]
    async fn locks_go_through_the_live_lease_and_a_stale_epoch_cannot_take_one() {
        let cas = crate::cas::Cas::open(std::env::temp_dir().join(format!("mcmesh-lockhttp-{}", std::process::id()))).unwrap();
        let mut g = Gateway::open(rusqlite::Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
        g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
        g.add_token("dev-a", "tok-a").unwrap();
        g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
        g.add_token("dev-b", "tok-b").unwrap();
        g.ops_init().unwrap();
        let app = router(AppState::new(g));
        let call = |tok: &'static str, method: &'static str, path: String, body: Value| {
            let app = app.clone();
            async move {
                let r = Request::builder().method(method).uri(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}")).body(Body::from(body.to_string())).unwrap();
                let resp = app.oneshot(r).await.unwrap();
                let code = resp.status().as_u16();
                let bytes = resp.into_body().collect().await.unwrap().to_bytes();
                (code, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
            }
        };
        let (_, v) = call("tok-a", "POST", "/v1/worlds/w1/join".into(), json!({ "hw": { "tier": 2, "score": 5.0 } })).await;
        let lease = v["lease"]["id"].as_str().unwrap().to_string();
        let path = format!("/v1/leases/{lease}/lock");
        let (c, v) = call("tok-a", "POST", path.clone(), json!({ "epoch": 1, "name": "quarry", "owner": "moda", "ttl_s": 30 })).await;
        assert_eq!((c, v["granted"].as_bool(), v["token"].as_i64()), (200, Some(true), Some(1)));
        let (_, v) = call("tok-a", "POST", path.clone(), json!({ "epoch": 1, "name": "quarry", "owner": "modb" })).await;
        assert_eq!((v["granted"].as_bool(), v["held_by"].as_str()), (Some(false), Some("moda")));
        assert_eq!(call("tok-a", "POST", path.clone(), json!({ "epoch": 1, "name": "Bad Name", "owner": "moda" })).await.0, 400);
        assert_eq!(call("tok-a", "POST", path.clone(), json!({ "epoch": 9, "name": "quarry", "owner": "moda" })).await.0, 409, "a wrong epoch is refused");
        assert_eq!(call("tok-b", "POST", path.clone(), json!({ "epoch": 1, "name": "x", "owner": "moda" })).await.0, 403, "only the lease holder");
        let (_, v) = call("tok-b", "GET", "/v1/worlds/w1/locks".into(), Value::Null).await;
        assert_eq!(v["locks"][0]["name"], "quarry", "members can see the locks");
        let (_, v) = call("tok-a", "POST", format!("/v1/leases/{lease}/unlock"), json!({ "epoch": 1, "name": "quarry", "owner": "moda" })).await;
        assert_eq!(v["released"], true);
        let (_, v) = call("tok-a", "POST", path, json!({ "epoch": 1, "name": "quarry", "owner": "modb" })).await;
        assert_eq!((v["granted"].as_bool(), v["token"].as_i64()), (Some(true), Some(2)));
    }

    #[tokio::test]
    async fn the_host_files_a_report_for_a_player_with_the_chat_they_agreed_to_share() {
        let cas = crate::cas::Cas::open(std::env::temp_dir().join(format!("mcmesh-hostreport-{}", std::process::id()))).unwrap();
        let mut g = Gateway::open(rusqlite::Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
        for (u, n, d, t, r) in [("u-a", "alice", "dev-a", "tok-a", Role::Admin), ("u-b", "bob", "dev-b", "tok-b", Role::HostEligible), ("u-c", "carol", "dev-c", "tok-c", Role::ClientOnly)] {
            g.add_member("w1", u, n, d, r).unwrap();
            g.add_token(d, t).unwrap();
        }
        g.ops_init().unwrap();
        let cfg = crate::auth::AuthCfg { admins: vec!["u-a".into()], ..Default::default() };
        let app = router(AppState::with_auth(g, cfg));
        let call = |tok: &'static str, method: &'static str, path: String, body: Value| {
            let app = app.clone();
            async move {
                let r = Request::builder().method(method).uri(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}")).body(Body::from(body.to_string())).unwrap();
                let resp = app.oneshot(r).await.unwrap();
                let code = resp.status().as_u16();
                let bytes = resp.into_body().collect().await.unwrap().to_bytes();
                (code, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
            }
        };
        let (_, v) = call("tok-b", "POST", "/v1/worlds/w1/join".into(), json!({ "hw": { "tier": 2, "score": 5.0 } })).await;
        let lease = v["lease"]["id"].as_str().unwrap().to_string();
        let path = format!("/v1/leases/{lease}/report");
        let body = |evidence: &str| json!({ "epoch": 1, "reporter": "carol", "name": "alice", "reason": "built over my base", "evidence": evidence });
        assert_eq!(call("tok-a", "POST", path.clone(), body("x")).await.0, 403, "only the lease holder can vouch");
        let (c, v) = call("tok-b", "POST", path.clone(), body("<alice> hi\n<alice> your base is mine")).await;
        assert_eq!((c, v["id"].as_i64()), (200, Some(1)));
        assert_eq!(call("tok-b", "POST", path.clone(), body(&"x".repeat(4001))).await.1["error"], "EVIDENCE_TOO_LONG");
        assert_eq!(call("tok-b", "POST", path.clone(), json!({ "epoch": 1, "reporter": "nobody", "name": "alice", "reason": "r" })).await.1["error"], "NO_SUCH_USER");
        assert_eq!(call("tok-b", "POST", path, json!({ "epoch": 1, "reporter": "carol", "name": "carol", "reason": "r" })).await.1["error"], "CANNOT_TARGET_SELF");
        let (_, v) = call("tok-a", "GET", "/v1/worlds/w1/reports".into(), Value::Null).await;
        assert_eq!((v["reports"][0]["reporter"].as_str(), v["reports"][0]["evidence"].as_str()), (Some("carol"), Some("<alice> hi\n<alice> your base is mine")));
        let (_, v) = call("tok-a", "GET", "/v1/worlds/w1/moderation".into(), Value::Null).await;
        assert_eq!(v["events"][0]["detail"]["via_host"], true, "the log says the host vouched for it");
    }

    #[test]
    fn log_files_rotate_once_and_stay_bounded() {
        let dir = std::env::temp_dir().join(format!("mcmesh-logrot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("alice.log");
        std::fs::write(&f, vec![b'a'; 100]).unwrap();
        rotate_log(&f, 1000);
        assert_eq!(std::fs::metadata(&f).unwrap().len(), 100, "under the cap nothing moves");
        std::fs::write(&f, vec![b'b'; 1000]).unwrap();
        rotate_log(&f, 1000);
        assert!(!f.exists());
        assert_eq!(std::fs::metadata(dir.join("alice.log.1")).unwrap().len(), 1000);
        std::fs::write(&f, vec![b'c'; 2000]).unwrap();
        rotate_log(&f, 1000);
        assert_eq!(std::fs::metadata(dir.join("alice.log.1")).unwrap().len(), 2000, "the older file is replaced, not kept");
    }
}
