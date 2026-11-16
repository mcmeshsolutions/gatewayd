//! Standalone sign-in for the web dashboard, independent of the per-player device/key identity in auth.rs.
//! An SSO account is a separate login (email + password); linking it to a Minecraft player is opt-in and
//! reuses the same one-time-code pattern as auth.rs's device linking.
use crate::lease::{Error, Gateway};
use crate::server::{ApiErr, AppState};
use axum::{
    extract::State,
    http::{header, HeaderMap},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

const PBKDF2_ITERS: u32 = 300_000;
const SESSION_COOKIE: &str = "mcmesh_sso";
const SESSION_MAX_AGE_S: i64 = 30 * 24 * 3600;
const EMAIL_MAX: usize = 256;
const PASSWORD_MIN: usize = 8;
const PASSWORD_MAX: usize = 256;

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut t = u;
    for _ in 1..iters {
        let mut mac = HmacSha256::new_from_slice(password).expect("hmac accepts any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for i in 0..32 {
            t[i] ^= u[i];
        }
    }
    t
}

fn rand_bytes(n: usize) -> Result<Vec<u8>, Error> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).map_err(|_| Error::Rand)?;
    Ok(b)
}

fn rand_token() -> Result<String, Error> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    Ok(URL_SAFE_NO_PAD.encode(rand_bytes(32)?))
}

fn valid_email(s: &str) -> bool {
    !s.is_empty() && s.len() <= EMAIL_MAX && s.contains('@') && !s.contains(char::is_whitespace)
}

pub struct SsoUser {
    pub id: String,
    pub email: String,
    pub is_superadmin: bool,
}

impl Gateway {
    pub fn sso_init(&self) -> Result<(), Error> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS sso_users(
               id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
               pass_salt BLOB NOT NULL, pass_hash BLOB NOT NULL,
               is_superadmin INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS sso_sessions(
               token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES sso_users(id),
               created_at INTEGER NOT NULL, last_used INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS sso_links(
               sso_user_id TEXT NOT NULL REFERENCES sso_users(id),
               player_uuid TEXT NOT NULL UNIQUE REFERENCES players(uuid),
               linked_at INTEGER NOT NULL, PRIMARY KEY(sso_user_id, player_uuid));",
        )?;
        Ok(())
    }

    fn sso_create(&self, email: &str, password: &str, superadmin: bool) -> Result<String, Error> {
        let id = rand_token()?;
        let salt = rand_bytes(16)?;
        let hash = pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERS);
        self.db.execute(
            "INSERT INTO sso_users(id,email,pass_salt,pass_hash,is_superadmin,created_at) VALUES(?,?,?,?,?,strftime('%s','now'))",
            rusqlite::params![id, email, salt, hash.to_vec(), superadmin as i64],
        )?;
        Ok(id)
    }

    fn sso_verify(&self, email: &str, password: &str) -> Result<Option<SsoUser>, Error> {
        let row: Option<(String, String, Vec<u8>, Vec<u8>, i64)> = self
            .db
            .query_row(
                "SELECT id,email,pass_salt,pass_hash,is_superadmin FROM sso_users WHERE email=? COLLATE NOCASE",
                rusqlite::params![email],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((id, email, salt, hash, superadmin)) = row else { return Ok(None) };
        let want = pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERS);
        // constant-time compare: a login must not be distinguishable by how many leading bytes matched
        let ok = want.len() == hash.len() && want.iter().zip(hash.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
        Ok(ok.then_some(SsoUser { id, email, is_superadmin: superadmin != 0 }))
    }

    fn sso_session(&self, token: &str) -> Result<Option<SsoUser>, Error> {
        use sha2::Digest;
        let h = Sha256::digest(token.as_bytes());
        let row: Option<(String, String, i64)> = self
            .db
            .query_row(
                "SELECT u.id,u.email,u.is_superadmin FROM sso_sessions s JOIN sso_users u ON u.id=s.user_id WHERE s.token_hash=?",
                rusqlite::params![h.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if row.is_some() {
            self.db.execute("UPDATE sso_sessions SET last_used=strftime('%s','now') WHERE token_hash=?", rusqlite::params![h.as_slice()])?;
        }
        Ok(row.map(|(id, email, superadmin)| SsoUser { id, email, is_superadmin: superadmin != 0 }))
    }

    fn sso_new_session(&self, user_id: &str) -> Result<String, Error> {
        use sha2::Digest;
        let token = rand_token()?;
        let h = Sha256::digest(token.as_bytes());
        self.db.execute(
            "INSERT INTO sso_sessions(token_hash,user_id,created_at,last_used) VALUES(?,?,strftime('%s','now'),strftime('%s','now'))",
            rusqlite::params![h.as_slice(), user_id],
        )?;
        Ok(token)
    }

    fn sso_drop_session(&self, token: &str) -> Result<(), Error> {
        use sha2::Digest;
        let h = Sha256::digest(token.as_bytes());
        self.db.execute("DELETE FROM sso_sessions WHERE token_hash=?", rusqlite::params![h.as_slice()])?;
        Ok(())
    }

    pub fn set_superadmin(&self, email: &str, on: bool) -> Result<bool, Error> {
        let n = self.db.execute("UPDATE sso_users SET is_superadmin=? WHERE email=? COLLATE NOCASE", rusqlite::params![on as i64, email])?;
        Ok(n > 0)
    }

    /// The player uuids an SSO account has linked, for "my worlds" views that are not superadmin.
    pub fn sso_linked_players(&self, sso_user_id: &str) -> Result<Vec<String>, Error> {
        let mut st = self.db.prepare("SELECT player_uuid FROM sso_links WHERE sso_user_id=?")?;
        let rows = st.query_map(rusqlite::params![sso_user_id], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn sso_link(&self, sso_user_id: &str, player_uuid: &str) -> Result<(), Error> {
        self.db.execute(
            "INSERT OR REPLACE INTO sso_links(sso_user_id,player_uuid,linked_at) VALUES(?,?,strftime('%s','now'))",
            rusqlite::params![sso_user_id, player_uuid],
        )?;
        Ok(())
    }
}

use rusqlite::OptionalExtension;

/// Reads the session cookie and resolves it to an SSO user; used by every dashboard route.
pub(crate) fn sso_auth(gw: &Gateway, h: &HeaderMap) -> Result<SsoUser, ApiErr> {
    let raw = h.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = raw
        .split(';')
        .map(|p| p.trim())
        .find_map(|p| p.strip_prefix(&format!("{SESSION_COOKIE}=")))
        .ok_or(ApiErr::Unauthorized)?;
    Ok(gw.sso_session(token)?.ok_or(ApiErr::Unauthorized)?)
}

fn session_cookie(token: &str, max_age_s: i64) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={max_age_s}")
}

#[derive(Deserialize)]
struct CredReq {
    email: String,
    password: String,
}

async fn register(State(s): State<Arc<AppState>>, Json(b): Json<CredReq>) -> Result<impl IntoResponse, ApiErr> {
    if !valid_email(&b.email) {
        return Err(ApiErr::BadRequest("BAD_EMAIL"));
    }
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&b.password.len()) {
        return Err(ApiErr::BadRequest("BAD_PASSWORD"));
    }
    let gw = s.gw();
    // the very first account on a fresh gateway starts as superadmin, so there is always a way in
    let first = gw.db.query_row("SELECT COUNT(*) FROM sso_users", [], |r| r.get::<_, i64>(0)).map_err(Error::Db)? == 0;
    let id = gw.sso_create(&b.email, &b.password, first).map_err(|e| match e {
        Error::Db(rusqlite::Error::SqliteFailure(ref se, _)) if se.code == rusqlite::ErrorCode::ConstraintViolation => ApiErr::Conflict("EMAIL_TAKEN"),
        e => e.into(),
    })?;
    let token = gw.sso_new_session(&id)?;
    Ok(([(header::SET_COOKIE, session_cookie(&token, SESSION_MAX_AGE_S))], Json(json!({ "ok": true, "email": b.email, "superadmin": first }))))
}

async fn login(State(s): State<Arc<AppState>>, Json(b): Json<CredReq>) -> Result<impl IntoResponse, ApiErr> {
    let gw = s.gw();
    let user = gw.sso_verify(&b.email, &b.password)?.ok_or(ApiErr::Unauthorized)?;
    let token = gw.sso_new_session(&user.id)?;
    Ok(([(header::SET_COOKIE, session_cookie(&token, SESSION_MAX_AGE_S))], Json(json!({ "ok": true, "email": user.email, "superadmin": user.is_superadmin }))))
}

async fn logout(State(s): State<Arc<AppState>>, h: HeaderMap) -> Result<impl IntoResponse, ApiErr> {
    let gw = s.gw();
    let raw = h.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if let Some(token) = raw.split(';').map(|p| p.trim()).find_map(|p| p.strip_prefix(&format!("{SESSION_COOKIE}="))) {
        gw.sso_drop_session(token)?;
    }
    Ok(([(header::SET_COOKIE, session_cookie("", 0))], Json(json!({ "ok": true }))))
}

async fn me(State(s): State<Arc<AppState>>, h: HeaderMap) -> Result<Json<serde_json::Value>, ApiErr> {
    let gw = s.gw();
    let user = sso_auth(&gw, &h)?;
    let players = gw.sso_linked_players(&user.id)?;
    Ok(Json(json!({ "email": user.email, "superadmin": user.is_superadmin, "linked_players": players })))
}

#[derive(Deserialize)]
struct LinkReq {
    code: String,
}

/// Consumes a one-time code minted by an already-authenticated Minecraft device (auth::link_code is the same
/// mechanism auth.rs uses to link a second device's key) and links that player to this SSO account.
async fn link(State(s): State<Arc<AppState>>, h: HeaderMap, Json(b): Json<LinkReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    let gw = s.gw();
    let user = sso_auth(&gw, &h)?;
    let player = {
        let mut m = s.link_codes.lock().unwrap_or_else(|e| e.into_inner());
        match m.remove(b.code.trim()) {
            Some((p, t)) if t.elapsed() < std::time::Duration::from_secs(300) => p,
            _ => return Err(ApiErr::Unauthorized),
        }
    };
    gw.sso_link(&user.id, &player)?;
    Ok(Json(json!({ "ok": true })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/auth/sso/register", post(register))
        .route("/v1/auth/sso/login", post(login))
        .route("/v1/auth/sso/logout", post(logout))
        .route("/v1/sso/me", axum::routing::get(me))
        .route("/v1/sso/link", post(link))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::Cas;

    fn gw() -> Gateway {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let k = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cas = Cas::open(std::env::temp_dir().join(format!("mcmesh-sso-{}-{k}", std::process::id()))).unwrap();
        let g = Gateway::open(rusqlite::Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.sso_init().unwrap();
        g
    }

    #[test]
    fn right_password_verifies_wrong_one_does_not() {
        let g = gw();
        g.sso_create("a@b.c", "correct horse battery", false).unwrap();
        assert!(g.sso_verify("a@b.c", "correct horse battery").unwrap().is_some());
        assert!(g.sso_verify("a@b.c", "wrong password").unwrap().is_none());
        assert!(g.sso_verify("nobody@b.c", "anything").unwrap().is_none());
        // email lookup is case-insensitive, like the player name lookup
        assert!(g.sso_verify("A@B.C", "correct horse battery").unwrap().is_some());
    }

    #[test]
    fn a_session_resolves_back_to_its_user_until_logged_out() {
        let g = gw();
        let id = g.sso_create("a@b.c", "correct horse battery", true).unwrap();
        let token = g.sso_new_session(&id).unwrap();
        let user = g.sso_session(&token).unwrap().expect("session is live");
        assert_eq!(user.email, "a@b.c");
        assert!(user.is_superadmin);
        g.sso_drop_session(&token).unwrap();
        assert!(g.sso_session(&token).unwrap().is_none());
    }

    #[test]
    fn linking_a_player_makes_it_show_up_for_that_account_only() {
        let g = gw();
        g.db.execute("INSERT INTO players(uuid,name,created_at) VALUES('player-uuid-1','alice',0)", []).unwrap();
        let a = g.sso_create("a@b.c", "correct horse battery", false).unwrap();
        let b = g.sso_create("x@y.z", "another password", false).unwrap();
        g.sso_link(&a, "player-uuid-1").unwrap();
        assert_eq!(g.sso_linked_players(&a).unwrap(), vec!["player-uuid-1".to_string()]);
        assert_eq!(g.sso_linked_players(&b).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn set_superadmin_reports_whether_the_email_exists() {
        let g = gw();
        g.sso_create("a@b.c", "correct horse battery", false).unwrap();
        assert!(g.set_superadmin("a@b.c", true).unwrap());
        assert!(g.sso_verify("a@b.c", "correct horse battery").unwrap().unwrap().is_superadmin);
        assert!(!g.set_superadmin("nobody@b.c", true).unwrap());
    }
}
