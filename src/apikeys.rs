//! Scoped API keys for bots and scripts. A key is shown once, stored only as a SHA-256 hash, and opens only the routes its
//! scopes name. Scopes: `read:status` (usage report, audit log, maintenance state) and `op:lifecycle` (switch maintenance
//! mode). Everything else needs a real admin login.

use crate::lease::{wall_s, Error, Gateway, Result};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const PREFIX: &str = "mcmesh_sk_";
pub const SCOPES: [&str; 2] = ["read:status", "op:lifecycle"];

#[derive(Debug, PartialEq, Eq)]
pub enum KeyCheck {
    Valid(i64, String),
    Unknown,
    /// the key exists but does not carry the scope
    Denied,
}

fn hash(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

impl Gateway {
    pub(crate) fn apikeys_init(&self) -> Result<()> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS api_keys(
               id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, key_hash BLOB NOT NULL UNIQUE, scopes TEXT NOT NULL,
               created_by TEXT NOT NULL, created_at INTEGER NOT NULL, last_used INTEGER, revoked INTEGER NOT NULL DEFAULT 0);",
        )?;
        Ok(())
    }

    /// Returns the new key's id and its secret; the secret cannot be read again.
    pub fn create_api_key(&mut self, name: &str, scopes: &[String], created_by: &str) -> Result<std::result::Result<(i64, String), &'static str>> {
        if name.is_empty() || name.len() > 64 {
            return Ok(Err("BAD_NAME"));
        }
        if scopes.is_empty() || scopes.iter().any(|s| !SCOPES.contains(&s.as_str())) {
            return Ok(Err("BAD_SCOPE"));
        }
        let mut raw = [0u8; 24];
        getrandom::getrandom(&mut raw).map_err(|_| Error::Rand)?;
        let secret = format!("{PREFIX}{}", raw.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let mut sorted: Vec<&str> = scopes.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted.dedup();
        self.db.execute(
            "INSERT INTO api_keys(name,key_hash,scopes,created_by,created_at) VALUES(?,?,?,?,?)",
            params![name, hash(&secret), sorted.join(" "), created_by, wall_s()],
        )?;
        Ok(Ok((self.db.last_insert_rowid(), secret)))
    }

    pub fn check_api_key(&self, secret: &str, scope: &str) -> Result<KeyCheck> {
        let row: Option<(i64, String, String)> = self
            .db
            .query_row("SELECT id, name, scopes FROM api_keys WHERE key_hash=? AND revoked=0", params![hash(secret)], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .optional()?;
        let Some((id, name, scopes)) = row else { return Ok(KeyCheck::Unknown) };
        if !scopes.split(' ').any(|s| s == scope) {
            return Ok(KeyCheck::Denied);
        }
        self.db.execute("UPDATE api_keys SET last_used=? WHERE id=?", params![wall_s(), id])?;
        Ok(KeyCheck::Valid(id, name))
    }

    pub fn list_api_keys(&self) -> Result<Vec<Value>> {
        let mut st = self.db.prepare("SELECT id, name, scopes, created_by, created_at, last_used, revoked FROM api_keys ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                "scopes": r.get::<_, String>(2)?.split(' ').map(str::to_string).collect::<Vec<_>>(),
                "created_by": r.get::<_, String>(3)?, "created_at": r.get::<_, i64>(4)?,
                "last_used": r.get::<_, Option<i64>>(5)?, "revoked": r.get::<_, bool>(6)?,
            }))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn revoke_api_key(&mut self, id: i64) -> Result<bool> {
        Ok(self.db.execute("UPDATE api_keys SET revoked=1 WHERE id=? AND revoked=0", params![id])? > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn gw() -> Gateway {
        let g = Gateway::open(Connection::open_in_memory().unwrap(), crate::cas::Cas::open(std::env::temp_dir().join(format!("mcmesh-keys-{}", std::process::id()))).unwrap(), 0).unwrap();
        g.apikeys_init().unwrap();
        g
    }

    #[test]
    fn a_key_works_only_for_its_scopes_and_is_stored_hashed() {
        let mut g = gw();
        let (id, secret) = g.create_api_key("grafana", &["read:status".into()], "alice").unwrap().unwrap();
        assert!(secret.starts_with(PREFIX) && secret.len() == PREFIX.len() + 48);
        assert_eq!(g.check_api_key(&secret, "read:status").unwrap(), KeyCheck::Valid(id, "grafana".into()));
        assert_eq!(g.check_api_key(&secret, "op:lifecycle").unwrap(), KeyCheck::Denied);
        assert_eq!(g.check_api_key("mcmesh_sk_nope", "read:status").unwrap(), KeyCheck::Unknown);
        let stored: Vec<u8> = g.db.query_row("SELECT key_hash FROM api_keys WHERE id=?", params![id], |r| r.get(0)).unwrap();
        assert!(!String::from_utf8_lossy(&stored).contains(&secret), "the secret itself is never stored");
        assert_eq!(stored, hash(&secret));
    }

    #[test]
    fn revoked_keys_stop_working_and_inputs_are_validated() {
        let mut g = gw();
        let (id, secret) = g.create_api_key("bot", &["read:status".into(), "op:lifecycle".into(), "read:status".into()], "alice").unwrap().unwrap();
        assert!(g.revoke_api_key(id).unwrap());
        assert!(!g.revoke_api_key(id).unwrap(), "revoking twice does nothing");
        assert_eq!(g.check_api_key(&secret, "read:status").unwrap(), KeyCheck::Unknown);
        assert_eq!(g.list_api_keys().unwrap()[0]["scopes"], json!(["op:lifecycle", "read:status"]), "scopes are stored sorted and unique");
        assert_eq!(g.create_api_key("", &["read:status".into()], "a").unwrap().unwrap_err(), "BAD_NAME");
        assert_eq!(g.create_api_key("x", &[], "a").unwrap().unwrap_err(), "BAD_SCOPE");
        assert_eq!(g.create_api_key("x", &["admin:everything".into()], "a").unwrap().unwrap_err(), "BAD_SCOPE");
    }
}
