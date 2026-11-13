use crate::lease::{wall_s, Error, Gateway};
use crate::server::{auth, ApiErr, AppState};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

const MAX_TEXT: usize = 256 * 1024;
const KEEP_PER_WORLD: i64 = 20;
const MIN_GAP_S: i64 = 60;
const HEAD_CHARS: usize = 2000;

impl Gateway {
    pub(crate) fn crash_init(&self) -> Result<(), Error> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS crash_reports(
               id INTEGER PRIMARY KEY AUTOINCREMENT, world_id TEXT NOT NULL, device TEXT NOT NULL,
               ts INTEGER NOT NULL, text TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS crash_world ON crash_reports(world_id, id);",
        )?;
        Ok(())
    }

    /// None when the world already got a report within the last minute.
    pub(crate) fn crash_store(&self, world: &str, device: &str, text: &str, now: i64) -> Result<Option<i64>, Error> {
        let db = &self.db;
        let last: Option<i64> = db.query_row("SELECT MAX(ts) FROM crash_reports WHERE world_id=?", params![world], |r| r.get(0))?;
        if last.is_some_and(|t| now - t < MIN_GAP_S) {
            return Ok(None);
        }
        db.execute("INSERT INTO crash_reports(world_id, device, ts, text) VALUES(?,?,?,?)", params![world, device, now, text])?;
        let id = db.last_insert_rowid();
        db.execute(
            "DELETE FROM crash_reports WHERE world_id=?1 AND id NOT IN (SELECT id FROM crash_reports WHERE world_id=?1 ORDER BY id DESC LIMIT ?2)",
            params![world, KEEP_PER_WORLD],
        )?;
        Ok(Some(id))
    }

    pub(crate) fn crash_list(&self, world: &str) -> Result<Vec<Value>, Error> {
        let mut st = self.db.prepare("SELECT id, ts, device, text FROM crash_reports WHERE world_id=? ORDER BY id DESC")?;
        let rows = st.query_map(params![world], |r| {
            let text: String = r.get(3)?;
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?, "device": r.get::<_, String>(2)?,
                "bytes": text.len(), "head": text.chars().take(HEAD_CHARS).collect::<String>(),
            }))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

#[derive(Deserialize)]
struct CrashReq {
    text: String,
}

async fn upload(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<CrashReq>) -> Result<Json<Value>, ApiErr> {
    if b.text.is_empty() || b.text.len() > MAX_TEXT {
        return Err(ApiErr::BadRequest("CRASH_REPORT_SIZE"));
    }
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.pack_of(&world)?;
    if !gw.role(&world, &dev)?.can_host() {
        return Err(ApiErr::Domain(Error::NotMember));
    }
    match gw.crash_store(&world, &dev, &b.text, wall_s())? {
        Some(id) => {
            gw.audit(&dev, "crash.report", &world, &id.to_string(), json!({ "bytes": b.text.len() }));
            Ok(Json(json!({ "stored": true, "id": id })))
        }
        None => Ok(Json(json!({ "stored": false, "reason": "rate_limited" }))),
    }
}

async fn list(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.pack_of(&world)?;
    crate::admin::require_owner_or_admin(&s, &gw, &dev, &world)?;
    Ok(Json(json!({ "reports": gw.crash_list(&world)? })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/v1/worlds/:id/crash-report", post(upload)).route("/v1/worlds/:id/crash-reports", get(list))
}
