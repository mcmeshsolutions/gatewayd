use crate::cas::{hex, parse_hex, sha256};
use crate::lease::{wall_s, Error, Gateway};
use crate::server::{auth, ApiErr, AppState};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

pub const MAX_SKIN_SIZE: usize = 256 * 1024;

/// Validates raw PNG bytes and returns (width, height)
pub fn validate_png(bytes: &[u8]) -> Result<(u32, u32), &'static str> {
    if bytes.len() < 33 {
        return Err("NOT_PNG");
    }
    if &bytes[0..8] != b"\x89PNG\r\n\x1a\n" {
        return Err("NOT_PNG");
    }
    if &bytes[12..16] != b"IHDR" {
        return Err("NOT_PNG");
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    if width != 64 || (height != 64 && height != 32) {
        return Err("BAD_DIMENSIONS");
    }
    Ok((width, height))
}

impl Gateway {
    pub fn set_player_skin(&mut self, player_uuid: &str, skin_bytes: &[u8]) -> Result<String, Error> {
        let hash = sha256(skin_bytes);
        self.cas().put(skin_bytes)?;
        let hash_hex = hex(&hash);
        let now = wall_s();
        self.db.execute(
            "INSERT INTO skins(player_uuid, skin_hash, updated_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(player_uuid) DO UPDATE SET skin_hash=?2, updated_at=?3",
            params![player_uuid, hash_hex, now],
        )?;
        Ok(hash_hex)
    }

    pub fn get_player_skin(&self, player_uuid: &str) -> Result<Option<(String, i64)>, Error> {
        let mut st = self.db.prepare("SELECT skin_hash, updated_at FROM skins WHERE player_uuid=?")?;
        let mut rows = st.query(params![player_uuid])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?)))
        } else {
            Ok(None)
        }
    }

    pub fn get_skin_bytes(&self, hash_hex: &str) -> Result<Option<Vec<u8>>, Error> {
        let Some(hash) = parse_hex(hash_hex) else {
            return Ok(None);
        };
        if !self.cas().has(&hash) {
            return Ok(None);
        }
        let data = self.cas().get(&hash)?;
        Ok(Some(data))
    }
}

#[derive(Deserialize)]
struct SkinJson {
    #[serde(default)]
    png_base64: Option<String>,
}

async fn get_skin(State(s): State<Arc<AppState>>, Path(hash): Path<String>) -> Result<Response, ApiErr> {
    let gw = s.gw();
    let bytes = gw.get_skin_bytes(&hash)?.ok_or(ApiErr::NotFound("NO_SUCH_SKIN"))?;
    Ok((
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=604800, immutable"),
        ],
        bytes,
    )
        .into_response())
}

async fn post_skin(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiErr> {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    let (player_uuid, _) = gw.device_player(&dev)?.ok_or(ApiErr::Unauthorized)?;

    let png_bytes = if body.starts_with(b"\x89PNG\r\n\x1a\n") {
        body.to_vec()
    } else if let Ok(j) = serde_json::from_slice::<SkinJson>(&body) {
        if let Some(b64) = j.png_base64 {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| ApiErr::BadRequest("BAD_BASE64"))?
        } else {
            return Err(ApiErr::BadRequest("MISSING_PNG"));
        }
    } else {
        return Err(ApiErr::BadRequest("BAD_BODY"));
    };

    if png_bytes.len() > MAX_SKIN_SIZE {
        return Err(ApiErr::BadRequest("SKIN_TOO_LARGE"));
    }
    validate_png(&png_bytes).map_err(ApiErr::BadRequest)?;
    let hash = gw.set_player_skin(&player_uuid, &png_bytes)?;
    Ok(Json(json!({
        "hash": hash,
        "url": format!("/v1/skins/{hash}")
    })))
}

async fn get_user_skin(
    State(s): State<Arc<AppState>>,
    Path(uuid): Path<String>,
) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let (hash, updated_at) = gw.get_player_skin(&uuid)?.ok_or(ApiErr::NotFound("NO_SUCH_SKIN"))?;
    Ok(Json(json!({
        "player_uuid": uuid,
        "skin_hash": hash,
        "skin_url": format!("/v1/skins/{hash}"),
        "updated_at": updated_at
    })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/skins/:hash", get(get_skin))
        .route("/v1/skins", post(post_skin).layer(DefaultBodyLimit::max(MAX_SKIN_SIZE)))
        .route("/v1/users/:uuid/skin", get(get_user_skin))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_png(w: u32, h: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        // IHDR chunk length = 13
        b.extend_from_slice(&13u32.to_be_bytes());
        b.extend_from_slice(b"IHDR");
        b.extend_from_slice(&w.to_be_bytes());
        b.extend_from_slice(&h.to_be_bytes());
        // bit depth, color type, compression, filter, interlace
        b.extend_from_slice(&[8, 6, 0, 0, 0]);
        // CRC 4 bytes
        b.extend_from_slice(&[0, 0, 0, 0]);
        // IEND chunk
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(b"IEND");
        b.extend_from_slice(&[0xae, 0x42, 0x60, 0x82]);
        b
    }

    #[test]
    fn test_validate_png() {
        let p64 = dummy_png(64, 64);
        assert_eq!(validate_png(&p64), Ok((64, 64)));

        let p32 = dummy_png(64, 32);
        assert_eq!(validate_png(&p32), Ok((64, 32)));

        let bad_dim = dummy_png(128, 128);
        assert_eq!(validate_png(&bad_dim), Err("BAD_DIMENSIONS"));

        let not_png = b"not a png image at all";
        assert_eq!(validate_png(not_png), Err("NOT_PNG"));
    }
}
