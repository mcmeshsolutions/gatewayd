//! Distributed worldgen broker (ROADMAP "Distributed predictive worldgen", board/PROTOCOL.md "Distributed worldgen").
//!
//! The gateway never looks inside a chunk. It queues region-aligned tiles the host wants, hands each one to workers,
//! and decides when independent peers agree: one worker generates the tile and uploads its chunks, the others only
//! report a digest of what they generated, and a tile is READY once `quorum` distinct devices reported the same digest
//! and one of them is the generator. Tables are created at runtime by `worldgen_init` (called from `ops_init`).

use crate::cas::{parse_hex, Hash};
use crate::lease::{wall_s, Error, Gateway};
use crate::server::{auth, ApiErr, AppState};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::HeaderMap,
    routing::{get, post, put},
    Json, Router,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// A tile is exactly one region file, so installing it needs no merging with anything already on disk.
pub const TILE_SIZE: i64 = 32;
/// Chunks generated around a tile and thrown away. The gateway dictates it so every worker cuts the same shape, which matters:
/// generation is only reproducible between identical requests. 4 settles vanilla (board/RESEARCH.md section 1); a modded pack may need
/// more (1f), so the world owner sets it and each tile keeps the value it was requested with.
pub const DEFAULT_HALO: i64 = 4;
const MIN_HALO: i64 = 4;
const MAX_HALO: i64 = 16;
/// Bumped when the worker procedure changes in a way that changes results; workers on different versions never agree.
pub const GEN_VERSION: i64 = 1;
const CLAIM_TTL_S: i64 = 1800;
/// A worker is expected to need this much longer than its average, so a tile that only just fits is not given to it.
const SAFETY: f64 = 1.3;
/// A tile that nobody who could make its deadline took within this time is given to whoever asks.
const ORPHAN_S: i64 = 600;
/// What a device that has never reported a tile is assumed to need.
const DEFAULT_TILE_S: f64 = 300.0;
const TILE_TTL_S: i64 = 86_400;
const MAX_ROUNDS: i64 = 3;
const MAX_QUEUED_PER_WORLD: i64 = 256;
const MAX_REQUEST_TILES: usize = 64;
const FRONTIER_MAX: i64 = 24;
const MAX_LEAVES: usize = 16 * 1024;
const KINDS: [&str; 3] = ["region", "entities", "poi"];
const MAX_RESULT_BODY: usize = 3 << 20;

/// One stored chunk of a tile: the blob is in the CAS under `hash`. `frontier` marks chunks outside the tile that carry
/// the spill of the tile's edge; they are not covered by the digest and only ever come from the generator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Leaf {
    pub kind: String,
    pub cx: i64,
    pub cz: i64,
    pub hash: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub frontier: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Claim {
    pub tile_id: i64,
    pub world: String,
    pub dim: String,
    pub x: i64,
    pub z: i64,
    pub size: i64,
    pub seed: String,
    pub profile: String,
    pub role: &'static str,
    pub halo: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Submit {
    /// stored, waiting for more peers
    Waiting,
    /// agreement reached, the tile can be installed
    Ready,
    /// the peers disagreed, results were cleared and the tile is queued for another round
    Retry,
    /// the peers disagreed too often, this pack does not reproduce tiles
    Rejected,
}

struct TileRow {
    id: i64,
    world: String,
    x: i64,
    z: i64,
    size: i64,
    quorum: i64,
}

fn rejected(why: &str) -> Error {
    Error::Rejected(why.to_string())
}

impl Gateway {
    pub(crate) fn worldgen_init(&self) -> Result<(), Error> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS worldgen_settings(
               world_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, quorum INTEGER NOT NULL DEFAULT 2, halo INTEGER NOT NULL DEFAULT 4) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS worldgen_tiles(
               id INTEGER PRIMARY KEY AUTOINCREMENT, world_id TEXT NOT NULL, dim TEXT NOT NULL,
               x INTEGER NOT NULL, z INTEGER NOT NULL, size INTEGER NOT NULL,
               profile TEXT NOT NULL, seed TEXT NOT NULL, quorum INTEGER NOT NULL, halo INTEGER NOT NULL DEFAULT 4,
               state TEXT NOT NULL CHECK(state IN('QUEUED','READY','REJECTED','CONSUMED')),
               attempts INTEGER NOT NULL DEFAULT 0, requested_at INTEGER NOT NULL, ready_at INTEGER, winner BLOB,
               UNIQUE(world_id, dim, x, z, size, profile));
             CREATE INDEX IF NOT EXISTS worldgen_tile_state ON worldgen_tiles(state, profile, id);
             CREATE TABLE IF NOT EXISTS worldgen_claims(
               tile_id INTEGER NOT NULL, device TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('generate','verify')),
               expires_at INTEGER NOT NULL, PRIMARY KEY(tile_id, device)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS worldgen_results(
               tile_id INTEGER NOT NULL, device TEXT NOT NULL, role TEXT NOT NULL, digest BLOB NOT NULL,
               chunk_digests TEXT, leaves TEXT, ts INTEGER NOT NULL, PRIMARY KEY(tile_id, device)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS worldgen_rounds(
               tile_id INTEGER NOT NULL, round INTEGER NOT NULL, devices TEXT NOT NULL, differing INTEGER, first_chunk INTEGER, ts INTEGER NOT NULL,
               PRIMARY KEY(tile_id, round)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS worldgen_speed(
               device TEXT PRIMARY KEY, ewma_s REAL NOT NULL, samples INTEGER NOT NULL) WITHOUT ROWID;",
        )?;
        // older databases lack the deadline; a tile without one is treated as having all the time in the world
        let _ = self.db.execute("ALTER TABLE worldgen_tiles ADD COLUMN deadline INTEGER", []);
        Ok(())
    }

    /// (enabled, quorum, halo). Off by default: a world opts in, because it spends other members' CPU.
    pub fn worldgen_settings(&self, world: &str) -> Result<(bool, i64, i64), Error> {
        Ok(self
            .db
            .query_row("SELECT enabled, quorum, halo FROM worldgen_settings WHERE world_id=?", params![world], |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))
            .optional()?
            .unwrap_or((false, 2, DEFAULT_HALO)))
    }

    pub fn set_worldgen(&self, world: &str, enabled: bool, quorum: i64, halo: i64) -> Result<(), Error> {
        if !(1..=2).contains(&quorum) {
            return Err(rejected("BAD_QUORUM"));
        }
        if !(MIN_HALO..=MAX_HALO).contains(&halo) {
            return Err(rejected("BAD_HALO"));
        }
        self.db.execute(
            "INSERT INTO worldgen_settings(world_id, enabled, quorum, halo) VALUES(?,?,?,?)
             ON CONFLICT(world_id) DO UPDATE SET enabled=excluded.enabled, quorum=excluded.quorum, halo=excluded.halo",
            params![world, enabled as i64, quorum, halo],
        )?;
        Ok(())
    }

    /// Expired claims, tiles nobody picked up in a day, and tiles the host has taken. Cheap, runs on every entry point.
    pub(crate) fn worldgen_gc(&self, now: i64) -> Result<(), Error> {
        self.db.execute("DELETE FROM worldgen_claims WHERE expires_at<=?", params![now])?;
        self.db.execute(
            "DELETE FROM worldgen_results WHERE tile_id IN (SELECT id FROM worldgen_tiles WHERE requested_at<? OR state='CONSUMED')",
            params![now - TILE_TTL_S],
        )?;
        self.db.execute("DELETE FROM worldgen_tiles WHERE requested_at<?", params![now - TILE_TTL_S])?;
        self.db.execute("DELETE FROM worldgen_rounds WHERE tile_id NOT IN (SELECT id FROM worldgen_tiles)", [])?;
        Ok(())
    }

    /// The host asks for tiles. `tiles` are the south-west chunk of each tile and must sit on the region grid.
    /// Returns how many were new; asking again for a tile that is queued, ready or already taken changes nothing.
    pub fn worldgen_request(&self, world: &str, profile: &str, seed: &str, dim: &str, tiles: &[(i64, i64)], now: i64) -> Result<usize, Error> {
        self.worldgen_request_eta(world, profile, seed, dim, tiles, &[], now)
    }

    /// `etas` is, per tile, how many seconds the host expects to have before a player needs it (empty: no estimate). A worker is only
    /// handed a tile it can finish in time at its measured speed.
    #[allow(clippy::too_many_arguments)]
    pub fn worldgen_request_eta(&self, world: &str, profile: &str, seed: &str, dim: &str, tiles: &[(i64, i64)], etas: &[i64], now: i64) -> Result<usize, Error> {
        let (enabled, quorum, halo) = self.worldgen_settings(world)?;
        if !enabled {
            return Err(rejected("WORLDGEN_OFF"));
        }
        if profile.is_empty() || profile.len() > 128 || seed.is_empty() || seed.len() > 24 || dim.is_empty() || dim.len() > 64 {
            return Err(rejected("BAD_TILE_REQUEST"));
        }
        if tiles.is_empty() || tiles.len() > MAX_REQUEST_TILES {
            return Err(rejected("BAD_TILE_COUNT"));
        }
        if tiles.iter().any(|(x, z)| x.rem_euclid(TILE_SIZE) != 0 || z.rem_euclid(TILE_SIZE) != 0 || x.abs() > 1 << 24 || z.abs() > 1 << 24) {
            return Err(rejected("TILE_NOT_ALIGNED"));
        }
        self.worldgen_gc(now)?;
        let queued: i64 = self.db.query_row("SELECT COUNT(*) FROM worldgen_tiles WHERE world_id=? AND state='QUEUED'", params![world], |r| r.get(0))?;
        let mut added = 0usize;
        let etas = if etas.len() == tiles.len() { etas } else { &[] };
        for (i, (x, z)) in tiles.iter().enumerate() {
            if queued + added as i64 >= MAX_QUEUED_PER_WORLD {
                return Err(rejected("TILE_QUEUE_FULL"));
            }
            let deadline: Option<i64> = etas.get(i).filter(|e| **e >= 0).map(|e| now + (*e).min(86_400));
            let new = self.db.execute(
                "INSERT OR IGNORE INTO worldgen_tiles(world_id, dim, x, z, size, profile, seed, quorum, halo, state, requested_at, deadline) VALUES(?,?,?,?,?,?,?,?,?,'QUEUED',?,?)",
                params![world, dim, x, z, TILE_SIZE, profile, seed, quorum, halo, now, deadline],
            )?;
            added += new;
            if new == 0 && deadline.is_some() {
                // asked again with a nearer need: the earlier of the two deadlines stands
                self.db.execute(
                    "UPDATE worldgen_tiles SET deadline=?1 WHERE world_id=?2 AND dim=?3 AND x=?4 AND z=?5 AND size=?6 AND profile=?7 AND state='QUEUED' AND (deadline IS NULL OR deadline>?1)",
                    params![deadline, world, dim, x, z, TILE_SIZE, profile],
                )?;
            }
        }
        Ok(added)
    }

    fn worldgen_claim_row(&self, tile_id: i64, device: &str, now: i64) -> Result<Option<Claim>, Error> {
        Ok(self
            .db
            .query_row(
                "SELECT t.world_id, t.dim, t.x, t.z, t.size, t.seed, t.profile, c.role, c.expires_at, t.halo
                 FROM worldgen_claims c JOIN worldgen_tiles t ON t.id=c.tile_id WHERE c.tile_id=? AND c.device=? AND c.expires_at>?",
                params![tile_id, device, now],
                |r| {
                    Ok(Claim {
                        tile_id,
                        world: r.get(0)?,
                        dim: r.get(1)?,
                        x: r.get(2)?,
                        z: r.get(3)?,
                        size: r.get(4)?,
                        seed: r.get(5)?,
                        profile: r.get(6)?,
                        role: if r.get::<_, String>(7)? == "generate" { "generate" } else { "verify" },
                        expires_at: r.get(8)?,
                        halo: r.get(9)?,
                    })
                },
            )
            .optional()?)
    }

    /// A worker asks for something to do. A device holds at most one claim, so asking again resumes it. Tiles go out
    /// oldest first, which is the host's priority order. The world's current host never gets its own tiles (sparing
    /// that machine is the point), and only members allowed to host may work.
    pub fn worldgen_claim(&self, device: &str, profile: &str, now: i64) -> Result<Option<Claim>, Error> {
        self.worldgen_gc(now)?;
        let open: Option<i64> = self
            .db
            .query_row("SELECT tile_id FROM worldgen_claims WHERE device=? AND expires_at>?", params![device, now], |r| r.get(0))
            .optional()?;
        if let Some(id) = open {
            return self.worldgen_claim_row(id, device, now);
        }
        let candidates: Vec<(i64, i64, Option<i64>, i64)> = {
            let mut st = self.db.prepare(
                "SELECT t.id, t.quorum, t.deadline, t.requested_at FROM worldgen_tiles t
                 JOIN worldgen_settings s ON s.world_id=t.world_id AND s.enabled=1
                 WHERE t.state='QUEUED' AND t.profile=?1
                   AND t.world_id IN (SELECT m.world_id FROM members m JOIN devices d ON d.player_uuid=m.player_uuid
                                      WHERE d.id=?2 AND d.revoked=0 AND m.role IN('ADMIN','HOST_ELIGIBLE'))
                   AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.world_id=t.world_id AND l.device_id=?2 AND l.status IN('ACTIVE','HANDOFF'))
                   AND NOT EXISTS (SELECT 1 FROM worldgen_results r WHERE r.tile_id=t.id AND r.device=?2)
                 ORDER BY t.id LIMIT 64",
            )?;
            let rows = st.query_map(params![profile, device], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        // best fit: of the tiles this device can still finish before they are needed, the one with the least time to spare, so a fast
        // machine takes the urgent tiles and a slow one only those that are far off. A tile nobody could make in time waits for a
        // faster machine, and is taken anyway once it has sat unclaimed for ORPHAN_S.
        // a device that has never reported has no speed yet: every tile fits it, and it is given the one with the most time to spare, so that
        // its first result costs the pool nothing and tells the gateway how fast it is
        let measured = self.worldgen_measured(device)?;
        let est = measured.unwrap_or(0.0);
        let mut ranked: Vec<(f64, i64, i64)> = Vec::new();
        for (id, quorum, deadline, requested_at) in candidates {
            let slack = match deadline {
                Some(d) => (d - now) as f64 - est * SAFETY,
                None => f64::MAX,
            };
            if slack >= 0.0 || now - requested_at > ORPHAN_S {
                ranked.push((slack.max(0.0), id, quorum));
            }
        }
        if measured.is_some() {
            ranked.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));
        } else {
            ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));
        }
        for (_, id, quorum) in ranked {
            let results: i64 = self.db.query_row("SELECT COUNT(*) FROM worldgen_results WHERE tile_id=?", params![id], |r| r.get(0))?;
            let live: i64 = self.db.query_row("SELECT COUNT(*) FROM worldgen_claims WHERE tile_id=? AND expires_at>?", params![id, now], |r| r.get(0))?;
            if results + live >= quorum {
                continue;
            }
            let have_generator: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM worldgen_results WHERE tile_id=?1 AND leaves IS NOT NULL)
                     OR EXISTS(SELECT 1 FROM worldgen_claims WHERE tile_id=?1 AND role='generate' AND expires_at>?2)",
                params![id, now],
                |r| r.get(0),
            )?;
            let role = if have_generator { "verify" } else { "generate" };
            self.db.execute("INSERT INTO worldgen_claims(tile_id, device, role, expires_at) VALUES(?,?,?,?)", params![id, device, role, now + CLAIM_TTL_S])?;
            return self.worldgen_claim_row(id, device, now);
        }
        Ok(None)
    }


    /// The (seed, profile) pairs a device could work on right now: queued tiles of worlds it may help with. Lets a worker learn the
    /// seed before it starts a server, since a worker's profile is derived from its own seed.
    pub fn worldgen_demand(&self, device: &str) -> Result<Vec<(String, String)>, Error> {
        self.worldgen_init()?;
        let mut st = self.db.prepare(
            "SELECT DISTINCT t.seed, t.profile FROM worldgen_tiles t
             JOIN worldgen_settings s ON s.world_id=t.world_id AND s.enabled=1
             WHERE t.state='QUEUED'
               AND t.world_id IN (SELECT m.world_id FROM members m JOIN devices d ON d.player_uuid=m.player_uuid
                                  WHERE d.id=?1 AND d.revoked=0 AND m.role IN('ADMIN','HOST_ELIGIBLE'))
               AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.world_id=t.world_id AND l.device_id=?1 AND l.status IN('ACTIVE','HANDOFF'))
             LIMIT 8",
        )?;
        let rows = st.query_map(params![device], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The world a device may upload tile blobs into right now: only a generator with a live claim.
    pub fn worldgen_claim_world(&self, device: &str, now: i64) -> Result<Option<String>, Error> {
        Ok(self
            .db
            .query_row(
                "SELECT t.world_id FROM worldgen_claims c JOIN worldgen_tiles t ON t.id=c.tile_id
                 WHERE c.device=? AND c.role='generate' AND c.expires_at>?",
                params![device, now],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// (world, x, z) of a tile, for the event the HTTP layer emits.
    pub fn worldgen_tile_where(&self, id: i64) -> Result<Option<(String, i64, i64)>, Error> {
        Ok(self.worldgen_tile(id)?.map(|(t, _)| (t.world, t.x, t.z)))
    }

    fn worldgen_tile(&self, id: i64) -> Result<Option<(TileRow, String)>, Error> {
        Ok(self
            .db
            .query_row("SELECT id, world_id, x, z, size, quorum, state FROM worldgen_tiles WHERE id=?", params![id], |r| {
                Ok((TileRow { id: r.get(0)?, world: r.get(1)?, x: r.get(2)?, z: r.get(3)?, size: r.get(4)?, quorum: r.get(5)? }, r.get::<_, String>(6)?))
            })
            .optional()?)
    }

    /// The generator's list of stored chunks must cover the whole tile and every blob must already be in the CAS, so a
    /// READY tile can always be installed completely.
    fn worldgen_check_leaves(&self, t: &TileRow, leaves: &[Leaf]) -> Result<(), Error> {
        if leaves.is_empty() || leaves.len() > MAX_LEAVES {
            return Err(rejected("BAD_LEAVES"));
        }
        let mut seen: HashSet<(&str, i64, i64)> = HashSet::new();
        let mut covered: HashSet<(i64, i64)> = HashSet::new();
        for l in leaves {
            let kind = KINDS.iter().find(|k| **k == l.kind).ok_or_else(|| rejected("BAD_LEAF_KIND"))?;
            let inside = l.cx >= t.x && l.cx < t.x + t.size && l.cz >= t.z && l.cz < t.z + t.size;
            let near = l.cx >= t.x - FRONTIER_MAX && l.cx < t.x + t.size + FRONTIER_MAX && l.cz >= t.z - FRONTIER_MAX && l.cz < t.z + t.size + FRONTIER_MAX;
            if !(inside || (l.frontier && near)) || (inside && l.frontier) {
                return Err(rejected("LEAF_OUT_OF_TILE"));
            }
            if !seen.insert((kind, l.cx, l.cz)) {
                return Err(rejected("DUPLICATE_LEAF"));
            }
            let h: Hash = parse_hex(&l.hash).ok_or_else(|| rejected("BAD_LEAF_HASH"))?;
            if !self.cas.has(&h) {
                return Err(Error::MissingBlob);
            }
            if inside && *kind == "region" {
                covered.insert((l.cx, l.cz));
            }
        }
        if covered.len() as i64 != t.size * t.size {
            return Err(rejected("TILE_INCOMPLETE"));
        }
        Ok(())
    }

    /// A claimant hands in its result. A generator sends `leaves` (its chunks, already uploaded), a verifier sends none.
    /// The device's smoothed seconds per tile, None until it has reported one.
    fn worldgen_measured(&self, device: &str) -> Result<Option<f64>, Error> {
        Ok(self.db.query_row("SELECT ewma_s FROM worldgen_speed WHERE device=?", params![device], |r| r.get(0)).optional()?)
    }

    /// Seconds this device usually needs for a tile (claim to result), smoothed over its last reports.
    pub fn worldgen_estimate(&self, device: &str) -> Result<f64, Error> {
        Ok(self.db.query_row("SELECT ewma_s FROM worldgen_speed WHERE device=?", params![device], |r| r.get(0)).optional()?.unwrap_or(DEFAULT_TILE_S))
    }

    fn worldgen_note_speed(&self, device: &str, seconds: f64) -> Result<(), Error> {
        self.db.execute(
            "INSERT INTO worldgen_speed(device, ewma_s, samples) VALUES(?1, ?2, 1)
             ON CONFLICT(device) DO UPDATE SET ewma_s = 0.7 * ewma_s + 0.3 * ?2, samples = samples + 1",
            params![device, seconds.max(1.0)],
        )?;
        Ok(())
    }

    /// (fastest, median) seconds per tile among the devices of the world that may host and have reported at least one; None until one has.
    pub fn worldgen_pool(&self, world: &str) -> Result<Option<(f64, f64)>, Error> {
        let mut st = self.db.prepare(
            "SELECT s.ewma_s FROM worldgen_speed s WHERE s.device IN (SELECT d.id FROM devices d JOIN members m ON m.player_uuid=d.player_uuid
                                                                     WHERE m.world_id=?1 AND d.revoked=0 AND m.role IN('ADMIN','HOST_ELIGIBLE')) ORDER BY s.ewma_s",
        )?;
        let v: Vec<f64> = st.query_map(params![world], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(v.first().map(|f| (*f, v[v.len() / 2])))
    }

    pub fn worldgen_submit(&self, device: &str, tile_id: i64, digest: Hash, chunk_digests: Option<&str>, leaves: Option<&[Leaf]>, now: i64) -> Result<Submit, Error> {
        let claim: Option<(String, i64)> = self
            .db
            .query_row("SELECT role, expires_at FROM worldgen_claims WHERE tile_id=? AND device=?", params![tile_id, device], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let (role, expires) = claim.ok_or_else(|| rejected("NO_CLAIM"))?;
        if expires <= now {
            self.db.execute("DELETE FROM worldgen_claims WHERE tile_id=? AND device=?", params![tile_id, device])?;
            return Err(rejected("CLAIM_EXPIRED"));
        }
        let (tile, state) = self.worldgen_tile(tile_id)?.ok_or_else(|| rejected("NO_SUCH_TILE"))?;
        if state != "QUEUED" {
            return Err(rejected("TILE_CLOSED"));
        }
        let leaves_json = match (role.as_str(), leaves) {
            ("generate", Some(l)) => {
                self.worldgen_check_leaves(&tile, l)?;
                Some(serde_json::to_string(l).map_err(|_| rejected("BAD_LEAVES"))?)
            }
            ("generate", None) => return Err(rejected("LEAVES_REQUIRED")),
            (_, Some(_)) => return Err(rejected("LEAVES_NOT_ALLOWED")),
            (_, None) => None,
        };
        if chunk_digests.is_some_and(|c| c.len() > 70_000) {
            return Err(rejected("BAD_CHUNK_DIGESTS"));
        }
        let tx = self.db.unchecked_transaction()?;
        self.db.execute(
            "INSERT INTO worldgen_results(tile_id, device, role, digest, chunk_digests, leaves, ts) VALUES(?,?,?,?,?,?,?)",
            params![tile_id, device, role, &digest[..], chunk_digests, leaves_json, now],
        )?;
        self.db.execute("DELETE FROM worldgen_claims WHERE tile_id=? AND device=?", params![tile_id, device])?;
        // how long this device took, for the next time it is offered a tile
        self.worldgen_note_speed(device, (now - (expires - CLAIM_TTL_S)) as f64)?;
        let outcome = self.worldgen_evaluate(&tile, now)?;
        tx.commit()?;
        Ok(outcome)
    }

    fn worldgen_evaluate(&self, t: &TileRow, now: i64) -> Result<Submit, Error> {
        let rows: Vec<(Vec<u8>, bool)> = {
            let mut st = self.db.prepare("SELECT digest, leaves IS NOT NULL FROM worldgen_results WHERE tile_id=?")?;
            let r = st.query_map(params![t.id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            r.collect::<rusqlite::Result<_>>()?
        };
        let mut votes: HashMap<&[u8], i64> = HashMap::new();
        for (d, _) in &rows {
            *votes.entry(d.as_slice()).or_default() += 1;
        }
        if let Some((best, n)) = votes.iter().max_by_key(|(_, n)| **n).map(|(d, n)| (d.to_vec(), *n)) {
            let generator_in_it = rows.iter().any(|(d, has)| *has && *d == best);
            if n >= t.quorum && generator_in_it {
                self.db.execute("UPDATE worldgen_tiles SET state='READY', winner=?, ready_at=? WHERE id=?", params![best, now, t.id])?;
                return Ok(Submit::Ready);
            }
        }
        if (rows.len() as i64) < t.quorum {
            return Ok(Submit::Waiting);
        }
        // everyone reported and nobody agreed with the generator: throw the round away and ask again
        let attempts: i64 = self.db.query_row("SELECT attempts+1 FROM worldgen_tiles WHERE id=?", params![t.id], |r| r.get(0))?;
        self.worldgen_note_disagreement(t, attempts, now)?;
        self.db.execute("DELETE FROM worldgen_results WHERE tile_id=?", params![t.id])?;
        if attempts >= MAX_ROUNDS {
            self.db.execute("UPDATE worldgen_tiles SET state='REJECTED', attempts=? WHERE id=?", params![attempts, t.id])?;
            Ok(Submit::Rejected)
        } else {
            self.db.execute("UPDATE worldgen_tiles SET attempts=? WHERE id=?", params![attempts, t.id])?;
            Ok(Submit::Retry)
        }
    }

    /// Keeps what a disagreement showed before the round is thrown away: which devices, and how many chunks of the tile differed
    /// (counted from the per-chunk digests of the first two results, 64 hex characters per chunk, tile order).
    fn worldgen_note_disagreement(&self, t: &TileRow, round: i64, now: i64) -> Result<(), Error> {
        let detail: Vec<(String, Option<String>)> = {
            let mut st = self.db.prepare("SELECT device, chunk_digests FROM worldgen_results WHERE tile_id=? ORDER BY ts, device")?;
            let r = st.query_map(params![t.id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            r.collect::<rusqlite::Result<_>>()?
        };
        let (mut differing, mut first) = (None, None);
        if let (Some(a), Some(b)) = (detail.first().and_then(|d| d.1.as_deref()), detail.get(1).and_then(|d| d.1.as_deref())) {
            if a.len() == b.len() && a.len() % 64 == 0 && a.is_ascii() && b.is_ascii() {
                let (mut n, mut f) = (0i64, None);
                for i in 0..a.len() / 64 {
                    if a[i * 64..(i + 1) * 64] != b[i * 64..(i + 1) * 64] {
                        n += 1;
                        f.get_or_insert(i as i64);
                    }
                }
                differing = Some(n);
                first = f;
            }
        }
        let devices = detail.iter().map(|d| d.0.as_str()).collect::<Vec<_>>().join(",");
        self.db.execute(
            "INSERT OR REPLACE INTO worldgen_rounds(tile_id, round, devices, differing, first_chunk, ts) VALUES(?,?,?,?,?,?)",
            params![t.id, round, devices, differing, first, now],
        )?;
        Ok(())
    }

    /// The last rounds in which workers disagreed, newest first: the tile, who, and how many chunks differed (null when they sent no per-chunk digests).
    pub fn worldgen_disagreements(&self, world: &str, limit: i64) -> Result<Vec<Value>, Error> {
        let mut st = self.db.prepare(
            "SELECT r.tile_id, t.x, t.z, r.round, r.devices, r.differing, r.first_chunk, r.ts FROM worldgen_rounds r JOIN worldgen_tiles t ON t.id=r.tile_id
             WHERE t.world_id=? ORDER BY r.ts DESC, r.round DESC LIMIT ?",
        )?;
        let rows = st.query_map(params![world, limit], |r| {
            Ok(json!({ "tile": r.get::<_, i64>(0)?, "x": r.get::<_, i64>(1)?, "z": r.get::<_, i64>(2)?, "round": r.get::<_, i64>(3)?, "devices": r.get::<_, String>(4)?,
                       "differing": r.get::<_, Option<i64>>(5)?, "first_chunk": r.get::<_, Option<i64>>(6)?, "ts": r.get::<_, i64>(7)? }))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// READY tiles with the generator's chunk list, and tiles the peers could never agree on, for the host.
    pub fn worldgen_ready(&self, world: &str, limit: i64) -> Result<(Vec<Value>, Vec<Value>), Error> {
        let ready = {
            let mut st = self.db.prepare(
                "SELECT t.id, t.dim, t.x, t.z, t.size, t.seed, t.profile, r.leaves
                 FROM worldgen_tiles t JOIN worldgen_results r ON r.tile_id=t.id AND r.digest=t.winner AND r.leaves IS NOT NULL
                 WHERE t.world_id=? AND t.state='READY' ORDER BY t.id LIMIT ?",
            )?;
            let rows = st.query_map(params![world, limit], |r| {
                let leaves: Vec<Leaf> = serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default();
                Ok(json!({ "tile": r.get::<_, i64>(0)?, "dim": r.get::<_, String>(1)?, "x": r.get::<_, i64>(2)?, "z": r.get::<_, i64>(3)?,
                           "size": r.get::<_, i64>(4)?, "seed": r.get::<_, String>(5)?, "profile": r.get::<_, String>(6)?, "leaves": leaves }))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let refused = {
            let mut st = self.db.prepare("SELECT id, dim, x, z FROM worldgen_tiles WHERE world_id=? AND state='REJECTED' ORDER BY id LIMIT 64")?;
            let rows = st.query_map(params![world], |r| Ok(json!({ "tile": r.get::<_, i64>(0)?, "dim": r.get::<_, String>(1)?, "x": r.get::<_, i64>(2)?, "z": r.get::<_, i64>(3)? })))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok((ready, refused))
    }

    /// The host has installed a tile (or acknowledged a refused one). The row stays for a day so a repeated request is a no-op.
    pub fn worldgen_consumed(&self, world: &str, tile_id: i64) -> Result<bool, Error> {
        let n = self.db.execute("UPDATE worldgen_tiles SET state='CONSUMED' WHERE id=? AND world_id=? AND state IN('READY','REJECTED')", params![tile_id, world])?;
        if n > 0 {
            self.db.execute("DELETE FROM worldgen_results WHERE tile_id=?", params![tile_id])?;
        }
        Ok(n > 0)
    }

    pub fn worldgen_counts(&self, world: &str) -> Result<Value, Error> {
        let mut st = self.db.prepare("SELECT state, COUNT(*) FROM worldgen_tiles WHERE world_id=? GROUP BY state")?;
        let rows = st.query_map(params![world], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut m = serde_json::Map::new();
        for r in rows {
            let (k, v) = r?;
            m.insert(k.to_lowercase(), json!(v));
        }
        Ok(Value::Object(m))
    }

    /// Blobs of tiles that are still waiting for the host, so the retention sweep does not delete them as unreferenced.
    pub(crate) fn worldgen_keep(&self, keep: &mut HashSet<Hash>) -> Result<(), Error> {
        self.worldgen_init()?;
        let mut st = self.db.prepare(
            "SELECT leaves FROM worldgen_results WHERE leaves IS NOT NULL AND tile_id IN (SELECT id FROM worldgen_tiles WHERE state IN('QUEUED','READY'))",
        )?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        for row in rows {
            for l in serde_json::from_str::<Vec<Leaf>>(&row?).unwrap_or_default() {
                if let Some(h) = parse_hex(&l.hash) {
                    keep.insert(h);
                }
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct SettingsReq {
    enabled: bool,
    #[serde(default = "default_quorum")]
    quorum: i64,
    #[serde(default = "default_halo")]
    halo: i64,
}

fn default_halo() -> i64 {
    DEFAULT_HALO
}

fn default_quorum() -> i64 {
    2
}

#[derive(Deserialize)]
struct TilesReq {
    profile: String,
    seed: String,
    dim: String,
    tiles: Vec<(i64, i64)>,
    /// per tile, seconds until a player is expected to need it; empty when the host has no estimate
    #[serde(default)]
    eta_s: Vec<i64>,
}

#[derive(Deserialize)]
struct ClaimReq {
    profile: String,
}

#[derive(Deserialize)]
struct ResultReq {
    digest: String,
    #[serde(default)]
    chunk_digests: Option<String>,
    #[serde(default)]
    leaves: Option<Vec<Leaf>>,
}

fn claim_json(c: &Claim, now: i64) -> Value {
    json!({
        "tile": c.tile_id, "world": c.world, "dim": c.dim, "x": c.x, "z": c.z, "size": c.size, "halo": c.halo,
        "gen_version": GEN_VERSION, "seed": c.seed, "profile": c.profile, "role": c.role, "expires_in": c.expires_at - now,
    })
}

async fn settings_get(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    gw.require_member(&world, &dev)?;
    let (enabled, quorum, halo) = gw.worldgen_settings(&world)?;
    Ok(Json(json!({ "enabled": enabled, "quorum": quorum, "tile_size": TILE_SIZE, "halo": halo, "gen_version": GEN_VERSION, "tiles": gw.worldgen_counts(&world)?, "pool": gw.worldgen_pool(&world)?.map(|(fastest, median)| json!({ "fastest_s": fastest, "median_s": median })), "recent_disagreements": gw.worldgen_disagreements(&world, 5)? })))
}

async fn settings_put(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<SettingsReq>) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    crate::admin::require_owner_or_admin(&s, &gw, &dev, &world)?;
    gw.set_worldgen(&world, b.enabled, b.quorum, b.halo).map_err(|e| match e {
        Error::Rejected(code) if code == "BAD_HALO" => ApiErr::BadRequest("BAD_HALO"),
        Error::Rejected(_) => ApiErr::BadRequest("BAD_QUORUM"),
        other => ApiErr::Domain(other),
    })?;
    gw.audit(&dev, "worldgen.settings", &world, "", json!({ "enabled": b.enabled, "quorum": b.quorum, "halo": b.halo }));
    Ok(Json(json!({ "enabled": b.enabled, "quorum": b.quorum, "halo": b.halo })))
}

fn reject(e: Error) -> ApiErr {
    match e {
        Error::Rejected(code) => ApiErr::Conflict(match code.as_str() {
            "WORLDGEN_OFF" => "WORLDGEN_OFF",
            "TILE_NOT_ALIGNED" => "TILE_NOT_ALIGNED",
            "TILE_QUEUE_FULL" => "TILE_QUEUE_FULL",
            "BAD_TILE_REQUEST" => "BAD_TILE_REQUEST",
            "BAD_TILE_COUNT" => "BAD_TILE_COUNT",
            "NO_CLAIM" => "NO_CLAIM",
            "CLAIM_EXPIRED" => "CLAIM_EXPIRED",
            "NO_SUCH_TILE" => "NO_SUCH_TILE",
            "TILE_CLOSED" => "TILE_CLOSED",
            "LEAVES_REQUIRED" => "LEAVES_REQUIRED",
            "LEAVES_NOT_ALLOWED" => "LEAVES_NOT_ALLOWED",
            "TILE_INCOMPLETE" => "TILE_INCOMPLETE",
            "LEAF_OUT_OF_TILE" => "LEAF_OUT_OF_TILE",
            "DUPLICATE_LEAF" => "DUPLICATE_LEAF",
            "BAD_LEAF_KIND" | "BAD_LEAF_HASH" | "BAD_LEAVES" | "BAD_CHUNK_DIGESTS" => "BAD_TILE_RESULT",
            _ => "WORLDGEN_REFUSED",
        }),
        other => ApiErr::Domain(other),
    }
}

/// Only the current host of the world may ask for tiles or take them.
fn require_host(gw: &Gateway, dev: &str, world: &str) -> Result<(), ApiErr> {
    if gw.hosted_world(dev)?.as_deref() == Some(world) {
        Ok(())
    } else {
        Err(ApiErr::Forbidden("NOT_LEASE_HOLDER"))
    }
}

async fn tiles_request(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<TilesReq>) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_host(&gw, &dev, &world)?;
    let added = gw.worldgen_request_eta(&world, &b.profile, &b.seed, &b.dim, &b.tiles, &b.eta_s, wall_s()).map_err(reject)?;
    Ok(Json(json!({ "queued": added, "requested": b.tiles.len() })))
}

async fn tiles_list(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_host(&gw, &dev, &world)?;
    let (ready, refused) = gw.worldgen_ready(&world, 4)?;
    Ok(Json(json!({ "ready": ready, "refused": refused })))
}

async fn tile_consumed(State(s): State<Arc<AppState>>, h: HeaderMap, Path((world, tile)): Path<(String, i64)>) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    require_host(&gw, &dev, &world)?;
    Ok(Json(json!({ "ok": gw.worldgen_consumed(&world, tile)? })))
}

async fn claim(State(s): State<Arc<AppState>>, h: HeaderMap, Json(b): Json<ClaimReq>) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let now = wall_s();
    Ok(Json(match gw.worldgen_claim(&dev, &b.profile, now)? {
        Some(c) => json!({ "claim": claim_json(&c, now) }),
        None => json!({ "claim": null }),
    }))
}

async fn demand(State(s): State<Arc<AppState>>, h: HeaderMap) -> Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let list: Vec<Value> = gw.worldgen_demand(&dev)?.into_iter().map(|(seed, profile)| json!({ "seed": seed, "profile": profile })).collect();
    Ok(Json(json!({ "demand": list })))
}

async fn result(State(s): State<Arc<AppState>>, h: HeaderMap, Path(tile): Path<i64>, Json(b): Json<ResultReq>) -> Result<Json<Value>, ApiErr> {
    let digest = parse_hex(&b.digest).ok_or(ApiErr::BadRequest("BAD_DIGEST"))?;
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    let outcome = gw.worldgen_submit(&dev, tile, digest, b.chunk_digests.as_deref(), b.leaves.as_deref(), wall_s()).map_err(reject)?;
    if matches!(outcome, Submit::Ready | Submit::Rejected) {
        if let Some((world, x, z)) = gw.worldgen_tile_where(tile)? {
            let name = if outcome == Submit::Ready { "worldgen.ready" } else { "worldgen.rejected" };
            s.hooks.emit(name, &world, json!({ "tile": tile, "x": x, "z": z }));
        }
    }
    Ok(Json(json!({ "outcome": match outcome {
        Submit::Waiting => "waiting",
        Submit::Ready => "ready",
        Submit::Retry => "retry",
        Submit::Rejected => "rejected",
    } })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/worlds/:id/worldgen", get(settings_get).put(settings_put))
        .route("/v1/worlds/:id/worldgen/tiles", get(tiles_list).post(tiles_request))
        .route("/v1/worlds/:id/worldgen/tiles/:tile/consumed", post(tile_consumed))
        .route("/v1/worldgen/claim", post(claim))
        .route("/v1/worldgen/demand", get(demand))
        .route("/v1/worldgen/tiles/:tile/result", put(result).layer(DefaultBodyLimit::max(MAX_RESULT_BODY)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::{hex, Cas};
    use crate::lease::Role;
    use rusqlite::Connection;

    const W: &str = "w";
    const P: &str = "profile-a";

    fn gw() -> Gateway {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let k = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cas = Cas::open(std::env::temp_dir().join(format!("mcmesh-wg-{}-{k}", std::process::id()))).unwrap();
        let mut g = Gateway::open(Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.create_world(W, "w", "1.21.1", "neoforge").unwrap();
        g.add_member(W, "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
        g.add_member(W, "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
        g.add_member(W, "u-c", "carol", "dev-c", Role::HostEligible).unwrap();
        g.add_member(W, "u-d", "dave", "dev-d", Role::ClientOnly).unwrap();
        g.ops_init().unwrap();
        g.set_worldgen(W, true, 2, 4).unwrap();
        g
    }

    /// Alice is the current host.
    fn hosting(g: &Gateway) {
        g.db()
            .execute(
                "INSERT INTO leases(id, world_id, device_id, epoch, ref_name, base_rev, tier, hmac_key, status, granted_at)
                 VALUES('l1', ?, 'dev-a', 1, 'main', 'r0', 1, x'00', 'ACTIVE', 0)",
                params![W],
            )
            .unwrap();
    }

    fn leaves(g: &Gateway, x: i64, z: i64) -> Vec<Leaf> {
        let blob = g.cas().put(b"a chunk").unwrap();
        let mut v = Vec::new();
        for cx in x..x + TILE_SIZE {
            for cz in z..z + TILE_SIZE {
                v.push(Leaf { kind: "region".into(), cx, cz, hash: hex(&blob), frontier: false });
            }
        }
        v
    }

    fn digest(n: u8) -> Hash {
        [n; 32]
    }

    #[test]
    fn a_fast_worker_takes_the_urgent_tile_and_a_slow_one_only_what_it_can_still_deliver() {
        let g = gw();
        g.set_worldgen(W, true, 1, 4).unwrap();
        hosting(&g);
        // tile 0,0 is needed in 100 s, tile 32,0 in 2000 s
        g.worldgen_request_eta(W, P, "4242", "minecraft:overworld", &[(0, 0), (32, 0)], &[100, 2000], 1_000).unwrap();
        g.worldgen_note_speed("dev-b", 50.0).unwrap();
        g.worldgen_note_speed("dev-c", 900.0).unwrap();
        let slow = g.worldgen_claim("dev-c", P, 1_000).unwrap().unwrap();
        assert_eq!((slow.x, slow.z), (32, 0), "the slow machine cannot make the urgent tile, it gets the one that has time");
        let fast = g.worldgen_claim("dev-b", P, 1_000).unwrap().unwrap();
        assert_eq!((fast.x, fast.z), (0, 0), "the fast machine takes the one with the least time to spare");
    }

    #[test]
    fn a_machine_that_has_never_reported_takes_the_tile_with_the_most_time_to_spare() {
        let g = gw();
        g.set_worldgen(W, true, 1, 4).unwrap();
        hosting(&g);
        g.worldgen_request_eta(W, P, "4242", "minecraft:overworld", &[(0, 0), (32, 0)], &[100, 2000], 1_000).unwrap();
        let first = g.worldgen_claim("dev-c", P, 1_000).unwrap().unwrap();
        assert_eq!((first.x, first.z), (32, 0), "the urgent tile is not risked on an unknown machine");
    }

    #[test]
    fn a_tile_nobody_can_make_waits_for_a_faster_machine_and_is_taken_when_it_has_waited_long_enough() {
        let g = gw();
        g.set_worldgen(W, true, 1, 4).unwrap();
        hosting(&g);
        g.worldgen_request_eta(W, P, "4242", "minecraft:overworld", &[(0, 0)], &[30], 1_000).unwrap();
        g.worldgen_note_speed("dev-c", 900.0).unwrap();
        assert!(g.worldgen_claim("dev-c", P, 1_001).unwrap().is_none(), "too slow for a tile needed in 30 s");
        assert!(g.worldgen_claim("dev-c", P, 1_000 + ORPHAN_S + 1).unwrap().is_some(), "but not for ever");
    }

    #[test]
    fn a_worker_that_reports_gets_a_speed_and_the_pool_is_summarised() {
        let g = gw();
        g.set_worldgen(W, true, 1, 4).unwrap();
        hosting(&g);
        assert!(g.worldgen_pool(W).unwrap().is_none(), "nobody has reported");
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        let c = g.worldgen_claim("dev-b", P, 20).unwrap().unwrap();
        let l = leaves(&g, 0, 0);
        g.worldgen_submit("dev-b", c.tile_id, digest(7), None, Some(&l), 20 + 60).unwrap();
        assert_eq!(g.worldgen_estimate("dev-b").unwrap(), 60.0);
        assert_eq!(g.worldgen_estimate("dev-c").unwrap(), DEFAULT_TILE_S, "a device that never reported is assumed to be average");
        assert_eq!(g.worldgen_pool(W).unwrap(), Some((60.0, 60.0)));
        g.worldgen_note_speed("dev-b", 160.0).unwrap();
        assert!((g.worldgen_estimate("dev-b").unwrap() - 90.0).abs() < 1e-9, "0.7 * 60 + 0.3 * 160");
    }

    #[test]
    fn a_tile_is_only_requested_for_an_enabled_world_on_the_region_grid() {
        let g = gw();
        assert_eq!(g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(64, -32)], 10).unwrap(), 1);
        assert_eq!(g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(64, -32)], 11).unwrap(), 0, "asking again is a no-op");
        assert!(matches!(g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(65, 0)], 10), Err(Error::Rejected(c)) if c == "TILE_NOT_ALIGNED"));
        assert!(matches!(g.worldgen_request(W, P, "4242", "minecraft:overworld", &[], 10), Err(Error::Rejected(c)) if c == "BAD_TILE_COUNT"));
        g.set_worldgen(W, false, 2, 4).unwrap();
        assert!(matches!(g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10), Err(Error::Rejected(c)) if c == "WORLDGEN_OFF"));
        assert!(g.set_worldgen(W, true, 3, 4).is_err(), "a quorum of 3 is not offered");
        assert!(g.set_worldgen(W, true, 2, 2).is_err() && g.set_worldgen(W, true, 2, 17).is_err(), "a halo under 4 or over 16 is refused");
    }

    #[test]
    fn a_worker_learns_the_seed_of_waiting_tiles_but_not_its_own_hosts_or_a_client_only_members() {
        let g = gw();
        hosting(&g);
        assert!(g.worldgen_demand("dev-b").unwrap().is_empty(), "nothing waiting");
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0), (32, 0)], 10).unwrap();
        assert_eq!(g.worldgen_demand("dev-b").unwrap(), vec![("4242".to_string(), P.to_string())], "one pair however many tiles");
        assert!(g.worldgen_demand("dev-a").unwrap().is_empty(), "the host does not work for itself");
        assert!(g.worldgen_demand("dev-d").unwrap().is_empty(), "a client-only member cannot work");
    }

    #[test]
    fn two_peers_that_agree_make_a_tile_ready_and_the_generators_chunks_are_listed() {
        let g = gw();
        hosting(&g);
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        let a = g.worldgen_claim("dev-b", P, 20).unwrap().unwrap();
        assert_eq!((a.role, a.x, a.z, a.size), ("generate", 0, 0, 32));
        let b = g.worldgen_claim("dev-c", P, 21).unwrap().unwrap();
        assert_eq!((b.tile_id, b.role), (a.tile_id, "verify"), "the second peer verifies the same tile");
        assert!(g.worldgen_claim("dev-a", P, 22).unwrap().is_none(), "the host never gets its own tiles");
        assert!(g.worldgen_claim("dev-d", P, 22).unwrap().is_none(), "a client-only member cannot work");
        assert_eq!(g.worldgen_claim_world("dev-b", 25).unwrap().as_deref(), Some(W));
        assert_eq!(g.worldgen_claim_world("dev-c", 25).unwrap(), None, "only a generator may upload");

        let l = leaves(&g, 0, 0);
        assert_eq!(g.worldgen_submit("dev-b", a.tile_id, digest(7), None, Some(&l), 30).unwrap(), Submit::Waiting);
        assert_eq!(g.worldgen_submit("dev-c", a.tile_id, digest(7), None, None, 31).unwrap(), Submit::Ready);
        let (ready, refused) = g.worldgen_ready(W, 4).unwrap();
        assert!(refused.is_empty());
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0]["leaves"].as_array().unwrap().len(), 1024);
        assert!(g.worldgen_consumed(W, a.tile_id).unwrap());
        assert!(g.worldgen_ready(W, 4).unwrap().0.is_empty());
        assert_eq!(g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 40).unwrap(), 0, "a taken tile is not generated again");
    }

    #[test]
    fn peers_that_never_agree_get_three_rounds_and_then_the_tile_is_refused() {
        let g = gw();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        let l = leaves(&g, 0, 0);
        // two peers whose per-chunk digests differ in exactly one chunk, number 5
        let da = "00".repeat(32 * 1024);
        let mut db = da.clone();
        db.replace_range(5 * 64..6 * 64, &"11".repeat(32));
        for round in 1..=3 {
            let a = g.worldgen_claim("dev-b", P, 100 * round).unwrap().unwrap();
            let b = g.worldgen_claim("dev-c", P, 100 * round + 1).unwrap().unwrap();
            assert_eq!((a.role, b.role), ("generate", "verify"));
            g.worldgen_submit("dev-b", a.tile_id, digest(1), Some(&da), Some(&l), 100 * round + 2).unwrap();
            let out = g.worldgen_submit("dev-c", a.tile_id, digest(2), Some(&db), None, 100 * round + 3).unwrap();
            assert_eq!(out, if round == 3 { Submit::Rejected } else { Submit::Retry });
        }
        assert!(g.worldgen_claim("dev-b", P, 1_000).unwrap().is_none(), "a refused tile is not handed out again");
        let why = g.worldgen_disagreements(W, 10).unwrap();
        assert_eq!(why.len(), 3, "every round that failed is remembered after its results are thrown away");
        assert_eq!((why[0]["differing"].as_i64(), why[0]["first_chunk"].as_i64()), (Some(1), Some(5)), "one chunk differed, number 5");
        assert_eq!(why[0]["devices"], "dev-b,dev-c");
        let (ready, refused) = g.worldgen_ready(W, 4).unwrap();
        assert!(ready.is_empty());
        assert_eq!(refused.len(), 1);
    }

    #[test]
    fn a_quorum_of_one_trusts_the_generator() {
        let g = gw();
        g.set_worldgen(W, true, 1, 4).unwrap();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        let a = g.worldgen_claim("dev-b", P, 20).unwrap().unwrap();
        g.worldgen_submit("dev-b", a.tile_id, digest(5), None, Some(&leaves(&g, 0, 0)), 30).unwrap();
        assert_eq!(g.worldgen_ready(W, 4).unwrap().0.len(), 1, "a quorum of one trusts the generator");
    }

    #[test]
    fn a_claim_that_expires_is_given_to_someone_else_and_one_claim_is_held_at_a_time() {
        let g = gw();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0), (32, 0)], 10).unwrap();
        let first = g.worldgen_claim("dev-b", P, 20).unwrap().unwrap();
        let again = g.worldgen_claim("dev-b", P, 21).unwrap().unwrap();
        assert_eq!(first.tile_id, again.tile_id, "asking again resumes the open claim");
        let later = g.worldgen_claim("dev-c", P, 22).unwrap().unwrap();
        assert_eq!((later.tile_id, later.role), (first.tile_id, "verify"));
        let after_expiry = g.worldgen_claim("dev-c", P, 20 + CLAIM_TTL_S + 5).unwrap().unwrap();
        assert_eq!(after_expiry.role, "generate", "with the generator gone the next claimant takes that role");
        assert!(matches!(g.worldgen_submit("dev-b", first.tile_id, digest(1), None, Some(&leaves(&g, 0, 0)), 20 + CLAIM_TTL_S + 6), Err(Error::Rejected(c)) if c == "NO_CLAIM"));
    }

    #[test]
    fn a_tile_keeps_the_halo_it_was_requested_with() {
        let g = gw();
        g.set_worldgen(W, true, 2, 8).unwrap();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        g.set_worldgen(W, true, 2, 12).unwrap();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(32, 0)], 11).unwrap();
        g.set_worldgen(W, true, 2, 4).unwrap();
        let first = g.worldgen_claim("dev-b", P, 20).unwrap().unwrap();
        assert_eq!((first.x, first.halo), (0, 8), "changing the setting later does not change a queued tile, or two workers could cut different shapes");
        g.worldgen_submit("dev-b", first.tile_id, digest(1), None, Some(&leaves(&g, 0, 0)), 30).unwrap();
        let second = g.worldgen_claim("dev-b", P, 40).unwrap().unwrap();
        assert_eq!((second.x, second.halo), (32, 12));
        assert_eq!(g.worldgen_settings(W).unwrap(), (true, 2, 4));
    }

    #[test]
    fn a_profile_mismatch_gets_nothing() {
        let g = gw();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        assert!(g.worldgen_claim("dev-b", "another-pack", 20).unwrap().is_none());
    }

    #[test]
    fn an_incomplete_or_dangling_chunk_list_is_refused_before_it_can_become_ready() {
        let g = gw();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        let a = g.worldgen_claim("dev-b", P, 20).unwrap().unwrap();
        let mut l = leaves(&g, 0, 0);
        let last = l.pop().unwrap();
        assert!(matches!(g.worldgen_submit("dev-b", a.tile_id, digest(1), None, Some(&l), 30), Err(Error::Rejected(c)) if c == "TILE_INCOMPLETE"));
        l.push(Leaf { hash: hex(&[9u8; 32]), ..last.clone() });
        assert!(matches!(g.worldgen_submit("dev-b", a.tile_id, digest(1), None, Some(&l), 31), Err(Error::MissingBlob)));
        l.pop();
        l.push(Leaf { cx: 400, ..last.clone() });
        assert!(matches!(g.worldgen_submit("dev-b", a.tile_id, digest(1), None, Some(&l), 32), Err(Error::Rejected(c)) if c == "LEAF_OUT_OF_TILE"));
        assert!(matches!(g.worldgen_submit("dev-b", a.tile_id, digest(1), None, None, 33), Err(Error::Rejected(c)) if c == "LEAVES_REQUIRED"));
        let b = g.worldgen_claim("dev-c", P, 34).unwrap().unwrap();
        assert!(matches!(g.worldgen_submit("dev-c", b.tile_id, digest(1), None, Some(&leaves(&g, 0, 0)), 35), Err(Error::Rejected(c)) if c == "LEAVES_NOT_ALLOWED"));
    }

    #[test]
    fn frontier_chunks_may_sit_just_outside_the_tile_and_are_kept_alive_until_the_host_takes_them() {
        let g = gw();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        let a = g.worldgen_claim("dev-b", P, 20).unwrap().unwrap();
        let blob = g.cas().put(b"a frontier chunk").unwrap();
        let mut far = leaves(&g, 0, 0);
        far.push(Leaf { kind: "region".into(), cx: -99, cz: 0, hash: hex(&blob), frontier: true });
        assert!(matches!(g.worldgen_submit("dev-b", a.tile_id, digest(3), None, Some(&far), 25), Err(Error::Rejected(c)) if c == "LEAF_OUT_OF_TILE"), "a frontier chunk far from the tile is refused");
        let mut l = leaves(&g, 0, 0);
        l.push(Leaf { kind: "region".into(), cx: -3, cz: 5, hash: hex(&blob), frontier: true });
        g.worldgen_submit("dev-b", a.tile_id, digest(3), None, Some(&l), 30).unwrap();
        let mut keep = HashSet::new();
        g.worldgen_keep(&mut keep).unwrap();
        assert!(keep.contains(&blob), "a waiting tile's blobs survive the retention sweep");
    }

    #[test]
    fn old_tiles_and_claims_are_cleaned_up() {
        let g = gw();
        g.worldgen_request(W, P, "4242", "minecraft:overworld", &[(0, 0)], 10).unwrap();
        g.worldgen_claim("dev-b", P, 20).unwrap().unwrap();
        g.worldgen_gc(10 + TILE_TTL_S + 1).unwrap();
        let n: i64 = g.db().query_row("SELECT COUNT(*) FROM worldgen_tiles", [], |r| r.get(0)).unwrap();
        let c: i64 = g.db().query_row("SELECT COUNT(*) FROM worldgen_claims", [], |r| r.get(0)).unwrap();
        assert_eq!((n, c), (0, 0));
    }
}
