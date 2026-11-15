//! Shard leases: more than one machine hosting the same world at once, each for its own set of regions (ROADMAP "Dynamic multi-host
//! sharding", board/RESEARCH.md 4 and 7). The world still has one lease and one head; this adds leases that can only write inside
//! a set of regions the main host gave up. Because the sets never overlap, a shard's changes commute with everything else and
//! its commit is applied on top of whatever the head is by then, so no host ever waits for another. The gateway enforces the
//! sets on every WAL append, so a bug or a lie in a mod can lose that host's own edits but never overwrite another host's chunks.

use crate::lease::{wall_s, Error, Gateway, Result, Revision, EXPIRY_MS, HEARTBEAT_MS};
use crate::manifest::Change;
use crate::server::{auth, frames_of, ApiErr, AppState, WalReq};
use crate::wal::Frame;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

const MAX_REGIONS_PER_OFFER: usize = 64;
const MAX_REGION_SPAN: i64 = 4096;
/// A shard host may carry its players' own files, nothing else outside its chunks.
const AUX_PREFIXES: [&str; 3] = ["playerdata/", "advancements/", "stats/"];

/// An inclusive rectangle of region files (32 x 32 chunks each) in one dimension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    pub dim: String,
    pub x1: i32,
    pub z1: i32,
    pub x2: i32,
    pub z2: i32,
}

impl Region {
    fn valid(&self) -> bool {
        !self.dim.is_empty()
            && self.dim.len() <= 64
            && self.x1 <= self.x2
            && self.z1 <= self.z2
            && (self.x2 as i64 - self.x1 as i64) < MAX_REGION_SPAN
            && (self.z2 as i64 - self.z1 as i64) < MAX_REGION_SPAN
    }

    fn contains(&self, dim: &str, rx: i32, rz: i32) -> bool {
        self.dim == dim && (self.x1..=self.x2).contains(&rx) && (self.z1..=self.z2).contains(&rz)
    }

    fn overlaps(&self, o: &Region) -> bool {
        self.dim == o.dim && self.x1 <= o.x2 && o.x1 <= self.x2 && self.z1 <= o.z2 && o.z1 <= self.z2
    }
}

/// The chunk a frame writes to, as (dimension, region x, region z); None for barriers and aux files.
fn frame_region(f: &Frame) -> Option<(&str, i32, i32)> {
    (f.op.starts_with("put:") || f.op.starts_with("del:")).then(|| (f.dim.as_str(), f.cx >> 5, f.cz >> 5))
}

/// True when `f` writes a chunk inside any of `regions`.
pub(crate) fn frame_hits(regions: &[Region], f: &Frame) -> bool {
    frame_region(f).is_some_and(|(d, x, z)| regions.iter().any(|r| r.contains(d, x, z)))
}

/// The player a path like `playerdata/<uuid>.dat` belongs to.
pub(crate) fn player_file_of(path: &str) -> Option<&str> {
    path.strip_prefix("playerdata/")?.strip_suffix(".dat").filter(|u| !u.is_empty() && !u.contains('/'))
}

fn aux_allowed(path: &str) -> bool {
    AUX_PREFIXES.iter().any(|p| path.starts_with(p)) && !path.contains("..")
}

pub struct ShardGrant {
    pub lease_id: String,
    pub epoch: i64,
    pub base_rev: String,
    pub hmac_key: [u8; 32],
    pub regions: Vec<Region>,
}

fn parse_regions(s: &str) -> Vec<Region> {
    serde_json::from_str(s).unwrap_or_default()
}

impl Gateway {
    /// Regions of every live shard lease and every open offer of the world: the main host may not write these.
    pub(crate) fn shard_reserved(&self, world: &str) -> Result<Vec<Region>> {
        let mut out = Vec::new();
        for sql in ["SELECT regions FROM shard_leases WHERE world_id=? AND status='ACTIVE'", "SELECT regions FROM shard_offers WHERE world_id=?"] {
            let mut st = self.db.prepare(sql)?;
            let rows = st.query_map(params![world], |r| r.get::<_, String>(0))?;
            for row in rows {
                out.extend(parse_regions(&row?));
            }
        }
        Ok(out)
    }

    /// The main host sets regions aside for another machine. Returns the offer id.
    pub fn shard_offer(&mut self, device: &str, world: &str, regions: Vec<Region>) -> Result<i64> {
        match self.active_lease(world)? {
            Some((_, d, _, _)) if d == device => {}
            _ => return Err(Error::Rejected("NOT_LEASE_HOLDER".into())),
        }
        if regions.is_empty() || regions.len() > MAX_REGIONS_PER_OFFER || !regions.iter().all(Region::valid) {
            return Err(Error::Rejected("BAD_SHARD_REGIONS".into()));
        }
        let reserved = self.shard_reserved(world)?;
        if regions.iter().any(|r| reserved.iter().any(|o| o.overlaps(r))) {
            return Err(Error::Rejected("SHARD_OVERLAP".into()));
        }
        self.db.execute(
            "INSERT INTO shard_offers(world_id, regions, created_at) VALUES(?,?,?)",
            params![world, serde_json::to_string(&regions).unwrap_or_default(), wall_s()],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    /// A machine that may host takes the oldest open offer of the world. None when there is nothing to take.
    pub fn shard_claim(&mut self, device: &str, world: &str) -> Result<Option<ShardGrant>> {
        let allowed: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM members m JOIN devices d ON d.player_uuid=m.player_uuid
                               WHERE d.id=?1 AND d.revoked=0 AND m.world_id=?2 AND m.role IN('ADMIN','HOST_ELIGIBLE'))",
                params![device, world],
                |r| r.get(0),
            )?;
        if !allowed {
            return Err(Error::NotMember);
        }
        // the main host never takes its own offers, and a device takes one shard of a world at a time
        let holds: bool = self.active_lease(world)?.is_some_and(|(_, d, _, _)| d == device)
            || self.db.query_row("SELECT EXISTS(SELECT 1 FROM shard_leases WHERE world_id=? AND device_id=? AND status='ACTIVE')", params![world, device], |r| r.get(0))?;
        if holds {
            return Ok(None);
        }
        let offer: Option<(i64, String)> =
            self.db.query_row("SELECT id, regions FROM shard_offers WHERE world_id=? ORDER BY id LIMIT 1", params![world], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let Some((offer_id, regions_json)) = offer else { return Ok(None) };
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| Error::Rand)?;
        let base = self.head(world)?;
        let id = format!("sh_{world}_{offer_id}");
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM shard_offers WHERE id=?", params![offer_id])?;
        tx.execute(
            "INSERT INTO shard_leases(id, world_id, device_id, epoch, hmac_key, regions, status, granted_at, last_hb) VALUES(?,?,?,?,?,?, 'ACTIVE', ?, ?)",
            params![id, world, device, offer_id, key.as_slice(), regions_json, wall_s(), wall_s()],
        )?;
        tx.commit()?;
        Ok(Some(ShardGrant { lease_id: id, epoch: offer_id, base_rev: base, hmac_key: key, regions: parse_regions(&regions_json) }))
    }

    /// (world, device, regions) of a live shard lease with this epoch.
    pub(crate) fn shard_live(&self, lease: &str, epoch: i64) -> Result<(String, String, Vec<Region>)> {
        self.db
            .query_row(
                "SELECT world_id, device_id, regions FROM shard_leases WHERE id=? AND epoch=? AND status='ACTIVE'",
                params![lease, epoch],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
            )
            .optional()?
            .map(|(w, d, r)| (w, d, parse_regions(&r)))
            .ok_or(Error::StaleEpoch)
    }

    pub fn shard_device(&self, lease: &str) -> Result<Option<String>> {
        Ok(self.db.query_row("SELECT device_id FROM shard_leases WHERE id=?", params![lease], |r| r.get(0)).optional()?)
    }

    /// The world a device holds a live shard of, so it may upload blobs for it.
    pub fn shard_world_of(&self, device: &str) -> Result<Option<String>> {
        Ok(self.db.query_row("SELECT world_id FROM shard_leases WHERE device_id=? AND status='ACTIVE'", params![device], |r| r.get(0)).optional()?)
    }

    pub fn shard_heartbeat(&mut self, lease: &str, epoch: i64) -> Result<()> {
        self.shard_live(lease, epoch)?;
        self.db.execute("UPDATE shard_leases SET last_hb=? WHERE id=?", params![wall_s(), lease])?;
        Ok(())
    }

    /// Chain check plus the shard rule: chunks only inside the regions, aux files only player files.
    pub fn shard_wal_append(&mut self, lease: &str, epoch: i64, frames: &[Frame]) -> Result<u64> {
        let (world, _, regions) = self.shard_live(lease, epoch)?;
        let key: Vec<u8> = self.db.query_row("SELECT hmac_key FROM shard_leases WHERE id=?", params![lease], |r| r.get(0))?;
        let next = self.wal_store(lease, &world, &key, frames, |f| match f.op.as_str() {
            "barrier" => Ok(()),
            "aux_put" | "aux_del" if aux_allowed(&f.dim) => Ok(()),
            "aux_put" | "aux_del" => Err(Error::Rejected("OUT_OF_SHARD".into())),
            _ if frame_hits(&regions, f) => Ok(()),
            _ => Err(Error::Rejected("OUT_OF_SHARD".into())),
        })?;
        // the machine that last wrote a player's file is where that player is: guests of that player are routed to it
        for f in frames {
            if let Some(uuid) = player_file_of(&f.dim) {
                if f.op == "aux_put" {
                    self.db.execute(
                        "INSERT INTO shard_homes(world_id, uuid, lease_id, ts) VALUES(?,?,?,?) ON CONFLICT(world_id, uuid) DO UPDATE SET lease_id=excluded.lease_id, ts=excluded.ts",
                        params![world, uuid, lease, wall_s()],
                    )?;
                }
            }
        }
        Ok(next)
    }

    /// The live shard lease that is home to this player, if any.
    pub fn shard_home(&self, world: &str, uuid: &str) -> Result<Option<String>> {
        Ok(self
            .db
            .query_row(
                "SELECT h.lease_id FROM shard_homes h JOIN shard_leases l ON l.id=h.lease_id WHERE h.world_id=? AND h.uuid=? AND l.status='ACTIVE'",
                params![world, uuid],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Players whose files only a live shard may write.
    pub(crate) fn shard_player_files(&self, world: &str) -> Result<Vec<String>> {
        let mut st = self.db.prepare("SELECT h.uuid FROM shard_homes h JOIN shard_leases l ON l.id=h.lease_id WHERE h.world_id=? AND l.status='ACTIVE'")?;
        let rows = st.query_map(params![world], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Builds a revision from the shard's WAL up to its last barrier on top of the current head. With `last` the shard ends and its
    /// regions go back to the main host. Returns the head when there was nothing to add.
    pub fn shard_commit(&mut self, lease: &str, epoch: i64, last: bool, kind: &str) -> Result<Revision> {
        let (world, _, _) = self.shard_live(lease, epoch)?;
        if !last {
            self.check_storage(&world)?;
        }
        let (changes, barrier): (Vec<Change>, Option<i64>) = self.wal_pending(lease)?;
        let rev = if changes.is_empty() {
            let head = self.head(&world)?;
            Revision { id: head.clone(), parent: head, seq: 0 }
        } else {
            self.new_revision(&world, lease, kind, &changes)?
        };
        self.wal_trim(lease, barrier, last)?;
        if last {
            self.db.execute("UPDATE shard_leases SET status='ENDED', end_reason='final commit' WHERE id=?", params![lease])?;
        } else {
            self.db.execute("UPDATE shard_leases SET last_hb=? WHERE id=?", params![wall_s(), lease])?;
        }
        Ok(rev)
    }

    /// Shard hosts that stopped heartbeating lose their lease; what reached a barrier is kept as a RECOVERED revision.
    pub(crate) fn shard_expire(&mut self) -> Result<()> {
        let dead: Vec<(String, String)> = {
            let mut st = self.db.prepare("SELECT id, world_id FROM shard_leases WHERE status='ACTIVE' AND last_hb < ?")?;
            let rows = st.query_map(params![wall_s() - (EXPIRY_MS / 1000) as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, world) in dead {
            let (changes, barrier): (Vec<Change>, Option<i64>) = self.wal_pending(&id)?;
            if barrier.is_some() && !changes.is_empty() {
                if let Err(Error::Rejected(why)) = self.new_revision(&world, &id, "RECOVERED", &changes) {
                    eprintln!("sanity gate held back recovery of shard {id}: {why}");
                }
            }
            self.wal_trim(&id, barrier, true)?;
            self.db.execute("UPDATE shard_leases SET status='ENDED', end_reason='missed heartbeats' WHERE id=?", params![id])?;
        }
        Ok(())
    }

    /// Live shards and open offers of a world, for the main host and the members.
    pub fn shard_list(&self, world: &str) -> Result<(Vec<(String, String, Vec<Region>)>, Vec<(i64, Vec<Region>)>)> {
        let mut shards = Vec::new();
        let mut st = self.db.prepare("SELECT id, device_id, regions FROM shard_leases WHERE world_id=? AND status='ACTIVE' ORDER BY id")?;
        for r in st.query_map(params![world], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
            let (id, dev, regions) = r?;
            shards.push((id, dev, parse_regions(&regions)));
        }
        let mut offers = Vec::new();
        let mut st = self.db.prepare("SELECT id, regions FROM shard_offers WHERE world_id=? ORDER BY id")?;
        for r in st.query_map(params![world], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
            let (id, regions) = r?;
            offers.push((id, parse_regions(&regions)));
        }
        Ok((shards, offers))
    }
}

#[derive(Deserialize)]
struct OfferReq {
    regions: Vec<Region>,
}

#[derive(Deserialize)]
struct EpochReq {
    epoch: i64,
}

#[derive(Deserialize)]
struct CommitReq {
    epoch: i64,
    #[serde(default)]
    last: bool,
    #[serde(default)]
    kind: String,
}

fn reject(e: Error) -> ApiErr {
    ApiErr::Domain(e)
}

async fn offer(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>, Json(b): Json<OfferReq>) -> std::result::Result<Json<Value>, ApiErr> {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    let id = gw.shard_offer(&dev, &world, b.regions).map_err(reject)?;
    Ok(Json(json!({ "offer": id })))
}

async fn list(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> std::result::Result<Json<Value>, ApiErr> {
    let gw = s.gw();
    let dev = auth(&gw, &h)?;
    if !gw.worlds_of(&dev)?.iter().any(|w| w.0 == world) {
        return Err(ApiErr::Forbidden("NOT_A_MEMBER"));
    }
    let (shards, offers) = gw.shard_list(&world)?;
    Ok(Json(json!({
        "shards": shards.iter().map(|(id, d, r)| json!({ "id": id, "device": d, "regions": r })).collect::<Vec<_>>(),
        "offers": offers.iter().map(|(id, r)| json!({ "id": id, "regions": r })).collect::<Vec<_>>(),
    })))
}

async fn claim(State(s): State<Arc<AppState>>, h: HeaderMap, Path(world): Path<String>) -> std::result::Result<Json<Value>, ApiErr> {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    Ok(Json(match gw.shard_claim(&dev, &world).map_err(reject)? {
        Some(g) => json!({ "grant": {
            "id": g.lease_id, "epoch": g.epoch, "base_rev": g.base_rev, "regions": g.regions,
            "hmac_key": URL_SAFE_NO_PAD.encode(g.hmac_key), "ttl_s": EXPIRY_MS / 1000, "heartbeat_s": HEARTBEAT_MS / 1000,
        } }),
        None => json!({ "grant": null }),
    }))
}

fn own(gw: &Gateway, dev: &str, lease: &str) -> std::result::Result<(), ApiErr> {
    match gw.shard_device(lease)? {
        Some(d) if d == dev => Ok(()),
        Some(_) => Err(ApiErr::Forbidden("NOT_LEASE_HOLDER")),
        None => Err(ApiErr::Domain(Error::StaleEpoch)),
    }
}

async fn heartbeat(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<EpochReq>) -> std::result::Result<Json<Value>, ApiErr> {
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    own(&gw, &dev, &lease)?;
    gw.shard_heartbeat(&lease, b.epoch).map_err(reject)?;
    Ok(Json(json!({ "ok": true })))
}

async fn wal(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<WalReq>) -> std::result::Result<Json<Value>, ApiErr> {
    let epoch = b.epoch;
    let frames = frames_of(b)?;
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    own(&gw, &dev, &lease)?;
    let next = gw.shard_wal_append(&lease, epoch, &frames).map_err(reject)?;
    Ok(Json(json!({ "next_seq": next })))
}

async fn commit(State(s): State<Arc<AppState>>, h: HeaderMap, Path(lease): Path<String>, Json(b): Json<CommitReq>) -> std::result::Result<Json<Value>, ApiErr> {
    let kind = match b.kind.as_str() {
        "" | "AUTOSAVE" => "AUTOSAVE",
        "SHUTDOWN" => "SHUTDOWN",
        _ => return Err(ApiErr::BadRequest("BAD_KIND")),
    };
    let mut gw = s.gw();
    let dev = auth(&gw, &h)?;
    own(&gw, &dev, &lease)?;
    let r = gw.shard_commit(&lease, b.epoch, b.last, kind).map_err(reject)?;
    Ok(Json(json!({ "rev_id": r.id, "parent": r.parent, "seq": r.seq })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/worlds/:id/shards", get(list).post(offer))
        .route("/v1/worlds/:id/shards/claim", post(claim))
        .route("/v1/shards/:id/heartbeat", post(heartbeat))
        .route("/v1/shards/:id/wal", post(wal).layer(axum::extract::DefaultBodyLimit::max(4 << 20)))
        .route("/v1/shards/:id/commit", post(commit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::Cas;
    use crate::chain::{next_mac, Entry};
    use crate::lease::{CommitKind, Hw, Join, Role};
    use crate::manifest::{self, Key, Kind};
    use rusqlite::Connection;

    const W: &str = "w";
    const OVER: &str = "minecraft:overworld";

    fn gw() -> Gateway {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let k = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cas = Cas::open(std::env::temp_dir().join(format!("mcmesh-shard-{}-{k}", std::process::id()))).unwrap();
        let mut g = Gateway::open(Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.create_world(W, "w", "1.21.1", "neoforge").unwrap();
        g.add_member(W, "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
        g.add_member(W, "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
        g.add_member(W, "u-d", "dave", "dev-d", Role::ClientOnly).unwrap();
        g
    }

    fn region(x1: i32, z1: i32, x2: i32, z2: i32) -> Region {
        Region { dim: OVER.into(), x1, z1, x2, z2 }
    }

    /// Alice hosts the world as before.
    fn main_host(g: &mut Gateway) -> crate::lease::Grant {
        match g.join(W, "dev-a", Hw { tier: 2, score: 5.0, wants_host: true, takeover: true }, 0).unwrap() {
            Join::Host(h) => h,
            other => panic!("expected Host, got {other:?}"),
        }
    }

    /// A WAL writer that keeps the chain state, for either kind of lease.
    struct Wal {
        lease: String,
        epoch: i64,
        key: Vec<u8>,
        next: u64,
        prev: [u8; 32],
    }

    impl Wal {
        fn new(lease: &str, epoch: i64, key: &[u8]) -> Self {
            Wal { lease: lease.into(), epoch, key: key.to_vec(), next: 0, prev: [0; 32] }
        }

        fn frames(&mut self, ops: &[(&str, &str, i32, i32, [u8; 32])]) -> Vec<Frame> {
            ops.iter()
                .map(|(op, dim, cx, cz, hash)| {
                    let e = Entry { seq: self.next, dim, kind: op, cx: *cx, cz: *cz, hash };
                    let mac = next_mac(&self.key, &self.prev, &e);
                    self.prev = mac;
                    self.next += 1;
                    Frame { seq: self.next - 1, op: op.to_string(), dim: dim.to_string(), cx: *cx, cz: *cz, hash: *hash, mac: mac.to_vec() }
                })
                .collect()
        }
    }

    fn chunk(g: &Gateway, cx: i32, cz: i32) -> Option<[u8; 32]> {
        let head = g.head(W).unwrap();
        manifest::lookup(&g.cas, g.revision_root(&head).unwrap(), &Key { dim: OVER.into(), kind: Kind::Region, cx, cz }).unwrap()
    }

    #[test]
    fn only_the_main_host_offers_regions_and_offers_may_not_overlap() {
        let mut g = gw();
        assert!(g.shard_offer("dev-a", W, vec![region(0, 0, 0, 0)]).is_err(), "nobody hosts yet");
        main_host(&mut g);
        assert!(g.shard_offer("dev-b", W, vec![region(0, 0, 0, 0)]).is_err(), "a guest cannot offer");
        assert!(g.shard_offer("dev-a", W, vec![]).is_err() && g.shard_offer("dev-a", W, vec![region(2, 0, 1, 0)]).is_err(), "empty and inverted sets are refused");
        g.shard_offer("dev-a", W, vec![region(10, 0, 12, 3)]).unwrap();
        assert!(matches!(g.shard_offer("dev-a", W, vec![region(12, 3, 14, 5)]), Err(Error::Rejected(c)) if c == "SHARD_OVERLAP"));
        g.shard_offer("dev-a", W, vec![region(13, 0, 14, 3)]).unwrap();
    }

    #[test]
    fn a_member_who_may_host_claims_an_offer_once_and_the_main_host_cannot() {
        let mut g = gw();
        main_host(&mut g);
        g.shard_offer("dev-a", W, vec![region(10, 0, 12, 3)]).unwrap();
        assert!(g.shard_claim("dev-a", W).unwrap().is_none(), "the main host does not take its own offer");
        assert!(matches!(g.shard_claim("dev-d", W), Err(Error::NotMember)), "a client-only member cannot host");
        let s = g.shard_claim("dev-b", W).unwrap().unwrap();
        assert_eq!(s.regions, vec![region(10, 0, 12, 3)]);
        assert!(g.shard_claim("dev-b", W).unwrap().is_none(), "nothing left to take");
        let (shards, offers) = g.shard_list(W).unwrap();
        assert_eq!((shards.len(), offers.len()), (1, 0));
    }

    #[test]
    fn a_shard_writes_inside_its_regions_only_and_the_main_host_stays_out_of_them() {
        let mut g = gw();
        let main = main_host(&mut g);
        g.shard_offer("dev-a", W, vec![region(10, 0, 12, 3)]).unwrap();
        let s = g.shard_claim("dev-b", W).unwrap().unwrap();
        let blob = g.cas.put(b"chunk").unwrap();
        let mut sw = Wal::new(&s.lease_id, s.epoch, &s.hmac_key);
        // chunk 320,0 is in region 10,0
        let inside = sw.frames(&[("put:region", OVER, 320, 0, blob)]);
        g.shard_wal_append(&s.lease_id, s.epoch, &inside).unwrap();
        // chunk 0,0 is region 0,0 and not the shard's; the other dimension is not either
        let outside = sw.frames(&[("put:region", OVER, 0, 0, blob)]);
        assert!(matches!(g.shard_wal_append(&s.lease_id, s.epoch, &outside), Err(Error::Rejected(c)) if c == "OUT_OF_SHARD"));
        let mut sw2 = Wal::new(&s.lease_id, s.epoch, &s.hmac_key);
        sw2.next = sw.next - 1;
        sw2.prev = sw.prev;
        // the rejected frame did not advance the chain on the gateway: a fresh frame with the right seq passes
        let nether = sw2.frames(&[("put:region", "minecraft:the_nether", 320, 0, blob)]);
        assert!(g.shard_wal_append(&s.lease_id, s.epoch, &nether).is_err());

        let mut mw = Wal::new(&main.lease_id, main.epoch, &main.hmac_key);
        let mine = mw.frames(&[("put:region", OVER, 0, 0, blob)]);
        g.wal_append(&main.lease_id, main.epoch, &mine).unwrap();
        let theirs = mw.frames(&[("put:region", OVER, 320, 0, blob)]);
        assert!(matches!(g.wal_append(&main.lease_id, main.epoch, &theirs), Err(Error::Rejected(c)) if c == "SHARD_OWNED"));
    }

    #[test]
    fn a_shard_may_carry_player_files_but_not_the_worlds() {
        let mut g = gw();
        main_host(&mut g);
        g.shard_offer("dev-a", W, vec![region(10, 0, 12, 3)]).unwrap();
        let s = g.shard_claim("dev-b", W).unwrap().unwrap();
        let blob = g.cas.put(b"data").unwrap();
        let mut sw = Wal::new(&s.lease_id, s.epoch, &s.hmac_key);
        g.shard_wal_append(&s.lease_id, s.epoch, &sw.frames(&[("aux_put", "playerdata/u-b.dat", 0, 0, blob)])).unwrap();
        for bad in ["level.dat", "mesh/ops.json", "playerdata/../level.dat"] {
            let mut w = Wal::new(&s.lease_id, s.epoch, &s.hmac_key);
            w.next = sw.next;
            w.prev = sw.prev;
            assert!(matches!(g.shard_wal_append(&s.lease_id, s.epoch, &w.frames(&[("aux_put", bad, 0, 0, blob)])), Err(Error::Rejected(_))), "{bad}");
        }
    }

    #[test]
    fn both_hosts_commit_and_the_head_has_both_sets_of_chunks() {
        let mut g = gw();
        let main = main_host(&mut g);
        g.shard_offer("dev-a", W, vec![region(10, 0, 12, 3)]).unwrap();
        let s = g.shard_claim("dev-b", W).unwrap().unwrap();
        let a = g.cas.put(b"from main").unwrap();
        let b = g.cas.put(b"from shard").unwrap();
        let mut mw = Wal::new(&main.lease_id, main.epoch, &main.hmac_key);
        let mut sw = Wal::new(&s.lease_id, s.epoch, &s.hmac_key);
        g.wal_append(&main.lease_id, main.epoch, &mw.frames(&[("put:region", OVER, 1, 1, a), ("barrier", "", 0, 0, [0; 32])])).unwrap();
        g.shard_wal_append(&s.lease_id, s.epoch, &sw.frames(&[("put:region", OVER, 330, 40, b), ("barrier", "", 0, 0, [0; 32])])).unwrap();
        // the shard commits first, so the head moves under the main host's commit, which must still go through on its own base
        g.shard_commit(&s.lease_id, s.epoch, false, "AUTOSAVE").unwrap();
        let base = main.base_rev.clone();
        assert!(matches!(g.commit(&main.lease_id, main.epoch, &base, CommitKind::Autosave, false, 1_000), Err(Error::HeadMoved)), "the main lease keeps its compare and swap");
        let head = g.head(W).unwrap();
        g.commit(&main.lease_id, main.epoch, &head, CommitKind::Autosave, false, 2_000).unwrap();
        assert_eq!(chunk(&g, 1, 1), Some(a));
        assert_eq!(chunk(&g, 330, 40), Some(b));
        // the shard ends: nothing is reserved any more and the main host may write there again
        g.shard_commit(&s.lease_id, s.epoch, true, "SHUTDOWN").unwrap();
        assert!(g.shard_reserved(W).unwrap().is_empty());
        let more = mw.frames(&[("put:region", OVER, 320, 0, a)]);
        g.wal_append(&main.lease_id, main.epoch, &more).unwrap();
    }

    #[test]
    fn a_shard_that_goes_silent_keeps_what_it_sealed() {
        let mut g = gw();
        main_host(&mut g);
        g.shard_offer("dev-a", W, vec![region(10, 0, 12, 3)]).unwrap();
        let s = g.shard_claim("dev-b", W).unwrap().unwrap();
        let b = g.cas.put(b"from shard").unwrap();
        let mut sw = Wal::new(&s.lease_id, s.epoch, &s.hmac_key);
        g.shard_wal_append(&s.lease_id, s.epoch, &sw.frames(&[("put:region", OVER, 330, 40, b), ("barrier", "", 0, 0, [0; 32]), ("put:region", OVER, 331, 40, b)])).unwrap();
        g.db().execute("UPDATE shard_leases SET last_hb=last_hb-1000 WHERE id=?", params![s.lease_id]).unwrap();
        g.shard_expire().unwrap();
        assert_eq!(chunk(&g, 330, 40), Some(b), "up to the barrier");
        assert_eq!(chunk(&g, 331, 40), None, "after it is dropped");
        assert!(g.shard_live(&s.lease_id, s.epoch).is_err());
        assert!(g.shard_reserved(W).unwrap().is_empty());
    }
}
