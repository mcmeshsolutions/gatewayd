//! Storage and world-count limits, and the retention sweep that frees space.
//! No row means unlimited. Nothing here may ever refuse a final commit or a crash recovery.
use crate::cas::{Cas, Hash};
use crate::lease::{wall_s, Error, Gateway, Result};
use crate::manifest;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    World,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::World => "world",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    pub storage_bytes: Option<u64>,
    pub world_count: Option<u64>,
    pub keep_revisions: Option<u64>,
    pub keep_days: Option<u64>,
    /// world scope: guests connected at once
    pub max_guests: Option<u64>,
    /// world scope: relayed bytes (both directions) per calendar month, UTC
    pub relay_bytes_month: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaHit {
    pub code: &'static str,
    pub limit: u64,
    pub used: u64,
}

#[derive(Debug, Default)]
pub struct SweepReport {
    pub pruned: Vec<String>,
    pub blobs_removed: u64,
    pub bytes_freed: u64,
}

pub(crate) fn migrate(db: &Connection, cas: &Cas) -> rusqlite::Result<()> {
    let _ = db.execute("ALTER TABLE worlds ADD COLUMN owner_uuid TEXT", []);
    let _ = db.execute("ALTER TABLE blob_world ADD COLUMN size INTEGER", []);
    let _ = db.execute("ALTER TABLE quotas ADD COLUMN max_guests INTEGER", []);
    let _ = db.execute("ALTER TABLE quotas ADD COLUMN relay_bytes_month INTEGER", []);
    let _ = db.execute("ALTER TABLE revisions ADD COLUMN pruned INTEGER NOT NULL DEFAULT 0", []);
    db.execute(
        "UPDATE worlds SET owner_uuid=(SELECT player_uuid FROM members m WHERE m.world_id=worlds.id AND m.role='ADMIN' ORDER BY m.rowid LIMIT 1) \
         WHERE owner_uuid IS NULL",
        [],
    )?;
    let unsized_: Vec<Vec<u8>> = {
        let mut st = db.prepare("SELECT DISTINCT hash FROM blob_world WHERE size IS NULL")?;
        let rows = st.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for h in unsized_ {
        let size = Hash::try_from(h.as_slice()).ok().and_then(|x| cas.size(&x)).unwrap_or(0);
        db.execute("UPDATE blob_world SET size=? WHERE hash=? AND size IS NULL", params![size as i64, h])?;
    }
    Ok(())
}

/// Name of the meter that counts relayed bytes for the calendar month (UTC) containing `secs`.
pub(crate) fn month_meter(secs: i64) -> String {
    // days since 1970-01-01 to a civil date, Howard Hinnant's algorithm
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("relay_month_{y:04}{m:02}")
}

impl Gateway {
    fn limit_row(&self, scope: Scope, id: &str) -> Result<Limits> {
        let row = self
            .db
            .query_row(
                "SELECT storage_bytes, world_count, keep_revisions, keep_days, max_guests, relay_bytes_month FROM quotas WHERE scope=? AND id=?",
                params![scope.as_str(), id],
                |r| {
                    let f = |i| r.get::<_, Option<i64>>(i).map(|v| v.map(|n| n.max(0) as u64));
                    Ok(Limits { storage_bytes: f(0)?, world_count: f(1)?, keep_revisions: f(2)?, keep_days: f(3)?, max_guests: f(4)?, relay_bytes_month: f(5)? })
                },
            )
            .optional()?;
        Ok(row.unwrap_or_default())
    }

    /// Replaces the limits of one user (player uuid) or world; `id` "*" sets the default for the scope.
    pub fn set_limits(&mut self, scope: Scope, id: &str, l: &Limits) -> Result<()> {
        let n = |v: Option<u64>| v.map(|x| x.min(i64::MAX as u64) as i64);
        self.db.execute(
            "INSERT OR REPLACE INTO quotas(scope,id,storage_bytes,world_count,keep_revisions,keep_days,max_guests,relay_bytes_month) VALUES(?,?,?,?,?,?,?,?)",
            params![scope.as_str(), id, n(l.storage_bytes), n(l.world_count), n(l.keep_revisions), n(l.keep_days), n(l.max_guests), n(l.relay_bytes_month)],
        )?;
        Ok(())
    }

    /// Effective limits: the row for `id`, with unset fields taken from the "*" row.
    pub fn limits(&self, scope: Scope, id: &str) -> Result<Limits> {
        let (own, def) = (self.limit_row(scope, id)?, self.limit_row(scope, "*")?);
        Ok(Limits {
            storage_bytes: own.storage_bytes.or(def.storage_bytes),
            world_count: own.world_count.or(def.world_count),
            keep_revisions: own.keep_revisions.or(def.keep_revisions),
            keep_days: own.keep_days.or(def.keep_days),
            max_guests: own.max_guests.or(def.max_guests),
            relay_bytes_month: own.relay_bytes_month.or(def.relay_bytes_month),
        })
    }

    pub fn owner_of(&self, world: &str) -> Result<Option<String>> {
        self.db
            .query_row("SELECT owner_uuid FROM worlds WHERE id=?", params![world], |r| r.get(0))
            .optional()?
            .ok_or(Error::NoSuchWorld)
    }

    /// Stored bytes of every blob uploaded for the world and not swept yet.
    pub fn world_usage(&self, world: &str) -> Result<u64> {
        let n: i64 =
            self.db.query_row("SELECT COALESCE(SUM(size),0) FROM blob_world WHERE world_id=?", params![world], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// (stored bytes, world count) over the worlds the player owns.
    pub fn user_usage(&self, uuid: &str) -> Result<(u64, u64)> {
        let bytes: i64 = self.db.query_row(
            "SELECT COALESCE(SUM(b.size),0) FROM blob_world b JOIN worlds w ON w.id=b.world_id WHERE w.owner_uuid=?",
            params![uuid],
            |r| r.get(0),
        )?;
        let worlds: i64 = self.db.query_row("SELECT COUNT(*) FROM worlds WHERE owner_uuid=?", params![uuid], |r| r.get(0))?;
        Ok((bytes as u64, worlds as u64))
    }

    pub(crate) fn meter_value(&self, world: &str, name: &str) -> u64 {
        let v: Option<i64> = self.db.query_row("SELECT value FROM meters WHERE world_id=? AND name=?", params![world, name], |r| r.get(0)).optional().ok().flatten();
        v.unwrap_or(0).max(0) as u64
    }

    /// Whether one more guest may connect: `guests_now` is the number already connected, `now_s` unix seconds.
    /// Over a cap the guest is turned away; nothing already connected is touched and no data is deleted.
    pub(crate) fn guest_admission(&self, world: &str, guests_now: u64, now_s: i64) -> Result<()> {
        let l = self.limits(Scope::World, world)?;
        if let Some(limit) = l.max_guests {
            if guests_now >= limit {
                return Err(Error::Quota(QuotaHit { code: "QUOTA_GUESTS", limit, used: guests_now }));
            }
        }
        if let Some(limit) = l.relay_bytes_month {
            let used = self.meter_value(world, &month_meter(now_s));
            if used >= limit {
                return Err(Error::Quota(QuotaHit { code: "QUOTA_RELAY_MONTH", limit, used }));
            }
        }
        Ok(())
    }

    pub(crate) fn check_world_count(&self, uuid: &str) -> Result<()> {
        let Some(limit) = self.limits(Scope::User, uuid)?.world_count else { return Ok(()) };
        let used = self.user_usage(uuid)?.1;
        if used >= limit {
            return Err(Error::Quota(QuotaHit { code: "QUOTA_WORLD_COUNT", limit, used }));
        }
        Ok(())
    }

    pub(crate) fn check_storage(&self, world: &str) -> Result<()> {
        self.check_storage_with(world, |limit| limit)
    }

    /// Checked before a blob is written. A host that is over its limit must still be able to upload the blobs of its
    /// final commit, which is never refused, so the line here sits at twice the limit plus 256 MiB: it stops a runaway
    /// host from filling the disk without ever blocking a normal shutdown.
    pub(crate) fn check_upload_headroom(&self, world: &str) -> Result<()> {
        self.check_storage_with(world, |limit| limit.saturating_mul(2).saturating_add(256 << 20))
    }

    fn check_storage_with(&self, world: &str, line: impl Fn(u64) -> u64) -> Result<()> {
        if let Some(limit) = self.limits(Scope::World, world)?.storage_bytes {
            let used = self.world_usage(world)?;
            if used > line(limit) {
                return Err(Error::Quota(QuotaHit { code: "QUOTA_STORAGE_WORLD", limit, used }));
            }
        }
        let Some(owner) = self.owner_of(world)? else { return Ok(()) };
        if let Some(limit) = self.limits(Scope::User, &owner)?.storage_bytes {
            let used = self.user_usage(&owner)?.0;
            if used > line(limit) {
                return Err(Error::Quota(QuotaHit { code: "QUOTA_STORAGE_USER", limit, used }));
            }
        }
        Ok(())
    }

    /// Drops usage rows of blobs no longer on disk.
    fn forget_missing_blobs(&mut self) -> Result<()> {
        let hashes: Vec<Vec<u8>> = {
            let mut st = self.db.prepare("SELECT DISTINCT hash FROM blob_world")?;
            let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let tx = self.db.transaction()?;
        for h in hashes {
            if Hash::try_from(h.as_slice()).map(|k| !self.cas.has(&k)).unwrap_or(false) {
                tx.execute("DELETE FROM blob_world WHERE hash=?", params![h])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// True once an operator has set any limit row; the periodic sweep stays off until then.
    pub fn quotas_configured(&self) -> Result<bool> {
        Ok(self.db.query_row("SELECT EXISTS(SELECT 1 FROM quotas)", [], |r| r.get::<_, bool>(0))?)
    }

    /// Marks revisions outside each world's retention as pruned, then deletes blobs nothing needs any more.
    /// A blob survives when any unpruned revision of any world reaches it, a WAL frame names it, or it was written
    /// less than `grace_s` ago. If one retained tree cannot be read, nothing is pruned or deleted.
    pub fn retention_sweep(&mut self, grace_s: u64) -> Result<SweepReport> {
        let mut rep = SweepReport::default();
        let now = wall_s();
        let worlds: Vec<String> = {
            let mut st = self.db.prepare("SELECT id FROM worlds")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut plan = Vec::new();
        for w in &worlds {
            let l = self.limits(Scope::World, w)?;
            if l.keep_revisions.is_none() && l.keep_days.is_none() {
                continue;
            }
            let head = self.head(w)?;
            let mut st = self.db.prepare(
                "SELECT id, created_at, pinned OR id IN (SELECT base_rev FROM leases WHERE status IN('ACTIVE','HANDOFF')) \
                 FROM revisions WHERE world_id=? AND pruned=0 ORDER BY seq DESC",
            )?;
            let rows = st.query_map(params![w], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, bool>(2)?)))?;
            for (i, row) in rows.enumerate() {
                let (id, at, held) = row?;
                let by_count = l.keep_revisions.is_none_or(|n| i as u64 >= n.max(1));
                let by_age = l.keep_days.is_none_or(|d| at < now - (d.min(1 << 32) as i64) * 86_400);
                if by_count && by_age && !held && id != head {
                    plan.push(id);
                }
            }
        }

        let mut keep: HashSet<Hash> = HashSet::new();
        {
            let doomed: HashSet<&str> = plan.iter().map(String::as_str).collect();
            let mut st = self.db.prepare("SELECT id, root_hash FROM revisions WHERE pruned=0")?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
            for row in rows {
                let (id, root) = row?;
                if doomed.contains(id.as_str()) {
                    continue;
                }
                let root: Hash = root.try_into().map_err(|_| Error::Store(format!("bad root hash on {id}")))?;
                manifest::reachable(&self.cas, root, &mut keep)
                    .map_err(|e| Error::Store(format!("sweep aborted, {id} is unreadable: {e}")))?;
            }
            let mut st = self.db.prepare("SELECT DISTINCT hash FROM chunk_wal")?;
            let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            for h in rows {
                if let Ok(h) = Hash::try_from(h?.as_slice()) {
                    keep.insert(h);
                }
            }
        }

        let tx = self.db.transaction()?;
        for id in &plan {
            tx.execute("UPDATE revisions SET pruned=1 WHERE id=?", params![id])?;
        }
        tx.commit()?;
        rep.pruned = plan;

        let swept = self.cas.sweep(&keep, std::time::Duration::from_secs(grace_s));
        // heal even when the sweep failed midway, so usage never stays counted for blobs that are gone
        self.forget_missing_blobs()?;
        let (removed, bytes) = swept?;
        rep.blobs_removed = removed.len() as u64;
        rep.bytes_freed = bytes;
        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{next_mac, Entry};
    use crate::wal::Frame;
    use crate::lease::{CommitKind, Hw, Join, Role};
    use crate::manifest::{Key, Kind};

    fn gw() -> Gateway {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let k = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cas = Cas::open(std::env::temp_dir().join(format!("mcmesh-quota-{}-{k}", std::process::id()))).unwrap();
        let mut g = Gateway::open(Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.create_world("w", "w", "1.21.1", "neoforge").unwrap();
        g.add_member("w", "u-a", "alice", "dev-a", Role::Admin).unwrap();
        g.db().execute("UPDATE worlds SET owner_uuid='u-a' WHERE id='w'", []).unwrap();
        g
    }

    struct WalWriter {
        key: [u8; 32],
        prev: [u8; 32],
        seq: u64,
    }

    impl WalWriter {
        fn new(g: &crate::lease::Grant) -> Self {
            WalWriter { key: g.hmac_key, prev: [0; 32], seq: 0 }
        }
        fn frame(&mut self, op: &str, dim: &str, cx: i32, cz: i32, hash: Hash) -> Frame {
            let e = Entry { seq: self.seq, dim, kind: op, cx, cz, hash: &hash };
            let mac = next_mac(&self.key, &self.prev, &e);
            self.prev = mac;
            self.seq += 1;
            Frame { seq: e.seq, op: op.into(), dim: dim.into(), cx, cz, hash, mac: mac.to_vec() }
        }
    }

    fn missing(g: &Gateway, rev: &str) -> usize {
        let mut reach = HashSet::new();
        manifest::reachable(g.cas(), g.revision_root(rev).unwrap(), &mut reach).unwrap();
        reach.iter().filter(|h| !g.cas().has(h)).count()
    }

    const HW: Hw = Hw { tier: 2, score: 5.0, wants_host: true, takeover: false };

    fn host(g: &mut Gateway, now: u64) -> (crate::lease::Grant, WalWriter) {
        match g.join("w", "dev-a", HW, now).unwrap() {
            Join::Host(gr) => {
                let w = WalWriter::new(&gr);
                (gr, w)
            }
            other => panic!("expected host, got {other:?}"),
        }
    }

    /// Uploads one incompressible chunk and a barrier, as a host would before a commit.
    fn save(g: &mut Gateway, gr: &crate::lease::Grant, w: &mut WalWriter, cx: i32, salt: u8) -> Hash {
        let mut body = vec![0u8; 4096];
        let mut x = (cx as u32 as u64) << 8 | salt as u64 | 1 << 40;
        for b in body.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        let h = g.cas().put(&body).unwrap();
        g.tag_blob("w", &h).unwrap();
        let frames = vec![w.frame("put:region", "minecraft:overworld", cx, 0, h), w.frame("barrier", "", 0, 0, [0; 32])];
        g.wal_append(&gr.lease_id, gr.epoch, &frames).unwrap();
        h
    }

    #[test]
    fn world_count_limit_inherits_default_and_can_be_overridden() {
        let mut g = gw();
        g.add_member("w", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
        g.set_limits(Scope::User, "*", &Limits { world_count: Some(1), ..Default::default() }).unwrap();
        let hit = match g.create_world_for("dev-a", "second", "1.21.1", "neoforge") {
            Err(Error::Quota(h)) => h,
            other => panic!("expected quota, got {other:?}"),
        };
        assert_eq!(hit, QuotaHit { code: "QUOTA_WORLD_COUNT", limit: 1, used: 1 });
        let b1 = g.create_world_for("dev-b", "bobs", "1.21.1", "neoforge").unwrap();
        assert_eq!(g.owner_of(&b1).unwrap().as_deref(), Some("u-b"));
        assert!(matches!(g.create_world_for("dev-b", "bobs2", "1.21.1", "neoforge"), Err(Error::Quota(_))));
        g.set_limits(Scope::User, "u-a", &Limits { world_count: Some(3), ..Default::default() }).unwrap();
        g.create_world_for("dev-a", "second", "1.21.1", "neoforge").unwrap();
        assert_eq!(g.user_usage("u-a").unwrap().1, 2);
    }

    #[test]
    fn over_quota_refuses_autosave_but_never_the_final_commit() {
        let mut g = gw();
        let (gr, mut w) = host(&mut g, 0);
        save(&mut g, &gr, &mut w, 0, 0);
        let r1 = g.commit(&gr.lease_id, gr.epoch, &gr.base_rev, CommitKind::Autosave, false, 1).unwrap();
        let used = g.world_usage("w").unwrap();
        assert!(used >= 4000, "usage counts stored blob bytes, got {used}");

        g.set_limits(Scope::World, "w", &Limits { storage_bytes: Some(used), ..Default::default() }).unwrap();
        let h2 = save(&mut g, &gr, &mut w, 1, 0);
        match g.commit(&gr.lease_id, gr.epoch, &r1.id, CommitKind::Autosave, false, 2) {
            Err(Error::Quota(h)) => assert_eq!(h.code, "QUOTA_STORAGE_WORLD"),
            other => panic!("expected quota, got {other:?}"),
        }
        assert_eq!(g.head("w").unwrap(), r1.id, "refused commit must not move the head");

        let r2 = g.commit(&gr.lease_id, gr.epoch, &r1.id, CommitKind::Shutdown, true, 3).unwrap();
        let root = g.revision_root(&r2.id).unwrap();
        let key = Key { dim: "minecraft:overworld".into(), kind: Kind::Region, cx: 1, cz: 0 };
        assert_eq!(manifest::lookup(g.cas(), root, &key).unwrap(), Some(h2), "the refused autosave's data arrives with the final commit");

        assert!(matches!(g.join("w", "dev-a", HW, 10), Err(Error::Quota(_))), "over-quota idle world is not hostable");
        g.set_limits(Scope::World, "w", &Limits::default()).unwrap();
        g.set_limits(Scope::User, "u-a", &Limits { storage_bytes: Some(1), ..Default::default() }).unwrap();
        match g.join("w", "dev-a", HW, 11) {
            Err(Error::Quota(h)) => assert_eq!(h.code, "QUOTA_STORAGE_USER"),
            other => panic!("expected user quota, got {other:?}"),
        }
        g.set_limits(Scope::User, "u-a", &Limits::default()).unwrap();
        assert!(matches!(g.join("w", "dev-a", HW, 12).unwrap(), Join::Host(_)));
    }

    #[test]
    fn crash_recovery_ignores_quota() {
        let mut g = gw();
        let (gr, mut w) = host(&mut g, 0);
        g.set_limits(Scope::World, "w", &Limits { storage_bytes: Some(1), ..Default::default() }).unwrap();
        let h = save(&mut g, &gr, &mut w, 5, 0);
        g.tick(crate::lease::EXPIRY_MS + 1).unwrap();
        let head = g.head("w").unwrap();
        assert_ne!(head, gr.base_rev, "recovery made a revision");
        let key = Key { dim: "minecraft:overworld".into(), kind: Kind::Region, cx: 5, cz: 0 };
        assert_eq!(manifest::lookup(g.cas(), g.revision_root(&head).unwrap(), &key).unwrap(), Some(h));
    }

    #[test]
    fn uploads_stop_at_twice_the_limit_plus_headroom_not_at_the_limit() {
        let mut g = gw();
        let (gr, mut w) = host(&mut g, 0);
        save(&mut g, &gr, &mut w, 0, 1);
        g.commit(&gr.lease_id, gr.epoch, &gr.base_rev, CommitKind::Autosave, false, 1).unwrap();
        let used = g.world_usage("w").unwrap();
        assert!(used > 0);
        g.set_limits(Scope::World, "w", &Limits { storage_bytes: Some(used / 2), ..Default::default() }).unwrap();
        assert!(matches!(g.check_storage("w"), Err(Error::Quota(_))), "over the limit: autosaves are refused");
        g.check_upload_headroom("w").unwrap();
        // a limit of zero and 300 MiB of usage is past the 256 MiB headroom
        g.db().execute("UPDATE blob_world SET size=size+?", params![300i64 << 20]).unwrap();
        g.set_limits(Scope::World, "w", &Limits { storage_bytes: Some(0), ..Default::default() }).unwrap();
        match g.check_upload_headroom("w") {
            Err(Error::Quota(h)) => assert_eq!(h.code, "QUOTA_STORAGE_WORLD"),
            other => panic!("expected a quota refusal, got {other:?}"),
        }
    }

    #[test]
    fn month_meter_names_follow_the_utc_calendar() {
        assert_eq!(month_meter(0), "relay_month_197001");
        assert_eq!(month_meter(951_782_400), "relay_month_200002");
        assert_eq!(month_meter(1_709_164_800), "relay_month_202402", "2024-02-29 00:00 UTC");
        assert_eq!(month_meter(1_709_251_199), "relay_month_202402");
        assert_eq!(month_meter(1_709_251_200), "relay_month_202403", "2024-03-01 00:00 UTC");
        assert_eq!(month_meter(1_700_000_000), "relay_month_202311");
        assert_eq!(month_meter(1_735_689_599), "relay_month_202412");
        assert_eq!(month_meter(1_735_689_600), "relay_month_202501");
    }

    #[test]
    fn guests_are_turned_away_at_the_cap_and_when_the_month_budget_is_spent() {
        let mut g = gw();
        g.ops_init().unwrap();
        g.guest_admission("w", 1_000, 0).unwrap();
        g.set_limits(Scope::World, "w", &Limits { max_guests: Some(2), relay_bytes_month: Some(1_000), ..Default::default() }).unwrap();
        g.guest_admission("w", 1, 0).unwrap();
        match g.guest_admission("w", 2, 0) {
            Err(Error::Quota(h)) => assert_eq!((h.code, h.limit, h.used), ("QUOTA_GUESTS", 2, 2)),
            other => panic!("expected the guest cap, got {other:?}"),
        }
        let now = 1_700_000_000;
        g.meter("w", &month_meter(now), 999);
        g.guest_admission("w", 0, now).unwrap();
        g.meter("w", &month_meter(now), 1);
        match g.guest_admission("w", 0, now) {
            Err(Error::Quota(h)) => assert_eq!((h.code, h.limit, h.used), ("QUOTA_RELAY_MONTH", 1_000, 1_000)),
            other => panic!("expected the bandwidth cap, got {other:?}"),
        }
        g.guest_admission("w", 0, now + 40 * 86_400).unwrap();
        g.set_limits(Scope::World, "*", &Limits { max_guests: Some(0), ..Default::default() }).unwrap();
        g.set_limits(Scope::World, "w", &Limits::default()).unwrap();
        assert!(g.guest_admission("w", 0, now).is_err(), "unset fields inherit the default row");
    }

    #[test]
    fn usage_rows_of_vanished_blobs_are_dropped_on_the_next_sweep() {
        let mut g = gw();
        let (gr, mut w) = host(&mut g, 0);
        let b = save(&mut g, &gr, &mut w, 0, 1);
        g.commit(&gr.lease_id, gr.epoch, &gr.base_rev, CommitKind::Autosave, false, 1).unwrap();
        let used = g.world_usage("w").unwrap();
        assert!(used > 0);
        let x = crate::cas::hex(&b);
        std::fs::remove_file(g.cas().root().join(&x[0..2]).join(&x[2..4]).join(&x)).unwrap();
        assert_eq!(g.world_usage("w").unwrap(), used, "rows still count the vanished blob");
        g.retention_sweep(0).unwrap();
        assert!(g.world_usage("w").unwrap() < used);
        assert!(!g.quotas_configured().unwrap());
        g.set_limits(Scope::World, "*", &Limits { keep_revisions: Some(5), ..Default::default() }).unwrap();
        assert!(g.quotas_configured().unwrap());
    }

    #[test]
    fn retention_prunes_old_revisions_and_frees_their_blobs() {
        let mut g = gw();
        let (gr, mut w) = host(&mut g, 0);
        let mut base = gr.base_rev.clone();
        let (mut revs, mut blobs) = (Vec::new(), Vec::new());
        for i in 0..5u8 {
            blobs.push(save(&mut g, &gr, &mut w, 0, i));
            let r = g.commit(&gr.lease_id, gr.epoch, &base, CommitKind::Autosave, false, i as u64).unwrap();
            base = r.id.clone();
            revs.push(r.id);
        }
        g.db().execute("UPDATE revisions SET pinned=1 WHERE id=?", params![revs[1]]).unwrap();
        let before = g.world_usage("w").unwrap();
        // an uploaded blob that is only in the WAL so far
        let pending = save(&mut g, &gr, &mut w, 9, 0);

        assert!(g.retention_sweep(0).unwrap().pruned.is_empty(), "no policy, no pruning");
        assert!(blobs.iter().all(|b| g.cas().has(b)));

        g.set_limits(Scope::World, "*", &Limits { keep_revisions: Some(2), ..Default::default() }).unwrap();
        let rep = g.retention_sweep(3600).unwrap();
        assert_eq!(rep.blobs_removed, 0, "fresh blobs are inside the grace period");
        // the lease base R_0000 is held by the live lease; revs[1] is pinned
        assert_eq!(rep.pruned, vec![revs[2].clone(), revs[0].clone()]);

        let rep = g.retention_sweep(0).unwrap();
        assert!(rep.pruned.is_empty());
        assert!(!g.cas().has(&blobs[0]) && !g.cas().has(&blobs[2]), "content only pruned revisions used is gone");
        assert!(g.cas().has(&blobs[1]) && g.cas().has(&blobs[3]) && g.cas().has(&blobs[4]), "pinned and newest stay");
        assert!(g.cas().has(&pending), "a blob named by a WAL frame stays");
        assert!(rep.bytes_freed > 0 && g.world_usage("w").unwrap() < before + 4096);

        assert!(matches!(g.revision_root(&revs[0]), Err(Error::Pruned)));
        for r in [&revs[1], &revs[3], &revs[4]] {
            assert_eq!(missing(&g, r), 0, "{r} lost a blob");
        }
        let scrub = g.scrub(g.cas().root()).unwrap();
        assert!(scrub.ok(), "pruned revisions keep the chain intact: {scrub:?}");

        // the pending WAL still commits after the sweep
        let r = g.commit(&gr.lease_id, gr.epoch, &base, CommitKind::Shutdown, true, 99).unwrap();
        assert_eq!(missing(&g, &r.id), 0);
    }

    #[test]
    fn keep_days_and_keep_revisions_must_both_agree() {
        let mut g = gw();
        let (gr, mut w) = host(&mut g, 0);
        let mut base = gr.base_rev.clone();
        let mut revs = Vec::new();
        for i in 0..4u8 {
            save(&mut g, &gr, &mut w, 0, i);
            let r = g.commit(&gr.lease_id, gr.epoch, &base, CommitKind::Autosave, false, i as u64).unwrap();
            base = r.id.clone();
            revs.push(r.id);
        }
        g.commit(&gr.lease_id, gr.epoch, &base, CommitKind::Shutdown, true, 9).unwrap();
        g.set_limits(Scope::World, "w", &Limits { keep_revisions: Some(1), keep_days: Some(7), ..Default::default() }).unwrap();
        assert!(g.retention_sweep(0).unwrap().pruned.is_empty(), "everything is younger than 7 days");
        g.db().execute("UPDATE revisions SET created_at=created_at-30*86400 WHERE id IN(?,?)", params![revs[0], revs[1]]).unwrap();
        let mut pruned = g.retention_sweep(0).unwrap().pruned;
        pruned.sort();
        assert_eq!(pruned, vec![revs[0].clone(), revs[1].clone()]);
    }
}
