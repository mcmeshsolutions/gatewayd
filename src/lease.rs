use crate::cas::{Cas, Hash};
use crate::manifest::{self, Change};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

pub const HEARTBEAT_MS: u64 = 15_000;
pub const EXPIRY_MS: u64 = 45_000;
pub const FENCE_MS: u64 = 35_000;
pub const BOOT_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MIN_HOLD_MS: u64 = 180_000;

/// How long a host keeps the world before a stronger machine may take it; MCMESH_MIN_HOLD_S overrides.
fn min_hold_ms() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("MCMESH_MIN_HOLD_S").ok().and_then(|v| v.parse::<u64>().ok()).map_or(DEFAULT_MIN_HOLD_MS, |s| s * 1000)
    })
}
const SCORE_MARGIN: f64 = 1.3;

#[derive(Debug)]
pub enum Error {
    Db(rusqlite::Error),
    Rand,
    NotMember,
    NoSuchWorld,
    StaleEpoch,
    HeadMoved,
    BadFrame(&'static str),
    BadMac,
    MissingBlob,
    Rejected(String),
    PackMismatch,
    Store(String),
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Store(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    HostEligible,
    ClientOnly,
}

impl Role {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "ADMIN",
            Role::HostEligible => "HOST_ELIGIBLE",
            Role::ClientOnly => "CLIENT_ONLY",
        }
    }
    fn parse(s: &str) -> Role {
        match s {
            "ADMIN" => Role::Admin,
            "HOST_ELIGIBLE" => Role::HostEligible,
            _ => Role::ClientOnly,
        }
    }
    fn can_host(self) -> bool {
        self != Role::ClientOnly
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Hw {
    pub tier: u8,
    pub score: f64,
    pub wants_host: bool,
    /// only an explicit take-over request may pull a healthy lease away from its host
    pub takeover: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    pub lease_id: String,
    pub world_id: String,
    pub epoch: i64,
    pub base_rev: String,
    pub hmac_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub enum Join {
    Host(Grant),
    Guest { epoch: i64, host_device: String },
    Wait { phase: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Directive {
    MigratePrepare { target_device: Option<String>, deadline_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitKind {
    Autosave,
    Migrate,
    Shutdown,
}

impl CommitKind {
    fn as_str(self) -> &'static str {
        match self {
            CommitKind::Autosave => "AUTOSAVE",
            CommitKind::Migrate => "MIGRATE",
            CommitKind::Shutdown => "SHUTDOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Revision {
    pub id: String,
    pub parent: String,
    pub seq: i64,
}

struct Cand {
    tier: u8,
    score: f64,
    seen: u64,
}

struct Timer {
    last_hb: u64,
    granted: u64,
    score: f64,
}

/// All timers use an injected monotonic clock in ms, never wall time.
pub struct Gateway {
    pub(crate) db: Connection,
    pub(crate) cas: Cas,
    cands: HashMap<(String, String), Cand>,
    timers: HashMap<String, Timer>,
    directives: HashMap<String, Vec<Directive>>,
    failed: HashMap<String, HashSet<String>>,
}

fn unix_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Idle time after which a login token stops working (MCMESH_SESSION_TTL_DAYS, default 30).
fn session_ttl_s() -> i64 {
    static TTL: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *TTL.get_or_init(|| std::env::var("MCMESH_SESSION_TTL_DAYS").ok().and_then(|v| v.parse::<i64>().ok()).unwrap_or(30) * 86_400)
}

fn token_hash(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes()).into()
}

pub(crate) fn wall_s() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl Gateway {
    pub fn open(db: Connection, cas: Cas, now: u64) -> Result<Self> {
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.execute_batch(include_str!("schema.sql"))?;
        // older databases lack the activity stamp; existing sessions start their expiry clock now
        let _ = db.execute("ALTER TABLE sessions ADD COLUMN last_used INTEGER", []);
        let _ = db.execute("ALTER TABLE worlds ADD COLUMN mods_json TEXT", []);
        let _ = db.execute("ALTER TABLE worlds ADD COLUMN pack_id TEXT NOT NULL DEFAULT 'default'", []);
        db.execute("UPDATE sessions SET last_used=? WHERE last_used IS NULL", params![unix_s()])?;
        db.execute("DELETE FROM sessions WHERE last_used>0 AND last_used<?", params![unix_s() - session_ttl_s()])?;
        let mut g = Gateway {
            db,
            cas,
            cands: HashMap::new(),
            timers: HashMap::new(),
            directives: HashMap::new(),
            failed: HashMap::new(),
        };
        // restart: give every live lease a full TTL before judging it dead
        let live: Vec<(String, i64)> = {
            let mut st = g.db.prepare("SELECT id, tier FROM leases WHERE status IN('ACTIVE','HANDOFF')")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (id, _) in live {
            g.timers.insert(id, Timer { last_hb: now, granted: now, score: 0.0 });
        }
        Ok(g)
    }

    pub fn create_world(&mut self, id: &str, name: &str, mc: &str, loader: &str) -> Result<()> {
        let empty = manifest::empty_root(&self.cas)?;
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO worlds(id,name,mc_version,loader,created_at) VALUES(?,?,?,?,?)",
            params![id, name, mc, loader, wall_s()],
        )?;
        let rev = format!("{id}:R_0000");
        tx.execute(
            "INSERT INTO revisions(id,world_id,parent_id,root_hash,seq,kind,created_at) VALUES(?,?,NULL,?,0,'IMPORT',?)",
            params![rev, id, empty.as_slice(), wall_s()],
        )?;
        tx.execute("INSERT INTO refs(world_id,name,rev_id) VALUES(?, 'main', ?)", params![id, rev])?;
        tx.commit()?;
        Ok(())
    }

    pub fn pack_of(&self, world: &str) -> Result<String> {
        self.db
            .query_row("SELECT pack_id FROM worlds WHERE id=?", params![world], |r| r.get(0))
            .optional()?
            .ok_or(Error::NoSuchWorld)
    }

    pub fn set_pack(&mut self, world: &str, pack: &str) -> Result<()> {
        if self.db.execute("UPDATE worlds SET pack_id=? WHERE id=?", params![pack, world])? == 0 {
            return Err(Error::NoSuchWorld);
        }
        Ok(())
    }

    /// A caller may only touch worlds of the modpack it was built for.
    pub fn require_pack(&self, world: &str, pack: &str) -> Result<()> {
        if self.pack_of(world)? == pack { Ok(()) } else { Err(Error::PackMismatch) }
    }

    /// Creates a world with a generated id and makes the device's player its admin.
    pub fn create_world_for(&mut self, device: &str, name: &str, mc: &str, loader: &str) -> Result<String> {
        let mut seed = [0u8; 6];
        getrandom::getrandom(&mut seed).map_err(|_| Error::Rand)?;
        let id = format!("w-{}", seed.iter().map(|b| format!("{b:02x}")).collect::<String>());
        self.create_world(&id, name, mc, loader)?;
        self.db.execute(
            "INSERT INTO members(world_id,player_uuid,role) SELECT ?, player_uuid, 'ADMIN' FROM devices WHERE id=?",
            params![id, device],
        )?;
        Ok(id)
    }

    /// (id, name, mc_version, role, state, host player name)
    #[allow(clippy::type_complexity)]
    pub fn worlds_of(&self, device: &str) -> Result<Vec<(String, String, String, String, String, Option<String>)>> {
        let mut st = self.db.prepare(
            "SELECT w.id, w.name, w.mc_version, m.role, w.state, \
               (SELECT p.name FROM leases l JOIN devices hd ON hd.id=l.device_id JOIN players p ON p.uuid=hd.player_uuid \
                WHERE l.world_id=w.id AND l.status IN('ACTIVE','HANDOFF')) \
             FROM worlds w JOIN members m ON m.world_id=w.id \
             JOIN devices d ON d.player_uuid=m.player_uuid WHERE d.id=? AND d.revoked=0 ORDER BY w.created_at, w.id",
        )?;
        let rows = st.query_map(params![device], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Seconds until `device`, with this hardware, may take the world over from its current host. None when it never could.
    pub fn takeover_in(&self, world: &str, device: &str, tier: u8, score: f64, now: u64) -> Option<u64> {
        if !self.role(world, device).ok()?.can_host() {
            return None;
        }
        let (state, _, _) = self.world_state(world).ok()?;
        if state != "LOCKED" {
            return None;
        }
        let (lid, dev, _, cur_tier) = self.active_lease(world).ok()??;
        let t = self.timers.get(&lid)?;
        let c = Cand { tier, score, seen: now };
        if dev == device || !Self::better(&c, cur_tier, t.score) {
            return None;
        }
        Some(min_hold_ms().saturating_sub(now.saturating_sub(t.granted)).div_ceil(1000))
    }

    pub fn create_invite(&mut self, device: &str, world: &str, role: Role) -> Result<String> {
        if self.role(world, device)? != Role::Admin {
            return Err(Error::NotMember);
        }
        let mut raw = [0u8; 5];
        getrandom::getrandom(&mut raw).map_err(|_| Error::Rand)?;
        let code: String = raw.iter().map(|b| format!("{b:02x}")).collect::<String>().to_uppercase();
        self.db.execute(
            "INSERT INTO invites(code,world_id,role,created_at) VALUES(?,?,?,?)",
            params![code, world, role.as_str(), wall_s()],
        )?;
        Ok(code)
    }

    /// Single use. An existing membership is never downgraded.
    pub fn redeem_invite(&mut self, device: &str, code: &str) -> Result<String> {
        let tx = self.db.transaction()?;
        let (world, role): (String, String) = tx
            .query_row("SELECT world_id, role FROM invites WHERE code=?", params![code.to_uppercase()], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .ok_or(Error::NoSuchWorld)?;
        tx.execute("DELETE FROM invites WHERE code=?", params![code.to_uppercase()])?;
        tx.execute(
            "INSERT OR IGNORE INTO members(world_id,player_uuid,role) SELECT ?, player_uuid, ? FROM devices WHERE id=?",
            params![world, role, device],
        )?;
        tx.commit()?;
        Ok(world)
    }

    pub fn add_member(&mut self, world: &str, uuid: &str, name: &str, device: &str, role: Role) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO players(uuid,name,created_at) VALUES(?,?,?)",
            params![uuid, name, wall_s()],
        )?;
        tx.execute("INSERT OR IGNORE INTO devices(id,player_uuid) VALUES(?,?)", params![device, uuid])?;
        tx.execute(
            "INSERT OR REPLACE INTO members(world_id,player_uuid,role) VALUES(?,?,?)",
            params![world, uuid, role.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn role(&self, world: &str, device: &str) -> Result<Role> {
        let r: Option<String> = self
            .db
            .query_row(
                "SELECT m.role FROM devices d JOIN members m ON m.player_uuid=d.player_uuid \
                 WHERE d.id=? AND m.world_id=? AND d.revoked=0",
                params![device, world],
                |r| r.get(0),
            )
            .optional()?;
        r.map(|s| Role::parse(&s)).ok_or(Error::NotMember)
    }

    pub(crate) fn world_state(&self, world: &str) -> Result<(String, Option<String>, i64)> {
        self.db
            .query_row("SELECT state, phase, epoch FROM worlds WHERE id=?", params![world], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?
            .ok_or(Error::NoSuchWorld)
    }

    fn active_lease(&self, world: &str) -> Result<Option<(String, String, i64, i64)>> {
        Ok(self
            .db
            .query_row(
                "SELECT id, device_id, epoch, tier FROM leases WHERE world_id=? AND status IN('ACTIVE','HANDOFF')",
                params![world],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?)
    }

    pub(crate) fn head(&self, world: &str) -> Result<String> {
        Ok(self.db.query_row(
            "SELECT rev_id FROM refs WHERE world_id=? AND name='main'",
            params![world],
            |r| r.get(0),
        )?)
    }

    fn set_state(&self, world: &str, state: &str, phase: Option<&str>) -> Result<()> {
        self.db.execute("UPDATE worlds SET state=?, phase=? WHERE id=?", params![state, phase, world])?;
        Ok(())
    }

    fn grant(&mut self, world: &str, device: &str, tier: u8, score: f64, now: u64) -> Result<Grant> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| Error::Rand)?;
        let base = self.head(world)?;
        let tx = self.db.transaction()?;
        tx.execute("UPDATE worlds SET epoch=epoch+1 WHERE id=?", params![world])?;
        let epoch: i64 = tx.query_row("SELECT epoch FROM worlds WHERE id=?", params![world], |r| r.get(0))?;
        let id = format!("ls_{world}_{epoch}");
        tx.execute(
            "INSERT INTO leases(id,world_id,device_id,epoch,ref_name,base_rev,tier,hmac_key,status,granted_at) \
             VALUES(?,?,?,?, 'main', ?,?,?, 'ACTIVE', ?)",
            params![id, world, device, epoch, base, tier, key.as_slice(), wall_s()],
        )?;
        tx.commit()?;
        self.timers.insert(id.clone(), Timer { last_hb: now, granted: now, score });
        Ok(Grant { lease_id: id, world_id: world.into(), epoch, base_rev: base, hmac_key: key })
    }

    fn end_lease(&mut self, lease: &str, status: &str, reason: &str) -> Result<()> {
        self.db.execute(
            "UPDATE leases SET status=?, end_reason=? WHERE id=? AND status IN('ACTIVE','HANDOFF')",
            params![status, reason, lease],
        )?;
        self.timers.remove(lease);
        self.directives.remove(lease);
        Ok(())
    }

    fn grant_view(&self, lease: &str, world: &str) -> Result<Grant> {
        Ok(self.db.query_row(
            "SELECT id, epoch, base_rev, hmac_key FROM leases WHERE id=?",
            params![lease],
            |r| {
                let k: Vec<u8> = r.get(3)?;
                let mut hk = [0u8; 32];
                hk.copy_from_slice(&k);
                Ok(Grant { lease_id: r.get(0)?, world_id: world.into(), epoch: r.get(1)?, base_rev: r.get(2)?, hmac_key: hk })
            },
        )?)
    }

    fn better(c: &Cand, cur_tier: i64, cur_score: f64) -> bool {
        (c.tier as i64) < cur_tier || c.score >= cur_score * SCORE_MARGIN
    }

    /// Picks the best fresh candidate and grants it a lease in MIGRATING/BOOTING, else IDLE.
    fn elect(&mut self, world: &str, exclude: &str, now: u64) -> Result<()> {
        let failed = self.failed.get(world).cloned().unwrap_or_default();
        let best = self
            .cands
            .iter()
            .filter(|((w, d), c)| {
                w == world && d != exclude && !failed.contains(d) && now.saturating_sub(c.seen) <= EXPIRY_MS
            })
            .min_by(|a, b| {
                a.1.tier
                    .cmp(&b.1.tier)
                    .then(b.1.score.partial_cmp(&a.1.score).unwrap_or(std::cmp::Ordering::Equal))
            })
            .map(|((_, d), c)| (d.clone(), c.tier, c.score));
        match best {
            Some((dev, tier, score)) => {
                self.grant(world, &dev, tier, score, now)?;
                self.set_state(world, "MIGRATING", Some("BOOTING"))
            }
            None => self.set_state(world, "IDLE", None),
        }
    }

    pub fn join(&mut self, world: &str, device: &str, hw: Hw, now: u64) -> Result<Join> {
        let role = self.role(world, device)?;
        let eligible = role.can_host() && hw.wants_host;
        let key = (world.to_string(), device.to_string());
        if eligible {
            self.cands.insert(key.clone(), Cand { tier: hw.tier, score: hw.score, seen: now });
        } else {
            self.cands.remove(&key);
        }
        let (state, phase, _) = self.world_state(world)?;
        let lease = self.active_lease(world)?;

        if let Some((lid, dev, _, _)) = &lease {
            if dev == device {
                return Ok(Join::Host(self.grant_view(lid, world)?));
            }
        }
        match state.as_str() {
            "IDLE" => {
                if !eligible {
                    return Ok(Join::Wait { phase: "NO_HOST".into() });
                }
                let g = self.grant(world, device, hw.tier, hw.score, now)?;
                self.set_state(world, "LOCKED", None)?;
                self.failed.remove(world);
                Ok(Join::Host(g))
            }
            "LOCKED" => {
                let (lid, dev, epoch, tier) = lease.expect("LOCKED world has a live lease");
                let t = &self.timers[&lid];
                let held = now.saturating_sub(t.granted);
                let cand = &self.cands.get(&key);
                if let Some(c) = cand {
                    if hw.takeover && held >= min_hold_ms() && Self::better(c, tier, t.score) {
                        self.set_state(world, "MIGRATING", Some("PREPARING"))?;
                        self.db.execute("UPDATE leases SET status='HANDOFF' WHERE id=?", params![lid])?;
                        self.directives.entry(lid).or_default().push(Directive::MigratePrepare {
                            target_device: Some(device.to_string()),
                            deadline_ms: 20_000,
                        });
                    }
                }
                Ok(Join::Guest { epoch, host_device: dev })
            }
            _ => Ok(Join::Wait { phase: phase.unwrap_or_default() }),
        }
    }

    pub fn lease_of_world(&self, world: &str) -> Option<String> {
        self.active_lease(world).ok().flatten().map(|l| l.0)
    }

    pub fn heartbeat(&mut self, lease: &str, epoch: i64, now: u64) -> Result<Vec<Directive>> {
        self.require_live(lease, epoch)?;
        if let Some(t) = self.timers.get_mut(lease) {
            t.last_hb = now;
        }
        Ok(self.directives.remove(lease).unwrap_or_default())
    }

    pub(crate) fn require_live(&self, lease: &str, epoch: i64) -> Result<(String, String)> {
        self.db
            .query_row(
                "SELECT world_id, device_id FROM leases WHERE id=? AND epoch=? AND status IN('ACTIVE','HANDOFF')",
                params![lease, epoch],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::StaleEpoch)
    }

    pub fn revision_world(&self, rev: &str) -> Result<Option<String>> {
        Ok(self.db.query_row("SELECT world_id FROM revisions WHERE id=?", params![rev], |r| r.get(0)).optional()?)
    }

    pub fn revision_root(&self, rev: &str) -> Result<Hash> {
        let b: Vec<u8> = self.db.query_row("SELECT root_hash FROM revisions WHERE id=?", params![rev], |r| r.get(0))?;
        b.try_into().map_err(|_| Error::Store("bad root hash length".into()))
    }

    /// Applies `changes` to the head and advances `main`. The caller has already checked the lease.
    fn new_revision(&mut self, world: &str, lease: &str, kind: &str, changes: &[Change]) -> Result<Revision> {
        let head = self.head(world)?;
        let base = self.revision_root(&head)?;
        let root = manifest::apply(&self.cas, Some(base), changes)?;
        if let Err(why) = crate::sanity::check(&self.cas, base, root) {
            return Err(Error::Rejected(why));
        }
        let tx = self.db.transaction()?;
        let seq: i64 = tx.query_row("SELECT MAX(seq)+1 FROM revisions WHERE world_id=?", params![world], |r| r.get(0))?;
        let id = format!("{world}:R_{seq:04}");
        tx.execute(
            "INSERT INTO revisions(id,world_id,parent_id,root_hash,seq,kind,lease_id,created_at) VALUES(?,?,?,?,?,?,?,?)",
            params![id, world, head, root.as_slice(), seq, kind, lease, wall_s()],
        )?;
        tx.execute("UPDATE refs SET rev_id=? WHERE world_id=? AND name='main'", params![id, world])?;
        tx.commit()?;
        Ok(Revision { id, parent: head, seq })
    }

    /// Compare-and-swap on the ref head; the new root is built here from the lease's WAL up to its last barrier.
    /// With `last`, the lease ends and the world hands off or goes idle.
    pub fn commit(
        &mut self,
        lease: &str,
        epoch: i64,
        base_rev: &str,
        kind: CommitKind,
        last: bool,
        now: u64,
    ) -> Result<Revision> {
        let (world, device) = self.require_live(lease, epoch)?;
        if self.head(&world)? != base_rev {
            return Err(Error::HeadMoved);
        }
        let (changes, barrier) = self.wal_pending(lease)?;
        let rev = self.new_revision(&world, lease, kind.as_str(), &changes)?;
        self.wal_trim(lease, barrier, last)?;
        if let Some(t) = self.timers.get_mut(lease) {
            t.last_hb = now;
        }
        if last {
            let (state, _, _) = self.world_state(&world)?;
            self.end_lease(lease, "RELEASED", "final commit")?;
            if state == "MIGRATING" {
                self.set_state(&world, "MIGRATING", Some("ELECTING"))?;
                self.elect(&world, &device, now)?;
            } else {
                self.set_state(&world, "IDLE", None)?;
            }
        }
        Ok(rev)
    }

    /// Turns the dead host's WAL, up to its last barrier, into a RECOVERED revision. Anything after the barrier is dropped.
    fn promote(&mut self, lease: &str, world: &str) -> Result<()> {
        let (changes, barrier) = self.wal_pending(lease)?;
        if barrier.is_some() {
            match self.new_revision(world, lease, "RECOVERED", &changes) {
                Ok(_) => {}
                Err(Error::Rejected(why)) => {
                    eprintln!("sanity gate held back recovery of {world} from {lease}: {why}");
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
        self.wal_trim(lease, barrier, true)
    }

    /// Host is leaving. With guests present the world migrates; the host still sends its final commit.
    pub fn release(&mut self, lease: &str, epoch: i64, guests_present: bool) -> Result<()> {
        let (world, _) = self.require_live(lease, epoch)?;
        if guests_present {
            self.set_state(&world, "MIGRATING", Some("PREPARING"))?;
            self.db.execute("UPDATE leases SET status='HANDOFF' WHERE id=?", params![lease])?;
        }
        Ok(())
    }

    pub fn host_ready(&mut self, lease: &str, epoch: i64) -> Result<()> {
        let (world, _) = self.require_live(lease, epoch)?;
        self.set_state(&world, "LOCKED", None)?;
        self.failed.remove(&world);
        Ok(())
    }

    /// Expires silent hosts and stuck boots, then re-elects. Call once a second or so.
    pub fn tick(&mut self, now: u64) -> Result<()> {
        let live: Vec<(String, String, String, i64)> = {
            let mut st = self.db.prepare(
                "SELECT l.id, l.world_id, l.device_id, 0 FROM leases l WHERE l.status IN('ACTIVE','HANDOFF')",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (lid, world, device, _) in live {
            let Some(t) = self.timers.get(&lid) else { continue };
            let (state, phase, _) = self.world_state(&world)?;
            let booting = state == "MIGRATING" && phase.as_deref() == Some("BOOTING");
            let dead = if booting {
                now.saturating_sub(t.granted) > BOOT_TIMEOUT_MS
            } else {
                now.saturating_sub(t.last_hb) > EXPIRY_MS
            };
            if !dead {
                continue;
            }
            self.promote(&lid, &world)?;
            self.end_lease(&lid, "EXPIRED", if booting { "boot timeout" } else { "missed heartbeats" })?;
            self.failed.entry(world.clone()).or_default().insert(device.clone());
            self.set_state(&world, "MIGRATING", Some("RECOVERING"))?;
            self.elect(&world, &device, now)?;
        }
        Ok(())
    }

    pub fn add_token(&mut self, device: &str, token: &str) -> Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO sessions(token_hash, device_id, last_used) VALUES(?,?,?)",
            params![token_hash(token).as_slice(), device, unix_s()],
        )?;
        Ok(())
    }

    pub fn first_admin_device(&self, world: &str) -> Result<String> {
        Ok(self.db.query_row(
            "SELECT d.id FROM members m JOIN devices d ON d.player_uuid=m.player_uuid WHERE m.world_id=? AND m.role='ADMIN' AND d.revoked=0 LIMIT 1",
            params![world],
            |r| r.get(0),
        )?)
    }

    pub fn drop_token(&mut self, token: &str) -> Result<bool> {
        Ok(self.db.execute("DELETE FROM sessions WHERE token_hash=?", params![token_hash(token).as_slice()])? > 0)
    }

    pub fn device_for_token(&self, token: &str) -> Result<Option<String>> {
        let h = token_hash(token);
        let now = unix_s();
        let row: Option<(String, i64)> = self
            .db
            .query_row(
                "SELECT s.device_id, COALESCE(s.last_used,0) FROM sessions s JOIN devices d ON d.id=s.device_id \
                 WHERE s.token_hash=? AND d.revoked=0",
                params![h.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((dev, last)) = row else { return Ok(None) };
        if last < now - session_ttl_s() {
            return Ok(None);
        }
        if now - last > 3600 {
            self.db.execute("UPDATE sessions SET last_used=? WHERE token_hash=?", params![now, h.as_slice()])?;
        }
        Ok(Some(dev))
    }

    /// Checks a tunnel HELLO proof against every live session of the lease's device; the key is the stored token hash.
    pub fn verify_tunnel_proof(&self, lease: &str, epoch: i64, ts: u64, proof_hex: &str) -> bool {
        use hmac::{Hmac, Mac};
        let Some(dev) = self.lease_device(lease).ok().flatten() else { return false };
        let proof: Option<Vec<u8>> = (proof_hex.len() % 2 == 0)
            .then(|| (0..proof_hex.len()).step_by(2).map(|i| u8::from_str_radix(proof_hex.get(i..i + 2)?, 16).ok()).collect())
            .flatten();
        let Some(proof) = proof else { return false };
        let Ok(mut st) = self.db.prepare("SELECT s.token_hash FROM sessions s JOIN devices d ON d.id=s.device_id WHERE s.device_id=? AND d.revoked=0") else { return false };
        let Ok(rows) = st.query_map(params![dev], |r| r.get::<_, Vec<u8>>(0)) else { return false };
        let msg = crate::tunnel::proof_message(lease, epoch, ts);
        let ok = rows.flatten().any(|key| {
            let mut m = Hmac::<sha2::Sha256>::new_from_slice(&key).expect("hmac accepts any key length");
            m.update(msg.as_bytes());
            m.verify_slice(&proof).is_ok()
        });
        ok
    }

    /// One line per world for the operator: lease, host, newest revision and their ages.
    pub fn status(&self) -> Result<Vec<String>> {
        let now = wall_s();
        let mut st = self.db.prepare(
            "SELECT w.id, w.state,                (SELECT p.name FROM leases l JOIN devices d ON d.id=l.device_id JOIN players p ON p.uuid=d.player_uuid WHERE l.world_id=w.id AND l.status IN('ACTIVE','HANDOFF')),                (SELECT l.epoch FROM leases l WHERE l.world_id=w.id AND l.status IN('ACTIVE','HANDOFF')),                (SELECT l.granted_at FROM leases l WHERE l.world_id=w.id AND l.status IN('ACTIVE','HANDOFF')),                (SELECT r.id FROM revisions r WHERE r.world_id=w.id ORDER BY r.seq DESC LIMIT 1),                (SELECT r.created_at FROM revisions r WHERE r.world_id=w.id ORDER BY r.seq DESC LIMIT 1) \
             FROM worlds w ORDER BY w.created_at, w.id",
        )?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<i64>>(4)?, r.get::<_, Option<String>>(5)?, r.get::<_, Option<i64>>(6)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, state, host, epoch, granted, rev, rev_at) = r?;
            out.push(format!(
                "{id} {state} host={} epoch={} lease_age_s={} latest={} rev_age_s={}",
                host.as_deref().unwrap_or("-"),
                epoch.map_or("-".into(), |e| e.to_string()),
                granted.map_or("-".into(), |g| (now - g).to_string()),
                rev.as_deref().unwrap_or("-"),
                rev_at.map_or("-".into(), |t| (now - t).to_string()),
            ));
        }
        Ok(out)
    }

    pub fn lease_device(&self, lease: &str) -> Result<Option<String>> {
        Ok(self
            .db
            .query_row("SELECT device_id FROM leases WHERE id=?", params![lease], |r| r.get(0))
            .optional()?)
    }

    pub fn state(&self, world: &str) -> Result<(String, Option<String>)> {
        let (s, p, _) = self.world_state(world)?;
        Ok((s, p))
    }

    pub fn live_lease_count(&self, world: &str) -> Result<i64> {
        Ok(self.db.query_row(
            "SELECT COUNT(*) FROM leases WHERE world_id=? AND status IN('ACTIVE','HANDOFF')",
            params![world],
            |r| r.get(0),
        )?)
    }

    #[cfg(test)]
    pub(crate) fn db(&self) -> &Connection {
        &self.db
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn idle_sessions_expire() {
        let dir = std::env::temp_dir().join(format!("mcmesh-sess-{}", std::process::id()));
        let mut g = Gateway::open(Connection::open_in_memory().unwrap(), Cas::open(dir).unwrap(), 0).unwrap();
        g.create_world("w", "w", "1.21.1", "neoforge").unwrap();
        g.add_member("w", "u", "alice", "d", Role::HostEligible).unwrap();
        g.add_token("d", "tok").unwrap();
        assert_eq!(g.device_for_token("tok").unwrap().as_deref(), Some("d"));
        g.db.execute("UPDATE sessions SET last_used=?", params![unix_s() - session_ttl_s() - 10]).unwrap();
        assert_eq!(g.device_for_token("tok").unwrap(), None);
    }
}
