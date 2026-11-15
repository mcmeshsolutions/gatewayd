use crate::cas::Hash;
use crate::chain::{self, Entry};
use crate::lease::{Error, Gateway, Result};
use crate::manifest::{Change, Key, Kind};
use rusqlite::{params, OptionalExtension};

pub struct Frame {
    pub seq: u64,
    pub op: String,
    pub dim: String,
    pub cx: i32,
    pub cz: i32,
    pub hash: Hash,
    pub mac: Vec<u8>,
}

fn kind_of(s: &str) -> Option<Kind> {
    match s {
        "region" => Some(Kind::Region),
        "entities" => Some(Kind::Entities),
        "poi" => Some(Kind::Poi),
        _ => None,
    }
}

/// `dim` doubles as the aux path for aux ops, so the MAC covers it either way.
fn change(op: &str, dim: &str, cx: i32, cz: i32, hash: Hash) -> Option<Option<Change>> {
    let key = |k: &str| kind_of(k).map(|kind| Key { dim: dim.into(), kind, cx, cz });
    Some(match op {
        "barrier" => None,
        "aux_put" => Some(Change::AuxPut(dim.into(), hash)),
        "aux_del" => Some(Change::AuxDelete(dim.into())),
        _ => match op.split_once(':')? {
            ("put", k) => Some(Change::Put(key(k)?, hash)),
            ("del", k) => Some(Change::Delete(key(k)?)),
            _ => return None,
        },
    })
}

const MAX_PENDING: i64 = 200_000;

impl Gateway {
    /// Verifies the HMAC chain frame by frame and stores them. All or nothing; returns the next expected seq.
    pub fn wal_append(&mut self, lease: &str, epoch: i64, frames: &[Frame]) -> Result<u64> {
        let (world, _) = self.require_live(lease, epoch)?;
        let key: Vec<u8> = self.db.query_row("SELECT hmac_key FROM leases WHERE id=?", params![lease], |r| r.get(0))?;
        // regions that a shard host owns are not the main host's to write
        let reserved = self.shard_reserved(&world)?;
        let away = self.shard_player_files(&world)?;
        self.wal_store(lease, &world, &key, frames, |f| {
            if crate::shard::frame_hits(&reserved, f) || crate::shard::player_file_of(&f.dim).is_some_and(|u| f.op.starts_with("aux_") && away.iter().any(|a| a == u)) {
                Err(Error::Rejected("SHARD_OWNED".into()))
            } else {
                Ok(())
            }
        })
    }

    /// The part of an append that every kind of lease shares: chain check, blob check, storage. `allow` can refuse a frame.
    pub(crate) fn wal_store(&mut self, lease: &str, world: &str, key: &[u8], frames: &[Frame], allow: impl Fn(&Frame) -> Result<()>) -> Result<u64> {
        let tx = self.db.transaction()?;
        let (mut next, prev): (i64, Vec<u8>) = tx
            .query_row("SELECT next_seq, prev_mac FROM wal_chain WHERE lease_id=?", params![lease], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .unwrap_or((0, vec![0; 32]));
        let mut prev: [u8; 32] = prev.try_into().map_err(|_| Error::BadFrame("chain state"))?;
        let pending: i64 = tx.query_row("SELECT COUNT(*) FROM chunk_wal WHERE lease_id=?", params![lease], |r| r.get(0))?;
        if pending + frames.len() as i64 > MAX_PENDING {
            return Err(Error::BadFrame("wal full, send a barrier and commit"));
        }
        for f in frames {
            if f.seq as i64 != next {
                return Err(Error::BadFrame("seq gap or replay"));
            }
            allow(f)?;
            let e = Entry { seq: f.seq, dim: &f.dim, kind: &f.op, cx: f.cx, cz: f.cz, hash: &f.hash };
            if !chain::verify_frame(key, &prev, &e, &f.mac) {
                return Err(Error::BadMac);
            }
            let ch = change(&f.op, &f.dim, f.cx, f.cz, f.hash).ok_or(Error::BadFrame("unknown op"))?;
            if matches!(ch, Some(Change::Put(..) | Change::AuxPut(..))) && !self.cas.has(&f.hash) {
                return Err(Error::MissingBlob);
            }
            // the host may have skipped the upload because another world already had the blob
            if matches!(ch, Some(Change::Put(..) | Change::AuxPut(..))) {
                tag(&tx, &self.cas, world, &f.hash)?;
            }
            tx.execute(
                "INSERT INTO chunk_wal(lease_id,seq,op,dim,cx,cz,hash) VALUES(?,?,?,?,?,?,?)",
                params![lease, f.seq as i64, f.op, f.dim, f.cx, f.cz, f.hash.as_slice()],
            )?;
            prev = chain::next_mac(key, &prev, &e);
            next += 1;
        }
        tx.execute(
            "INSERT INTO wal_chain(lease_id,next_seq,prev_mac) VALUES(?,?,?) \
             ON CONFLICT(lease_id) DO UPDATE SET next_seq=excluded.next_seq, prev_mac=excluded.prev_mac",
            params![lease, next, prev.as_slice()],
        )?;
        tx.commit()?;
        Ok(next as u64)
    }

    /// Changes up to and including the last barrier, plus that barrier's seq.
    pub(crate) fn wal_pending(&self, lease: &str) -> Result<(Vec<Change>, Option<i64>)> {
        let mut st = self
            .db
            .prepare("SELECT seq, op, dim, cx, cz, hash FROM chunk_wal WHERE lease_id=? ORDER BY seq")?;
        let rows = st.query_map(params![lease], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get(3)?, r.get(4)?, r.get::<_, Vec<u8>>(5)?))
        })?;
        let (mut all, mut cut, mut barrier) = (Vec::new(), 0, None);
        for row in rows {
            let (seq, op, dim, cx, cz, hash) = row?;
            let hash: Hash = hash.try_into().map_err(|_| Error::BadFrame("stored hash"))?;
            match change(&op, &dim, cx, cz, hash).ok_or(Error::BadFrame("stored op"))? {
                Some(c) => all.push(c),
                None => {
                    cut = all.len();
                    barrier = Some(seq);
                }
            }
        }
        all.truncate(cut);
        Ok((all, barrier))
    }

    pub(crate) fn wal_trim(&mut self, lease: &str, barrier: Option<i64>, all: bool) -> Result<()> {
        if all {
            self.db.execute("DELETE FROM chunk_wal WHERE lease_id=?", params![lease])?;
            self.db.execute("DELETE FROM wal_chain WHERE lease_id=?", params![lease])?;
        } else if let Some(b) = barrier {
            self.db.execute("DELETE FROM chunk_wal WHERE lease_id=? AND seq<=?", params![lease, b])?;
        }
        Ok(())
    }

    pub fn device_hosts(&self, device: &str) -> Result<bool> {
        Ok(self
            .db
            .query_row(
                "SELECT 1 FROM leases WHERE device_id=? AND status IN('ACTIVE','HANDOFF')",
                params![device],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn hosted_world(&self, device: &str) -> Result<Option<String>> {
        Ok(self
            .db
            .query_row(
                "SELECT world_id FROM leases WHERE device_id=? AND status IN('ACTIVE','HANDOFF')",
                params![device],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn tag_blob(&self, world: &str, hash: &[u8; 32]) -> Result<()> {
        Ok(tag(&self.db, &self.cas, world, hash)?)
    }

    pub fn blob_visible(&self, device: &str, hash: &[u8; 32]) -> Result<bool> {
        Ok(self
            .db
            .query_row(
                "SELECT 1 FROM blob_world b JOIN members m ON m.world_id=b.world_id JOIN devices d ON d.player_uuid=m.player_uuid \
                 WHERE b.hash=? AND d.id=? AND d.revoked=0",
                params![&hash[..], device],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn cas(&self) -> &crate::cas::Cas {
        &self.cas
    }
}

fn tag(db: &rusqlite::Connection, cas: &crate::cas::Cas, world: &str, hash: &Hash) -> rusqlite::Result<()> {
    db.execute(
        "INSERT OR IGNORE INTO blob_world(hash, world_id, size) VALUES(?,?,?)",
        params![&hash[..], world, cas.size(hash).unwrap_or(0) as i64],
    )?;
    Ok(())
}
