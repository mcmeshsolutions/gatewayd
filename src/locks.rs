//! Named locks for mods, fenced by the host epoch. Only the live host of a world can take one. A lock taken under an older epoch
//! is void: a new host never waits for a lock that an old host died holding. The token only ever grows per lock, so a service that
//! receives work from two hosts can refuse the one with the smaller token.

use crate::lease::{wall_s, Error, Gateway};
use rusqlite::params;

pub const MAX_TTL_S: i64 = 3600;

#[derive(Debug, PartialEq, Eq)]
pub enum Taken {
    Granted { token: i64 },
    HeldBy { owner: String, until: i64 },
}

impl Gateway {
    pub(crate) fn locks_init(&self) -> rusqlite::Result<()> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS world_locks(
               world_id TEXT NOT NULL, name TEXT NOT NULL, owner TEXT NOT NULL, epoch INTEGER NOT NULL, token INTEGER NOT NULL, expires_at INTEGER NOT NULL,
               PRIMARY KEY(world_id, name)) WITHOUT ROWID;",
        )
    }

    /// Takes the lock for `owner`, or renews it when `owner` already has it under this epoch. `now` is wall seconds.
    pub fn lock_take(&self, world: &str, name: &str, owner: &str, epoch: i64, ttl_s: i64, now: i64) -> Result<Taken, Error> {
        let row: Option<(String, i64, i64, i64)> = self
            .db
            .query_row("SELECT owner, epoch, token, expires_at FROM world_locks WHERE world_id=? AND name=?", params![world, name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .ok();
        let until = now + ttl_s.clamp(1, MAX_TTL_S);
        let token = match row {
            Some((o, e, t, exp)) if e == epoch && exp > now && o == owner => {
                self.db.execute("UPDATE world_locks SET expires_at=? WHERE world_id=? AND name=?", params![until, world, name]).map_err(Error::Db)?;
                return Ok(Taken::Granted { token: t });
            }
            Some((o, e, _, exp)) if e == epoch && exp > now => return Ok(Taken::HeldBy { owner: o, until: exp }),
            Some((_, _, t, _)) => t + 1,
            None => 1,
        };
        self.db
            .execute(
                "INSERT INTO world_locks(world_id, name, owner, epoch, token, expires_at) VALUES(?,?,?,?,?,?) \
                 ON CONFLICT(world_id, name) DO UPDATE SET owner=excluded.owner, epoch=excluded.epoch, token=excluded.token, expires_at=excluded.expires_at",
                params![world, name, owner, epoch, token, until],
            )
            .map_err(Error::Db)?;
        Ok(Taken::Granted { token })
    }

    /// Frees the lock if `owner` holds it under this epoch. Returns whether anything was released.
    pub fn lock_release(&self, world: &str, name: &str, owner: &str, epoch: i64) -> Result<bool, Error> {
        let n = self
            .db
            .execute("UPDATE world_locks SET expires_at=0 WHERE world_id=? AND name=? AND owner=? AND epoch=? AND expires_at>?", params![world, name, owner, epoch, wall_s()])
            .map_err(Error::Db)?;
        Ok(n > 0)
    }

    pub fn locks_list(&self, world: &str, now: i64) -> Result<Vec<(String, String, i64, i64, i64)>, Error> {
        let mut st = self
            .db
            .prepare("SELECT name, owner, epoch, token, expires_at FROM world_locks WHERE world_id=? AND expires_at>? ORDER BY name")
            .map_err(Error::Db)?;
        let rows = st.query_map(params![world, now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).map_err(Error::Db)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Error::Db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gw() -> Gateway {
        let cas = crate::cas::Cas::open(std::env::temp_dir().join(format!("mcmesh-locks-{}", std::process::id()))).unwrap();
        let g = Gateway::open(rusqlite::Connection::open_in_memory().unwrap(), cas, 0).unwrap();
        g.locks_init().unwrap();
        g
    }

    #[test]
    fn one_owner_at_a_time_and_renewal_keeps_the_token() {
        let g = gw();
        assert_eq!(g.lock_take("w", "quarry", "modA", 1, 60, 100).unwrap(), Taken::Granted { token: 1 });
        assert_eq!(g.lock_take("w", "quarry", "modB", 1, 60, 110).unwrap(), Taken::HeldBy { owner: "modA".into(), until: 160 });
        assert_eq!(g.lock_take("w", "quarry", "modA", 1, 60, 120).unwrap(), Taken::Granted { token: 1 }, "renewal");
        assert_eq!(g.lock_take("w", "quarry", "modB", 1, 60, 170).unwrap(), Taken::HeldBy { owner: "modA".into(), until: 180 }, "renewed to 180");
        assert_eq!(g.lock_take("w", "quarry", "modB", 1, 60, 181).unwrap(), Taken::Granted { token: 2 }, "after expiry the token grows");
    }

    #[test]
    fn a_lock_from_an_older_epoch_is_void_and_the_token_still_grows() {
        let g = gw();
        assert_eq!(g.lock_take("w", "l", "modA", 1, 3600, 100).unwrap(), Taken::Granted { token: 1 });
        assert_eq!(g.lock_take("w", "l", "modA", 2, 60, 101).unwrap(), Taken::Granted { token: 2 }, "the new host does not wait for the dead one");
        assert_eq!(g.lock_take("w", "other", "modA", 2, 60, 101).unwrap(), Taken::Granted { token: 1 }, "tokens are per lock");
    }

    #[test]
    fn release_only_by_the_owner_under_the_same_epoch() {
        let g = gw();
        g.lock_take("w", "l", "modA", 1, 3600, wall_s()).unwrap();
        assert!(!g.lock_release("w", "l", "modB", 1).unwrap());
        assert!(!g.lock_release("w", "l", "modA", 2).unwrap());
        assert!(g.lock_release("w", "l", "modA", 1).unwrap());
        assert_eq!(g.lock_take("w", "l", "modB", 1, 60, wall_s()).unwrap(), Taken::Granted { token: 2 });
    }
}
