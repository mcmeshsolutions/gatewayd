//! Device keys and signed commits, byte layouts from PROTOCOL.md "Commit signature field and key registration".

use crate::lease::{Error, Gateway, Result};
use rusqlite::{params, OptionalExtension};

fn lp(out: &mut Vec<u8>, s: &str) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend(s.as_bytes());
}

pub fn commit_message(world: &str, lease: &str, epoch: i64, base_rev: &str, kind: &str, last: bool, barrier_seq: i64) -> Vec<u8> {
    let mut m = b"mcmesh-commit-v1\0".to_vec();
    lp(&mut m, world);
    lp(&mut m, lease);
    m.extend(epoch.to_be_bytes());
    lp(&mut m, base_rev);
    lp(&mut m, kind);
    m.push(last as u8);
    m.extend(barrier_seq.to_be_bytes());
    m
}

pub fn device_key_message(device: &str, pubkey: &[u8; 32]) -> Vec<u8> {
    let mut m = b"mcmesh-devkey-v1\0".to_vec();
    lp(&mut m, device);
    m.extend(pubkey);
    m
}

pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pubkey) else { return false };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
}

impl Gateway {
    pub fn device_key(&self, device: &str) -> Result<Option<[u8; 32]>> {
        let k: Option<Option<Vec<u8>>> = self.db.query_row("SELECT pubkey FROM devices WHERE id=?", params![device], |r| r.get(0)).optional()?;
        Ok(k.flatten().and_then(|v| v.try_into().ok()))
    }

    /// First key wins. The same key again is fine; a different key, or a key another device already uses, is refused.
    pub fn set_device_key(&mut self, device: &str, key: &[u8; 32]) -> Result<()> {
        if let Some(existing) = self.device_key(device)? {
            return if &existing == key { Ok(()) } else { Err(Error::DeviceKeySet) };
        }
        match self.db.execute("UPDATE devices SET pubkey=? WHERE id=? AND pubkey IS NULL", params![key.as_slice(), device]) {
            Ok(1) => Ok(()),
            Ok(_) => Err(Error::NotMember),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => Err(Error::DeviceKeySet),
            Err(e) => Err(e.into()),
        }
    }

    /// The seq of the last barrier frame in the lease's WAL, the point a commit covers; -1 when there is none.
    fn last_barrier(&self, lease: &str) -> Result<i64> {
        let seq: Option<i64> = self.db.query_row("SELECT MAX(seq) FROM chunk_wal WHERE lease_id=? AND op='barrier'", params![lease], |r| r.get(0))?;
        Ok(seq.unwrap_or(-1))
    }

    /// Checks a commit signature against the lease device's registered key and the gateway's own view of the WAL.
    pub(crate) fn verify_commit(&self, world: &str, lease: &str, device: &str, epoch: i64, base_rev: &str, kind: &str, last: bool, sig: &[u8; 64]) -> Result<[u8; 32]> {
        let key = self.device_key(device)?.ok_or(Error::NoDeviceKey)?;
        let msg = commit_message(world, lease, epoch, base_rev, kind, last, self.last_barrier(lease)?);
        if verify(&key, &msg, sig) {
            Ok(key)
        } else {
            Err(Error::BadSignature)
        }
    }

    pub(crate) fn store_signature(&self, rev: &str, signer: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
        self.db.execute("UPDATE revisions SET sig=?, signer=? WHERE id=?", params![sig.as_slice(), signer.as_slice(), rev])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn byte_layouts_match_the_reference_vectors_the_java_side_also_checks() {
        let c = commit_message("w1", "L1", 7, "r0", "AUTOSAVE", false, 5);
        assert_eq!(hx(&c), "6d636d6573682d636f6d6d69742d763100000000027731000000024c310000000000000007000000027230000000084155544f53415645000000000000000005");
        let f = commit_message("w1", "L1", 7, "r0", "SHUTDOWN", true, -1);
        assert_eq!(hx(&f), "6d636d6573682d636f6d6d69742d763100000000027731000000024c3100000000000000070000000272300000000853485554444f574e01ffffffffffffffff");
        let d = device_key_message("dev-1", &[7u8; 32]);
        assert_eq!(hx(&d), "6d636d6573682d6465766b65792d763100000000056465762d310707070707070707070707070707070707070707070707070707070707070707");
    }

    #[test]
    fn verify_accepts_only_the_exact_message_and_key() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let msg = commit_message("w", "l", 1, "r", "AUTOSAVE", false, 2);
        let sig = sk.sign(&msg).to_bytes();
        assert!(verify(&pk, &msg, &sig));
        assert!(!verify(&pk, &commit_message("w", "l", 1, "r", "AUTOSAVE", false, 3), &sig));
        assert!(!verify(&SigningKey::from_bytes(&[4u8; 32]).verifying_key().to_bytes(), &msg, &sig));
        assert!(!verify(&[0xffu8; 32], &msg, &sig), "an invalid key never verifies");
    }
}
