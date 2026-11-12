//! Operator tools that protect stored worlds: integrity scrub and incremental backup.
use crate::cas::{hex, Hash};
use crate::lease::{Gateway, Result};
use crate::manifest;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct ScrubReport {
    pub blobs: u64,
    pub corrupt: Vec<String>,
    pub revisions: u64,
    pub broken_revisions: Vec<String>,
    pub missing: Vec<String>,
    pub chain_breaks: Vec<String>,
}

impl ScrubReport {
    pub fn ok(&self) -> bool {
        self.corrupt.is_empty() && self.chain_breaks.is_empty() && self.broken_revisions.is_empty() && self.missing.is_empty()
    }
}

fn blob_files(cas: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for a in fs::read_dir(cas)? {
        let a = a?.path();
        if !a.is_dir() {
            continue;
        }
        for b in fs::read_dir(a)? {
            let b = b?.path();
            if !b.is_dir() {
                continue;
            }
            for f in fs::read_dir(b)? {
                let f = f?.path();
                let named = f.file_name().and_then(|n| n.to_str()).map(|n| n.len() == 64).unwrap_or(false);
                if named {
                    out.push(f);
                }
            }
        }
    }
    Ok(out)
}

impl Gateway {
    /// Re-hashes every stored blob, then checks that each revision's whole tree is present and readable.
    pub fn scrub(&self, cas_root: &Path) -> Result<ScrubReport> {
        let mut rep = ScrubReport::default();
        let mut bad: HashSet<String> = HashSet::new();
        for f in blob_files(cas_root)? {
            rep.blobs += 1;
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
            let Some(h) = crate::cas::parse_hex(&name) else { continue };
            if self.cas.get(&h).is_err() {
                bad.insert(name.clone());
                rep.corrupt.push(name);
            }
        }
        {
            let mut st = self.db.prepare("SELECT id, chain_hash FROM revisions ORDER BY world_id, seq")?;
            let rows: Vec<(String, Option<Vec<u8>>)> =
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?;
            let mut sealed_worlds: HashSet<String> = HashSet::new();
            for (id, stored) in rows {
                let world = id.split(":R_").next().unwrap_or_default().to_string();
                match stored {
                    None if sealed_worlds.contains(&world) => rep.chain_breaks.push(id),
                    None => {}
                    Some(s) => {
                        sealed_worlds.insert(world);
                        if crate::lease::chain_hash_of(&self.db, &id)?.as_slice() != s.as_slice() {
                            rep.chain_breaks.push(id);
                        }
                    }
                }
            }
        }
        let mut st = self.db.prepare("SELECT id, root_hash FROM revisions ORDER BY id")?;
        let revs: Vec<(String, Vec<u8>)> =
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<std::result::Result<_, _>>()?;
        let mut seen_missing: HashSet<Hash> = HashSet::new();
        for (id, root) in revs {
            rep.revisions += 1;
            let Ok(root): std::result::Result<Hash, _> = root.try_into() else {
                rep.broken_revisions.push(id);
                continue;
            };
            let mut reach = HashSet::new();
            if manifest::reachable(&self.cas, root, &mut reach).is_err() {
                rep.broken_revisions.push(id);
                continue;
            }
            for h in reach {
                if !self.cas.has(&h) && seen_missing.insert(h) {
                    rep.missing.push(hex(&h));
                }
            }
        }
        Ok(rep)
    }

    /// Copies the database (consistent snapshot) and any CAS blobs `dest` does not hold yet. Safe to repeat.
    pub fn backup(&self, cas_root: &Path, dest: &Path) -> Result<(u64, u64)> {
        fs::create_dir_all(dest)?;
        let db_out = dest.join("mcmesh.db");
        let tmp = dest.join("mcmesh.db.tmp");
        let _ = fs::remove_file(&tmp);
        self.db.execute("VACUUM INTO ?", [tmp.to_string_lossy().as_ref()])?;
        fs::rename(&tmp, &db_out)?;
        let (mut copied, mut skipped) = (0u64, 0u64);
        for f in blob_files(cas_root)? {
            let rel = f.strip_prefix(cas_root).expect("blob under cas root");
            let to = dest.join("cas").join(rel);
            if to.is_file() {
                skipped += 1;
                continue;
            }
            fs::create_dir_all(to.parent().expect("blob has parent"))?;
            let part = to.with_extension("part");
            fs::copy(&f, &part)?;
            fs::rename(&part, &to)?;
            copied += 1;
        }
        Ok((copied, skipped))
    }
}

