use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub type Hash = [u8; 32];

static TMP: AtomicU64 = AtomicU64::new(0);

pub fn sha256(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}

pub fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Blobs are named by the SHA-256 of their uncompressed bytes and stored zstd-compressed.
#[derive(Clone)]
pub struct Cas {
    root: PathBuf,
}

impl Cas {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Cas { root })
    }

    fn path(&self, h: &Hash) -> PathBuf {
        let x = hex(h);
        self.root.join(&x[0..2]).join(&x[2..4]).join(x)
    }

    pub fn has(&self, h: &Hash) -> bool {
        self.path(h).is_file()
    }

    /// On-disk (compressed) size of a blob.
    pub fn stored_len(&self, h: &Hash) -> io::Result<u64> {
        Ok(fs::metadata(self.path(h))?.len())
    }

    pub fn put(&self, raw: &[u8]) -> io::Result<Hash> {
        let h = sha256(raw);
        let p = self.path(&h);
        if p.is_file() {
            return Ok(h);
        }
        fs::create_dir_all(p.parent().expect("cas path has a parent"))?;
        let tmp = p.with_extension(format!("tmp{}.{}", std::process::id(), TMP.fetch_add(1, Ordering::Relaxed)));
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&zstd::encode_all(raw, 3)?)?;
        f.sync_all()?;
        fs::rename(&tmp, &p)?;
        Ok(h)
    }

    pub fn get(&self, h: &Hash) -> io::Result<Vec<u8>> {
        let raw = zstd::decode_all(fs::File::open(self.path(h))?)?;
        if sha256(&raw) != *h {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("cas blob {} is corrupt", hex(h))));
        }
        Ok(raw)
    }

    /// Deletes every blob not in `keep`; returns how many were removed.
    pub fn sweep(&self, keep: &HashSet<Hash>) -> io::Result<u64> {
        let mut removed = 0;
        for a in fs::read_dir(&self.root)? {
            for b in fs::read_dir(a?.path())? {
                for f in fs::read_dir(b?.path())? {
                    let f = f?;
                    let name = f.file_name();
                    let Some(h) = name.to_str().and_then(parse_hex) else { continue };
                    if !keep.contains(&h) {
                        fs::remove_file(f.path())?;
                        removed += 1;
                    }
                }
            }
        }
        Ok(removed)
    }
}
