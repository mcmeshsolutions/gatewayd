//! Operator tools that protect stored worlds: integrity scrub and incremental backup.
use crate::cas::{hex, Cas, Hash};
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

#[derive(Debug, Default)]
pub struct RevScan {
    pub blobs: u64,
    pub missing: Vec<String>,
    pub corrupt: Vec<String>,
    pub chain_ok: bool,
}

impl RevScan {
    pub fn ok(&self) -> bool {
        self.missing.is_empty() && self.corrupt.is_empty() && self.chain_ok
    }
}

/// Same blob test as `scrub` (present, then re-hashed by `Cas::get`), limited to what one root references.
fn verify_tree(cas: &Cas, root: Hash) -> (u64, Vec<String>, Vec<String>) {
    let mut reach = HashSet::new();
    let mut unreadable = Vec::new();
    manifest::reachable_lenient(cas, root, &mut reach, &mut unreadable);
    let (mut missing, mut corrupt) = (Vec::new(), Vec::new());
    for h in &reach {
        if !cas.has(h) {
            missing.push(hex(h));
        } else if cas.get(h).is_err() || unreadable.contains(h) {
            corrupt.push(hex(h));
        }
    }
    missing.sort();
    corrupt.sort();
    (reach.len() as u64, missing, corrupt)
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

    /// Checks one revision: its manifest, every blob it references, and its place in the hash chain.
    pub fn scan_revision(&self, rev: &str) -> Result<RevScan> {
        let root = self.revision_root(rev)?;
        let (blobs, missing, corrupt) = verify_tree(&self.cas, root);
        let (stored, world, seq): (Option<Vec<u8>>, String, i64) =
            self.db.query_row("SELECT chain_hash, world_id, seq FROM revisions WHERE id=?", [rev], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        let chain_ok = match stored {
            Some(s) => crate::lease::chain_hash_of(&self.db, rev)?.as_slice() == s.as_slice(),
            None => {
                let sealed_before: i64 = self.db.query_row(
                    "SELECT COUNT(*) FROM revisions WHERE world_id=? AND seq<? AND chain_hash IS NOT NULL",
                    rusqlite::params![world, seq],
                    |r| r.get(0),
                )?;
                sealed_before == 0
            }
        };
        Ok(RevScan { blobs, missing, corrupt, chain_ok })
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExportStats {
    pub files: u64,
    pub chunks: u64,
    pub bytes: u64,
}

fn invalid(m: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, m.into())
}

struct ZipEntry {
    name: String,
    crc: u32,
    size: u64,
    off: u64,
}

/// Minimal zip writer: stored entries, zip64 fields only where a value does not fit 32 bits.
struct ZipOut<W: std::io::Write> {
    out: W,
    pos: u64,
    limit: u64,
    entries: Vec<ZipEntry>,
}

const DOS_DATE: u16 = (1 << 5) | 1;

impl<W: std::io::Write> ZipOut<W> {
    fn new(out: W, limit: u64) -> Self {
        ZipOut { out, pos: 0, limit, entries: Vec::new() }
    }

    fn put(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.out.write_all(b)?;
        self.pos += b.len() as u64;
        Ok(())
    }

    fn add(&mut self, name: &str, data: &[u8]) -> std::io::Result<()> {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let size = data.len() as u64;
        let big = size >= self.limit;
        let mut h = Vec::new();
        h.extend_from_slice(&0x04034b50u32.to_le_bytes());
        h.extend_from_slice(&(if big { 45u16 } else { 20 }).to_le_bytes());
        h.extend_from_slice(&0x0800u16.to_le_bytes());
        h.extend_from_slice(&[0, 0, 0, 0]);
        h.extend_from_slice(&DOS_DATE.to_le_bytes());
        h.extend_from_slice(&crc.sum().to_le_bytes());
        let (s32, extra) = if big {
            let mut e = vec![1, 0, 16, 0];
            e.extend_from_slice(&size.to_le_bytes());
            e.extend_from_slice(&size.to_le_bytes());
            (u32::MAX, e)
        } else {
            (size as u32, Vec::new())
        };
        h.extend_from_slice(&s32.to_le_bytes());
        h.extend_from_slice(&s32.to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        h.extend_from_slice(&extra);
        let off = self.pos;
        self.put(&h)?;
        self.put(data)?;
        self.entries.push(ZipEntry { name: name.to_string(), crc: crc.sum(), size, off });
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<()> {
        let cd_off = self.pos;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let (big_size, big_off) = (e.size >= self.limit, e.off >= self.limit);
            let mut extra = Vec::new();
            if big_size {
                extra.extend_from_slice(&e.size.to_le_bytes());
                extra.extend_from_slice(&e.size.to_le_bytes());
            }
            if big_off {
                extra.extend_from_slice(&e.off.to_le_bytes());
            }
            let mut z = Vec::new();
            if !extra.is_empty() {
                z.extend_from_slice(&1u16.to_le_bytes());
                z.extend_from_slice(&(extra.len() as u16).to_le_bytes());
                z.extend_from_slice(&extra);
            }
            let ver = if z.is_empty() { 20u16 } else { 45 };
            let mut c = Vec::new();
            c.extend_from_slice(&0x02014b50u32.to_le_bytes());
            c.extend_from_slice(&ver.to_le_bytes());
            c.extend_from_slice(&ver.to_le_bytes());
            c.extend_from_slice(&0x0800u16.to_le_bytes());
            c.extend_from_slice(&[0, 0, 0, 0]);
            c.extend_from_slice(&DOS_DATE.to_le_bytes());
            c.extend_from_slice(&e.crc.to_le_bytes());
            let s32 = if big_size { u32::MAX } else { e.size as u32 };
            c.extend_from_slice(&s32.to_le_bytes());
            c.extend_from_slice(&s32.to_le_bytes());
            c.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            c.extend_from_slice(&(z.len() as u16).to_le_bytes());
            c.extend_from_slice(&[0; 6]);
            c.extend_from_slice(&0u32.to_le_bytes());
            c.extend_from_slice(&(if big_off { u32::MAX } else { e.off as u32 }).to_le_bytes());
            c.extend_from_slice(e.name.as_bytes());
            c.extend_from_slice(&z);
            self.put(&c)?;
        }
        let cd_size = self.pos - cd_off;
        let n = entries.len() as u64;
        let mut t = Vec::new();
        if n >= 0xFFFF || cd_off >= self.limit || cd_size >= self.limit {
            let z64_at = self.pos;
            t.extend_from_slice(&0x06064b50u32.to_le_bytes());
            t.extend_from_slice(&44u64.to_le_bytes());
            t.extend_from_slice(&45u16.to_le_bytes());
            t.extend_from_slice(&45u16.to_le_bytes());
            t.extend_from_slice(&[0; 8]);
            for v in [n, n, cd_size, cd_off] {
                t.extend_from_slice(&v.to_le_bytes());
            }
            t.extend_from_slice(&0x07064b50u32.to_le_bytes());
            t.extend_from_slice(&0u32.to_le_bytes());
            t.extend_from_slice(&z64_at.to_le_bytes());
            t.extend_from_slice(&1u32.to_le_bytes());
        }
        t.extend_from_slice(&0x06054b50u32.to_le_bytes());
        t.extend_from_slice(&[0; 4]);
        let n16 = if n >= 0xFFFF { 0xFFFF } else { n as u16 };
        t.extend_from_slice(&n16.to_le_bytes());
        t.extend_from_slice(&n16.to_le_bytes());
        t.extend_from_slice(&(if cd_size >= self.limit { u32::MAX } else { cd_size as u32 }).to_le_bytes());
        t.extend_from_slice(&(if cd_off >= self.limit { u32::MAX } else { cd_off as u32 }).to_le_bytes());
        t.extend_from_slice(&0u16.to_le_bytes());
        self.put(&t)?;
        self.out.flush()
    }
}

fn safe_rel(p: &str) -> std::io::Result<()> {
    if p.is_empty() || p.starts_with('/') || p.contains('\\') || p.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(invalid(format!("unsafe path in manifest: {p}")));
    }
    Ok(())
}

fn dim_dir(dim: &str) -> std::io::Result<String> {
    Ok(match dim {
        "minecraft:overworld" => String::new(),
        "minecraft:the_nether" => "DIM-1/".into(),
        "minecraft:the_end" => "DIM1/".into(),
        other => {
            let (ns, path) = other.split_once(':').ok_or_else(|| invalid(format!("bad dimension id: {other}")))?;
            safe_rel(ns)?;
            safe_rel(path)?;
            format!("dimensions/{ns}/{path}/")
        }
    })
}

/// Rebuilds one anvil region file; chunk blobs hold the uncompressed NBT and go back in as zlib (type 2).
fn build_mca(cas: &Cas, chunks: &[(usize, Hash)]) -> std::io::Result<Vec<u8>> {
    use std::io::Write;
    let mut file = vec![0u8; 8192];
    for (idx, h) in chunks {
        let raw = cas.get(h)?;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&raw)?;
        let comp = z.finish()?;
        let mut payload = Vec::with_capacity(comp.len() + 5);
        payload.extend_from_slice(&(comp.len() as u32 + 1).to_be_bytes());
        payload.push(2);
        payload.extend_from_slice(&comp);
        let sectors = payload.len().div_ceil(4096);
        if sectors > 255 {
            return Err(invalid("chunk too large for an inline region entry"));
        }
        let at = file.len() / 4096;
        file[idx * 4..idx * 4 + 4].copy_from_slice(&(((at as u32) << 8) | sectors as u32).to_be_bytes());
        file.extend_from_slice(&payload);
        file.resize(file.len().div_ceil(4096) * 4096, 0);
    }
    Ok(file)
}

type RegionGroup = ((String, manifest::Kind, i32, i32), Vec<(usize, Hash)>);

/// Writes revision `root` as a vanilla world folder zip. Refuses, before writing anything, if any referenced blob is missing or corrupt.
pub fn export_zip<W: std::io::Write + std::io::Seek>(cas: &Cas, root: Hash, out: W) -> std::io::Result<ExportStats> {
    export_zip_limit(cas, root, out, 0xFFFF_FFFF)
}

fn export_zip_limit<W: std::io::Write>(cas: &Cas, root: Hash, out: W, limit: u64) -> std::io::Result<ExportStats> {
    let (_, missing, corrupt) = verify_tree(cas, root);
    if !missing.is_empty() || !corrupt.is_empty() {
        return Err(invalid(format!("revision is damaged: {} missing, {} corrupt blobs", missing.len(), corrupt.len())));
    }
    let mut zip = ZipOut::new(out, limit);
    let mut st = ExportStats::default();
    let mut cur: Option<RegionGroup> = None;
    let flush = |zip: &mut ZipOut<W>, st: &mut ExportStats, g: RegionGroup| -> std::io::Result<()> {
        let ((dim, kind, rx, rz), chunks) = g;
        let dir = match kind {
            manifest::Kind::Region => "region",
            manifest::Kind::Entities => "entities",
            manifest::Kind::Poi => "poi",
        };
        let data = build_mca(cas, &chunks)?;
        zip.add(&format!("{}{dir}/r.{rx}.{rz}.mca", dim_dir(&dim)?), &data)?;
        st.files += 1;
        st.chunks += chunks.len() as u64;
        st.bytes += data.len() as u64;
        Ok(())
    };
    manifest::for_each_leaf(cas, root, &mut |item, h| {
        match item {
            manifest::Item::Aux(path) => {
                safe_rel(&path)?;
                let data = cas.get(&h)?;
                zip.add(&path, &data)?;
                st.files += 1;
                st.bytes += data.len() as u64;
            }
            manifest::Item::Chunk(k) => {
                let region = (k.dim, k.kind, k.cx >> 5, k.cz >> 5);
                let idx = ((k.cz & 31) * 32 + (k.cx & 31)) as usize;
                match &mut cur {
                    Some((r, v)) if *r == region => v.push((idx, h)),
                    _ => {
                        if let Some(done) = cur.replace((region, vec![(idx, h)])) {
                            flush(&mut zip, &mut st, done)?;
                        }
                    }
                }
            }
        }
        Ok(())
    })?;
    if let Some(done) = cur.take() {
        flush(&mut zip, &mut st, done)?;
    }
    zip.finish()?;
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Change, Key, Kind};
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read};

    fn cas() -> Cas {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Cas::open(std::env::temp_dir().join(format!("mcmesh-exp-{}-{n}", std::process::id()))).unwrap()
    }

    fn le(b: &[u8]) -> u64 {
        b.iter().rev().fold(0, |a, x| (a << 8) | *x as u64)
    }

    /// Reads the central directory (zip64 aware) and checks every crc.
    fn read_zip(z: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let eocd = (0..z.len() - 21).rev().find(|&i| z[i..i + 4] == [0x50, 0x4b, 5, 6]).unwrap();
        let (mut n, mut cd) = (le(&z[eocd + 10..eocd + 12]), le(&z[eocd + 16..eocd + 20]));
        if cd == 0xFFFF_FFFF {
            let l = eocd - 20;
            assert_eq!(z[l..l + 4], [0x50, 0x4b, 6, 7]);
            let r = le(&z[l + 8..l + 16]) as usize;
            n = le(&z[r + 32..r + 40]);
            cd = le(&z[r + 48..r + 56]);
        }
        let (mut p, mut out) = (cd as usize, BTreeMap::new());
        for _ in 0..n {
            assert_eq!(z[p..p + 4], [0x50, 0x4b, 1, 2]);
            let crc = le(&z[p + 16..p + 20]) as u32;
            let (mut size, mut off) = (le(&z[p + 24..p + 28]), le(&z[p + 42..p + 46]));
            let (nl, xl) = (le(&z[p + 28..p + 30]) as usize, le(&z[p + 30..p + 32]) as usize);
            let name = String::from_utf8(z[p + 46..p + 46 + nl].to_vec()).unwrap();
            let mut x = &z[p + 46 + nl..p + 46 + nl + xl];
            if !x.is_empty() {
                assert_eq!(le(&x[0..2]), 1);
                x = &x[4..];
                if size == 0xFFFF_FFFF {
                    size = le(&x[0..8]);
                    x = &x[16..];
                }
                if off == 0xFFFF_FFFF {
                    off = le(&x[0..8]);
                }
            }
            let off = off as usize;
            let (lnl, lxl) = (le(&z[off + 26..off + 28]) as usize, le(&z[off + 28..off + 30]) as usize);
            let start = off + 30 + lnl + lxl;
            let data = z[start..start + size as usize].to_vec();
            let mut c = flate2::Crc::new();
            c.update(&data);
            assert_eq!(c.sum(), crc, "crc of {name}");
            out.insert(name, data);
            p += 46 + nl + xl;
        }
        out
    }

    fn mca_chunks(f: &[u8]) -> BTreeMap<usize, Vec<u8>> {
        let mut out = BTreeMap::new();
        for i in 0..1024 {
            let e = u32::from_be_bytes(f[i * 4..i * 4 + 4].try_into().unwrap());
            if e == 0 {
                continue;
            }
            let at = (e >> 8) as usize * 4096;
            let len = u32::from_be_bytes(f[at..at + 4].try_into().unwrap()) as usize;
            assert_eq!(f[at + 4], 2);
            let mut raw = Vec::new();
            flate2::read::ZlibDecoder::new(&f[at + 5..at + 4 + len]).read_to_end(&mut raw).unwrap();
            out.insert(i, raw);
        }
        out
    }

    fn key(dim: &str, kind: Kind, cx: i32, cz: i32) -> Key {
        Key { dim: dim.into(), kind, cx, cz }
    }

    fn build(c: &Cas) -> (Hash, Vec<(Key, Vec<u8>)>, Vec<(&'static str, Vec<u8>)>) {
        let chunks: Vec<(Key, Vec<u8>)> = vec![
            (key("minecraft:overworld", Kind::Region, 0, 0), b"chunk-0-0".repeat(50)),
            (key("minecraft:overworld", Kind::Region, 31, 31), b"chunk-31-31".to_vec()),
            (key("minecraft:overworld", Kind::Region, -1, 40), b"neg".to_vec()),
            (key("minecraft:overworld", Kind::Entities, 3, 4), b"ents".to_vec()),
            (key("minecraft:the_nether", Kind::Poi, 5, 5), b"poi".to_vec()),
            (key("minecraft:the_end", Kind::Region, 1, 1), b"end".to_vec()),
            (key("tf:twilight", Kind::Region, 2, 2), b"mod dim".to_vec()),
        ];
        let aux = vec![("level.dat", b"leveldata".to_vec()), ("playerdata/p.dat", vec![9u8; 3000])];
        let mut ch: Vec<Change> = chunks.iter().map(|(k, d)| Change::Put(k.clone(), c.put(d).unwrap())).collect();
        ch.extend(aux.iter().map(|(p, d)| Change::AuxPut(p.to_string(), c.put(d).unwrap())));
        (manifest::apply(c, None, &ch).unwrap(), chunks, aux)
    }

    fn check_zip(zip: &[u8], chunks: &[(Key, Vec<u8>)], aux: &[(&str, Vec<u8>)]) {
        let files = read_zip(zip);
        let mut names: Vec<&str> = files.keys().map(String::as_str).collect();
        names.sort();
        let mut want = vec![
            "DIM-1/poi/r.0.0.mca",
            "DIM1/region/r.0.0.mca",
            "dimensions/tf/twilight/region/r.0.0.mca",
            "entities/r.0.0.mca",
            "level.dat",
            "playerdata/p.dat",
            "region/r.-1.1.mca",
            "region/r.0.0.mca",
        ];
        want.sort();
        assert_eq!(names, want);
        for (p, d) in aux {
            assert_eq!(&files[*p], d);
        }
        let got = mca_chunks(&files["region/r.0.0.mca"]);
        assert_eq!(got[&0], chunks[0].1);
        assert_eq!(got[&(31 * 32 + 31)], chunks[1].1);
        assert_eq!(mca_chunks(&files["region/r.-1.1.mca"])[&(8 * 32 + 31)], b"neg");
        assert_eq!(mca_chunks(&files["DIM-1/poi/r.0.0.mca"])[&(5 * 32 + 5)], b"poi");
    }

    #[test]
    fn export_round_trips_files_and_bytes() {
        let c = cas();
        let (root, chunks, aux) = build(&c);
        let mut out = Cursor::new(Vec::new());
        let st = export_zip(&c, root, &mut out).unwrap();
        assert_eq!((st.files, st.chunks), (8, 7));
        check_zip(out.get_ref(), &chunks, &aux);
    }

    #[test]
    fn export_uses_zip64_fields_when_sizes_overflow() {
        let c = cas();
        let (root, chunks, aux) = build(&c);
        let mut out = Vec::new();
        export_zip_limit(&c, root, &mut out, 100).unwrap();
        check_zip(&out, &chunks, &aux);
    }

    #[test]
    fn export_refuses_a_corrupt_world_and_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("mcmesh-exp-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = Cas::open(&dir).unwrap();
        let (root, chunks, _) = build(&c);
        let x = hex(&c.put(&chunks[1].1).unwrap());
        std::fs::write(dir.join(&x[0..2]).join(&x[2..4]).join(&x), b"garbage").unwrap();
        let mut out = Vec::new();
        let err = export_zip_limit(&c, root, &mut out, 0xFFFF_FFFF).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(out.is_empty());
    }
}

