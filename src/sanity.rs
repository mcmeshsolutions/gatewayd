//! Last line of defence for player data: refuse a revision that looks like a wiped or truncated world.
use crate::cas::{Cas, Hash};
use crate::manifest::{self, Kind};

const MIN_BASE_CHUNKS: u64 = 64;
const MIN_BASE_BYTES: u64 = 1 << 20;
const MAX_GROWTH_FACTOR: u64 = 8;
const MIN_GROWTH_BYTES: u64 = 1 << 30;

fn enabled() -> bool {
    std::env::var("MCMESH_SANITY").map(|v| v != "off").unwrap_or(true)
}

/// Stored size of recently seen revision roots. A commit knows the size of its new root from the delta, so only the first check after a restart walks every blob.
#[derive(Default)]
pub struct SizeCache(std::collections::HashMap<Hash, u64>);

/// Compares the head root with the root a commit would produce. `Err` carries the reason.
pub fn check(cas: &Cas, base: Hash, next: Hash, cache: &mut SizeCache) -> Result<(), String> {
    check_cached(enabled(), cas, base, next, cache)
}

/// Stored bytes of every leaf under `root`; unreadable leaves count as zero so one lost blob cannot freeze commits.
fn total_bytes(cas: &Cas, root: Hash) -> std::io::Result<u64> {
    let mut n = 0u64;
    manifest::for_each_leaf(cas, root, &mut |_, h| {
        n += cas.stored_len(&h).unwrap_or(0);
        Ok(())
    })?;
    Ok(n)
}

fn size_verdict(before: u64, after: u64) -> Result<(), String> {
    if before < MIN_BASE_BYTES {
        return Ok(());
    }
    if after * 2 < before {
        return Err(format!("stored size fell from {before} to {after} bytes"));
    }
    if after > before.saturating_mul(MAX_GROWTH_FACTOR) && after - before > MIN_GROWTH_BYTES {
        return Err(format!("stored size grew from {before} to {after} bytes"));
    }
    Ok(())
}

#[cfg(test)]
fn check_with(on: bool, cas: &Cas, base: Hash, next: Hash) -> Result<(), String> {
    check_cached(on, cas, base, next, &mut SizeCache::default())
}

fn check_cached(on: bool, cas: &Cas, base: Hash, next: Hash, cache: &mut SizeCache) -> Result<(), String> {
    if !on || base == next {
        return Ok(());
    }
    let io = |e: std::io::Error| format!("manifest unreadable: {e}");
    let before = manifest::chunk_count(cas, base, Kind::Region).map_err(io)?;
    let after = manifest::chunk_count(cas, next, Kind::Region).map_err(io)?;
    if before >= MIN_BASE_CHUNKS && after * 2 < before {
        return Err(format!("chunk count fell from {before} to {after}"));
    }
    let had = manifest::aux_lookup(cas, base, "level.dat").map_err(io)?.is_some();
    let has = manifest::aux_lookup(cas, next, "level.dat").map_err(io)?.is_some();
    if had && !has {
        return Err("level.dat disappeared".into());
    }
    let before = match cache.0.get(&base) {
        Some(b) => *b,
        None => total_bytes(cas, base).map_err(io)?,
    };
    let delta = manifest::diff(cas, Some(base), Some(next)).map_err(io)?;
    let size_of = |h: Option<Hash>| h.map(|h| cas.stored_len(&h).unwrap_or(0)).unwrap_or(0);
    let added: u64 = delta.iter().map(|d| size_of(d.new)).sum();
    let removed: u64 = delta.iter().map(|d| size_of(d.old)).sum();
    let after = (before + added).saturating_sub(removed);
    if cache.0.len() >= 16 {
        cache.0.clear();
    }
    cache.0.insert(next, after);
    size_verdict(before, after)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Change, Key};

    fn cas() -> Cas {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Cas::open(std::env::temp_dir().join(format!("mcmesh-san-{}-{n}", std::process::id()))).unwrap()
    }

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn key(i: i32) -> Key {
        Key { dim: "minecraft:overworld".into(), kind: Kind::Region, cx: i, cz: 0 }
    }

    fn world(c: &Cas, sizes: &[usize]) -> Hash {
        let ch: Vec<Change> = sizes.iter().enumerate().map(|(i, n)| Change::Put(key(i as i32), c.put(&noise(*n, i as u64 + 7)).unwrap())).collect();
        manifest::apply(c, None, &ch).unwrap()
    }

    #[test]
    fn size_collapse_is_rejected_and_normal_edits_pass() {
        let c = cas();
        let base = world(&c, &[400_000; 4]);
        let tiny = world(&c, &[400_000, 10, 10, 10]);
        let why = check_with(true, &c, base, tiny).unwrap_err();
        assert!(why.contains("fell"), "{why}");
        let slim = world(&c, &[400_000, 400_000, 400_000, 300_000]);
        check_with(true, &c, base, slim).unwrap();
        let bigger = world(&c, &[400_000; 6]);
        check_with(true, &c, base, bigger).unwrap();
    }

    #[test]
    fn the_size_of_a_new_root_comes_from_the_delta_and_equals_a_full_walk() {
        let c = cas();
        let base = world(&c, &[400_000; 4]);
        let next = world(&c, &[400_000, 400_000, 400_000, 300_000]);
        let mut cache = SizeCache::default();
        check_cached(true, &c, base, next, &mut cache).unwrap();
        assert_eq!(cache.0.get(&next).copied(), Some(total_bytes(&c, next).unwrap()), "the cached size must be the real size");
    }

    #[test]
    fn a_cached_size_is_used_instead_of_walking_the_base() {
        let c = cas();
        let base = world(&c, &[400_000; 4]);
        let tiny = world(&c, &[400_000, 10, 10, 10]);
        assert!(check_cached(true, &c, base, tiny, &mut SizeCache::default()).is_err(), "a real walk sees the collapse");
        let mut cache = SizeCache::default();
        cache.0.insert(base, 100 << 20);
        assert!(check_cached(true, &c, base, tiny, &mut cache).is_ok(), "with a cached (wrong) size of 100 MiB the same delta looks small, so the cache was used");
    }

    #[test]
    fn size_check_ignores_first_and_small_revisions_and_off_switch() {
        let c = cas();
        let empty = manifest::empty_root(&c).unwrap();
        let first = world(&c, &[400_000; 4]);
        check_with(true, &c, empty, first).unwrap();
        let small = world(&c, &[100, 100]);
        let smaller = world(&c, &[1, 1]);
        check_with(true, &c, small, smaller).unwrap();
        let tiny = world(&c, &[400_000, 10, 10, 10]);
        check_with(false, &c, first, tiny).unwrap();
    }

    #[test]
    fn growth_needs_both_factor_and_absolute_jump() {
        let base = 2 << 20;
        assert!(size_verdict(base, base * 9).is_ok());
        assert!(size_verdict(base, base + (2 << 30)).is_err());
        assert!(size_verdict(0, 5 << 30).is_ok());
    }
}
