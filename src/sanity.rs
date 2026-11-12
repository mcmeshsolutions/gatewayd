//! Last line of defence for player data: refuse a revision that looks like a wiped or truncated world.
use crate::cas::{Cas, Hash};
use crate::manifest::{self, Kind};

const MIN_BASE_CHUNKS: u64 = 64;

fn enabled() -> bool {
    std::env::var("MCMESH_SANITY").map(|v| v != "off").unwrap_or(true)
}

/// Compares the head root with the root a commit would produce. `Err` carries the reason.
pub fn check(cas: &Cas, base: Hash, next: Hash) -> Result<(), String> {
    if !enabled() || base == next {
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
    Ok(())
}
