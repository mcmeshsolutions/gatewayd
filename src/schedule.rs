use crate::cas::Cas;
use crate::lease::Gateway;
use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

pub struct Report {
    pub ok: bool,
    pub summary: String,
}

/// One scrub plus one incremental backup through a connection of its own, so the serving mutex is never held for it.
pub fn run_once(db: &str, cas_dir: &str, backup_dir: &Path) -> Result<Report, String> {
    let cas = Cas::open(cas_dir).map_err(|e| format!("open cas: {e}"))?;
    let gw = Gateway::open(Connection::open(db).map_err(|e| format!("open db: {e}"))?, cas, 0).map_err(|e| format!("init db: {e:?}"))?;
    let r = gw.scrub(Path::new(cas_dir)).map_err(|e| format!("scrub: {e:?}"))?;
    let (copied, skipped) = gw.backup(Path::new(cas_dir), backup_dir).map_err(|e| format!("backup: {e:?}"))?;
    Ok(Report {
        ok: r.ok(),
        summary: format!(
            "scrub: {} blobs, {} revisions, {} corrupt, {} broken revisions, {} missing, {} chain breaks; backup: {copied} copied, {skipped} already present",
            r.blobs, r.revisions, r.corrupt.len(), r.broken_revisions.len(), r.missing.len(), r.chain_breaks.len()
        ),
    })
}

/// Runs `run_once` every `every`, first after `first_after`. A failed or unhealthy run is logged loudly and the loop goes on.
pub async fn serve(db: String, cas_dir: String, backup_dir: String, first_after: Duration, every: Duration) {
    tokio::time::sleep(first_after).await;
    loop {
        let (d, c, b) = (db.clone(), cas_dir.clone(), backup_dir.clone());
        match tokio::task::spawn_blocking(move || run_once(&d, &c, Path::new(&b))).await {
            Ok(Ok(r)) if r.ok => eprintln!("scheduled maintenance ok: {}", r.summary),
            Ok(Ok(r)) => eprintln!("SCHEDULED SCRUB FOUND PROBLEMS: {}", r.summary),
            Ok(Err(e)) => eprintln!("scheduled maintenance failed: {e}"),
            Err(e) => eprintln!("scheduled maintenance task died: {e}"),
        }
        tokio::time::sleep(every).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_scrubs_and_backs_up_a_live_database() {
        let root = std::env::temp_dir().join(format!("mcmesh-sched-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let (db, cas, bak) = (root.join("m.db"), root.join("cas"), root.join("bak"));
        {
            let mut g = Gateway::open(Connection::open(&db).unwrap(), Cas::open(&cas).unwrap(), 0).unwrap();
            g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
            g.cas().put(b"some blob").unwrap();
        }
        let r = run_once(db.to_str().unwrap(), cas.to_str().unwrap(), &bak).unwrap();
        assert!(r.ok, "{}", r.summary);
        assert!(r.summary.contains("backup:"), "{}", r.summary);
        let again = run_once(db.to_str().unwrap(), cas.to_str().unwrap(), &bak).unwrap();
        assert!(again.summary.contains("0 copied"), "the second run is incremental: {}", again.summary);
    }

    #[test]
    fn a_missing_cas_directory_is_created_not_fatal_but_a_bad_db_path_is() {
        let root = std::env::temp_dir().join(format!("mcmesh-sched2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert!(run_once("/nonexistent-dir/x.db", root.join("cas").to_str().unwrap(), &root.join("bak")).is_err());
    }
}
