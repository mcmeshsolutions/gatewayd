//! ZFS snapshots on milestone commits (`MCMESH_ZFS_DATASET`).
//! After a SHUTDOWN or MIGRATE commit (or any final one) the dataset holding the gateway data dir is
//! snapshotted, giving an instant bit-for-bit rollback point on TrueNAS, unRAID and Proxmox hosts.

use std::process::Command;
use std::sync::Mutex;

pub struct ZfsSnapshotter {
    dataset: Option<String>,
    bin: String,
    /// Keep this many `mcmesh-` snapshots, 0 keeps all.
    keep: usize,
    kinds: Vec<String>,
    last: Mutex<Option<String>>,
}

impl ZfsSnapshotter {
    pub fn from_env() -> Self {
        let kinds = std::env::var("MCMESH_ZFS_KINDS").unwrap_or_else(|_| "SHUTDOWN,MIGRATE".into());
        Self::new(
            std::env::var("MCMESH_ZFS_DATASET").ok(),
            std::env::var("MCMESH_ZFS_BIN").unwrap_or_else(|_| "zfs".into()),
            std::env::var("MCMESH_ZFS_KEEP").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
            &kinds,
        )
    }

    pub fn new(dataset: Option<String>, bin: String, keep: usize, kinds: &str) -> Self {
        let dataset = dataset.map(|d| d.trim().to_string()).filter(|d| valid_dataset(d));
        let kinds = kinds.split(',').map(|k| k.trim().to_uppercase()).filter(|k| !k.is_empty()).collect();
        Self { dataset, bin, keep, kinds, last: Mutex::new(None) }
    }

    pub fn enabled(&self) -> bool {
        self.dataset.is_some()
    }

    pub fn last_snapshot(&self) -> Option<String> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Snapshots when the commit is a milestone. Blocking; callers run it off the request path.
    pub fn on_commit(&self, world: &str, rev: &str, kind: &str, last: bool, now: u64) -> Option<String> {
        let ds = self.dataset.as_ref()?;
        if !last && !self.kinds.iter().any(|k| k == kind) {
            return None;
        }
        let name = snapshot_name(world, rev, now);
        let full = format!("{ds}@{name}");
        match Command::new(&self.bin).args(["snapshot", &full]).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                eprintln!("zfs snapshot {full} failed: {}", String::from_utf8_lossy(&o.stderr).trim());
                return None;
            }
            Err(e) => {
                eprintln!("zfs snapshot {full} failed: {e}");
                return None;
            }
        }
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(full.clone());
        self.prune(ds);
        Some(full)
    }

    fn prune(&self, ds: &str) {
        if self.keep == 0 {
            return;
        }
        let Ok(o) = Command::new(&self.bin)
            .args(["list", "-H", "-t", "snapshot", "-o", "name", "-s", "creation", "-d", "1", ds])
            .output()
        else {
            return;
        };
        let prefix = format!("{ds}@mcmesh-");
        let ours: Vec<String> =
            String::from_utf8_lossy(&o.stdout).lines().filter(|l| l.starts_with(&prefix)).map(String::from).collect();
        for old in ours.iter().take(ours.len().saturating_sub(self.keep)) {
            let _ = Command::new(&self.bin).args(["destroy", old]).output();
        }
    }
}

fn valid_dataset(d: &str) -> bool {
    !d.is_empty()
        && !d.starts_with('-')
        && !d.contains('@')
        && d.chars().all(|c| c.is_ascii_alphanumeric() || "/_-.:".contains(c))
}

fn snapshot_name(world: &str, rev: &str, now: u64) -> String {
    let clean = |s: &str| s.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect::<String>();
    format!("mcmesh-{now}-{}-{}", clean(world), clean(rev))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(dir: &std::path::Path) -> String {
        let p = dir.join("zfs");
        std::fs::write(&p, format!("#!/bin/sh\necho \"$@\" >> {}/log\n", dir.display())).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p.display().to_string()
    }

    #[test]
    fn dataset_validation() {
        assert!(valid_dataset("tank/mcmesh"));
        assert!(!valid_dataset("tank/x@snap"));
        assert!(!valid_dataset("-r tank"));
        assert!(!valid_dataset("tank; rm -rf /"));
    }

    #[test]
    fn snapshots_only_milestones() {
        let dir = std::env::temp_dir().join(format!("mcmesh-zfs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let z = ZfsSnapshotter::new(Some("tank/mcmesh".into()), fake(&dir), 0, "SHUTDOWN,MIGRATE");
        assert!(z.on_commit("w1", "r1", "AUTOSAVE", false, 5).is_none());
        let s = z.on_commit("w1", "abc-123", "SHUTDOWN", true, 7).unwrap();
        assert_eq!(s, "tank/mcmesh@mcmesh-7-w1-abc123");
        assert!(z.on_commit("w1", "r2", "AUTOSAVE", true, 8).is_some());
        let log = std::fs::read_to_string(dir.join("log")).unwrap();
        assert!(log.starts_with("snapshot tank/mcmesh@mcmesh-7-w1-abc123"));
        assert_eq!(z.last_snapshot().unwrap(), "tank/mcmesh@mcmesh-8-w1-r2");
        let off = ZfsSnapshotter::new(None, "zfs".into(), 0, "SHUTDOWN");
        assert!(!off.enabled() && off.on_commit("w", "r", "SHUTDOWN", true, 1).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
