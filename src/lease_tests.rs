use crate::lease::*;
use rusqlite::Connection;

fn test_cas() -> crate::cas::Cas {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    crate::cas::Cas::open(std::env::temp_dir().join(format!("mcmesh-lt-{}-{n}", std::process::id()))).unwrap()
}

const W: &str = "w1";

fn hw(tier: u8, score: f64) -> Hw {
    Hw { tier, score, wants_host: true, takeover: true }
}

fn setup() -> Gateway {
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), test_cas(), 0).unwrap();
    g.create_world(W, "Create Full Stack", "1.21.1", "neoforge").unwrap();
    g.add_member(W, "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_member(W, "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_member(W, "u-c", "carol", "dev-c", Role::ClientOnly).unwrap();
    g
}

fn host(j: Join) -> Grant {
    match j {
        Join::Host(g) => g,
        other => panic!("expected Host, got {other:?}"),
    }
}

#[test]
fn first_eligible_becomes_host_others_guest() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    assert_eq!(a.epoch, 1);
    assert_eq!(g.state(W).unwrap().0, "LOCKED");
    assert!(matches!(g.join(W, "dev-b", hw(2, 5.0), 10).unwrap(), Join::Guest { epoch: 1, .. }));
    assert_eq!(g.live_lease_count(W).unwrap(), 1);
}

#[test]
fn client_only_and_non_members_cannot_host() {
    let mut g = setup();
    assert_eq!(g.join(W, "dev-c", hw(1, 99.0), 0).unwrap(), Join::Wait { phase: "NO_HOST".into() });
    g.add_member("w1", "u-x", "xavier", "dev-x", Role::HostEligible).unwrap();
    g.db().execute("DELETE FROM members WHERE player_uuid='u-x'", []).unwrap();
    assert!(matches!(g.join(W, "dev-x", hw(1, 1.0), 0), Err(Error::NotMember)));
}

#[test]
fn expiry_elects_warm_candidate_and_fences_old_epoch() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    g.join(W, "dev-b", hw(3, 2.0), 1_000).unwrap();
    g.heartbeat(&a.lease_id, a.epoch, 15_000).unwrap();
    g.join(W, "dev-b", hw(3, 2.0), 40_000).unwrap();
    g.tick(59_999).unwrap();
    assert_eq!(g.state(W).unwrap().0, "LOCKED");
    g.tick(60_001).unwrap();
    assert_eq!(g.state(W).unwrap(), ("MIGRATING".into(), Some("BOOTING".into())));
    assert!(matches!(g.heartbeat(&a.lease_id, a.epoch, 60_002), Err(Error::StaleEpoch)));
    let b = host(g.join(W, "dev-b", hw(3, 2.0), 61_000).unwrap());
    assert_eq!(b.epoch, 2);
    g.host_ready(&b.lease_id, b.epoch).unwrap();
    assert_eq!(g.state(W).unwrap().0, "LOCKED");
    assert_eq!(g.live_lease_count(W).unwrap(), 1);
}

#[test]
fn expiry_with_nobody_waiting_goes_idle() {
    let mut g = setup();
    host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    g.tick(46_000).unwrap();
    assert_eq!(g.state(W).unwrap().0, "IDLE");
}

#[test]
fn stale_host_cannot_commit_after_fencing() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    g.join(W, "dev-b", hw(3, 2.0), 40_000).unwrap();
    g.tick(46_000).unwrap();
    let r = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 46_001);
    assert!(matches!(r, Err(Error::StaleEpoch)));
}

#[test]
fn commit_is_compare_and_swap_on_head() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let r1 = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 100).unwrap();
    assert_eq!(r1.seq, 1);
    assert!(matches!(
        g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 200),
        Err(Error::HeadMoved)
    ));
    let r2 = g.commit(&a.lease_id, a.epoch, &r1.id, CommitKind::Autosave, false, 300).unwrap();
    assert_eq!((r2.seq, r2.parent), (2, r1.id));
}

#[test]
fn preemption_respects_min_hold_then_hands_off() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(3, 2.0), 0).unwrap());
    g.join(W, "dev-b", hw(1, 9.0), 30_000).unwrap();
    assert_eq!(g.state(W).unwrap().0, "LOCKED", "inside min hold");
    g.heartbeat(&a.lease_id, a.epoch, 600_000).unwrap();
    g.join(W, "dev-b", hw(1, 9.0), 600_001).unwrap();
    assert_eq!(g.state(W).unwrap(), ("MIGRATING".into(), Some("PREPARING".into())));
    let d = g.heartbeat(&a.lease_id, a.epoch, 601_000).unwrap();
    assert_eq!(d, vec![Directive::MigratePrepare { target_device: Some("dev-b".into()), deadline_ms: 20_000 }]);
    let rev = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Migrate, true, 602_000).unwrap();
    assert_eq!(g.state(W).unwrap(), ("MIGRATING".into(), Some("BOOTING".into())));
    let b = host(g.join(W, "dev-b", hw(1, 9.0), 603_000).unwrap());
    assert_eq!((b.epoch, b.base_rev.as_str()), (2, rev.id.as_str()));
    g.host_ready(&b.lease_id, b.epoch).unwrap();
    assert!(matches!(g.heartbeat(&a.lease_id, a.epoch, 604_000), Err(Error::StaleEpoch)));
}

#[test]
fn host_leaving_with_guests_migrates_without_guests_idles() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    g.join(W, "dev-b", hw(3, 2.0), 1_000).unwrap();
    g.release(&a.lease_id, a.epoch, true).unwrap();
    g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Shutdown, true, 2_000).unwrap();
    assert_eq!(g.state(W).unwrap(), ("MIGRATING".into(), Some("BOOTING".into())));
    let b = host(g.join(W, "dev-b", hw(3, 2.0), 3_000).unwrap());
    g.host_ready(&b.lease_id, b.epoch).unwrap();
    g.release(&b.lease_id, b.epoch, false).unwrap();
    g.commit(&b.lease_id, b.epoch, "w1:R_0001", CommitKind::Shutdown, true, 4_000).unwrap();
    assert_eq!(g.state(W).unwrap().0, "IDLE");
}

#[test]
fn silent_boot_target_is_skipped() {
    let mut g = setup();
    g.add_member(W, "u-d", "dave", "dev-d", Role::HostEligible).unwrap();
    let a = host(g.join(W, "dev-a", hw(3, 2.0), 0).unwrap());
    g.join(W, "dev-b", hw(1, 9.0), 1_000).unwrap();
    g.join(W, "dev-d", hw(2, 5.0), 1_000).unwrap();
    g.release(&a.lease_id, a.epoch, true).unwrap();
    g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Migrate, true, 2_000).unwrap();
    g.join(W, "dev-d", hw(2, 5.0), 40_000).unwrap();
    g.join(W, "dev-b", hw(1, 9.0), 40_000).unwrap();
    g.tick(62_001).unwrap();
    let d = host(g.join(W, "dev-d", hw(2, 5.0), 62_100).unwrap());
    assert_eq!(d.epoch, 3, "dev-b (epoch 2) timed out, dev-d next");
}

#[test]
fn database_refuses_two_live_leases() {
    let mut g = setup();
    host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let r = g.db().execute(
        "INSERT INTO leases(id,world_id,device_id,epoch,ref_name,base_rev,tier,hmac_key,status,granted_at) \
         VALUES('dup','w1','dev-b',99,'main','w1:R_0000',1,zeroblob(32),'ACTIVE',0)",
        [],
    );
    assert!(r.is_err());
}

#[test]
fn restart_grants_a_full_ttl_grace() {
    let dir = std::env::temp_dir().join(format!("mcmesh-test-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    {
        let mut g = Gateway::open(Connection::open(&dir).unwrap(), test_cas(), 0).unwrap();
        g.create_world(W, "x", "1.21.1", "neoforge").unwrap();
        g.add_member(W, "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
        host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    }
    let mut g = Gateway::open(Connection::open(&dir).unwrap(), test_cas(), 1_000_000).unwrap();
    g.tick(1_030_000).unwrap();
    assert_eq!(g.state(W).unwrap().0, "LOCKED");
    g.tick(1_046_000).unwrap();
    assert_eq!(g.state(W).unwrap().0, "IDLE");
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn passive_candidate_never_migrates_a_healthy_host() {
    let mut g = setup();
    host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let passive = Hw { tier: 1, score: 1000.0, wants_host: true, takeover: false };
    assert!(matches!(g.join(W, "dev-b", passive, 100_000_000).unwrap(), Join::Guest { .. }));
    assert_eq!(g.state(W).unwrap().0, "LOCKED");
}

#[test]
fn status_lists_world_lease_and_revision() {
    let mut g = setup();
    assert!(g.status().unwrap()[0].contains("host=- "));
    host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let l = &g.status().unwrap()[0];
    assert!(l.starts_with("w1 LOCKED host=") && l.contains("epoch=1") && l.contains("latest=w1:R_0000"), "{l}");
}

fn wal_row(g: &Gateway, lease: &str, seq: i64, op: &str, cx: i32, cz: i32, hash: [u8; 32]) {
    g.db()
        .execute(
            "INSERT INTO chunk_wal(lease_id,seq,op,dim,cx,cz,hash) VALUES(?,?,?,?,?,?,?)",
            rusqlite::params![lease, seq, op, "minecraft:overworld", cx, cz, hash.as_slice()],
        )
        .unwrap();
}

#[test]
fn sanity_gate_blocks_world_wipe_and_keeps_head_and_wal() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let h = g.cas.put(b"chunk").unwrap();
    for i in 0..100 {
        wal_row(&g, &a.lease_id, i + 1, "put:region", i as i32, 0, h);
    }
    wal_row(&g, &a.lease_id, 101, "barrier", 0, 0, [0; 32]);
    let r1 = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 1_000).unwrap();
    for i in 0..60 {
        wal_row(&g, &a.lease_id, 102 + i, "del:region", i as i32, 0, [0; 32]);
    }
    wal_row(&g, &a.lease_id, 200, "barrier", 0, 0, [0; 32]);
    let err = g.commit(&a.lease_id, a.epoch, &r1.id, CommitKind::Autosave, false, 2_000).unwrap_err();
    assert!(matches!(err, Error::Rejected(_)), "{err:?}");
    let rows: i64 = g.db().query_row("SELECT COUNT(*) FROM chunk_wal WHERE lease_id=?", rusqlite::params![a.lease_id], |r| r.get(0)).unwrap();
    assert_eq!(rows, 61, "rejected frames must stay in the WAL");
    // a normal small delete passes after the bad frames are gone
    g.db().execute("DELETE FROM chunk_wal WHERE seq>=102", []).unwrap();
    for i in 0..5 {
        wal_row(&g, &a.lease_id, 102 + i, "del:region", i as i32, 0, [0; 32]);
    }
    wal_row(&g, &a.lease_id, 200, "barrier", 0, 0, [0; 32]);
    g.commit(&a.lease_id, a.epoch, &r1.id, CommitKind::Autosave, false, 3_000).unwrap();
}

#[test]
fn packs_are_isolated() {
    let mut g = setup();
    assert_eq!(g.pack_of(W).unwrap(), "default");
    g.require_pack(W, "default").unwrap();
    assert!(matches!(g.require_pack(W, "other"), Err(Error::PackMismatch)));
    g.set_pack(W, "other").unwrap();
    g.require_pack(W, "other").unwrap();
    assert!(matches!(g.require_pack(W, "default"), Err(Error::PackMismatch)));
    assert!(matches!(g.set_pack("nope", "x"), Err(Error::NoSuchWorld)));
}

#[test]
fn scrub_finds_corruption_and_backup_is_incremental() {
    let mut g = setup();
    let root = std::env::temp_dir().join(format!("mcmesh-maint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let cas_dir = root.join("cas");
    g.cas = crate::cas::Cas::open(&cas_dir).unwrap();
    g.create_world("w9", "m", "1.21.1", "neoforge").unwrap();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let h = g.cas.put(b"chunk-data").unwrap();
    wal_row(&g, &a.lease_id, 1, "put:region", 1, 1, h);
    wal_row(&g, &a.lease_id, 2, "barrier", 0, 0, [0; 32]);
    g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 1_000).unwrap();
    assert!(g.scrub(&cas_dir).unwrap().ok());
    let dest = root.join("bk");
    let (c1, _) = g.backup(&cas_dir, &dest).unwrap();
    let (c2, s2) = g.backup(&cas_dir, &dest).unwrap();
    assert!(c1 > 0 && c2 == 0 && s2 == c1);
    assert!(dest.join("mcmesh.db").is_file());
    let x = crate::cas::hex(&h);
    let blob = cas_dir.join(&x[0..2]).join(&x[2..4]).join(&x);
    std::fs::write(&blob, b"garbage").unwrap();
    let rep = g.scrub(&cas_dir).unwrap();
    assert!(!rep.ok() && rep.corrupt == vec![x.clone()], "{rep:?}");
    std::fs::remove_file(&blob).unwrap();
    let rep = g.scrub(&cas_dir).unwrap();
    assert!(rep.missing.contains(&x), "{rep:?}");
}

#[test]
fn revision_chain_detects_tampering() {
    let mut g = setup();
    let root = std::env::temp_dir().join(format!("mcmesh-chain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    g.cas = crate::cas::Cas::open(&root.join("cas")).unwrap();
    g.create_world("w8", "m", "1.21.1", "neoforge").unwrap();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let mut base = a.base_rev.clone();
    for i in 0..3u8 {
        let h = g.cas.put(&[i; 8]).unwrap();
        wal_row(&g, &a.lease_id, 1 + 2 * i as i64, "put:region", i as i32, 0, h);
        wal_row(&g, &a.lease_id, 2 + 2 * i as i64, "barrier", 0, 0, [0; 32]);
        base = g.commit(&a.lease_id, a.epoch, &base, CommitKind::Autosave, false, 1_000 + i as u64).unwrap().id;
    }
    assert!(g.scrub(&root.join("cas")).unwrap().chain_breaks.is_empty());
    g.db().execute("UPDATE revisions SET kind='MANUAL' WHERE id='w1:R_0002'", []).unwrap();
    let rep = g.scrub(&root.join("cas")).unwrap();
    assert_eq!(rep.chain_breaks, vec!["w1:R_0002".to_string()]);
}

#[test]
fn scan_revision_names_the_corrupt_and_missing_blobs() {
    let mut g = setup();
    let root = std::env::temp_dir().join(format!("mcmesh-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let cas_dir = root.join("cas");
    g.cas = crate::cas::Cas::open(&cas_dir).unwrap();
    g.create_world("w7", "m", "1.21.1", "neoforge").unwrap();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let (h1, h2) = (g.cas.put(b"chunk-one").unwrap(), g.cas.put(b"chunk-two").unwrap());
    wal_row(&g, &a.lease_id, 1, "put:region", 1, 1, h1);
    wal_row(&g, &a.lease_id, 2, "put:region", 2, 1, h2);
    wal_row(&g, &a.lease_id, 3, "barrier", 0, 0, [0; 32]);
    let r = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 1_000).unwrap();
    let clean = g.scan_revision(&r.id).unwrap();
    assert!(clean.ok() && clean.blobs >= 2, "{clean:?}");
    let path = |h: &[u8; 32]| {
        let x = crate::cas::hex(h);
        cas_dir.join(&x[0..2]).join(&x[2..4]).join(x)
    };
    std::fs::write(path(&h1), b"garbage").unwrap();
    std::fs::remove_file(path(&h2)).unwrap();
    let bad = g.scan_revision(&r.id).unwrap();
    assert_eq!(bad.corrupt, vec![crate::cas::hex(&h1)]);
    assert_eq!(bad.missing, vec![crate::cas::hex(&h2)]);
    assert!(!bad.ok());
}

#[test]
fn heartbeat_stores_players_and_missing_field_keeps_it() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    assert_eq!(g.lease_players(W).unwrap(), None);
    g.heartbeat(&a.lease_id, a.epoch, 1_000).unwrap();
    assert_eq!(g.lease_players(W).unwrap(), None);
    g.heartbeat_players(&a.lease_id, a.epoch, Some(3), 2_000).unwrap();
    assert_eq!(g.lease_players(W).unwrap(), Some(3));
    g.heartbeat(&a.lease_id, a.epoch, 3_000).unwrap();
    assert_eq!(g.lease_players(W).unwrap(), Some(3));
    g.heartbeat_players(&a.lease_id, a.epoch, Some(0), 4_000).unwrap();
    assert_eq!(g.lease_players(W).unwrap(), Some(0));
    g.heartbeat_players(&a.lease_id, a.epoch, None, 5_000).unwrap();
    assert_eq!(g.lease_players(W).unwrap(), Some(0));
}

#[test]
fn players_rejects_stale_epoch_and_resets_for_new_lease() {
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    assert!(matches!(g.heartbeat_players(&a.lease_id, a.epoch + 1, Some(5), 1_000), Err(Error::StaleEpoch)));
    assert_eq!(g.lease_players(W).unwrap(), None);
    g.heartbeat_players(&a.lease_id, a.epoch, Some(4), 1_000).unwrap();
    g.tick(100_000).unwrap();
    assert_eq!(g.lease_players(W).unwrap(), None);
    let b = host(g.join(W, "dev-b", hw(2, 5.0), 100_000).unwrap());
    assert_eq!(b.epoch, 2);
    assert_eq!(g.lease_players(W).unwrap(), None);
}

#[test]
fn players_survive_restart() {
    let dir = std::env::temp_dir().join(format!("mcmesh-test-players-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    {
        let mut g = Gateway::open(Connection::open(&dir).unwrap(), test_cas(), 0).unwrap();
        g.create_world(W, "x", "1.21.1", "neoforge").unwrap();
        g.add_member(W, "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
        let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
        g.heartbeat_players(&a.lease_id, a.epoch, Some(2), 1_000).unwrap();
    }
    let g = Gateway::open(Connection::open(&dir).unwrap(), test_cas(), 1_000_000).unwrap();
    assert_eq!(g.lease_players(W).unwrap(), Some(2));
    let _ = std::fs::remove_file(&dir);
}

const HOLD: u64 = 180_000;

fn locked_host(g: &mut Gateway, tier: u8, score: f64) -> Grant {
    let a = host(g.join(W, "dev-a", hw(tier, score), 0).unwrap());
    g.host_ready(&a.lease_id, a.epoch).unwrap();
    a
}

fn migrating(g: &Gateway) -> bool {
    g.state(W).unwrap().0 == "MIGRATING"
}

#[test]
fn anchor_never_displaces_host_below_two_players() {
    for players in [None, Some(0), Some(1)] {
        let mut g = setup();
        g.set_anchor("dev-b", true).unwrap();
        let a = locked_host(&mut g, 3, 1.0);
        g.heartbeat_players(&a.lease_id, a.epoch, players, 10_000).unwrap();
        g.join(W, "dev-b", hw(1, 50.0), HOLD + 1_000).unwrap();
        assert!(!migrating(&g), "players {players:?}");
        assert!(g.takeover_in(W, "dev-b", 1, 50.0, HOLD + 1_000).is_none());
    }
}

#[test]
fn anchor_displaces_host_at_exactly_two_players() {
    let mut g = setup();
    g.set_anchor("dev-b", true).unwrap();
    let a = locked_host(&mut g, 3, 1.0);
    g.heartbeat_players(&a.lease_id, a.epoch, Some(2), 10_000).unwrap();
    g.join(W, "dev-b", hw(1, 50.0), HOLD + 1_000).unwrap();
    assert!(migrating(&g));
}

#[test]
fn non_anchor_displaces_host_with_few_players() {
    let mut g = setup();
    let a = locked_host(&mut g, 3, 1.0);
    g.heartbeat_players(&a.lease_id, a.epoch, Some(1), 10_000).unwrap();
    g.join(W, "dev-b", hw(1, 50.0), HOLD + 1_000).unwrap();
    assert!(migrating(&g));
}

#[test]
fn anchor_host_is_displaced_by_players_under_rule_one_only() {
    let mut g = setup();
    g.set_anchor("dev-a", true).unwrap();
    let a = locked_host(&mut g, 3, 1.0);
    g.heartbeat_players(&a.lease_id, a.epoch, Some(0), 10_000).unwrap();
    g.join(W, "dev-b", hw(1, 50.0), HOLD + 1_000).unwrap();
    assert!(migrating(&g));
}

#[test]
fn margin_is_exactly_one_point_three() {
    let mut g = setup();
    locked_host(&mut g, 2, 10.0);
    g.join(W, "dev-b", hw(2, 12.99), HOLD).unwrap();
    assert!(!migrating(&g));
    g.join(W, "dev-b", hw(2, 13.0), HOLD).unwrap();
    assert!(migrating(&g));
}

#[test]
fn lower_tier_wins_without_margin() {
    let mut g = setup();
    locked_host(&mut g, 2, 10.0);
    g.join(W, "dev-b", hw(1, 1.0), HOLD).unwrap();
    assert!(migrating(&g));
}

#[test]
fn min_hold_boundary() {
    let mut g = setup();
    locked_host(&mut g, 3, 1.0);
    g.join(W, "dev-b", hw(1, 50.0), HOLD - 1).unwrap();
    assert!(!migrating(&g));
    g.join(W, "dev-b", hw(1, 50.0), HOLD).unwrap();
    assert!(migrating(&g));
}

#[test]
fn takeover_flag_is_required() {
    let mut g = setup();
    locked_host(&mut g, 3, 1.0);
    g.join(W, "dev-b", Hw { tier: 1, score: 50.0, wants_host: true, takeover: false }, HOLD * 2).unwrap();
    assert!(!migrating(&g));
}

#[test]
fn anchor_gets_no_special_rank_in_a_fresh_election() {
    let mut g = setup();
    g.add_member(W, "u-d", "dave", "dev-d", Role::HostEligible).unwrap();
    g.set_anchor("dev-b", true).unwrap();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    g.join(W, "dev-b", hw(2, 9.0), 1_000).unwrap();
    g.join(W, "dev-d", hw(1, 2.0), 1_000).unwrap();
    g.release(&a.lease_id, a.epoch, true).unwrap();
    g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Shutdown, true, 2_000).unwrap();
    let elected: String = g
        .db()
        .query_row("SELECT device_id FROM leases WHERE world_id=? AND status='ACTIVE'", [W], |r| r.get(0))
        .unwrap();
    assert_eq!(elected, "dev-d");
}

#[test]
fn signed_commits_verify_against_the_registered_key_and_keep_the_signature() {
    use ed25519_dalek::{Signer, SigningKey};
    let mut g = setup();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let sign = |base: &str, last: bool, barrier: i64| {
        sk.sign(&crate::devsig::commit_message(W, &a.lease_id, a.epoch, base, if last { "SHUTDOWN" } else { "AUTOSAVE" }, last, barrier)).to_bytes()
    };
    let no_key = sign(&a.base_rev, false, -1);
    assert!(matches!(g.commit_signed(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, Some(&no_key), 1_000), Err(Error::NoDeviceKey)));

    g.set_device_key("dev-a", &pk).unwrap();
    g.set_device_key("dev-a", &pk).unwrap();
    assert!(matches!(g.set_device_key("dev-a", &[1u8; 32]), Err(Error::DeviceKeySet)), "first key wins");
    assert!(matches!(g.set_device_key("dev-b", &pk), Err(Error::DeviceKeySet)), "a key belongs to one device");

    let wrong_barrier = sign(&a.base_rev, false, 99);
    assert!(matches!(g.commit_signed(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, Some(&wrong_barrier), 1_000), Err(Error::BadSignature)));
    let wrong_kind = sign(&a.base_rev, true, -1);
    assert!(matches!(g.commit_signed(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, Some(&wrong_kind), 1_000), Err(Error::BadSignature)));
    assert_eq!(g.head(W).unwrap(), a.base_rev, "a refused signature commits nothing");

    let good = sign(&a.base_rev, false, -1);
    let r = g.commit_signed(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, Some(&good), 1_000).unwrap();
    let (sig, signer): (Vec<u8>, Vec<u8>) =
        g.db.query_row("SELECT sig, signer FROM revisions WHERE id=?", rusqlite::params![r.id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!((sig, signer), (good.to_vec(), pk.to_vec()));

    let unsigned = g.commit(&a.lease_id, a.epoch, &r.id, CommitKind::Autosave, false, 2_000).unwrap();
    let none: Option<Vec<u8>> = g.db.query_row("SELECT sig FROM revisions WHERE id=?", rusqlite::params![unsigned.id], |row| row.get(0)).unwrap();
    assert_eq!(none, None, "unsigned commits stay unsigned");
}
