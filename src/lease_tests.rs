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

#[test]
fn recover_head_finds_the_newest_intact_revision_and_moves_the_head_there() {
    let mut g = setup();
    let root = std::env::temp_dir().join(format!("mcmesh-recover-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let cas_dir = root.join("cas");
    g.cas = crate::cas::Cas::open(&cas_dir).unwrap();
    // creating any world writes the shared empty tree into the new store
    g.create_world("w8", "m", "1.21.1", "neoforge").unwrap();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let blobs: Vec<[u8; 32]> = (1..=3).map(|i| g.cas.put(format!("chunk-{i}").as_bytes()).unwrap()).collect();
    let mut base = a.base_rev.clone();
    let mut revs = Vec::new();
    for (i, h) in blobs.iter().enumerate() {
        let n = i as i64 * 2;
        wal_row(&g, &a.lease_id, n + 1, "put:region", i as i32 + 1, 1, *h);
        wal_row(&g, &a.lease_id, n + 2, "barrier", 0, 0, [0; 32]);
        let last = i == 2;
        let kind = if last { CommitKind::Shutdown } else { CommitKind::Autosave };
        let r = g.commit(&a.lease_id, a.epoch, &base, kind, last, 1_000 + i as u64).unwrap();
        base = r.id.clone();
        revs.push(r.id);
    }
    let r = g.recover_head(W, false).unwrap();
    assert!(r.head_ok && r.applied.is_none(), "a healthy head is left alone");

    let path = |h: &[u8; 32]| {
        let x = crate::cas::hex(h);
        cas_dir.join(&x[0..2]).join(&x[2..4]).join(x)
    };
    std::fs::remove_file(path(&blobs[2])).unwrap();
    std::fs::write(path(&blobs[1]), b"garbage").unwrap();
    let dry = g.recover_head(W, false).unwrap();
    assert!(!dry.head_ok);
    assert_eq!(dry.good.as_deref(), Some(revs[0].as_str()), "the two newest are damaged, the first autosave is intact");
    assert_eq!(dry.damaged, vec![revs[2].clone(), revs[1].clone()]);
    assert!(dry.applied.is_none());
    assert_eq!(g.head(W).unwrap(), revs[2], "a dry run changes nothing");

    let done = g.recover_head(W, true).unwrap();
    let new_head = done.applied.expect("head moved");
    assert_eq!(g.head(W).unwrap(), new_head);
    assert!(g.recover_head(W, false).unwrap().head_ok);
    let kind: String = g.db.query_row("SELECT kind FROM revisions WHERE id=?", rusqlite::params![new_head], |row| row.get(0)).unwrap();
    assert_eq!(kind, "ROLLBACK");
    assert!(g.scan_revision(&revs[2]).is_ok(), "the damaged revisions stay in the history");
}

#[test]
fn recover_head_without_an_intact_revision_reports_it_and_changes_nothing() {
    let mut g = setup();
    let root = std::env::temp_dir().join(format!("mcmesh-recover2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let cas_dir = root.join("cas");
    g.cas = crate::cas::Cas::open(&cas_dir).unwrap();
    g.create_world("w9", "m", "1.21.1", "neoforge").unwrap();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let h = g.cas.put(b"only chunk").unwrap();
    wal_row(&g, &a.lease_id, 1, "put:region", 1, 1, h);
    wal_row(&g, &a.lease_id, 2, "barrier", 0, 0, [0; 32]);
    let r = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Shutdown, true, 1_000).unwrap();
    let x = crate::cas::hex(&h);
    std::fs::remove_file(cas_dir.join(&x[0..2]).join(&x[2..4]).join(x)).unwrap();
    let out = g.recover_head(W, true).unwrap();
    assert!(!out.head_ok, "head still intact: {out:?}");
    assert!(out.good.is_none(), "found a good revision: {out:?}");
    assert!(out.applied.is_none(), "applied: {out:?}");
    assert_eq!(g.head(W).unwrap(), r.id);
}

#[test]
fn a_struggling_host_is_replaced_sooner_and_by_a_smaller_margin() {
    let mut g = setup();
    let a = locked_host(&mut g, 2, 10.0);
    // healthy host: 5% better is not enough and 40 s is inside the hold
    g.join(W, "dev-b", hw(2, 10.6), 40_000).unwrap();
    assert!(!migrating(&g));
    // the host reports a heavy shed level
    g.heartbeat_status(&a.lease_id, a.epoch, Some(3), Some(2), 41_000).unwrap();
    assert!(g.takeover_in(W, "dev-b", 2, 10.6, 41_000).is_some(), "the margin is now 1.05");
    g.join(W, "dev-b", hw(2, 10.4), 41_000).unwrap();
    assert!(!migrating(&g), "4% better is still not enough");
    g.join(W, "dev-b", hw(2, 10.0), 41_000).unwrap();
    assert!(!migrating(&g), "an equal machine never takes over, no ping-pong");
    g.join(W, "dev-b", hw(2, 10.6), 29_000).unwrap();
    assert!(!migrating(&g), "the short hold of 30 s still applies");
    g.join(W, "dev-b", hw(2, 10.6), 41_000).unwrap();
    assert!(migrating(&g));
}

#[test]
fn a_host_that_recovers_gets_the_normal_terms_back() {
    let mut g = setup();
    let a = locked_host(&mut g, 2, 10.0);
    g.heartbeat_status(&a.lease_id, a.epoch, None, Some(3), 1_000).unwrap();
    g.heartbeat_status(&a.lease_id, a.epoch, None, Some(0), 2_000).unwrap();
    g.join(W, "dev-b", hw(2, 10.6), 41_000).unwrap();
    assert!(!migrating(&g));
    g.heartbeat_status(&a.lease_id, a.epoch, None, None, 3_000).unwrap();
    g.join(W, "dev-b", hw(2, 12.99), HOLD).unwrap();
    assert!(!migrating(&g), "no load field keeps the last value, which is 0");
}

#[test]
fn a_struggling_host_does_not_lift_the_anchor_rule() {
    let mut g = setup();
    let a = locked_host(&mut g, 2, 10.0);
    g.set_anchor("dev-b", true).unwrap();
    g.heartbeat_status(&a.lease_id, a.epoch, Some(1), Some(3), 1_000).unwrap();
    g.join(W, "dev-b", hw(2, 50.0), 41_000).unwrap();
    assert!(!migrating(&g), "an anchor still never displaces a host with fewer than 2 players");
    g.heartbeat_status(&a.lease_id, a.epoch, Some(2), Some(3), 42_000).unwrap();
    g.join(W, "dev-b", hw(2, 50.0), 43_000).unwrap();
    assert!(migrating(&g));
}

fn vote_world() -> (Gateway, Grant) {
    let mut g = setup();
    g.add_member(W, "u-d", "dave", "dev-d", Role::HostEligible).unwrap();
    g.ops_init().unwrap();
    g.set_vote_enabled(W, true).unwrap();
    let a = locked_host(&mut g, 2, 5.0);
    (g, a)
}

const T: u64 = 70_000;

#[test]
fn a_vote_needs_the_switch_a_live_host_and_recent_guests() {
    let mut g = setup();
    g.add_member(W, "u-d", "dave", "dev-d", Role::HostEligible).unwrap();
    g.ops_init().unwrap();
    locked_host(&mut g, 2, 5.0);
    g.join(W, "dev-b", hw(2, 9.0), T).unwrap();
    assert_eq!(g.propose_handover(W, "dev-b", 2, 9.0, T).unwrap().unwrap_err(), VoteError::Disabled);
    g.set_vote_enabled(W, true).unwrap();
    assert_eq!(g.propose_handover(W, "dev-d", 2, 9.0, T).unwrap().unwrap_err(), VoteError::NotGuest, "dave never joined as a guest");
    assert_eq!(g.propose_handover(W, "dev-a", 2, 9.0, T).unwrap().unwrap_err(), VoteError::NoLiveHost, "the host cannot propose itself");
    assert_eq!(g.propose_handover(W, "dev-b", 2, 9.0, 30_000).unwrap().unwrap_err(), VoteError::TooEarly);
    assert_eq!(g.propose_handover(W, "dev-b", 2, 5.5, T).unwrap().unwrap_err(), VoteError::NotBetter, "10% is under the 15% margin");
    assert!(g.propose_handover(W, "dev-b", 2, 9.0, T).unwrap().is_ok());
    assert_eq!(g.propose_handover(W, "dev-b", 2, 9.0, T + 1).unwrap().unwrap_err(), VoteError::RoundOpen);
}

#[test]
fn a_majority_makes_the_takeover_immediate_and_it_goes_through_the_normal_handover() {
    let (mut g, a) = vote_world();
    for (d, s) in [("dev-b", 9.0), ("dev-d", 3.0), ("dev-c", 1.0)] {
        g.join(W, d, hw(2, s), T).unwrap();
    }
    let r = g.propose_handover(W, "dev-b", 2, 9.0, T).unwrap().unwrap();
    assert_eq!((r.yes, r.needed, r.approved, r.improvement_pct), (1, 2, false, 80), "three guests need two yes votes");
    assert!(g.takeover_in(W, "dev-b", 2, 9.0, T).is_some_and(|s| s > 0), "not yet: the normal hold still applies");
    g.join(W, "dev-b", hw(2, 9.0), T + 1).unwrap();
    assert!(!migrating(&g), "a bid before approval still needs the normal hold");

    let r = g.cast_handover_vote(W, "dev-d", true, T + 2).unwrap().unwrap();
    assert!(r.approved && r.yes == 2);
    assert_eq!(g.takeover_in(W, "dev-b", 2, 9.0, T + 2), Some(0));
    assert_eq!(g.takeover_in(W, "dev-d", 2, 3.0, T + 2), None, "approval belongs to the proposer only");
    g.join(W, "dev-b", hw(2, 9.0), T + 3).unwrap();
    assert!(migrating(&g));
    let dirs = g.heartbeat(&a.lease_id, a.epoch, T + 4).unwrap();
    assert_eq!(dirs, vec![Directive::MigratePrepare { target_device: Some("dev-b".into()), deadline_ms: 20_000 }], "the host is asked to hand over as usual");
    assert!(g.handover_round(W, "dev-b", T + 5).unwrap().is_none(), "the round is spent");
}

#[test]
fn the_host_cannot_vote_and_a_lone_guest_can_never_force_a_move() {
    let (mut g, _) = vote_world();
    g.join(W, "dev-b", hw(2, 9.0), T).unwrap();
    let r = g.propose_handover(W, "dev-b", 2, 9.0, T).unwrap().unwrap();
    assert_eq!((r.needed, r.approved), (2, false), "at least two yes votes are always needed");
    assert_eq!(g.cast_handover_vote(W, "dev-a", true, T + 1).unwrap().unwrap_err(), VoteError::NotGuest, "the host's own player never decides");
    assert_eq!(g.cast_handover_vote(W, "dev-d", true, T + 1).unwrap().unwrap_err(), VoteError::NotGuest, "dave is not playing");
    assert!(!g.takeover_in(W, "dev-b", 2, 9.0, T + 1).is_some_and(|s| s == 0));
}

#[test]
fn a_lost_vote_starts_a_cooldown_and_a_stale_round_expires() {
    let (mut g, _) = vote_world();
    for (d, s) in [("dev-b", 9.0), ("dev-d", 3.0), ("dev-c", 1.0)] {
        g.join(W, d, hw(2, s), T).unwrap();
    }
    g.propose_handover(W, "dev-b", 2, 9.0, T).unwrap().unwrap();
    g.cast_handover_vote(W, "dev-d", false, T + 1).unwrap().unwrap();
    let lost = g.cast_handover_vote(W, "dev-c", false, T + 2).unwrap();
    assert_eq!(lost.unwrap_err(), VoteError::NoRound, "two no votes of three guests make a majority impossible");
    assert_eq!(g.propose_handover(W, "dev-b", 2, 9.0, T + 3).unwrap().unwrap_err(), VoteError::Cooldown);
    assert!(g.propose_handover(W, "dev-b", 2, 9.0, T + 11 * 60_000).unwrap().is_ok(), "ten minutes later the candidate may try again");

    let (mut g, _) = vote_world();
    g.join(W, "dev-b", hw(2, 9.0), T).unwrap();
    g.propose_handover(W, "dev-b", 2, 9.0, T).unwrap().unwrap();
    assert!(g.handover_round(W, "dev-b", T + 299_000).unwrap().is_some());
    assert!(g.handover_round(W, "dev-b", T + 301_000).unwrap().is_none(), "a round lives five minutes");
}

#[test]
fn switching_the_vote_off_drops_an_open_round() {
    let (mut g, _) = vote_world();
    g.join(W, "dev-b", hw(2, 9.0), T).unwrap();
    g.propose_handover(W, "dev-b", 2, 9.0, T).unwrap().unwrap();
    g.set_vote_enabled(W, false).unwrap();
    assert!(g.handover_round(W, "dev-b", T + 1).unwrap().is_none());
}

#[test]
fn a_region_rollback_restores_only_the_chunks_inside_the_rectangle() {
    use crate::manifest::Item;
    let mut g = setup();
    let root = std::env::temp_dir().join(format!("mcmesh-rollback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    g.cas = crate::cas::Cas::open(root.join("cas")).unwrap();
    g.create_world("w5", "m", "1.21.1", "neoforge").unwrap();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let put = |g: &Gateway, text: &str| g.cas.put(text.as_bytes()).unwrap();
    // revision 1: chunks 1 and 2 as "v1"; revision 2: both change, chunk 3 appears; the second one ends the session
    let (a1, b1) = (put(&g, "a1"), put(&g, "b1"));
    wal_row(&g, &a.lease_id, 1, "put:region", 1, 1, a1);
    wal_row(&g, &a.lease_id, 2, "put:region", 2, 1, b1);
    wal_row(&g, &a.lease_id, 3, "barrier", 0, 0, [0; 32]);
    let r1 = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 1_000).unwrap();
    let (a2, b2, c2) = (put(&g, "a2"), put(&g, "b2"), put(&g, "c2"));
    wal_row(&g, &a.lease_id, 4, "put:region", 1, 1, a2);
    wal_row(&g, &a.lease_id, 5, "put:region", 2, 1, b2);
    wal_row(&g, &a.lease_id, 6, "put:region", 3, 1, c2);
    wal_row(&g, &a.lease_id, 7, "barrier", 0, 0, [0; 32]);
    let r2 = g.commit(&a.lease_id, a.epoch, &r1.id, CommitKind::Shutdown, true, 2_000).unwrap();

    let leaves = |g: &Gateway, rev: &str| {
        let mut m = std::collections::BTreeMap::new();
        crate::manifest::for_each_leaf(&g.cas, g.revision_root(rev).unwrap(), &mut |item, h| {
            if let Item::Chunk(k) = item {
                m.insert(k.cx, h);
            }
            Ok(())
        })
        .unwrap();
        m
    };
    assert_eq!(g.rollback_region(W, &r1.id, "minecraft:overworld", 2, 0, 1, 9).unwrap(), Err("BAD_REGION"));
    assert_eq!(g.rollback_region(W, "nope", "minecraft:overworld", 0, 0, 9, 9).unwrap(), Err("NO_SUCH_REVISION"));
    assert_eq!(g.rollback_region(W, &r1.id, "minecraft:the_nether", 0, 0, 9, 9).unwrap(), Err("NOTHING_TO_ROLLBACK"), "nothing in that dimension differs");

    let done = g.rollback_region(W, &r1.id, "minecraft:overworld", 0, 0, 1, 9).unwrap().unwrap();
    assert_eq!((done.restored, done.removed), (1, 0), "only chunk 1 is inside the rectangle");
    assert_eq!(g.head(W).unwrap(), done.revision);
    let now = leaves(&g, &done.revision);
    assert_eq!(now[&1], a1, "inside: back to the old content");
    assert_eq!(now[&2], b2, "outside: untouched");
    assert_eq!(now[&3], c2, "outside: untouched");

    // chunk 3 did not exist in revision 1, so a rectangle around it removes it
    let gone = g.rollback_region(W, &r1.id, "minecraft:overworld", 3, 0, 3, 9).unwrap().unwrap();
    assert_eq!((gone.restored, gone.removed), (0, 1));
    assert!(!leaves(&g, &gone.revision).contains_key(&3));
    let kind: String = g.db.query_row("SELECT kind FROM revisions WHERE id=?", rusqlite::params![gone.revision], |row| row.get(0)).unwrap();
    assert_eq!(kind, "ROLLBACK");
    assert!(g.scan_revision(&r2.id).unwrap().ok(), "earlier revisions stay intact");
}

#[test]
fn a_region_rollback_is_refused_while_a_host_is_running() {
    let mut g = setup();
    let a = locked_host(&mut g, 2, 5.0);
    assert_eq!(g.rollback_region(W, &a.base_rev, "minecraft:overworld", 0, 0, 1, 1).unwrap(), Err("WORLD_RUNNING"));
}

#[test]
fn scrub_flags_a_signer_that_matches_no_registered_device() {
    let mut g = setup();
    let root = std::env::temp_dir().join(format!("mcmesh-signer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    g.cas = crate::cas::Cas::open(&root.join("cas")).unwrap();
    g.create_world("w9", "m", "1.21.1", "neoforge").unwrap();
    let a = host(g.join(W, "dev-a", hw(2, 5.0), 0).unwrap());
    let h = g.cas.put(&[1; 8]).unwrap();
    wal_row(&g, &a.lease_id, 1, "put:region", 0, 0, h);
    wal_row(&g, &a.lease_id, 2, "barrier", 0, 0, [0; 32]);
    let rev = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 1_000).unwrap();
    g.set_device_key("dev-a", &[7; 32]).unwrap();
    g.db().execute("UPDATE revisions SET sig=?, signer=? WHERE id=?", rusqlite::params![[0u8; 64].as_slice(), [7u8; 32].as_slice(), rev.id]).unwrap();
    assert!(g.scrub(&root.join("cas")).unwrap().unknown_signers.is_empty());
    g.db().execute("UPDATE revisions SET signer=? WHERE id=?", rusqlite::params![[8u8; 32].as_slice(), rev.id]).unwrap();
    let rep = g.scrub(&root.join("cas")).unwrap();
    assert_eq!(rep.unknown_signers, vec![rev.id.clone()]);
    assert!(!rep.ok());
}
