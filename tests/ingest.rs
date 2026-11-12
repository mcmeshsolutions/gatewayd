use gatewayd::cas::{sha256, Cas, Hash};
use gatewayd::chain::{next_mac, Entry};
use gatewayd::lease::{CommitKind, Error, Gateway, Grant, Hw, Join, Role};
use gatewayd::manifest::{aux_lookup, lookup, Key, Kind};
use gatewayd::wal::Frame;
use rusqlite::Connection;
use std::sync::atomic::{AtomicU32, Ordering};

const W: &str = "w1";
static N: AtomicU32 = AtomicU32::new(0);

fn setup() -> Gateway {
    let dir = std::env::temp_dir().join(format!("mcmesh-ing-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world(W, "w", "1.21.1", "neoforge").unwrap();
    g.add_member(W, "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_member(W, "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g
}

fn host(g: &mut Gateway, dev: &str, now: u64) -> Grant {
    match g.join(W, dev, Hw { tier: 2, score: 5.0, wants_host: true, takeover: true }, now).unwrap() {
        Join::Host(x) => x,
        o => panic!("expected host, got {o:?}"),
    }
}

struct Writer {
    key: [u8; 32],
    prev: [u8; 32],
    seq: u64,
}

impl Writer {
    fn new(g: &Grant) -> Self {
        Writer { key: g.hmac_key, prev: [0; 32], seq: 0 }
    }
    fn frame(&mut self, op: &str, dim: &str, cx: i32, cz: i32, hash: Hash) -> Frame {
        let e = Entry { seq: self.seq, dim, kind: op, cx, cz, hash: &hash };
        let mac = next_mac(&self.key, &self.prev, &e);
        self.prev = mac;
        self.seq += 1;
        Frame { seq: e.seq, op: op.into(), dim: dim.into(), cx, cz, hash, mac: mac.to_vec() }
    }
}

const OW: &str = "minecraft:overworld";

fn key(cx: i32, cz: i32) -> Key {
    Key { dim: OW.into(), kind: Kind::Region, cx, cz }
}

#[test]
fn commit_builds_root_from_wal_up_to_last_barrier() {
    let mut g = setup();
    let a = host(&mut g, "dev-a", 0);
    let (c1, c2, lv) = (g.cas().put(b"chunk1").unwrap(), g.cas().put(b"chunk2").unwrap(), g.cas().put(b"level").unwrap());
    let mut w = Writer::new(&a);
    let frames = vec![
        w.frame("put:region", OW, 1, 1, c1),
        w.frame("aux_put", "level.dat", 0, 0, lv),
        w.frame("barrier", "", 0, 0, [0; 32]),
        w.frame("put:region", OW, 2, 2, c2),
    ];
    assert_eq!(g.wal_append(&a.lease_id, a.epoch, &frames).unwrap(), 4);
    let rev = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 100).unwrap();
    let root = rev_root(&g, &rev.id);
    assert_eq!(lookup(g.cas(), root, &key(1, 1)).unwrap(), Some(c1));
    assert_eq!(aux_lookup(g.cas(), root, "level.dat").unwrap(), Some(lv));
    assert_eq!(lookup(g.cas(), root, &key(2, 2)).unwrap(), None, "write after the barrier is not committed yet");

    let more = vec![w.frame("barrier", "", 0, 0, [0; 32])];
    g.wal_append(&a.lease_id, a.epoch, &more).unwrap();
    let rev2 = g.commit(&a.lease_id, a.epoch, &rev.id, CommitKind::Autosave, false, 200).unwrap();
    let root2 = rev_root(&g, &rev2.id);
    assert_eq!(lookup(g.cas(), root2, &key(2, 2)).unwrap(), Some(c2), "chain and wal survive across commits");
    assert_eq!(lookup(g.cas(), root2, &key(1, 1)).unwrap(), Some(c1));
}

fn rev_root(g: &Gateway, rev: &str) -> Hash {
    let first = format!("{W}:R_");
    assert!(rev.starts_with(&first));
    g.revision_root(rev).unwrap()
}

#[test]
fn tampered_replayed_gapped_and_unknown_frames_are_rejected_atomically() {
    let mut g = setup();
    let a = host(&mut g, "dev-a", 0);
    let c = g.cas().put(b"x").unwrap();
    let mut w = Writer::new(&a);
    let good = w.frame("put:region", OW, 1, 1, c);

    let mut forged = Writer::new(&a);
    forged.key = [7; 32];
    let bad = forged.frame("put:region", OW, 1, 1, c);
    assert!(matches!(g.wal_append(&a.lease_id, a.epoch, &[bad]), Err(Error::BadMac)));

    let mut moved = Writer::new(&a);
    let mut f = moved.frame("put:region", OW, 1, 1, c);
    f.cx = 9;
    assert!(matches!(g.wal_append(&a.lease_id, a.epoch, &[f]), Err(Error::BadMac)));

    let missing = w.frame("put:region", OW, 3, 3, sha256(b"never uploaded"));
    assert!(matches!(g.wal_append(&a.lease_id, a.epoch, &[good_copy(&good), missing]), Err(Error::MissingBlob)));
    // the batch above failed as a whole, so seq 0 is still free
    assert_eq!(g.wal_append(&a.lease_id, a.epoch, &[good_copy(&good)]).unwrap(), 1);
    assert!(matches!(g.wal_append(&a.lease_id, a.epoch, &[good_copy(&good)]), Err(Error::BadFrame(_))), "replay");

    let nonsense = Writer { seq: 1, key: a.hmac_key, prev: good.mac.clone().try_into().unwrap() }.frame("explode", OW, 0, 0, c);
    assert!(matches!(g.wal_append(&a.lease_id, a.epoch, &[nonsense]), Err(Error::BadFrame(_))));
    let skipped = Writer { seq: 5, key: a.hmac_key, prev: [0; 32] }.frame("barrier", "", 0, 0, [0; 32]);
    assert!(matches!(g.wal_append(&a.lease_id, a.epoch, &[skipped]), Err(Error::BadFrame(_))));
    assert!(matches!(g.wal_append(&a.lease_id, a.epoch + 1, &[]), Err(Error::StaleEpoch)));
}

fn good_copy(f: &Frame) -> Frame {
    Frame { seq: f.seq, op: f.op.clone(), dim: f.dim.clone(), cx: f.cx, cz: f.cz, hash: f.hash, mac: f.mac.clone() }
}

#[test]
fn expiry_promotes_wal_to_last_barrier_as_recovered_revision() {
    let mut g = setup();
    let a = host(&mut g, "dev-a", 0);
    let b = g.join(W, "dev-b", Hw { tier: 2, score: 4.0, wants_host: true, takeover: true }, 1).unwrap();
    assert!(matches!(b, Join::Guest { .. }));
    let (c1, c2) = (g.cas().put(b"kept").unwrap(), g.cas().put(b"lost").unwrap());
    let mut w = Writer::new(&a);
    let frames = vec![
        w.frame("put:region", OW, 4, 4, c1),
        w.frame("barrier", "", 0, 0, [0; 32]),
        w.frame("put:region", OW, 5, 5, c2),
    ];
    g.wal_append(&a.lease_id, a.epoch, &frames).unwrap();
    assert!(matches!(g.join(W, "dev-b", Hw { tier: 2, score: 4.0, wants_host: true, takeover: true }, 40_000).unwrap(), Join::Guest { .. }));
    g.tick(46_000).unwrap();
    let head = g.state(W).unwrap();
    assert_eq!(head.0, "MIGRATING");
    let b2 = host_rejoin(&mut g);
    let root = g.revision_root(&b2.base_rev).unwrap();
    assert_eq!(lookup(g.cas(), root, &key(4, 4)).unwrap(), Some(c1));
    assert_eq!(lookup(g.cas(), root, &key(5, 5)).unwrap(), None, "unbarriered tail is dropped");
    assert!(matches!(g.wal_append(&a.lease_id, a.epoch, &[]), Err(Error::StaleEpoch)), "old host is fenced");
}

fn host_rejoin(g: &mut Gateway) -> Grant {
    match g.join(W, "dev-b", Hw { tier: 2, score: 4.0, wants_host: true, takeover: true }, 46_500).unwrap() {
        Join::Host(x) => x,
        o => panic!("expected the elected device to get the lease, got {o:?}"),
    }
}

#[test]
fn revert_adds_a_commit_with_old_content_and_only_when_idle() {
    let mut g = setup();
    g.add_member(W, "u-c", "carol", "dev-c", Role::Admin).unwrap();
    let a = host(&mut g, "dev-a", 0);
    let (c1, c2) = (g.cas().put(b"one").unwrap(), g.cas().put(b"two").unwrap());
    let mut w = Writer::new(&a);
    g.wal_append(&a.lease_id, a.epoch, &[w.frame("put:region", OW, 1, 1, c1), w.frame("barrier", "", 0, 0, [0; 32])]).unwrap();
    let r1 = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 100).unwrap();
    g.wal_append(&a.lease_id, a.epoch, &[w.frame("put:region", OW, 1, 1, c2), w.frame("barrier", "", 0, 0, [0; 32])]).unwrap();
    let r2 = g.commit(&a.lease_id, a.epoch, &r1.id, CommitKind::Shutdown, true, 200).unwrap();

    assert!(g.revert("dev-a", W, &r1.id).is_err(), "not an admin");
    let id = g.revert("dev-c", W, &r1.id).unwrap().unwrap();
    assert_eq!(lookup(g.cas(), g.revision_root(&id).unwrap(), &key(1, 1)).unwrap(), Some(c1));
    let list = g.revisions(W, 10).unwrap();
    assert_eq!(list[0]["kind"], "ROLLBACK");
    assert_eq!(list.len(), 4, "history is kept");
    let back = g.revert("dev-c", W, &r2.id).unwrap().unwrap();
    assert_eq!(lookup(g.cas(), g.revision_root(&back).unwrap(), &key(1, 1)).unwrap(), Some(c2), "a revert can be reverted");

    host(&mut g, "dev-a", 1_000);
    assert_eq!(g.revert("dev-c", W, &r1.id).unwrap(), Err("WORLD_RUNNING"));
}

#[test]
fn mod_requests_extend_the_allowlist_and_bench_shows_per_member() {
    let mut g = setup();
    g.add_member(W, "u-c", "carol", "dev-c", Role::Admin).unwrap();
    g.set_world_mods("dev-c", W, &serde_json::json!({ "allow": [{ "id": "create", "hash": "aa" }] })).unwrap();
    g.add_mod_requests("dev-a", W, &[("create".into(), "bb".into()), ("jei".into(), "cc".into())]).unwrap();
    assert_eq!(g.mod_requests(W).unwrap().len(), 2);
    assert!(g.resolve_mod_request("dev-a", W, "jei", "cc", true).is_err(), "not an admin");
    assert!(g.resolve_mod_request("dev-c", W, "create", "bb", true).unwrap());
    assert!(g.resolve_mod_request("dev-c", W, "jei", "cc", false).unwrap());
    assert!(g.mod_requests(W).unwrap().is_empty());
    let allow = g.world_mods(W).unwrap();
    assert_eq!(allow["allow"], serde_json::json!([{ "id": "create", "hash": "bb" }]));

    g.record_bench("dev-a", &serde_json::json!({ "cpu": 300, "cores": 8 })).unwrap();
    let m = g.members_hw(W).unwrap();
    assert!(m.iter().any(|v| v["hw"]["cpu"] == 300));
    assert!(m.iter().any(|v| v["hw"].is_null()));
}
