//! Seeded chaos simulation of the lease FSM: crashes, zombie hosts, races and clock jumps against the safety invariants.
use crate::lease::*;
use rusqlite::{params, Connection};

const W: &str = "w1";
const DEVS: [&str; 4] = ["dev-a", "dev-b", "dev-c", "dev-d"];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct Dev {
    name: &'static str,
    grant: Option<Grant>,
    base: String,
    crashed: bool,
    tier: u8,
    score: f64,
}

fn gateway(n: usize) -> Gateway {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let k = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let cas = crate::cas::Cas::open(std::env::temp_dir().join(format!("mcmesh-chaos-{}-{k}", std::process::id()))).unwrap();
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), cas, 0).unwrap();
    g.create_world(W, "chaos", "1.21.1", "neoforge").unwrap();
    for (i, d) in DEVS.iter().enumerate().take(n) {
        g.add_member(W, &format!("u-{i}"), d, d, Role::HostEligible).unwrap();
    }
    g
}

fn benign(e: &Error) -> bool {
    matches!(e, Error::StaleEpoch | Error::HeadMoved | Error::NotMember)
}

fn invariants(g: &Gateway, seed: u64, step: usize, last_epoch: &mut i64, last_seq: &mut i64) {
    let ctx = format!("seed {seed} step {step}");
    assert!(g.live_lease_count(W).unwrap() <= 1, "two live leases, {ctx}");
    let epoch: i64 = g.db().query_row("SELECT COALESCE(MAX(epoch),0) FROM leases WHERE world_id=?", params![W], |r| r.get(0)).unwrap();
    assert!(epoch >= *last_epoch, "epoch went backwards, {ctx}");
    *last_epoch = epoch;
    let mut st = g.db().prepare("SELECT seq, id, parent_id FROM revisions WHERE world_id=? ORDER BY seq").unwrap();
    let rows: Vec<(i64, String, Option<String>)> =
        st.query_map(params![W], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(|r| r.unwrap()).collect();
    for w in rows.windows(2) {
        assert_eq!(w[1].0, w[0].0 + 1, "revision seq gap, {ctx}");
        assert_eq!(w[1].2.as_deref(), Some(w[0].1.as_str()), "revision parent broken, {ctx}");
    }
    let head = rows.last().map(|r| r.0).unwrap_or(0);
    assert!(head >= *last_seq, "head moved backwards, {ctx}");
    *last_seq = head;
}

fn run(seed: u64, steps: usize, n: usize) {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut g = gateway(n);
    let mut devs: Vec<Dev> = DEVS
        .iter()
        .take(n)
        .map(|d| Dev { name: d, grant: None, base: String::new(), crashed: false, tier: 1 + rng.below(3) as u8, score: 1.0 + rng.below(90) as f64 / 10.0 })
        .collect();
    let (mut now, mut last_epoch, mut last_seq) = (0u64, 0i64, 0i64);
    // odd seeds flip a storage quota the world is already over; only joins and autosaves may be refused
    let over = seed % 2 == 1;
    if over {
        g.db().execute("INSERT INTO blob_world(hash,world_id,size) VALUES(zeroblob(32),?,1000)", params![W]).unwrap();
    }
    let quota = |g: &mut Gateway, on: bool| {
        let l = crate::quota::Limits { storage_bytes: on.then_some(1), ..Default::default() };
        g.set_limits(crate::quota::Scope::World, W, &l).unwrap();
    };

    for step in 0..steps {
        now += 500 + rng.below(20_000);
        if rng.below(40) == 0 {
            now += 60_000 + rng.below(120_000);
        }
        g.tick(now).unwrap();
        let i = rng.below(n as u64) as usize;
        let action = rng.below(10);
        let d = &mut devs[i];
        match action {
            0..=2 => {
                if d.crashed && rng.below(2) == 0 {
                    d.crashed = false;
                }
                if !d.crashed {
                    let hw = Hw { tier: d.tier, score: d.score, wants_host: true, takeover: rng.below(2) == 0 };
                    match g.join(W, d.name, hw, now) {
                        Ok(Join::Host(gr)) => {
                            d.base = gr.base_rev.clone();
                            d.grant = Some(gr);
                        }
                        Ok(_) => {}
                        Err(Error::Quota(_)) => assert!(over),
                        Err(e) => assert!(benign(&e), "join failed {e:?}, seed {seed} step {step}"),
                    }
                }
            }
            3..=5 => {
                if let Some(gr) = d.grant.clone() {
                    match g.heartbeat(&gr.lease_id, gr.epoch, now) {
                        Ok(dirs) => {
                            assert_eq!(g.lease_of_world(W).as_deref(), Some(gr.lease_id.as_str()), "fenced host heartbeat accepted, seed {seed} step {step}");
                            if !dirs.is_empty() && !d.crashed {
                                match g.commit(&gr.lease_id, gr.epoch, &d.base, CommitKind::Migrate, true, now) {
                                    Ok(_) => d.grant = None,
                                    Err(e) => assert!(benign(&e), "migrate commit {e:?}, seed {seed} step {step}"),
                                }
                            }
                        }
                        Err(e) => {
                            assert!(benign(&e), "heartbeat {e:?}, seed {seed} step {step}");
                            d.grant = None;
                        }
                    }
                }
            }
            6 => {
                if let Some(gr) = d.grant.clone() {
                    let _ = g.host_ready(&gr.lease_id, gr.epoch);
                    match g.commit(&gr.lease_id, gr.epoch, &d.base, CommitKind::Autosave, false, now) {
                        Ok(rev) => {
                            assert_eq!(g.lease_of_world(W).as_deref(), Some(gr.lease_id.as_str()), "fenced host committed, seed {seed} step {step}");
                            d.base = rev.id;
                        }
                        Err(Error::Quota(_)) => assert!(over),
                        Err(e) => assert!(benign(&e), "commit {e:?}, seed {seed} step {step}"),
                    }
                }
            }
            7 => d.crashed = true,
            8 => {
                if let Some(gr) = d.grant.clone() {
                    let guests = rng.below(2) == 0;
                    if g.release(&gr.lease_id, gr.epoch, guests).is_ok() {
                        match g.commit(&gr.lease_id, gr.epoch, &d.base, CommitKind::Shutdown, true, now) {
                            Ok(_) => d.grant = None,
                            Err(e) => assert!(benign(&e), "shutdown commit {e:?}, seed {seed} step {step}"),
                        }
                    }
                }
            }
            9 if over => quota(&mut g, rng.below(2) == 0),
            _ => {}
        }
        invariants(&g, seed, step, &mut last_epoch, &mut last_seq);
    }

    // everything healthy again: the world must be hostable within bounded time
    quota(&mut g, false);
    for d in devs.iter_mut() {
        d.crashed = false;
    }
    let mut hosted = false;
    for _ in 0..40 {
        now += 10_000;
        g.tick(now).unwrap();
        for d in devs.iter_mut() {
            let hw = Hw { tier: d.tier, score: d.score, wants_host: true, takeover: false };
            if let Ok(Join::Host(gr)) = g.join(W, d.name, hw, now) {
                let _ = g.host_ready(&gr.lease_id, gr.epoch);
                d.grant = Some(gr);
            }
            if let Some(gr) = &d.grant {
                let _ = g.heartbeat(&gr.lease_id, gr.epoch, now);
            }
        }
        if g.state(W).unwrap().0 == "LOCKED" {
            hosted = true;
            break;
        }
    }
    assert!(hosted, "world never became hostable again, seed {seed}");
}

#[test]
fn chaos_two_to_four_devices() {
    for seed in 1..=300u64 {
        run(seed, 400, 2 + (seed % 3) as usize);
    }
}
