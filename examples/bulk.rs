//! Timing of the gateway core on a synthetic world: how long does a commit hold the gateway lock?
//! usage: cargo run --release --example bulk -- [chunks, default 100000]
use gatewayd::chain::{next_mac, Entry};
use gatewayd::lease::{CommitKind, Gateway, Hw, Join, Role};
use gatewayd::wal::Frame;
use rusqlite::Connection;
use std::time::Instant;

fn main() {
    let n: i32 = std::env::args().nth(1).and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let side = (n as f64).sqrt().ceil() as i32;
    let dir = std::env::temp_dir().join(format!("mcmesh-bulk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut g = Gateway::open(Connection::open(dir.with_extension("db")).unwrap(), gatewayd::cas::Cas::open(&dir).unwrap(), 0).unwrap();
    g.create_world("w1", "bulk", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    let Join::Host(a) = g.join("w1", "dev-a", Hw { tier: 2, score: 5.0, wants_host: true, takeover: true }, 0).unwrap() else { panic!("host") };

    let t = Instant::now();
    let mut prev = [0u8; 32];
    let mut seq = 0u64;
    let mut batch: Vec<Frame> = Vec::new();
    let push = |g: &mut Gateway, batch: &mut Vec<Frame>, prev: &mut [u8; 32], seq: &mut u64, op: &str, dim: &str, cx: i32, cz: i32, hash: [u8; 32], flush: bool| {
        let e = Entry { seq: *seq, dim, kind: op, cx, cz, hash: &hash };
        *prev = next_mac(&a.hmac_key, prev, &e);
        batch.push(Frame { seq: *seq, op: op.into(), dim: dim.into(), cx, cz, hash, mac: prev.to_vec() });
        *seq += 1;
        if flush || batch.len() >= 2000 {
            g.wal_append(&a.lease_id, a.epoch, batch).unwrap();
            batch.clear();
        }
    };
    for i in 0..n {
        let (cx, cz) = (i % side, i / side);
        let hash = g.cas().put(format!("chunk {cx} {cz} v1").as_bytes()).unwrap();
        push(&mut g, &mut batch, &mut prev, &mut seq, "put:region", "minecraft:overworld", cx, cz, hash, false);
    }
    push(&mut g, &mut batch, &mut prev, &mut seq, "barrier", "", 0, 0, [0u8; 32], true);
    println!("seed: {n} chunk blobs stored and {seq} WAL frames appended in {:.1} s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let r1 = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 1_000).unwrap();
    println!("first commit of {n} chunks: {:.2} s", t.elapsed().as_secs_f64());

    for i in 0..200 {
        let (cx, cz) = ((i * 7) % side, (i * 13) % side);
        let hash = g.cas().put(format!("chunk {cx} {cz} v2").as_bytes()).unwrap();
        push(&mut g, &mut batch, &mut prev, &mut seq, "put:region", "minecraft:overworld", cx, cz, hash, false);
    }
    push(&mut g, &mut batch, &mut prev, &mut seq, "barrier", "", 0, 0, [0u8; 32], true);
    let t = Instant::now();
    let r2 = g.commit(&a.lease_id, a.epoch, &r1.id, CommitKind::Autosave, false, 2_000).unwrap();
    println!("autosave of 200 changed chunks on top of {n}: {:.3} s (this holds the gateway lock)", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let d = g.diff_report(&r1.id, &r2.id, 5).unwrap();
    println!("diff of the two revisions: {:.3} s ({})", t.elapsed().as_secs_f64(), d[0]);
    let t = Instant::now();
    let s = g.scan_revision(&r2.id).unwrap();
    println!("scan of the head revision: {:.2} s ({} blobs, ok {})", t.elapsed().as_secs_f64(), s.blobs, s.ok());
    let t = Instant::now();
    let sr = g.scrub(&dir).unwrap();
    println!("scrub of the whole store: {:.2} s (blobs {}, ok {})", t.elapsed().as_secs_f64(), sr.blobs, sr.ok());
    let t = Instant::now();
    let zip = dir.with_extension("zip");
    let f = std::fs::File::create(&zip).unwrap();
    let st = gatewayd::maintenance::export_zip(g.cas(), g.revision_root(&r2.id).unwrap(), f).unwrap();
    println!("world zip export: {:.2} s ({} files, {} chunks, {} bytes)", t.elapsed().as_secs_f64(), st.files, st.chunks, st.bytes);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(dir.with_extension("db"));
    let _ = std::fs::remove_file(zip);
}
