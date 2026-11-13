use gatewayd::cas::{sha256, Cas, Hash};
use gatewayd::manifest::*;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

fn tmp() -> (PathBuf, Cas) {
    let p = std::env::temp_dir().join(format!("mcmesh-cas-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&p);
    let c = Cas::open(&p).unwrap();
    (p, c)
}

fn key(cx: i32, cz: i32) -> Key {
    Key { dim: "minecraft:overworld".into(), kind: Kind::Region, cx, cz }
}

fn blob(cas: &Cas, s: &str) -> Hash {
    cas.put(s.as_bytes()).unwrap()
}

fn files(p: &PathBuf) -> usize {
    fn walk(p: &std::path::Path) -> usize {
        std::fs::read_dir(p).unwrap().map(|e| {
            let e = e.unwrap().path();
            if e.is_dir() { walk(&e) } else { 1 }
        }).sum()
    }
    walk(p)
}

#[test]
fn cas_roundtrip_dedup_and_corruption() {
    let (p, cas) = tmp();
    let h = cas.put(b"hello chunk").unwrap();
    assert_eq!(h, sha256(b"hello chunk"));
    assert_eq!(cas.put(b"hello chunk").unwrap(), h);
    assert_eq!(cas.get(&h).unwrap(), b"hello chunk");
    assert!(cas.has(&h));
    assert!(cas.get(&sha256(b"missing")).is_err());
    let x = gatewayd::cas::hex(&h);
    let path = p.join(&x[0..2]).join(&x[2..4]).join(&x);
    std::fs::write(&path, zstd_of(b"tampered")).unwrap();
    assert!(cas.get(&h).is_err(), "content that does not match its name is rejected");
}

fn zstd_of(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    std::io::copy(&mut std::io::Cursor::new(b), &mut v).unwrap();
    // plain bytes are not valid zstd, which is also a corruption case
    v
}

#[test]
fn lookup_across_region_and_super_boundaries_with_negatives() {
    let (_p, cas) = tmp();
    let coords = [(0, 0), (-1, -1), (31, 31), (32, 32), (-33, 5), (511, -512), (512, 512), (-513, -513), (100000, -100000)];
    let changes: Vec<_> = coords.iter().map(|&(x, z)| Change::Put(key(x, z), blob(&cas, &format!("{x},{z}")))).collect();
    let root = apply(&cas, None, &changes).unwrap();
    for &(x, z) in &coords {
        assert_eq!(lookup(&cas, root, &key(x, z)).unwrap(), Some(sha256(format!("{x},{z}").as_bytes())), "{x},{z}");
    }
    assert_eq!(lookup(&cas, root, &key(1, 1)).unwrap(), None);
    let other_dim = Key { dim: "minecraft:the_nether".into(), ..key(0, 0) };
    assert_eq!(lookup(&cas, root, &other_dim).unwrap(), None);
}

#[test]
fn same_content_gives_same_root_regardless_of_order_and_batching() {
    let (_p, cas) = tmp();
    let a: Vec<_> = (0..40).map(|i| Change::Put(key(i * 7 - 100, i * 3), blob(&cas, &format!("c{i}")))).collect();
    let r1 = apply(&cas, None, &a).unwrap();
    let mut rev = a.clone();
    rev.reverse();
    let r2 = apply(&cas, None, &rev).unwrap();
    let mid = apply(&cas, None, &a[..13]).unwrap();
    let r3 = apply(&cas, Some(mid), &a[13..]).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(r1, r3);
}

#[test]
fn delete_and_overwrite_restore_canonical_roots() {
    let (_p, cas) = tmp();
    let empty = empty_root(&cas).unwrap();
    let h1 = blob(&cas, "one");
    let h2 = blob(&cas, "two");
    let r1 = apply(&cas, None, &[Change::Put(key(5, 5), h1), Change::AuxPut("level.dat".into(), h1)]).unwrap();
    let r2 = apply(&cas, Some(r1), &[Change::Put(key(5, 5), h2)]).unwrap();
    assert_ne!(r1, r2);
    let r3 = apply(&cas, Some(r2), &[Change::Put(key(5, 5), h1)]).unwrap();
    assert_eq!(r1, r3, "putting the old value back restores the old root");
    let r4 = apply(&cas, Some(r1), &[Change::Delete(key(5, 5)), Change::AuxDelete("level.dat".into())]).unwrap();
    assert_eq!(r4, empty, "deleting everything gives the empty root");
    let r5 = apply(&cas, Some(r4), &[Change::Delete(key(9, 9))]).unwrap();
    assert_eq!(r5, empty);
}

#[test]
fn commit_touches_only_one_path_of_nodes() {
    let (p, cas) = tmp();
    let base: Vec<_> = (0..200).map(|i| Change::Put(key(i, i * 2 - 150), blob(&cas, &format!("b{i}")))).collect();
    let r1 = apply(&cas, None, &base).unwrap();
    let new_leaf = blob(&cas, "changed");
    let before = files(&p);
    apply(&cas, Some(r1), &[Change::Put(key(3, -144), new_leaf)]).unwrap();
    assert_eq!(files(&p) - before, 4, "region, super, top and root nodes only");
}

#[test]
fn diff_lists_exact_changed_leaves_and_aux() {
    let (_p, cas) = tmp();
    let (a, b, c) = (blob(&cas, "a"), blob(&cas, "b"), blob(&cas, "c"));
    let base: Vec<_> = (-50..50).map(|i| Change::Put(key(i, -i), a)).collect();
    let r1 = apply(&cas, None, &[base, vec![Change::AuxPut("level.dat".into(), a)]].concat()).unwrap();
    let r2 = apply(&cas, Some(r1), &[
        Change::Put(key(-33, 33), b),
        Change::Delete(key(10, -10)),
        Change::Put(key(1000, 1000), c),
        Change::AuxPut("level.dat".into(), b),
        Change::AuxPut("playerdata/x.dat".into(), c),
    ]).unwrap();
    let d = diff(&cas, Some(r1), Some(r2)).unwrap();
    let find = |it: Item| d.iter().find(|x| x.item == it).unwrap_or_else(|| panic!("missing {it:?}"));
    assert_eq!(d.len(), 5);
    assert_eq!((find(Item::Chunk(key(-33, 33))).old, find(Item::Chunk(key(-33, 33))).new), (Some(a), Some(b)));
    assert_eq!((find(Item::Chunk(key(10, -10))).old, find(Item::Chunk(key(10, -10))).new), (Some(a), None));
    assert_eq!((find(Item::Chunk(key(1000, 1000))).old, find(Item::Chunk(key(1000, 1000))).new), (None, Some(c)));
    assert_eq!(find(Item::Aux("level.dat".into())).new, Some(b));
    assert_eq!(find(Item::Aux("playerdata/x.dat".into())).old, None);
    assert!(diff(&cas, Some(r2), Some(r2)).unwrap().is_empty());
    let from_empty = diff(&cas, None, Some(r1)).unwrap();
    assert_eq!(from_empty.len(), 101);
}

#[test]
fn gc_keeps_retained_revisions_and_drops_the_rest() {
    let (_p, cas) = tmp();
    let (a, b, c) = (blob(&cas, "a"), blob(&cas, "b"), blob(&cas, "c"));
    let r1 = apply(&cas, None, &[Change::Put(key(0, 0), a), Change::Put(key(1, 0), b)]).unwrap();
    let r2 = apply(&cas, Some(r1), &[Change::Put(key(1, 0), c)]).unwrap();
    let mut both = HashSet::new();
    reachable(&cas, r1, &mut both).unwrap();
    reachable(&cas, r2, &mut both).unwrap();
    assert!(both.contains(&b), "retaining the older revision pins its blobs");
    let mut keep = HashSet::new();
    reachable(&cas, r2, &mut keep).unwrap();
    assert!(keep.contains(&a) && keep.contains(&c) && !keep.contains(&b));
    let removed = cas.sweep(&keep, std::time::Duration::ZERO).unwrap().0.len();
    assert!(removed >= 1);
    assert!(!cas.has(&b));
    assert!(lookup(&cas, r2, &key(0, 0)).unwrap().is_some());
    assert!(cas.get(&c).is_ok());
}
