//! Sparse Merkle manifest: root -> (dim,kind) top -> super (16x16 regions) -> region (32x32 chunks) -> leaf.
//! Nodes live in the CAS, so a commit rewrites only the touched path and revisions share everything else.
use crate::cas::{Cas, Hash};
use std::collections::{BTreeMap, HashSet};
use std::io::{self, Result};

const T_ROOT: u8 = 1;
const T_AUX: u8 = 2;
const T_TOP: u8 = 3;
const T_SUP: u8 = 4;
const T_REG: u8 = 5;
const NONE: Hash = [0; 32];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Kind {
    Region = 0,
    Entities = 1,
    Poi = 2,
}

impl Kind {
    fn from_u8(b: u8) -> Result<Kind> {
        match b {
            0 => Ok(Kind::Region),
            1 => Ok(Kind::Entities),
            2 => Ok(Kind::Poi),
            _ => Err(bad("unknown chunk kind")),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Key {
    pub dim: String,
    pub kind: Kind,
    pub cx: i32,
    pub cz: i32,
}

#[derive(Clone, Debug)]
pub enum Change {
    Put(Key, Hash),
    Delete(Key),
    AuxPut(String, Hash),
    AuxDelete(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Item {
    Chunk(Key),
    Aux(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Diff {
    pub item: Item,
    pub old: Option<Hash>,
    pub new: Option<Hash>,
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n).ok_or_else(|| bad("truncated node"))?;
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn hash(&mut self) -> Result<Hash> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn str(&mut self) -> Result<String> {
        let n = self.u16()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| bad("bad utf8"))
    }
    fn tagged(cas: &Cas, h: Hash, tag: u8) -> Result<Vec<u8>> {
        let b = cas.get(&h)?;
        if b.first() != Some(&tag) {
            return Err(bad("unexpected node type"));
        }
        Ok(b)
    }
    fn end(&self) -> Result<()> {
        if self.p == self.b.len() { Ok(()) } else { Err(bad("trailing bytes in node")) }
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

struct RootN {
    aux: Option<Hash>,
    subs: BTreeMap<(String, Kind), Hash>,
}

fn load_root(cas: &Cas, h: Option<Hash>) -> Result<RootN> {
    let Some(h) = h else { return Ok(RootN { aux: None, subs: BTreeMap::new() }) };
    let b = Rd::tagged(cas, h, T_ROOT)?;
    let mut r = Rd { b: &b, p: 1 };
    let aux = r.hash()?;
    let n = r.u32()?;
    let mut subs = BTreeMap::new();
    for _ in 0..n {
        let dim = r.str()?;
        let kind = Kind::from_u8(r.u8()?)?;
        subs.insert((dim, kind), r.hash()?);
    }
    r.end()?;
    Ok(RootN { aux: (aux != NONE).then_some(aux), subs })
}

fn store_root(cas: &Cas, n: &RootN) -> Result<Hash> {
    let mut o = vec![T_ROOT];
    o.extend_from_slice(&n.aux.unwrap_or(NONE));
    o.extend_from_slice(&(n.subs.len() as u32).to_be_bytes());
    for ((dim, kind), h) in &n.subs {
        put_str(&mut o, dim);
        o.push(*kind as u8);
        o.extend_from_slice(h);
    }
    cas.put(&o)
}

fn load_aux(cas: &Cas, h: Option<Hash>) -> Result<BTreeMap<String, Hash>> {
    let mut m = BTreeMap::new();
    let Some(h) = h else { return Ok(m) };
    let b = Rd::tagged(cas, h, T_AUX)?;
    let mut r = Rd { b: &b, p: 1 };
    for _ in 0..r.u32()? {
        let p = r.str()?;
        m.insert(p, r.hash()?);
    }
    r.end()?;
    Ok(m)
}

fn store_aux(cas: &Cas, m: &BTreeMap<String, Hash>) -> Result<Option<Hash>> {
    if m.is_empty() {
        return Ok(None);
    }
    let mut o = vec![T_AUX];
    o.extend_from_slice(&(m.len() as u32).to_be_bytes());
    for (p, h) in m {
        put_str(&mut o, p);
        o.extend_from_slice(h);
    }
    Ok(Some(cas.put(&o)?))
}

type Top = BTreeMap<(i32, i32), Hash>;

fn load_top(cas: &Cas, h: Option<Hash>) -> Result<Top> {
    let mut m = BTreeMap::new();
    let Some(h) = h else { return Ok(m) };
    let b = Rd::tagged(cas, h, T_TOP)?;
    let mut r = Rd { b: &b, p: 1 };
    for _ in 0..r.u32()? {
        let x = r.i32()?;
        let z = r.i32()?;
        m.insert((x, z), r.hash()?);
    }
    r.end()?;
    Ok(m)
}

fn store_top(cas: &Cas, m: &Top) -> Result<Option<Hash>> {
    if m.is_empty() {
        return Ok(None);
    }
    let mut o = vec![T_TOP];
    o.extend_from_slice(&(m.len() as u32).to_be_bytes());
    for ((x, z), h) in m {
        o.extend_from_slice(&x.to_be_bytes());
        o.extend_from_slice(&z.to_be_bytes());
        o.extend_from_slice(h);
    }
    Ok(Some(cas.put(&o)?))
}

fn load_arr(cas: &Cas, tag: u8, n: usize, h: Option<Hash>) -> Result<Vec<Option<Hash>>> {
    let mut v = vec![None; n];
    let Some(h) = h else { return Ok(v) };
    let b = Rd::tagged(cas, h, tag)?;
    let mut r = Rd { b: &b, p: 1 };
    let bm = r.take(n / 8)?;
    for (i, slot) in v.iter_mut().enumerate() {
        if bm[i / 8] & (1 << (i % 8)) != 0 {
            *slot = Some(r.hash()?);
        }
    }
    r.end()?;
    Ok(v)
}

fn store_arr(cas: &Cas, tag: u8, v: &[Option<Hash>]) -> Result<Option<Hash>> {
    if v.iter().all(Option::is_none) {
        return Ok(None);
    }
    let mut bm = vec![0u8; v.len() / 8];
    let mut body = Vec::new();
    for (i, h) in v.iter().enumerate() {
        if let Some(h) = h {
            bm[i / 8] |= 1 << (i % 8);
            body.extend_from_slice(h);
        }
    }
    let mut o = vec![tag];
    o.extend_from_slice(&bm);
    o.extend_from_slice(&body);
    Ok(Some(cas.put(&o)?))
}

fn split(k: &Key) -> ((i32, i32), usize, usize) {
    let (rx, rz) = (k.cx >> 5, k.cz >> 5);
    let (sx, sz) = (rx >> 4, rz >> 4);
    let sup_idx = ((rz & 15) * 16 + (rx & 15)) as usize;
    let reg_idx = ((k.cz & 31) * 32 + (k.cx & 31)) as usize;
    ((sx, sz), sup_idx, reg_idx)
}

pub fn empty_root(cas: &Cas) -> Result<Hash> {
    apply(cas, None, &[])
}

/// Applies changes (later ones win) and returns the new root. Equal trees always give equal roots.
pub fn apply(cas: &Cas, root: Option<Hash>, changes: &[Change]) -> Result<Hash> {
    let mut r = load_root(cas, root)?;
    let mut aux = load_aux(cas, r.aux)?;
    type Group<'a> = BTreeMap<(i32, i32), BTreeMap<usize, Vec<(usize, Option<Hash>)>>>;
    let mut groups: BTreeMap<(String, Kind), Group> = BTreeMap::new();
    for c in changes {
        let (k, h) = match c {
            Change::AuxPut(p, h) => {
                aux.insert(p.clone(), *h);
                continue;
            }
            Change::AuxDelete(p) => {
                aux.remove(p);
                continue;
            }
            Change::Put(k, h) => (k, Some(*h)),
            Change::Delete(k) => (k, None),
        };
        let (s, si, ri) = split(k);
        groups.entry((k.dim.clone(), k.kind)).or_default().entry(s).or_default().entry(si).or_default().push((ri, h));
    }
    for (gk, supers) in groups {
        let mut top = load_top(cas, r.subs.get(&gk).copied())?;
        for (s, regions) in supers {
            let mut sup = load_arr(cas, T_SUP, 256, top.get(&s).copied())?;
            for (si, leaves) in regions {
                let mut reg = load_arr(cas, T_REG, 1024, sup[si])?;
                for (ri, h) in leaves {
                    reg[ri] = h;
                }
                sup[si] = store_arr(cas, T_REG, &reg)?;
            }
            match store_arr(cas, T_SUP, &sup)? {
                Some(h) => top.insert(s, h),
                None => top.remove(&s),
            };
        }
        match store_top(cas, &top)? {
            Some(h) => r.subs.insert(gk, h),
            None => r.subs.remove(&gk),
        };
    }
    r.aux = store_aux(cas, &aux)?;
    store_root(cas, &r)
}

pub fn lookup(cas: &Cas, root: Hash, k: &Key) -> Result<Option<Hash>> {
    let r = load_root(cas, Some(root))?;
    let Some(t) = r.subs.get(&(k.dim.clone(), k.kind)) else { return Ok(None) };
    let (s, si, ri) = split(k);
    let Some(sh) = load_top(cas, Some(*t))?.get(&s).copied() else { return Ok(None) };
    let Some(rh) = load_arr(cas, T_SUP, 256, Some(sh))?[si] else { return Ok(None) };
    Ok(load_arr(cas, T_REG, 1024, Some(rh))?[ri])
}

pub fn aux_lookup(cas: &Cas, root: Hash, path: &str) -> Result<Option<Hash>> {
    let r = load_root(cas, Some(root))?;
    Ok(load_aux(cas, r.aux)?.get(path).copied())
}

/// Leaf-level difference between two roots; identical subtrees are skipped by hash.
pub fn diff(cas: &Cas, a: Option<Hash>, b: Option<Hash>) -> Result<Vec<Diff>> {
    let mut out = Vec::new();
    if a == b {
        return Ok(out);
    }
    let (ra, rb) = (load_root(cas, a)?, load_root(cas, b)?);
    if ra.aux != rb.aux {
        let (xa, xb) = (load_aux(cas, ra.aux)?, load_aux(cas, rb.aux)?);
        let paths: std::collections::BTreeSet<_> = xa.keys().chain(xb.keys()).collect();
        for p in paths {
            let (o, n) = (xa.get(p).copied(), xb.get(p).copied());
            if o != n {
                out.push(Diff { item: Item::Aux(p.clone()), old: o, new: n });
            }
        }
    }
    let gks: std::collections::BTreeSet<_> = ra.subs.keys().chain(rb.subs.keys()).collect();
    for gk in gks {
        let (ha, hb) = (ra.subs.get(gk).copied(), rb.subs.get(gk).copied());
        if ha == hb {
            continue;
        }
        let (ta, tb) = (load_top(cas, ha)?, load_top(cas, hb)?);
        let ss: std::collections::BTreeSet<_> = ta.keys().chain(tb.keys()).collect();
        for s in ss {
            let (sa, sb) = (ta.get(s).copied(), tb.get(s).copied());
            if sa == sb {
                continue;
            }
            let (va, vb) = (load_arr(cas, T_SUP, 256, sa)?, load_arr(cas, T_SUP, 256, sb)?);
            for si in 0..256 {
                if va[si] == vb[si] {
                    continue;
                }
                let (la, lb) = (load_arr(cas, T_REG, 1024, va[si])?, load_arr(cas, T_REG, 1024, vb[si])?);
                let (rx, rz) = (s.0 * 16 + (si as i32 & 15), s.1 * 16 + (si as i32 >> 4));
                for ri in 0..1024 {
                    if la[ri] != lb[ri] {
                        let key = Key {
                            dim: gk.0.clone(),
                            kind: gk.1,
                            cx: rx * 32 + (ri as i32 & 31),
                            cz: rz * 32 + (ri as i32 >> 5),
                        };
                        out.push(Diff { item: Item::Chunk(key), old: la[ri], new: lb[ri] });
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Every node and leaf blob hash reachable from `root`; feed the union over retained revisions to `Cas::sweep`.
pub fn reachable(cas: &Cas, root: Hash, out: &mut HashSet<Hash>) -> Result<()> {
    if !out.insert(root) {
        return Ok(());
    }
    let r = load_root(cas, Some(root))?;
    if let Some(a) = r.aux {
        out.insert(a);
        out.extend(load_aux(cas, Some(a))?.into_values());
    }
    for t in r.subs.into_values() {
        out.insert(t);
        for s in load_top(cas, Some(t))?.into_values() {
            if !out.insert(s) {
                continue;
            }
            for rh in load_arr(cas, T_SUP, 256, Some(s))?.into_iter().flatten() {
                if !out.insert(rh) {
                    continue;
                }
                out.extend(load_arr(cas, T_REG, 1024, Some(rh))?.into_iter().flatten());
            }
        }
    }
    Ok(())
}
