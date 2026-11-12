use hmac::{Hmac, Mac};
use sha2::Sha256;

type H = Hmac<Sha256>;

pub struct Entry<'a> {
    pub seq: u64,
    pub dim: &'a str,
    pub kind: &'a str,
    pub cx: i32,
    pub cz: i32,
    pub hash: &'a [u8; 32],
}

pub fn next_mac(key: &[u8], prev: &[u8; 32], e: &Entry) -> [u8; 32] {
    let mut m = H::new_from_slice(key).expect("hmac accepts any key length");
    m.update(prev);
    m.update(&e.seq.to_be_bytes());
    for s in [e.dim, e.kind] {
        m.update(&(s.len() as u32).to_be_bytes());
        m.update(s.as_bytes());
    }
    m.update(&e.cx.to_be_bytes());
    m.update(&e.cz.to_be_bytes());
    m.update(e.hash);
    m.finalize().into_bytes().into()
}

pub fn verify_frame(key: &[u8], prev: &[u8; 32], e: &Entry, mac: &[u8]) -> bool {
    let mut m = H::new_from_slice(key).expect("hmac accepts any key length");
    m.update(prev);
    m.update(&e.seq.to_be_bytes());
    for s in [e.dim, e.kind] {
        m.update(&(s.len() as u32).to_be_bytes());
        m.update(s.as_bytes());
    }
    m.update(&e.cx.to_be_bytes());
    m.update(&e.cz.to_be_bytes());
    m.update(e.hash);
    m.verify_slice(mac).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_tamper_reorder_and_wrong_key() {
        let key = [7u8; 32];
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let e1 = Entry { seq: 1, dim: "minecraft:overworld", kind: "region", cx: 3, cz: -4, hash: &h1 };
        let e2 = Entry { seq: 2, dim: "minecraft:overworld", kind: "region", cx: 3, cz: -3, hash: &h2 };
        let m0 = [0u8; 32];
        let m1 = next_mac(&key, &m0, &e1);
        let m2 = next_mac(&key, &m1, &e2);
        assert!(verify_frame(&key, &m0, &e1, &m1));
        assert!(verify_frame(&key, &m1, &e2, &m2));
        assert!(!verify_frame(&key, &m0, &e2, &m2), "skipped frame");
        assert!(!verify_frame(&[8u8; 32], &m0, &e1, &m1), "wrong key");
        let forged = Entry { hash: &h2, ..e1 };
        assert!(!verify_frame(&key, &m0, &forged, &m1), "tampered hash");
    }
}
