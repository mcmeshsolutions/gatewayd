//! Logs in to a mesh world as a guest the way the mod does (ticket in the handshake address) and reports what the server
//! answers up to Login Success. Used by scripts/headless-e2e.sh.
//! usage: guestjoin <api-url> <world> <token|-> <relay host:port> <name>     (a token of "-" sends no ticket)
use gatewayd::mcproto::{read_varint, write_varint};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn put_string(out: &mut Vec<u8>, s: &str) {
    write_varint(out, s.len() as i32);
    out.extend_from_slice(s.as_bytes());
}

fn framed(body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, body.len() as i32);
    out.extend(body);
    out
}

fn read_packet(s: &mut TcpStream, compressed: bool) -> std::io::Result<Vec<u8>> {
    let mut len = 0u32;
    for i in 0..5 {
        let mut b = [0u8; 1];
        s.read_exact(&mut b)?;
        len |= ((b[0] & 0x7f) as u32) << (7 * i);
        if b[0] & 0x80 == 0 {
            break;
        }
    }
    let mut body = vec![0u8; len as usize];
    s.read_exact(&mut body)?;
    if compressed {
        let (data_len, n) = read_varint(&body).ok_or_else(|| std::io::Error::other("bad data length"))?;
        if data_len != 0 {
            return Err(std::io::Error::other("compressed packet, not handled"));
        }
        body.drain(..n);
    }
    Ok(body)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() != 5 {
        eprintln!("usage: guestjoin <api-url> <world> <token|-> <relay host:port> <name>");
        std::process::exit(2);
    }
    let (api, world, token, relay, name) = (&a[0], &a[1], &a[2], &a[3], &a[4]);
    let mut address = "127.0.0.1".to_string();
    if token != "-" {
        let r: serde_json::Value = ureq::post(&format!("{api}/v1/worlds/{world}/ticket"))
            .set("Authorization", &format!("Bearer {token}"))
            .call()
            .unwrap_or_else(|e| {
                eprintln!("ticket request failed: {e}");
                std::process::exit(1)
            })
            .into_json()
            .expect("ticket json");
        address = format!("{address}\0mesh={}", r["ticket"].as_str().expect("ticket"));
    }
    let mut s = TcpStream::connect(relay).expect("connect to the relay");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut hs = Vec::new();
    write_varint(&mut hs, 0);
    write_varint(&mut hs, 767);
    put_string(&mut hs, &address);
    hs.extend_from_slice(&25565u16.to_be_bytes());
    write_varint(&mut hs, 2);
    let mut login = Vec::new();
    write_varint(&mut login, 0);
    put_string(&mut login, name);
    login.extend_from_slice(&[0u8; 16]);
    let mut out = framed(hs);
    out.extend(framed(login));
    s.write_all(&out).expect("send handshake and login start");
    let mut compressed = false;
    loop {
        let body = match read_packet(&mut s, compressed) {
            Ok(b) => b,
            Err(e) => {
                println!("connection closed without a login answer: {e}");
                std::process::exit(1);
            }
        };
        let (id, n) = read_varint(&body).expect("packet id");
        match id {
            0x03 => compressed = true,
            0x02 => {
                println!("login success");
                return;
            }
            0x01 => {
                println!("server wants encryption (online mode), login reached the server");
                return;
            }
            0x00 => {
                let (len, m) = read_varint(&body[n..]).unwrap_or((0, 0));
                let msg = String::from_utf8_lossy(&body[n + m..(n + m + len as usize).min(body.len())]);
                println!("disconnected: {msg}");
                std::process::exit(1);
            }
            other => println!("packet {other:#x}"),
        }
    }
}
