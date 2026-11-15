//! A guest that stays: logs in through the relay like the mod does, answers the configuration phase and keep-alives, and when the
//! connection drops it logs in again, writing a millisecond timeline. Measures what a handover costs a guest (RESEARCH.md 5).
//! usage: guestbot <api-url> <world> <token> <relay host:port> <name> <seconds>
//! Prints "t=<ms> <event>" lines and a "gap" line per reconnect: from the last packet of the old session to the new Login (play).
//! Vanilla client behaviour only: it cannot join a server that requires mod channels, so point it at a server with just the mesh mod.
use flate2::read::ZlibDecoder;
use gatewayd::mcproto::{read_varint, write_varint};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const CFG_FINISH: i32 = 0x03;
const CFG_KEEPALIVE: i32 = 0x04;
const CFG_PING: i32 = 0x05;
const CFG_KNOWN_PACKS: i32 = 0x0e;
const CFG_TRANSFER: i32 = 0x0b;
const PLAY_LOGIN: i32 = 0x2b;
const PLAY_KEEPALIVE: i32 = 0x26;
const PLAY_DISCONNECT: i32 = 0x1d;
const PLAY_START_CONFIG: i32 = 0x6d;
const PLAY_SYNC_POS: i32 = 0x40;
const SB_KEEPALIVE: i32 = 0x18;
const SB_TELEPORT_CONFIRM: i32 = 0x00;

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

struct Conn {
    s: TcpStream,
    compressed: bool,
}

enum Read1 {
    Packet(Vec<u8>),
    Idle,
    Closed(String),
}

impl Conn {
    fn send(&mut self, id: i32, payload: &[u8]) -> std::io::Result<()> {
        let mut body = Vec::new();
        if self.compressed {
            write_varint(&mut body, 0);
        }
        write_varint(&mut body, id);
        body.extend_from_slice(payload);
        self.s.write_all(&framed(body))
    }

    fn read(&mut self) -> Read1 {
        self.s.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let mut first = [0u8; 1];
        match self.s.read(&mut first) {
            Ok(0) => return Read1::Closed("closed by the other side".into()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => return Read1::Idle,
            Err(e) => return Read1::Closed(e.to_string()),
        }
        self.s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut len = (first[0] & 0x7f) as u32;
        let mut b = first[0];
        let mut i = 1;
        while b & 0x80 != 0 && i < 5 {
            let mut x = [0u8; 1];
            if let Err(e) = self.s.read_exact(&mut x) {
                return Read1::Closed(e.to_string());
            }
            b = x[0];
            len |= ((b & 0x7f) as u32) << (7 * i);
            i += 1;
        }
        let mut body = vec![0u8; len as usize];
        if let Err(e) = self.s.read_exact(&mut body) {
            return Read1::Closed(e.to_string());
        }
        if self.compressed {
            let (data_len, n) = match read_varint(&body) {
                Some(v) => v,
                None => return Read1::Closed("bad data length".into()),
            };
            body.drain(..n);
            if data_len != 0 {
                let mut out = Vec::with_capacity(data_len as usize);
                if let Err(e) = ZlibDecoder::new(&body[..]).read_to_end(&mut out) {
                    return Read1::Closed(format!("zlib: {e}"));
                }
                body = out;
            }
        }
        Read1::Packet(body)
    }
}

#[derive(Default)]
struct Session {
    login_ms: Option<u128>,
    config_ms: Option<u128>,
    play_ms: Option<u128>,
    first_chunk_ms: Option<u128>,
    last_packet_ms: u128,
    end_reason: String,
}

fn ticket(api: &str, world: &str, token: &str) -> Result<String, String> {
    let r: serde_json::Value = ureq::post(&format!("{api}/v1/worlds/{world}/ticket"))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| format!("ticket request failed: {e}"))?
        .into_json()
        .map_err(|e| e.to_string())?;
    r["ticket"].as_str().map(str::to_string).ok_or_else(|| "no ticket in the answer".to_string())
}

fn log(t0: Instant, what: &str) {
    println!("t={} {what}", t0.elapsed().as_millis());
}

fn run_session(t0: Instant, api: &str, world: &str, token: &str, relay: &str, name: &str, deadline: Instant) -> Result<Session, String> {
    let address = format!("127.0.0.1\0mesh={}", ticket(api, world, token)?);
    let s = TcpStream::connect(relay).map_err(|e| format!("connect: {e}"))?;
    s.set_nodelay(true).ok();
    let mut c = Conn { s, compressed: false };
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
    c.s.write_all(&out).map_err(|e| e.to_string())?;
    log(t0, "connected, login sent");
    let mut ss = Session::default();
    // 0 login, 1 configuration, 2 play
    let mut state = 0;
    let mut chunk_packets = 0u32;
    while Instant::now() < deadline {
        let body = match c.read() {
            Read1::Idle => continue,
            Read1::Closed(why) => {
                ss.end_reason = why;
                return Ok(ss);
            }
            Read1::Packet(b) => b,
        };
        ss.last_packet_ms = t0.elapsed().as_millis();
        let (id, n) = match read_varint(&body) {
            Some(v) => v,
            None => continue,
        };
        let payload = &body[n..];
        match state {
            0 => match id {
                0x03 => c.compressed = true,
                0x02 => {
                    ss.login_ms = Some(ss.last_packet_ms);
                    log(t0, "login success");
                    c.send(0x03, &[]).map_err(|e| e.to_string())?;
                    state = 1;
                }
                0x00 => {
                    ss.end_reason = "refused at login".into();
                    return Ok(ss);
                }
                0x01 => {
                    ss.end_reason = "server wants encryption".into();
                    return Ok(ss);
                }
                _ => {}
            },
            1 => match id {
                CFG_FINISH => {
                    c.send(CFG_FINISH, &[]).map_err(|e| e.to_string())?;
                    ss.config_ms = Some(ss.last_packet_ms);
                    log(t0, "configuration finished");
                    state = 2;
                }
                CFG_KEEPALIVE => c.send(CFG_KEEPALIVE, payload).map_err(|e| e.to_string())?,
                CFG_PING => c.send(CFG_PING, payload).map_err(|e| e.to_string())?,
                CFG_KNOWN_PACKS => {
                    let mut p = Vec::new();
                    write_varint(&mut p, 0);
                    c.send(0x07, &p).map_err(|e| e.to_string())?;
                }
                CFG_TRANSFER => log(t0, "transfer packet received"),
                0x02 => {
                    ss.end_reason = "disconnected in configuration".into();
                    return Ok(ss);
                }
                _ => {}
            },
            _ => match id {
                PLAY_LOGIN if ss.play_ms.is_none() => {
                    ss.play_ms = Some(ss.last_packet_ms);
                    log(t0, "play: login");
                }
                PLAY_KEEPALIVE => c.send(SB_KEEPALIVE, payload).map_err(|e| e.to_string())?,
                PLAY_SYNC_POS => {
                    if let Some((tp, _)) = read_varint(&payload[payload.len().min(1)..]).filter(|_| false) {
                        let _ = tp;
                    }
                    // teleport id is the first varint of the packet (1.21.1)
                    if let Some((tp, _)) = read_varint(payload) {
                        let mut p = Vec::new();
                        write_varint(&mut p, tp);
                        c.send(SB_TELEPORT_CONFIRM, &p).map_err(|e| e.to_string())?;
                    }
                    log(t0, "play: position sync");
                }
                PLAY_DISCONNECT => log(t0, "play: disconnect packet"),
                PLAY_START_CONFIG => log(t0, "play: back to configuration (transfer or reconfigure)"),
                _ => {
                    if body.len() > 2000 {
                        chunk_packets += 1;
                        if ss.first_chunk_ms.is_none() {
                            ss.first_chunk_ms = Some(ss.last_packet_ms);
                            log(t0, "play: first large packet (chunk data)");
                        }
                    }
                }
            },
        }
    }
    ss.end_reason = format!("deadline, {chunk_packets} large packets");
    Ok(ss)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() != 6 {
        eprintln!("usage: guestbot <api-url> <world> <token> <relay host:port> <name> <seconds>");
        std::process::exit(2);
    }
    let secs: u64 = a[5].parse().expect("seconds");
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(secs);
    let mut previous: Option<Session> = None;
    let mut refused = 0;
    while Instant::now() < deadline {
        match run_session(t0, &a[0], &a[1], &a[2], &a[3], &a[4], deadline) {
            Ok(ss) => {
                log(t0, &format!("session ended: {}", ss.end_reason));
                if let (Some(prev), Some(play)) = (previous.as_ref(), ss.play_ms) {
                    println!("gap {} ms (last packet of the old session to Login of the new one, {} refused attempts between)", play.saturating_sub(prev.last_packet_ms), refused);
                    refused = 0;
                }
                if ss.play_ms.is_some() {
                    previous = Some(ss);
                } else {
                    refused += 1;
                }
            }
            Err(e) => {
                refused += 1;
                log(t0, &format!("attempt failed: {e}"));
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = previous.map(|p| (p.login_ms, p.config_ms, p.first_chunk_ms));
}
