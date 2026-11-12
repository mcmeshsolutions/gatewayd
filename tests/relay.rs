use axum::{body::Body, http::Request};
use gatewayd::cas::Cas;
use gatewayd::lease::{Gateway, Role};
use gatewayd::relay::{serve_agents, serve_guests, serve_voice, Relay};
use gatewayd::server::{router, AppState};
use gatewayd::tunnel::*;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tower::ServiceExt;

struct Env {
    app: axum::Router,
    agents: SocketAddr,
    guests: SocketAddr,
    voice: SocketAddr,
    lease: String,
    base: String,
}

async fn http(app: &axum::Router, tok: &str, path: &str, body: Value) -> Value {
    let r = Request::post(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap_or(Value::Null)
}

async fn env() -> Env {
    env_with(false).await
}

async fn env_with(require_ticket: bool) -> Env {
    let dir = std::env::temp_dir().join(format!("mcmesh-relay-{}-{}", std::process::id(), rand_id()));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "w", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::ClientOnly).unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    g.add_member("w1", "u-c", "carol", "dev-c", Role::ClientOnly).unwrap();
    g.add_token("dev-c", "tok-c").unwrap();
    let cfg = gatewayd::auth::AuthCfg { require_ticket, ..Default::default() };
    let state = AppState::with_auth(g, cfg);
    let app = router(state.clone());
    let j = http(&app, "tok-a", "/v1/worlds/w1/join", json!({"hw":{"tier":2,"score":5.0}})).await;
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let voice = udp.local_addr().unwrap();
    let relay = Relay::new(state, Some("w1"), Some(udp.clone()));
    let al = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (agents, guests) = (al.local_addr().unwrap(), gl.local_addr().unwrap());
    tokio::spawn(serve_agents(relay.clone(), al));
    tokio::spawn(serve_guests(relay.clone(), gl));
    tokio::spawn(serve_voice(relay, udp));
    Env {
        app,
        agents,
        guests,
        voice,
        lease: j["lease"]["id"].as_str().unwrap().into(),
        base: j["lease"]["base_rev"].as_str().unwrap().into(),
    }
}

fn rand_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// Stand-in for the mod's agent: tcp streams go to an upper-casing server, udp to an echo.
async fn fake_server() -> (SocketAddr, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || s.write_all(&b[..n].to_ascii_uppercase()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = u.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = u.recv_from(&mut b).await {
            let _ = u.send_to(&b[..n], from).await;
        }
    });
    (tcp, udp)
}

async fn run_agent(e: &Env, tok: &str, epoch: i64, mc: SocketAddr, voice: SocketAddr) -> Result<(), String> {
    let s = TcpStream::connect(e.agents).await.unwrap();
    let (rd, mut wr) = s.into_split();
    let mut rd = BufReader::new(rd);
    let h = Hello { lease: e.lease.clone(), epoch, token: tok.into(), ts: None, proof: None };
    write_frame(&mut wr, &Frame::new(HELLO, 0, serde_json::to_vec(&h).unwrap())).await.unwrap();
    let f = read_frame(&mut rd).await.unwrap();
    if f.ty != HELLO_OK {
        return Err(String::from_utf8_lossy(&f.data).into());
    }
    let (up, mut up_rx) = mpsc::channel::<Frame>(256);
    tokio::spawn(async move {
        while let Some(f) = up_rx.recv().await {
            if write_frame(&mut wr, &f).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
        let mut peers: HashMap<u32, Arc<UdpSocket>> = HashMap::new();
        while let Ok(f) = read_frame(&mut rd).await {
            match f.ty {
                OPEN => {
                    let (tx, rx) = mpsc::channel(32);
                    streams.insert(f.id, tx);
                    let up = up.clone();
                    tokio::spawn(async move {
                        match TcpStream::connect(mc).await {
                            Ok(s) => pump(s, f.id, up, rx).await,
                            Err(_) => {
                                let _ = up.send(Frame::new(CLOSE, f.id, vec![])).await;
                            }
                        }
                    });
                }
                DATA => {
                    if let Some(tx) = streams.get(&f.id) {
                        let _ = tx.send(f.data).await;
                    }
                }
                CLOSE => {
                    streams.remove(&f.id);
                }
                UDP => {
                    let sock = match peers.get(&f.id) {
                        Some(s) => s.clone(),
                        None => {
                            let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                            s.connect(voice).await.unwrap();
                            let (r, up, id) = (s.clone(), up.clone(), f.id);
                            tokio::spawn(async move {
                                let mut b = [0u8; 2048];
                                while let Ok(n) = r.recv(&mut b).await {
                                    let _ = up.send(Frame::new(UDP, id, b[..n].to_vec())).await;
                                }
                            });
                            peers.insert(f.id, s.clone());
                            s
                        }
                    };
                    let _ = sock.send(&f.data).await;
                }
                UDP_CLOSE => {
                    peers.remove(&f.id);
                }
                _ => {}
            }
        }
    });
    Ok(())
}

async fn roundtrip(addr: SocketAddr, msg: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(msg).await.unwrap();
    let mut out = vec![0; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut out)).await.expect("timeout").unwrap();
    out
}

#[tokio::test]
async fn guests_reach_the_host_through_its_tunnel() {
    let e = env().await;
    let (mc, vc) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    let (a, b) = tokio::join!(roundtrip(e.guests, b"hello from alice"), roundtrip(e.guests, b"bob is here"));
    assert_eq!(a, b"HELLO FROM ALICE");
    assert_eq!(b, b"BOB IS HERE");
    let big = vec![b'x'; 300_000];
    let mut s = TcpStream::connect(e.guests).await.unwrap();
    let (mut r, mut w) = s.split();
    let write = async { w.write_all(&big).await.unwrap() };
    let read = async {
        let mut got = vec![0; big.len()];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(write, read) }).await.expect("large transfer");
    assert!(got.iter().all(|&c| c == b'X'));
}

#[tokio::test]
async fn voice_udp_roundtrips_per_peer() {
    let e = env().await;
    let (mc, vc) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    let mut socks = Vec::new();
    for i in 0..2u8 {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.connect(e.voice).await.unwrap();
        s.send(&[i, 9, 9]).await.unwrap();
        socks.push(s);
    }
    for (i, s) in socks.iter().enumerate() {
        let mut b = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), s.recv(&mut b)).await.expect("udp timeout").unwrap();
        assert_eq!(&b[..n], &[i as u8, 9, 9], "each peer gets its own packets back");
    }
}

#[tokio::test]
async fn bad_credentials_and_stale_epochs_are_refused() {
    let e = env().await;
    let (mc, vc) = fake_server().await;
    assert_eq!(run_agent(&e, "wrong", 1, mc, vc).await.unwrap_err(), "unauthorized");
    assert_eq!(run_agent(&e, "tok-a", 9, mc, vc).await.unwrap_err(), "unauthorized");
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
}

#[tokio::test]
async fn guests_are_dropped_without_a_tunnel_and_after_the_lease_ends() {
    let e = env().await;
    let (mc, vc) = fake_server().await;
    let mut s = TcpStream::connect(e.guests).await.unwrap();
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b).await.unwrap_or(0), 0, "no host tunnel yet");
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    assert_eq!(roundtrip(e.guests, b"ok").await, b"OK");
    let r = http(&e.app, "tok-a", &format!("/v1/leases/{}/commit", e.lease), json!({"epoch":1,"base_rev":e.base,"kind":"SHUTDOWN","final":true})).await;
    assert!(r["rev_id"].is_string());
    let mut s = TcpStream::connect(e.guests).await.unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await.expect("closed").unwrap_or(0), 0, "ended lease carries no traffic");
}

fn login_bytes(host: &str, name: &str, next: i32) -> (Vec<u8>, Vec<u8>) {
    use gatewayd::mcproto::*;
    let hs = build_handshake(&Handshake { protocol: 767, address: host.into(), port: 25565, next });
    let mut body = vec![0];
    write_varint(&mut body, name.len() as i32);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&[7u8; 16]);
    let mut login = Vec::new();
    write_varint(&mut login, body.len() as i32);
    login.extend_from_slice(&body);
    (hs, login)
}

async fn ticket(e: &Env, tok: &str) -> String {
    http(&e.app, tok, "/v1/worlds/w1/ticket", json!({})).await["ticket"].as_str().unwrap_or("").to_string()
}

/// Sends bytes to the guest port and returns what came back before the connection went quiet or closed.
async fn send_and_read(addr: SocketAddr, bytes: &[u8], want: usize) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(bytes).await.unwrap();
    let mut out = vec![0u8; want];
    let mut got = 0;
    while got < want {
        match tokio::time::timeout(Duration::from_secs(2), s.read(&mut out[got..])).await {
            Ok(Ok(n)) if n > 0 => got += n,
            _ => break,
        }
    }
    out.truncate(got);
    out
}

#[tokio::test]
async fn ticket_gate_forwards_only_verified_logins() {
    let e = env_with(true).await;
    let (mc, voice) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, voice).await.unwrap();

    let t = ticket(&e, "tok-b").await;
    assert!(!t.is_empty());
    let (hs, login) = login_bytes(&format!("play.example.org\0mesh={t}"), "Bob", 2);
    let (clean_hs, _) = login_bytes("play.example.org", "Bob", 2);
    let mut want = clean_hs.clone();
    want.extend_from_slice(&login);
    let got = send_and_read(e.guests, &[hs.clone(), login.clone()].concat(), want.len()).await;
    assert_eq!(got, want.to_ascii_uppercase(), "ticket stripped, login forwarded");

    // ticket is one-time
    assert!(send_and_read(e.guests, &[hs, login].concat(), 1).await.is_empty());

    // right ticket, wrong name
    let t = ticket(&e, "tok-b").await;
    let (hs, login) = login_bytes(&format!("h\0mesh={t}"), "Carol", 2);
    assert!(send_and_read(e.guests, &[hs, login].concat(), 1).await.is_empty());

    // no ticket at all, and a nonsense ticket
    let (hs, login) = login_bytes("h", "Bob", 2);
    assert!(send_and_read(e.guests, &[hs, login].concat(), 1).await.is_empty());
    let (hs, login) = login_bytes("h\0mesh=forged", "Bob", 2);
    assert!(send_and_read(e.guests, &[hs, login].concat(), 1).await.is_empty());

    // server list pings pass through untouched
    let (hs, _) = login_bytes("h", "x", 1);
    let got = send_and_read(e.guests, &hs, hs.len()).await;
    assert_eq!(got, hs.to_ascii_uppercase());

    // non-members cannot get tickets
    assert!(ticket(&e, "bad-token").await.is_empty());
}

async fn hello_reply(e: &Env, h: &Hello) -> u8 {
    let s = TcpStream::connect(e.agents).await.unwrap();
    let (rd, mut wr) = s.into_split();
    let mut rd = BufReader::new(rd);
    write_frame(&mut wr, &Frame::new(HELLO, 0, serde_json::to_vec(h).unwrap())).await.unwrap();
    read_frame(&mut rd).await.unwrap().ty
}

#[tokio::test]
async fn tunnel_hello_proof_accepts_valid_and_refuses_bad_or_stale() {
    let e = env().await;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mk = |tok: &str, epoch: i64, ts: u64| Hello {
        lease: e.lease.clone(),
        epoch,
        token: String::new(),
        ts: Some(ts),
        proof: Some(tunnel_proof(tok, &e.lease, epoch, ts)),
    };
    assert_eq!(hello_reply(&e, &mk("wrong", 1, now)).await, ERR);
    assert_eq!(hello_reply(&e, &mk("tok-b", 1, now)).await, ERR);
    assert_eq!(hello_reply(&e, &mk("tok-a", 1, now - 120)).await, ERR);
    assert_eq!(hello_reply(&e, &mk("tok-a", 9, now)).await, ERR);
    let mut tampered = mk("tok-a", 1, now);
    tampered.epoch = 2;
    assert_eq!(hello_reply(&e, &tampered).await, ERR);
    assert_eq!(hello_reply(&e, &mk("tok-a", 1, now + 30)).await, HELLO_OK);
}
