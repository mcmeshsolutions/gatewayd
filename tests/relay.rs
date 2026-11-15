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
    proxy: bool,
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
    env_full(require_ticket, false).await
}

async fn env_full(require_ticket: bool, proxy_protocol: bool) -> Env {
    env_limited(require_ticket, proxy_protocol, None).await
}

async fn env_limited(require_ticket: bool, proxy_protocol: bool, limits: Option<gatewayd::quota::Limits>) -> Env {
    let dir = std::env::temp_dir().join(format!("mcmesh-relay-{}-{}", std::process::id(), rand_id()));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "w", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::ClientOnly).unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    g.add_member("w1", "u-c", "carol", "dev-c", Role::ClientOnly).unwrap();
    g.add_token("dev-c", "tok-c").unwrap();
    g.add_member("w1", "u-s", "sam", "dev-s", Role::HostEligible).unwrap();
    g.add_token("dev-s", "tok-s").unwrap();
    if let Some(l) = limits {
        g.set_limits(gatewayd::quota::Scope::World, "w1", &l).unwrap();
    }
    let cfg = gatewayd::auth::AuthCfg { require_ticket, ..Default::default() };
    let state = AppState::with_auth(g, cfg);
    let app = router(state.clone());
    let j = http(&app, "tok-a", "/v1/worlds/w1/join", json!({"hw":{"tier":2,"score":5.0}})).await;
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let voice = udp.local_addr().unwrap();
    let relay = Relay::with_proxy_protocol(state, Some("w1"), Some(udp.clone()), proxy_protocol);
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
        proxy: proxy_protocol,
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
    run_agent_for(e, &e.lease, tok, epoch, mc, voice).await
}

async fn run_agent_for(e: &Env, lease: &str, tok: &str, epoch: i64, mc: SocketAddr, voice: SocketAddr) -> Result<(), String> {
    let mut s = TcpStream::connect(e.agents).await.unwrap();
    if e.proxy {
        s.write_all(b"PROXY TCP4 192.0.2.10 10.0.0.1 41000 9000\r\n").await.unwrap();
    }
    let (rd, mut wr) = s.into_split();
    let mut rd = BufReader::new(rd);
    let h = Hello { lease: lease.to_string(), epoch, token: tok.into(), ts: None, proof: None };
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
    roundtrip_after(addr, &[], msg).await
}

/// Sends `prefix` then `msg`, and reads back only as many bytes as `msg` has (a prefix is consumed by the relay).
async fn roundtrip_after(addr: SocketAddr, prefix: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(prefix).await.unwrap();
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

#[tokio::test]
async fn a_proxy_header_is_consumed_and_the_payload_still_reaches_the_host() {
    let e = env_full(false, true).await;
    let (mc, vc) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    let v1 = b"PROXY TCP4 203.0.113.7 10.0.0.1 40000 25565\r\n";
    assert_eq!(&roundtrip_after(e.guests, v1, b"hello via the vps").await[..], &b"HELLO VIA THE VPS"[..]);
    let mut v2 = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    v2.extend([0x21, 0x11, 0, 12, 198, 51, 100, 9, 10, 0, 0, 1, 0x9c, 0x40, 0x63, 0xdd]);
    assert_eq!(&roundtrip_after(e.guests, &v2, b"v2 works too").await[..], &b"V2 WORKS TOO"[..]);
}

#[tokio::test]
async fn without_a_proxy_header_the_connection_is_dropped_when_it_is_required() {
    let e = env_full(false, true).await;
    let (mc, vc) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    let mut s = TcpStream::connect(e.guests).await.unwrap();
    s.write_all(b"direct connection, no header, long enough").await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.expect("closed in time").unwrap_or(0);
    assert_eq!(n, 0, "nothing is relayed to a client that skipped the header");
}

#[tokio::test]
async fn a_guest_that_drips_bytes_is_cut_at_the_handshake_deadline() {
    let e = env_with(true).await;
    let (mc, vc) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    let mut s = TcpStream::connect(e.guests).await.unwrap();
    let started = std::time::Instant::now();
    // never completes a packet, but sends often enough to defeat the per-read timeout
    let closed = async {
        loop {
            if s.write_all(&[0x80]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(40), closed).await.expect("relay must cut the connection");
    assert!(started.elapsed() < Duration::from_secs(30), "cut near the 20 s deadline, not later");
}

#[tokio::test]
async fn a_world_at_its_guest_cap_turns_new_guests_away_without_relaying() {
    let limits = gatewayd::quota::Limits { max_guests: Some(0), ..Default::default() };
    let e = env_limited(false, false, Some(limits)).await;
    let (mc, vc) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    let mut s = TcpStream::connect(e.guests).await.unwrap();
    let _ = s.write_all(b"let me in").await;
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.expect("closed in time").unwrap_or(0);
    assert_eq!(n, 0, "nothing is echoed back by the host");
}

#[tokio::test]
async fn a_world_without_caps_still_relays() {
    let e = env_limited(false, false, Some(gatewayd::quota::Limits { max_guests: Some(5), relay_bytes_month: Some(1 << 30), ..Default::default() })).await;
    let (mc, vc) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    assert_eq!(&roundtrip(e.guests, b"under the cap").await[..], &b"UNDER THE CAP"[..]);
}

#[tokio::test]
async fn voice_udp_is_dropped_until_the_sender_passed_the_ticket_gate() {
    let e = env_with(true).await;
    let (mc, vc) = fake_server().await;
    run_agent(&e, "tok-a", 1, mc, vc).await.unwrap();
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect(e.voice).await.unwrap();
    let mut b = [0u8; 16];

    s.send(&[1, 2, 3]).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(700), s.recv(&mut b)).await.is_err(), "unknown address must get nothing");

    let t = ticket(&e, "tok-b").await;
    let (hs, login) = login_bytes(&format!("h\0mesh={t}"), "Bob", 2);
    assert!(!send_and_read(e.guests, &[hs, login].concat(), 1).await.is_empty());

    s.send(&[4, 5, 6]).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), s.recv(&mut b)).await.expect("udp timeout").unwrap();
    assert_eq!(&b[..n], &[4, 5, 6]);
}

/// Like the stand-in above but it answers in lower case, so a test can tell which host a guest reached.
async fn fake_server_lower() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || s.write_all(&b[..n].to_ascii_lowercase()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    tcp
}

async fn put_blob(app: &axum::Router, tok: &str, data: &[u8]) -> [u8; 32] {
    let hash = gatewayd::cas::sha256(data);
    let r = Request::put(format!("/v1/blobs/{}", gatewayd::cas::hex(&hash))).header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(data.to_vec())).unwrap()).await.unwrap();
    assert!(resp.status().is_success(), "blob upload refused: {}", resp.status());
    hash
}

#[tokio::test]
async fn a_guest_whose_player_file_a_shard_wrote_is_routed_to_that_shard_host() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let e = env_with(true).await;
    let (main_mc, voice) = fake_server().await;
    let shard_mc = fake_server_lower().await;
    run_agent(&e, "tok-a", 1, main_mc, voice).await.unwrap();

    let offer = http(&e.app, "tok-a", "/v1/worlds/w1/shards", json!({"regions": [{"dim": "minecraft:overworld", "x1": 10, "z1": 0, "x2": 12, "z2": 3}]})).await;
    assert!(offer["offer"].as_i64().is_some(), "{offer}");
    let grant = http(&e.app, "tok-s", "/v1/worlds/w1/shards/claim", json!({})).await["grant"].clone();
    let (lease, epoch) = (grant["id"].as_str().unwrap().to_string(), grant["epoch"].as_i64().unwrap());
    let key = URL_SAFE_NO_PAD.decode(grant["hmac_key"].as_str().unwrap()).unwrap();

    // the shard host writes Bob's player file: from now on Bob belongs to it
    let blob = put_blob(&e.app, "tok-s", b"bob's player data").await;
    let path = "playerdata/u-b.dat";
    let entry = gatewayd::chain::Entry { seq: 0, dim: path, kind: "aux_put", cx: 0, cz: 0, hash: &blob };
    let mac = gatewayd::chain::next_mac(&key, &[0; 32], &entry);
    let wal = http(&e.app, "tok-s", &format!("/v1/shards/{lease}/wal"), json!({"epoch": epoch, "frames": [{"seq": 0, "op": "aux_put", "dim": path, "cx": 0, "cz": 0, "hash": format!("sha256:{}", gatewayd::cas::hex(&blob)), "mac": gatewayd::cas::hex(&mac)}]})).await;
    assert_eq!(wal["next_seq"], 1, "{wal}");

    // before the shard host is connected, Bob is turned away rather than sent to a host that does not have his part of the world
    let t = ticket(&e, "tok-b").await;
    let (hs, login) = login_bytes(&format!("play.example.org\0mesh={t}"), "Bob", 2);
    let (clean, _) = login_bytes("play.example.org", "Bob", 2);
    let mut sent = clean.clone();
    sent.extend_from_slice(&login);
    let got = send_and_read(e.guests, &[hs, login].concat(), sent.len()).await;
    assert_ne!(got, sent.to_ascii_uppercase(), "the main host does not take a player who lives on the shard");

    run_agent_for(&e, &lease, "tok-s", epoch, shard_mc, voice).await.unwrap();
    let t = ticket(&e, "tok-b").await;
    let (hs, login) = login_bytes(&format!("play.example.org\0mesh={t}"), "Bob", 2);
    let (clean, _) = login_bytes("play.example.org", "Bob", 2);
    let mut want = clean.clone();
    want.extend_from_slice(&login);
    let got = send_and_read(e.guests, &[hs, login].concat(), want.len()).await;
    assert_eq!(got, want.to_ascii_lowercase(), "Bob reached the shard host");

    // Carol has no file on the shard: the main host
    let t = ticket(&e, "tok-c").await;
    let (hs, login) = login_bytes(&format!("play.example.org\0mesh={t}"), "Carol", 2);
    let (clean, _) = login_bytes("play.example.org", "Carol", 2);
    let mut want = clean.clone();
    want.extend_from_slice(&login);
    let got = send_and_read(e.guests, &[hs, login].concat(), want.len()).await;
    assert_eq!(got, want.to_ascii_uppercase(), "Carol reached the main host");
}
