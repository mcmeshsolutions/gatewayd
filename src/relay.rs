//! Inverted ingress: the host dials us, guests dial us, and we splice them through the host's tunnel.
use crate::server::AppState;
use crate::tunnel::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify};

const MAX_PEERS: usize = 4096;
const KEEPALIVE: Duration = Duration::from_secs(10);
const KNOWN_IP_TTL: Duration = Duration::from_secs(12 * 3600);
const PEER_IDLE: Duration = Duration::from_secs(60);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Default)]
struct Peers {
    by_addr: HashMap<(u8, SocketAddr), (u32, Instant)>,
    by_id: HashMap<u32, (u8, SocketAddr)>,
    next: u32,
}

struct Tunnel {
    world: String,
    lease: String,
    epoch: i64,
    up: mpsc::Sender<Frame>,
    streams: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
    next: AtomicU32,
    peers: Mutex<Peers>,
    kill: Notify,
}

pub struct Relay {
    state: Arc<AppState>,
    /// Used for guests that carry no ticket and for UDP, which has no way to name a world.
    default_world: Option<String>,
    udp: Option<Arc<UdpSocket>>,
    /// Extra channels in config order, channel number = index + 1. UDP ones keep their socket here.
    chan_udp: Mutex<HashMap<u8, Arc<UdpSocket>>>,
    /// Source addresses that recently passed the ticket gate; extra TCP channels only talk to them.
    known_ips: Mutex<HashMap<std::net::IpAddr, Instant>>,
    cur: Mutex<HashMap<String, Arc<Tunnel>>>,
}

impl Relay {
    pub fn new(state: Arc<AppState>, default_world: Option<&str>, udp: Option<Arc<UdpSocket>>) -> Arc<Self> {
        Arc::new(Relay { state, default_world: default_world.map(Into::into), udp, chan_udp: Mutex::new(HashMap::new()), known_ips: Mutex::new(HashMap::new()), cur: Mutex::new(HashMap::new()) })
    }

    fn current(&self, world: &str) -> Option<Arc<Tunnel>> {
        lock(&self.cur).get(world).cloned()
    }

    fn all(&self) -> Vec<Arc<Tunnel>> {
        lock(&self.cur).values().cloned().collect()
    }

    /// UDP carries no world name: it goes to the default world, or to the only tunnel when there is just one.
    fn udp_tunnel(&self) -> Option<Arc<Tunnel>> {
        let cur = lock(&self.cur);
        match &self.default_world {
            Some(w) => cur.get(w).cloned(),
            None if cur.len() == 1 => cur.values().next().cloned(),
            None => None,
        }
    }

    fn drop_tunnel(&self, t: &Arc<Tunnel>) {
        let mut cur = lock(&self.cur);
        if cur.get(&t.world).is_some_and(|c| Arc::ptr_eq(c, t)) {
            cur.remove(&t.world);
            lock(&self.state.live_worlds).remove(&t.world);
        }
    }

    /// Only the lease epoch the gateway currently honours may carry traffic.
    fn live(&self, t: &Arc<Tunnel>) -> bool {
        if self.state.lease_live(&t.lease, t.epoch) {
            return true;
        }
        self.drop_tunnel(t);
        t.kill.notify_one();
        false
    }
}

pub async fn serve_agents(relay: Arc<Relay>, l: TcpListener) {
    loop {
        let Ok((sock, _)) = l.accept().await else { continue };
        let r = relay.clone();
        tokio::spawn(async move { agent_session(r, sock).await });
    }
}

async fn agent_session(relay: Arc<Relay>, sock: TcpStream) {
    let _ = sock.set_nodelay(true);
    let (rd, mut wr) = sock.into_split();
    let mut rd = BufReader::new(rd);
    let hello = match tokio::time::timeout(Duration::from_secs(10), read_frame(&mut rd)).await {
        Ok(Ok(f)) if f.ty == HELLO => serde_json::from_slice::<Hello>(&f.data).ok(),
        _ => None,
    };
    let world = hello.as_ref().and_then(|h| match (&h.proof, h.ts) {
        (Some(p), Some(ts)) => relay.state.tunnel_auth_proof(&h.lease, h.epoch, ts, p),
        _ => relay.state.tunnel_auth(&h.token, &h.lease, h.epoch),
    });
    let (Some(h), Some(w)) = (hello, world) else {
        let _ = write_frame(&mut wr, &Frame::new(ERR, 0, b"unauthorized".to_vec())).await;
        return;
    };
    let (up, mut up_rx) = mpsc::channel::<Frame>(256);
    let t = Arc::new(Tunnel {
        world: w,
        lease: h.lease,
        epoch: h.epoch,
        up,
        streams: Mutex::new(HashMap::new()),
        next: AtomicU32::new(1),
        peers: Mutex::new(Peers::default()),
        kill: Notify::new(),
    });
    let superseded = {
        let mut cur = lock(&relay.cur);
        if cur.get(&t.world).is_some_and(|c| c.epoch > t.epoch) {
            true
        } else {
            if let Some(old) = cur.insert(t.world.clone(), t.clone()) {
                old.kill.notify_one();
            }
            lock(&relay.state.live_worlds).insert(t.world.clone());
            false
        }
    };
    if superseded {
        let _ = write_frame(&mut wr, &Frame::new(ERR, 0, b"superseded".to_vec())).await;
        return;
    }
    if write_frame(&mut wr, &Frame::new(HELLO_OK, 0, Vec::new())).await.is_err() {
        relay.drop_tunnel(&t);
        return;
    }
    let since = Instant::now();
    let host = relay.state.gw().lease_device(&t.lease).ok().flatten().unwrap_or_default();
    eprintln!("tunnel up: world={} host_device={host} epoch={}", t.world, t.epoch);
    let meter = (relay.state.clone(), t.world.clone());
    let writer = tokio::spawn(async move {
        while let Some(f) = up_rx.recv().await {
            meter.0.relay_meter(&meter.1, f.data.len() as u64, 0);
            if write_frame(&mut wr, &f).await.is_err() {
                break;
            }
        }
    });
    let pinger = {
        let up = t.up.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(KEEPALIVE);
            loop {
                iv.tick().await;
                if up.send(Frame::new(PING, 0, Vec::new())).await.is_err() {
                    break;
                }
            }
        })
    };
    let reason;
    loop {
        let f = tokio::select! {
            f = tokio::time::timeout(KEEPALIVE * 4, read_frame(&mut rd)) => match f {
                Ok(Ok(f)) => f,
                Ok(Err(e)) => { reason = format!("read error: {e}"); break }
                Err(_) => { reason = "keepalive timeout".to_string(); break }
            },
            _ = t.kill.notified() => { reason = "superseded or lease ended".to_string(); break }
        };
        if matches!(f.ty, DATA | UDP | CUDP) {
            relay.state.relay_meter(&t.world, 0, f.data.len() as u64);
        }
        match f.ty {
            DATA => {
                let tx = lock(&t.streams).get(&f.id).cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(f.data).await;
                }
            }
            CLOSE => {
                lock(&t.streams).remove(&f.id);
            }
            UDP => {
                let peer = lock(&t.peers).by_id.get(&f.id).copied();
                if let Some((chan, addr)) = peer {
                    let sock = if chan == 0 { relay.udp.clone() } else { lock(&relay.chan_udp).get(&chan).cloned() };
                    if let Some(u) = sock {
                        let _ = u.send_to(&f.data, addr).await;
                    }
                }
            }
            _ => {}
        }
    }
    eprintln!("tunnel down: world={} host_device={host} epoch={} up_s={} reason={reason}", t.world, t.epoch, since.elapsed().as_secs());
    relay.drop_tunnel(&t);
    pinger.abort();
    writer.abort();
    lock(&t.streams).clear();
}

pub async fn serve_guests(relay: Arc<Relay>, l: TcpListener) {
    loop {
        let Ok((sock, _)) = l.accept().await else { continue };
        let r = relay.clone();
        tokio::spawn(async move { guest_session(r, sock).await });
    }
}

/// Reads the handshake (and Login Start for logins) and returns the bytes to forward, or None to drop.
/// Returns the bytes to forward and the world the guest's ticket was issued for.
async fn gate(relay: &Relay, sock: &mut TcpStream) -> Option<(Vec<u8>, String)> {
    use crate::mcproto::{build_handshake, frame, parse_handshake, parse_login_start, split_ticket, Frame as P};
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    let next_packet = |buf: &mut Vec<u8>| -> Option<Option<(Vec<u8>, usize)>> {
        match frame(buf) {
            P::Need => Some(None),
            P::Bad => None,
            P::Packet { body, total } => Some(Some((body.to_vec(), total))),
        }
    };
    macro_rules! packet {
        () => {{
            loop {
                if let Some((body, total)) = next_packet(&mut buf)? {
                    break (body, total);
                }
                let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut chunk)).await.ok()?.ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }};
    }
    let (hs_body, hs_len) = packet!();
    let mut hs = parse_handshake(&hs_body).or_else(|| {
        eprintln!("relay gate: unparsable handshake {:02x?}", &hs_body[..hs_body.len().min(48)]);
        None
    })?;
    if hs.next == 1 {
        return Some((buf, relay.default_world.clone()?));
    }
    if hs.next != 2 && hs.next != 3 {
        return None;
    }
    let (clean, ticket) = split_ticket(&hs.address);
    eprintln!("relay gate: next={} addr={:?} ticket_present={}", hs.next, clean, ticket.is_some());
    let ticket = relay.state.take_ticket_any(&ticket?).or_else(|| {
        eprintln!("relay gate: ticket unknown, expired or wrong world");
        None
    })?;
    buf.drain(..hs_len);
    let (login_body, _) = packet!();
    let name = parse_login_start(&login_body).or_else(|| {
        eprintln!("relay gate: unparsable login start {:02x?}", &login_body[..login_body.len().min(48)]);
        None
    })?;
    if !name.eq_ignore_ascii_case(&ticket.name) {
        return None;
    }
    hs.address = clean;
    let mut out = build_handshake(&hs);
    out.extend_from_slice(&buf);
    Some((out, ticket.world))
}

fn is_status(first: &[u8]) -> bool {
    use crate::mcproto::{frame, parse_handshake, Frame as P};
    matches!(frame(first), P::Packet { body, .. } if parse_handshake(body).is_some_and(|h| h.next == 1))
}

/// Answers a server-list ping ourselves when there is no host to forward it to.
async fn status_reply(sock: &mut TcpStream, first: &[u8], motd: &str) {
    use crate::mcproto::{frame, parse_handshake, read_varint, status_response, Frame as P};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (protocol, used) = match frame(first) {
        P::Packet { body, total } => (parse_handshake(body).map_or(0, |h| h.protocol), total),
        _ => return,
    };
    let mut buf = first[used..].to_vec();
    let mut chunk = [0u8; 256];
    for _ in 0..4 {
        loop {
            let (id, bytes) = match frame(&buf) {
                P::Packet { body, total } => (read_varint(body).map(|v| v.0), total),
                P::Bad => return,
                P::Need => break,
            };
            let ping = buf[..bytes].to_vec();
            buf.drain(..bytes);
            match id {
                Some(0) => {
                    if sock.write_all(&status_response(protocol, motd)).await.is_err() {
                        return;
                    }
                }
                Some(1) => {
                    let _ = sock.write_all(&ping).await;
                    return;
                }
                _ => return,
            }
        }
        match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    }
}

async fn guest_session(relay: Arc<Relay>, mut sock: TcpStream) {
    let (first, world) = if relay.state.auth.require_ticket {
        match gate(&relay, &mut sock).await {
            Some((b, w)) => {
                if let Ok(a) = sock.peer_addr() {
                    let mut k = lock(&relay.known_ips);
                    k.retain(|_, t| t.elapsed() < KNOWN_IP_TTL);
                    k.insert(a.ip(), Instant::now());
                }
                (Some(b), w)
            }
            None => {
                eprintln!("relay: guest dropped at gate (bad handshake, ticket or name)");
                return;
            }
        }
    } else {
        let Some(w) = relay.default_world.clone() else { return };
        (None, w)
    };
    let tunnel = relay.current(&world).filter(|t| relay.live(t));
    let Some(t) = tunnel else {
        eprintln!("relay: guest turned away, no live host tunnel for {world}");
        if let Some(b) = first.as_deref().filter(|b| is_status(b)) {
            status_reply(&mut sock, b, "The host is loading the world. Try again in a minute.").await;
        } else if first.is_some() {
            use tokio::io::AsyncWriteExt;
            let msg = "The host is still loading the world (downloading the latest save). Please try again in a minute or two.";
            let _ = sock.write_all(&crate::mcproto::login_disconnect(msg)).await;
        }
        return;
    };
    let _ = sock.set_nodelay(true);
    let id = t.next.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel(32);
    lock(&t.streams).insert(id, tx);
    if t.up.send(Frame::new(OPEN, id, Vec::new())).await.is_ok() {
        if let Some(b) = first {
            for c in b.chunks(MAX_PAYLOAD) {
                if t.up.send(Frame::new(DATA, id, c.to_vec())).await.is_err() {
                    break;
                }
            }
        }
        pump(sock, id, t.up.clone(), rx).await;
    }
    lock(&t.streams).remove(&id);
}

pub async fn serve_voice(relay: Arc<Relay>, sock: Arc<UdpSocket>) {
    let sweeper = relay.clone();
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(15));
        loop {
            iv.tick().await;
            for t in sweeper.all() {
            let gone: Vec<u32> = {
                let mut p = lock(&t.peers);
                let dead: Vec<((u8, SocketAddr), u32)> =
                    p.by_addr.iter().filter(|(_, (_, seen))| seen.elapsed() > PEER_IDLE).map(|(a, (id, _))| (*a, *id)).collect();
                for (a, id) in &dead {
                    p.by_addr.remove(a);
                    p.by_id.remove(id);
                }
                dead.into_iter().map(|(_, id)| id).collect()
            };
            for id in gone {
                let _ = t.up.try_send(Frame::new(UDP_CLOSE, id, Vec::new()));
            }
            }
        }
    });
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
        let Some(t) = relay.udp_tunnel() else { continue };
        let id = {
            let mut p = lock(&t.peers);
            if let Some(e) = p.by_addr.get_mut(&(0, from)) {
                e.1 = Instant::now();
                e.0
            } else if p.by_addr.len() >= MAX_PEERS {
                continue;
            } else {
                p.next += 1;
                let id = p.next;
                p.by_addr.insert((0, from), (id, Instant::now()));
                p.by_id.insert(id, (0, from));
                id
            }
        };
        let _ = t.up.try_send(Frame::new(UDP, id, buf[..n].to_vec()));
    }
}

/// Extra TCP channel (another mod's port): only addresses that already passed the ticket gate get through.
pub async fn serve_channel_tcp(relay: Arc<Relay>, chan: u8, l: TcpListener) {
    loop {
        let Ok((sock, from)) = l.accept().await else { continue };
        let r = relay.clone();
        tokio::spawn(async move {
            if r.state.auth.require_ticket {
                let ok = lock(&r.known_ips).get(&from.ip()).is_some_and(|t| t.elapsed() < KNOWN_IP_TTL);
                if !ok {
                    return;
                }
            }
            let Some(t) = r.udp_tunnel() else { return };
            if !r.live(&t) {
                return;
            }
            let _ = sock.set_nodelay(true);
            let id = t.next.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::channel(32);
            lock(&t.streams).insert(id, tx);
            if t.up.send(Frame::new(OPEN, id, vec![chan])).await.is_ok() {
                pump(sock, id, t.up.clone(), rx).await;
            }
            lock(&t.streams).remove(&id);
        });
    }
}

/// Extra UDP channel: packets are tagged with the channel so the host can pick the local port.
pub async fn serve_channel_udp(relay: Arc<Relay>, chan: u8, sock: Arc<UdpSocket>) {
    lock(&relay.chan_udp).insert(chan, sock.clone());
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
        let Some(t) = relay.udp_tunnel() else { continue };
        let id = {
            let mut p = lock(&t.peers);
            if let Some(e) = p.by_addr.get_mut(&(chan, from)) {
                e.1 = Instant::now();
                e.0
            } else if p.by_addr.len() >= MAX_PEERS {
                continue;
            } else {
                p.next += 1;
                let id = p.next;
                p.by_addr.insert((chan, from), (id, Instant::now()));
                p.by_id.insert(id, (chan, from));
                id
            }
        };
        let mut data = Vec::with_capacity(n + 1);
        data.push(chan);
        data.extend_from_slice(&buf[..n]);
        let _ = t.up.try_send(Frame::new(CUDP, id, data));
    }
}
