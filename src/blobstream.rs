//! A second connection type, parallel to the host-relay tunnel in `relay`/`tunnel`: one persistent,
//! framed TCP connection for pulling many blobs without paying a full HTTP request (TCP/TLS handshake,
//! headers, round trip) per file. A full or incremental world sync wants thousands of small blobs; doing
//! that as one-GET-per-blob means the per-file overhead (not bandwidth) dominates. This reuses the exact
//! frame wire format from `tunnel` (type|id|len|payload) since it already does exactly what is needed
//! here and is already tested - this module just defines its own, disjoint set of message types for a
//! connection that only ever talks to the gateway's own blob store, never to a host.
//!
//! Protocol: client sends HELLO{token}, gets HELLO_OK or ERR. Client then sends any number of WANT(id,
//! hash) frames - id is picked by the client and echoed back on the matching response, so responses may
//! arrive in a different order than requests (each blob is fetched and streamed by its own task, bounded
//! by a semaphore). A found blob is BLOB_BEGIN(id, total_len as 8 bytes BE) followed by one or more
//! BLOB_DATA(id, chunk) frames summing to total_len; a missing or not-visible hash is MISSING(id). The
//! client can keep the connection open and send more WANTs at any time - a full sync just sends its whole
//! list up front and closes once every id it sent has a response, but nothing here requires that; lazy
//! bootstrap can send WANTs on demand later over the same connection without reconnecting.
use crate::cas::Cas;
use crate::server::AppState;
use crate::tunnel::{read_frame, write_frame, Frame, MAX_PAYLOAD};
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{timeout, Duration};

pub const HELLO: u8 = 1;
pub const HELLO_OK: u8 = 2;
pub const ERR: u8 = 3;
/// client -> server: id is a request id the client picks (echoed on the matching response), data is the
/// 32-byte blob hash.
pub const WANT: u8 = 4;
/// server -> client: id matches a WANT, data is the 8-byte (BE) total length of the blob about to follow.
pub const BLOB_BEGIN: u8 = 5;
/// server -> client: id matches a WANT, data is up to MAX_PAYLOAD bytes of that blob's content - one or
/// more of these per blob depending on its size.
pub const BLOB_DATA: u8 = 6;
/// server -> client: id matches a WANT, the hash does not exist or is not visible to this device.
pub const MISSING: u8 = 7;
pub const PING: u8 = 8;
pub const PONG: u8 = 9;

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// No frame from the client for this long (no WANT, no PING) and the connection is considered dead. Long
/// enough that a quiet lazy-bootstrap connection between requests does not get cut, short enough that a
/// half-open socket does not linger forever.
const IDLE_DEADLINE: Duration = Duration::from_secs(120);
/// Bounded so one client cannot have unlimited blob reads running at once; matches WorldDownloader's own
/// default client-side worker count, since that is the number of WANTs a default client has in flight.
const MAX_INFLIGHT: usize = 16;

#[derive(Deserialize)]
struct Hello {
    token: String,
}

pub async fn serve(state: Arc<AppState>, l: TcpListener) {
    loop {
        let Ok((sock, _)) = l.accept().await else { continue };
        let s = state.clone();
        tokio::spawn(session(s, sock));
    }
}

async fn session(state: Arc<AppState>, sock: TcpStream) {
    let _ = sock.set_nodelay(true);
    let (rd, mut wr) = sock.into_split();
    let mut rd = BufReader::new(rd);

    let Ok(Ok(f)) = timeout(HANDSHAKE_DEADLINE, read_frame(&mut rd)).await else {
        let _ = write_frame(&mut wr, &Frame::new(ERR, 0, b"unauthorized".to_vec())).await;
        return;
    };
    if f.ty != HELLO {
        let _ = write_frame(&mut wr, &Frame::new(ERR, 0, b"unauthorized".to_vec())).await;
        return;
    }
    session_after_hello(state, rd, wr, &f.data).await;
}

pub(crate) async fn session_after_hello(
    state: Arc<AppState>,
    mut rd: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut wr: tokio::net::tcp::OwnedWriteHalf,
    hello_payload: &[u8],
) {
    let hello = serde_json::from_slice::<Hello>(hello_payload).ok();
    let device = hello.and_then(|h| state.gw().device_for_token(&h.token).ok().flatten());
    let Some(device) = device else {
        let _ = write_frame(&mut wr, &Frame::new(ERR, 0, b"unauthorized".to_vec())).await;
        return;
    };

    let (tx, mut rx) = mpsc::channel::<Frame>(64);
    let writer = tokio::spawn(async move {
        if write_frame(&mut wr, &Frame::new(HELLO_OK, 0, Vec::new())).await.is_err() {
            return;
        }
        while let Some(f) = rx.recv().await {
            if write_frame(&mut wr, &f).await.is_err() {
                break;
            }
        }
    });

    let cas = state.gw().cas().clone();
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    loop {
        let f = match timeout(IDLE_DEADLINE, read_frame(&mut rd)).await {
            Ok(Ok(f)) => f,
            _ => break,
        };
        match f.ty {
            WANT if f.data.len() == 32 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&f.data);
                spawn_fetch(state.clone(), cas.clone(), device.clone(), sem.clone(), tx.clone(), f.id, hash);
            }
            PING => {
                if tx.send(Frame::new(PONG, 0, Vec::new())).await.is_err() {
                    break;
                }
            }
            _ => {}
        }
    }
    drop(tx);
    writer.abort();
}

fn spawn_fetch(state: Arc<AppState>, cas: Cas, device: String, sem: Arc<Semaphore>, tx: mpsc::Sender<Frame>, id: u32, hash: [u8; 32]) {
    tokio::spawn(async move {
        let _permit = sem.acquire().await;
        let visible = state.gw().blob_visible(&device, &hash).unwrap_or(false);
        if !visible || !cas.has(&hash) {
            let _ = tx.send(Frame::new(MISSING, id, Vec::new())).await;
            return;
        }
        let read = {
            let cas = cas.clone();
            tokio::task::spawn_blocking(move || cas.get(&hash)).await
        };
        let Ok(Ok(data)) = read else {
            let _ = tx.send(Frame::new(MISSING, id, Vec::new())).await;
            return;
        };
        {
            let gw = state.gw();
            if let Some(world) = gw.blob_world_for(&device, &hash) {
                gw.meter(&world, "blob_get_bytes", data.len() as u64);
            }
        }
        if tx.send(Frame::new(BLOB_BEGIN, id, (data.len() as u64).to_be_bytes().to_vec())).await.is_err() {
            return;
        }
        for chunk in data.chunks(MAX_PAYLOAD) {
            if tx.send(Frame::new(BLOB_DATA, id, chunk.to_vec())).await.is_err() {
                return;
            }
        }
    });
}
