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
//!
//! Uploads are the mirror image: PUT_BEGIN(id, total_len as 8 bytes BE) followed by one or more
//! PUT_DATA(id, chunk) frames summing to total_len, answered with PUT_OK(id, 32-byte hash) once it is
//! durably in the CAS, or PUT_ERR(id, utf8 reason) on a quota/validation failure. The id picks which
//! upload a PUT_DATA belongs to, so many uploads can be in flight at once on one connection exactly like
//! downloads - the same reasoning as WorldDownloader on the way down applies to ChunkUploader on the way
//! up: one-PUT-per-file over HTTP pays a full request's overhead per chunk, when overlapping many small
//! writes on one already-open connection is what actually saturates the link.
use crate::cas::Cas;
use crate::server::{AppState, MAX_BLOB};
use crate::tunnel::{read_frame, write_frame, Frame, MAX_PAYLOAD};
use serde::Deserialize;
use std::collections::HashMap;
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
/// client -> server: id is an upload id the client picks (echoed on the matching response), data is the
/// 8-byte (BE) total length of the blob about to follow.
pub const PUT_BEGIN: u8 = 10;
/// client -> server: id matches a PUT_BEGIN, data is up to MAX_PAYLOAD bytes of that upload's content.
pub const PUT_DATA: u8 = 11;
/// server -> client: id matches a PUT_BEGIN, data is the 32-byte hash the upload was stored under.
pub const PUT_OK: u8 = 12;
/// server -> client: id matches a PUT_BEGIN, the upload was rejected (too large, over quota, no lease).
pub const PUT_ERR: u8 = 13;

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// No frame from the client for this long (no WANT, no PING) and the connection is considered dead. Long
/// enough that a quiet lazy-bootstrap connection between requests does not get cut, short enough that a
/// half-open socket does not linger forever.
const IDLE_DEADLINE: Duration = Duration::from_secs(120);
/// Bounded so one client cannot have unlimited blob reads running at once; matches WorldDownloader's own
/// default client-side worker count, since that is the number of WANTs a default client has in flight.
const MAX_INFLIGHT: usize = 128;
/// Separate, smaller cap on concurrent uploads being reassembled: each one holds its whole body in memory
/// until PUT_DATA frames finish summing to its announced length, so this bounds worst-case memory per
/// connection (MAX_UPLOAD_INFLIGHT * MAX_BLOB) rather than sharing MAX_INFLIGHT's much larger budget, which
/// is fine for read-only fetches that stream straight through without buffering a whole blob up front.
const MAX_UPLOAD_INFLIGHT: usize = 16;

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
    let mut uploads: HashMap<u32, Upload> = HashMap::new();
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
            PUT_BEGIN if f.data.len() == 8 => {
                let expected = u64::from_be_bytes(f.data[..8].try_into().unwrap());
                if expected as usize > MAX_BLOB {
                    let _ = tx.send(Frame::new(PUT_ERR, f.id, b"BLOB_TOO_LARGE".to_vec())).await;
                } else if uploads.len() >= MAX_UPLOAD_INFLIGHT {
                    let _ = tx.send(Frame::new(PUT_ERR, f.id, b"TOO_MANY_UPLOADS".to_vec())).await;
                } else {
                    uploads.insert(f.id, Upload { expected, buf: Vec::with_capacity(expected as usize) });
                }
            }
            PUT_DATA => {
                let Some(up) = uploads.get_mut(&f.id) else { continue };
                if up.buf.len() + f.data.len() > up.expected as usize {
                    uploads.remove(&f.id);
                    let _ = tx.send(Frame::new(PUT_ERR, f.id, b"OVERSENT".to_vec())).await;
                    continue;
                }
                up.buf.extend_from_slice(&f.data);
                if up.buf.len() as u64 == up.expected {
                    let Upload { buf, .. } = uploads.remove(&f.id).unwrap();
                    spawn_store(state.clone(), cas.clone(), device.clone(), sem.clone(), tx.clone(), f.id, buf);
                }
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

struct Upload {
    expected: u64,
    buf: Vec<u8>,
}

/// Same world-resolution and quota/visibility rules as the HTTP `PUT /v1/blobs/:hash` handler - a device
/// may upload while hosting, while running a shard, or while working a claimed worldgen tile. Unlike that
/// handler the client never claims a hash up front: the CAS computes it from the actual bytes, and the
/// client is expected to compare that against its own hash of what it sent.
fn spawn_store(state: Arc<AppState>, cas: Cas, device: String, sem: Arc<Semaphore>, tx: mpsc::Sender<Frame>, id: u32, data: Vec<u8>) {
    tokio::spawn(async move {
        let _permit = sem.acquire().await;
        let world = {
            let gw = state.gw();
            match gw.hosted_world(&device) {
                Ok(Some(w)) => Some(w),
                _ => match gw.shard_world_of(&device) {
                    Ok(Some(w)) => Some(w),
                    _ => gw.worldgen_claim_world(&device, crate::lease::wall_s()).ok().flatten(),
                },
            }
        };
        let Some(world) = world else {
            let _ = tx.send(Frame::new(PUT_ERR, id, b"NOT_LEASE_HOLDER".to_vec())).await;
            return;
        };
        let headroom = { state.gw().check_upload_headroom(&world) };
        if let Err(e) = headroom {
            let _ = tx.send(Frame::new(PUT_ERR, id, format!("{e:?}").into_bytes())).await;
            return;
        }
        let len = data.len() as u64;
        let stored = tokio::task::spawn_blocking(move || cas.put(&data)).await;
        let Ok(Ok(hash)) = stored else {
            let _ = tx.send(Frame::new(PUT_ERR, id, b"STORE_FAILED".to_vec())).await;
            return;
        };
        {
            let gw = state.gw();
            let _ = gw.tag_blob(&world, &hash);
            gw.meter(&world, "blob_put_bytes", len);
        }
        let _ = tx.send(Frame::new(PUT_OK, id, hash.to_vec())).await;
    });
}

fn spawn_fetch(state: Arc<AppState>, cas: Cas, device: String, sem: Arc<Semaphore>, tx: mpsc::Sender<Frame>, id: u32, hash: [u8; 32]) {
    tokio::spawn(async move {
        let _permit = sem.acquire().await;
        let world = state.gw().blob_accessible_world(&device, &hash).ok().flatten();
        let Some(world) = world else {
            let _ = tx.send(Frame::new(MISSING, id, Vec::new())).await;
            return;
        };
        if !cas.has(&hash) {
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
        state.gw().meter(&world, "blob_get_bytes", data.len() as u64);
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
