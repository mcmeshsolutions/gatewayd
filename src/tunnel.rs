//! Wire format of the host tunnel: one TCP connection, many multiplexed streams.
//! Frame = type u8 | id u32 BE | len u32 BE | payload (len <= MAX_PAYLOAD).
//! The host opens with HELLO (json {lease, epoch, token}) and gets HELLO_OK or ERR.
//! Gateway to host: OPEN(id) for a new guest TCP stream, DATA, CLOSE, UDP(peer id), UDP_CLOSE.
//! Host to gateway: DATA, CLOSE, UDP.
//! Extra channels: OPEN carries the channel number as its 1-byte payload, CUDP is UDP with the channel as first payload byte.
//! Replies from the host use plain UDP, the peer id already names the channel. PING/PONG keep the path honest.
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub const MAX_PAYLOAD: usize = 64 * 1024;
pub const HELLO: u8 = 1;
pub const HELLO_OK: u8 = 2;
pub const ERR: u8 = 3;
pub const OPEN: u8 = 4;
pub const DATA: u8 = 5;
pub const CLOSE: u8 = 6;
pub const UDP: u8 = 7;
pub const UDP_CLOSE: u8 = 8;
pub const PING: u8 = 9;
pub const PONG: u8 = 10;
pub const CUDP: u8 = 11;
pub const BCAST: u8 = 12;

/// `token` is the legacy plaintext login. Newer hosts send `ts` (unix seconds) and `proof` instead:
/// lowercase hex HMAC-SHA256 over "mcmesh-tunnel|lease|epoch|ts", keyed by SHA-256(token) as raw bytes.
#[derive(Serialize, Deserialize)]
pub struct Hello {
    pub lease: String,
    pub epoch: i64,
    #[serde(default)]
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

pub fn proof_message(lease: &str, epoch: i64, ts: u64) -> String {
    format!("mcmesh-tunnel|{lease}|{epoch}|{ts}")
}

pub fn tunnel_proof(token: &str, lease: &str, epoch: i64, ts: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    let key = Sha256::digest(token.as_bytes());
    let mut m = Hmac::<Sha256>::new_from_slice(&key).expect("hmac accepts any key length");
    m.update(proof_message(lease, epoch, ts).as_bytes());
    m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Frame {
    pub ty: u8,
    pub id: u32,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(ty: u8, id: u32, data: Vec<u8>) -> Self {
        Frame { ty, id, data }
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
    let mut h = [0u8; 9];
    r.read_exact(&mut h).await?;
    let len = u32::from_be_bytes(h[5..9].try_into().unwrap()) as usize;
    if len > MAX_PAYLOAD {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut data = vec![0; len];
    r.read_exact(&mut data).await?;
    Ok(Frame { ty: h[0], id: u32::from_be_bytes(h[1..5].try_into().unwrap()), data })
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> io::Result<()> {
    if f.data.len() > MAX_PAYLOAD {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    let mut hdr = [0u8; 9];
    hdr[0] = f.ty;
    hdr[1..5].copy_from_slice(&f.id.to_be_bytes());
    hdr[5..9].copy_from_slice(&(f.data.len() as u32).to_be_bytes());
    w.write_all(&hdr).await?;
    if !f.data.is_empty() {
        w.write_all(&f.data).await?;
    }
    Ok(())
}

/// Copies between a TCP socket and the tunnel until either side ends, then tells the peer with CLOSE.
pub async fn pump(sock: TcpStream, id: u32, up: mpsc::Sender<Frame>, mut down: mpsc::Receiver<Vec<u8>>) {
    let (mut rd, mut wr) = sock.into_split();
    let a = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.send(Frame::new(DATA, id, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let b = async {
        while let Some(d) = down.recv().await {
            if wr.write_all(&d).await.is_err() {
                break;
            }
        }
    };
    tokio::select! { _ = a => {}, _ = b => {} }
    let _ = up.send(Frame::new(CLOSE, id, Vec::new())).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_and_limits() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::new(DATA, 7, b"hi".to_vec())).await.unwrap();
        let f = read_frame(&mut buf.as_slice()).await.unwrap();
        assert_eq!((f.ty, f.id, f.data.as_slice()), (DATA, 7, b"hi".as_slice()));
        assert!(write_frame(&mut Vec::new(), &Frame::new(DATA, 1, vec![0; MAX_PAYLOAD + 1])).await.is_err());
        let mut evil = vec![DATA, 0, 0, 0, 1];
        evil.extend_from_slice(&((MAX_PAYLOAD as u32) + 1).to_be_bytes());
        assert!(read_frame(&mut evil.as_slice()).await.is_err());
        assert!(read_frame(&mut [DATA, 0].as_slice()).await.is_err(), "truncated header");
    }
}
