use gatewayd::blobstream::{serve, BLOB_BEGIN, BLOB_DATA, ERR, HELLO, HELLO_OK, MISSING, PONG, PUT_BEGIN, PUT_DATA, PUT_ERR, PUT_OK, WANT};
use gatewayd::lease::{Gateway, Hw, Role};
use gatewayd::server::AppState;
use gatewayd::tunnel::{read_frame, write_frame, Frame};
use rusqlite::Connection;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};

fn cas_dir() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    std::env::temp_dir().join(format!("mcmesh-blobstream-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}

/// Sets up a world with one tagged blob, starts the blobstream listener, and returns its address
/// alongside the blob's hash and content so a test can connect and ask for it.
async fn env() -> (std::net::SocketAddr, [u8; 32], Vec<u8>, String) {
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w1", "w", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    let data = b"some region data, big enough to be interesting".to_vec();
    let hash = g.cas().put(&data).unwrap();
    g.tag_blob("w1", &hash).unwrap();
    let state = AppState::new(g);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve(state, l));
    (addr, hash, data, "tok-a".to_string())
}

/// A world with dev-a holding the active lease, for tests that upload (only the lease holder, a shard
/// host, or a worldgen worker may).
async fn env_hosting() -> (std::net::SocketAddr, String) {
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w1", "w", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.join("w1", "dev-a", Hw { tier: 1, score: 1.0, wants_host: true, takeover: false }, 0).unwrap();
    let state = AppState::new(g);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve(state, l));
    (addr, "tok-a".to_string())
}

async fn connect_and_hello(addr: std::net::SocketAddr, token: &str) -> (BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf, Frame) {
    let sock = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = sock.into_split();
    let mut rd = BufReader::new(rd);
    let hello = serde_json::json!({ "token": token }).to_string();
    write_frame(&mut wr, &Frame::new(HELLO, 0, hello.into_bytes())).await.unwrap();
    let reply = read_frame(&mut rd).await.unwrap();
    // keep the same BufReader for the rest of the connection - unwrapping it here would silently
    // discard whatever it already buffered past this one frame, desyncing every read after it
    (rd, wr, reply)
}

#[tokio::test]
async fn hello_with_a_bad_token_is_refused() {
    let (addr, _, _, _) = env().await;
    let sock = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = sock.into_split();
    let mut rd = BufReader::new(rd);
    write_frame(&mut wr, &Frame::new(HELLO, 0, b"{\"token\":\"bad\"}".to_vec())).await.unwrap();
    let reply = read_frame(&mut rd).await.unwrap();
    assert_eq!(reply.ty, ERR);
}

#[tokio::test]
async fn a_tagged_blob_comes_back_whole_and_correct() {
    let (addr, hash, data, token) = env().await;
    let (mut rd, mut wr, hello_reply) = connect_and_hello(addr, &token).await;
    assert_eq!(hello_reply.ty, HELLO_OK);

    write_frame(&mut wr, &Frame::new(WANT, 42, hash.to_vec())).await.unwrap();
    let begin = read_frame(&mut rd).await.unwrap();
    assert_eq!(begin.ty, BLOB_BEGIN);
    assert_eq!(begin.id, 42, "the response must echo the id the request used");
    let total = u64::from_be_bytes(begin.data.as_slice().try_into().unwrap());
    assert_eq!(total, data.len() as u64);

    let mut got = Vec::new();
    while (got.len() as u64) < total {
        let f = read_frame(&mut rd).await.unwrap();
        assert_eq!(f.ty, BLOB_DATA);
        assert_eq!(f.id, 42);
        got.extend_from_slice(&f.data);
    }
    assert_eq!(got, data);
}

#[tokio::test]
async fn an_untagged_or_unknown_hash_is_reported_missing_not_silently_dropped() {
    let (addr, _, _, token) = env().await;
    let (mut rd, mut wr, hello_reply) = connect_and_hello(addr, &token).await;
    assert_eq!(hello_reply.ty, HELLO_OK);

    let fake = [7u8; 32];
    write_frame(&mut wr, &Frame::new(WANT, 9, fake.to_vec())).await.unwrap();
    let reply = read_frame(&mut rd).await.unwrap();
    assert_eq!((reply.ty, reply.id), (MISSING, 9));
}

#[tokio::test]
async fn several_wants_on_one_connection_each_get_their_own_id_back() {
    let (addr, hash, data, token) = env().await;
    let (mut rd, mut wr, hello_reply) = connect_and_hello(addr, &token).await;
    assert_eq!(hello_reply.ty, HELLO_OK);

    // one real blob and one miss, both on the same still-open connection - the whole point of this
    // protocol is never needing to reconnect between requests.
    write_frame(&mut wr, &Frame::new(WANT, 1, hash.to_vec())).await.unwrap();
    write_frame(&mut wr, &Frame::new(WANT, 2, [9u8; 32].to_vec())).await.unwrap();

    let mut seen_begin_for_1 = false;
    let mut seen_missing_for_2 = false;
    let mut bytes_for_1 = Vec::new();
    while !seen_missing_for_2 || bytes_for_1.len() < data.len() {
        let f = read_frame(&mut rd).await.unwrap();
        match (f.ty, f.id) {
            (BLOB_BEGIN, 1) => seen_begin_for_1 = true,
            (BLOB_DATA, 1) => bytes_for_1.extend_from_slice(&f.data),
            (MISSING, 2) => seen_missing_for_2 = true,
            other => panic!("unexpected frame {other:?}"),
        }
    }
    assert!(seen_begin_for_1);
    assert_eq!(bytes_for_1, data);
}

#[tokio::test]
async fn ping_gets_a_pong_without_needing_a_want() {
    let (addr, _, _, token) = env().await;
    let (mut rd, mut wr, hello_reply) = connect_and_hello(addr, &token).await;
    assert_eq!(hello_reply.ty, PONG_OR_OK);
    write_frame(&mut wr, &Frame::new(gatewayd::blobstream::PING, 0, Vec::new())).await.unwrap();
    let reply = read_frame(&mut rd).await.unwrap();
    assert_eq!(reply.ty, PONG);
}

const PONG_OR_OK: u8 = HELLO_OK;

#[tokio::test]
async fn relay_agent_listener_also_serves_blob_streams() {
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w1", "w", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    let data = b"chunk payload over relay listener".to_vec();
    let hash = g.cas().put(&data).unwrap();
    g.tag_blob("w1", &hash).unwrap();
    let state = AppState::new(g);
    let relay = gatewayd::relay::Relay::new(state, Some("w1"), None);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(gatewayd::relay::serve_agents(relay, l));

    let (mut rd, mut wr, hello_reply) = connect_and_hello(addr, "tok-a").await;
    assert_eq!(hello_reply.ty, HELLO_OK);
    write_frame(&mut wr, &Frame::new(WANT, 7, hash.to_vec())).await.unwrap();
    let begin = read_frame(&mut rd).await.unwrap();
    assert_eq!((begin.ty, begin.id), (BLOB_BEGIN, 7));
    let f = read_frame(&mut rd).await.unwrap();
    assert_eq!((f.ty, f.id, f.data), (BLOB_DATA, 7, data));
}

#[tokio::test]
async fn a_put_is_stored_and_echoes_back_its_hash() {
    let (addr, token) = env_hosting().await;
    let (mut rd, mut wr, hello_reply) = connect_and_hello(addr, &token).await;
    assert_eq!(hello_reply.ty, HELLO_OK);

    let data = b"uploaded region bytes from the lease holder".to_vec();
    write_frame(&mut wr, &Frame::new(PUT_BEGIN, 5, (data.len() as u64).to_be_bytes().to_vec())).await.unwrap();
    write_frame(&mut wr, &Frame::new(PUT_DATA, 5, data.clone())).await.unwrap();
    let reply = read_frame(&mut rd).await.unwrap();
    assert_eq!((reply.ty, reply.id), (PUT_OK, 5));
    assert_eq!(reply.data, gatewayd::cas::sha256(&data).to_vec());
}

#[tokio::test]
async fn a_put_split_across_several_data_frames_still_assembles_correctly() {
    let (addr, token) = env_hosting().await;
    let (mut rd, mut wr, hello_reply) = connect_and_hello(addr, &token).await;
    assert_eq!(hello_reply.ty, HELLO_OK);

    let data = b"this one arrives in three separate frames instead of one".to_vec();
    write_frame(&mut wr, &Frame::new(PUT_BEGIN, 1, (data.len() as u64).to_be_bytes().to_vec())).await.unwrap();
    for chunk in data.chunks(7) {
        write_frame(&mut wr, &Frame::new(PUT_DATA, 1, chunk.to_vec())).await.unwrap();
    }
    let reply = read_frame(&mut rd).await.unwrap();
    assert_eq!((reply.ty, reply.id), (PUT_OK, 1));
    assert_eq!(reply.data, gatewayd::cas::sha256(&data).to_vec());
}

#[tokio::test]
async fn a_put_from_a_device_with_no_lease_is_rejected() {
    let (addr, _, _, token) = env().await;
    let (mut rd, mut wr, hello_reply) = connect_and_hello(addr, &token).await;
    assert_eq!(hello_reply.ty, HELLO_OK);

    let data = b"not allowed, dev-a never took this world's lease".to_vec();
    write_frame(&mut wr, &Frame::new(PUT_BEGIN, 1, (data.len() as u64).to_be_bytes().to_vec())).await.unwrap();
    write_frame(&mut wr, &Frame::new(PUT_DATA, 1, data)).await.unwrap();
    let reply = read_frame(&mut rd).await.unwrap();
    assert_eq!((reply.ty, reply.id), (PUT_ERR, 1));
}

