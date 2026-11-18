use axum::{body::Body, http::Request, Router};
use gatewayd::auth::AuthCfg;
use gatewayd::hotreload::{bind_reuseport, VirtualLimbo};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn tmp(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    std::env::temp_dir().join(format!("mcmesh-hotreload-{tag}-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}

fn gateway(conn: Connection) -> Gateway {
    let mut g = Gateway::open(conn, gatewayd::cas::Cas::open(tmp("cas")).unwrap(), 0).unwrap();
    g.create_world("w1", "HotReload World", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-alice", "alice", "dev-alice", Role::Admin).unwrap();
    g.add_member("w1", "u-bob", "bob", "dev-bob", Role::ClientOnly).unwrap();
    g.add_token("dev-alice", "tok-alice").unwrap();
    g.add_token("dev-bob", "tok-bob").unwrap();
    g
}

fn cfg() -> AuthCfg {
    AuthCfg { admins: vec!["u-alice".into()], allow_create: true, ..Default::default() }
}

fn app() -> Router {
    router(AppState::with_auth(gateway(Connection::open_in_memory().unwrap()), cfg()))
}

async fn req(app: &Router, method: &str, tok: Option<&str>, path: &str, body: Option<Value>) -> (u16, Value) {
    let mut r = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(r.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn so_reuseport_allows_concurrent_socket_binding() {
    // Pick an available ephemeral port
    let dummy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = dummy.local_addr().unwrap();
    drop(dummy);

    // Bind first listener with SO_REUSEPORT
    let l1 = bind_reuseport(addr);
    assert!(l1.is_ok(), "First bind with reuseport should succeed: {:?}", l1.err());

    // Bind second listener to the exact same address and port
    let l2 = bind_reuseport(addr);
    assert!(l2.is_ok(), "Second bind with reuseport on same port should succeed: {:?}", l2.err());
}

#[test]
fn virtual_limbo_buffering_and_drain_lifecycle() {
    let limbo = VirtualLimbo::new();
    assert!(!limbo.is_limbo_active());
    assert!(!limbo.is_draining());

    // Buffer packet before active -> rejected
    assert!(!limbo.buffer_packet(101, b"before-active".to_vec()));

    // Engage for 30s
    limbo.engage(30);
    assert!(limbo.is_limbo_active());

    // Buffer packets across multiple streams
    assert!(limbo.buffer_packet(101, b"stream1-pkt1".to_vec()));
    assert!(limbo.buffer_packet(101, b"stream1-pkt2".to_vec()));
    assert!(limbo.buffer_packet(102, b"stream2-pkt1".to_vec()));

    let stats = limbo.stats();
    assert_eq!(stats.buffered_streams, 2);
    assert_eq!(stats.buffered_packets, 3);
    assert_eq!(stats.buffered_bytes, b"stream1-pkt1".len() as u64 + b"stream1-pkt2".len() as u64 + b"stream2-pkt1".len() as u64);

    // Drain stream 101
    let d1 = limbo.drain_stream(101);
    assert_eq!(d1, vec![b"stream1-pkt1".to_vec(), b"stream1-pkt2".to_vec()]);

    let stats2 = limbo.stats();
    assert_eq!(stats2.buffered_streams, 1);
    assert_eq!(stats2.buffered_packets, 1);

    // Set drain mode
    limbo.set_drain(true);
    assert!(limbo.is_draining());

    // Clear all
    limbo.clear();
    assert!(!limbo.is_limbo_active());
    assert_eq!(limbo.stats().buffered_packets, 0);
}

#[tokio::test]
async fn admin_hot_reload_endpoints() {
    let app = app();

    // 1. Non-admin is rejected
    let (c, _) = req(&app, "POST", Some("tok-bob"), "/v1/admin/hot-reload", Some(json!({}))).await;
    assert_eq!(c, 403);

    let (c, _) = req(&app, "GET", Some("tok-bob"), "/v1/admin/hot-reload/status", None).await;
    assert_eq!(c, 403);

    // 2. Initial status for admin
    let (c, v) = req(&app, "GET", Some("tok-alice"), "/v1/admin/hot-reload/status", None).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["ok"], true);
    assert_eq!(v["stats"]["active"], false);
    assert_eq!(v["stats"]["draining"], false);

    // 3. Trigger hot-reload with 45s grace period
    let (c, v) = req(&app, "POST", Some("tok-alice"), "/v1/admin/hot-reload", Some(json!({
        "grace_period_s": 45,
        "engage_limbo": true
    }))).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["ok"], true);
    assert_eq!(v["status"], "RELOAD_READY");
    assert_eq!(v["grace_period_s"], 45);
    assert_eq!(v["limbo_engaged"], true);

    // 4. Status reflects limbo active
    let (c, v) = req(&app, "GET", Some("tok-alice"), "/v1/admin/hot-reload/status", None).await;
    assert_eq!(c, 200);
    assert_eq!(v["stats"]["active"], true);

    // 5. Post drain
    let (c, v) = req(&app, "POST", Some("tok-alice"), "/v1/admin/hot-reload/drain", Some(json!({}))).await;
    assert_eq!(c, 200);
    assert_eq!(v["ok"], true);
    assert_eq!(v["draining"], true);
}
