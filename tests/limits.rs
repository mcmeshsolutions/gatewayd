use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use rusqlite::Connection;
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-limits-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    router(AppState::new(g))
}

async fn status(app: &Router, method: &str, path: &str, ctype: &str, body: Vec<u8>) -> u16 {
    let r = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", ctype)
        .header("authorization", "Bearer tok-a")
        .body(Body::from(body))
        .unwrap();
    app.clone().oneshot(r).await.unwrap().status().as_u16()
}

fn padded_json(bytes: usize) -> Vec<u8> {
    format!("{{\"pad\":\"{}\"}}", "x".repeat(bytes)).into_bytes()
}

#[tokio::test]
async fn json_routes_refuse_bodies_over_64_kib() {
    let app = app();
    assert_eq!(status(&app, "POST", "/v1/worlds/w1/join", "application/json", padded_json(70 << 10)).await, 413);
    assert_ne!(status(&app, "POST", "/v1/worlds/w1/join", "application/json", padded_json(1 << 10)).await, 413);
}

#[tokio::test]
async fn blob_upload_and_log_chunks_keep_their_bigger_limits() {
    let app = app();
    let hash = "0".repeat(64);
    let big = vec![7u8; 1 << 20];
    assert_ne!(status(&app, "PUT", &format!("/v1/blobs/{hash}"), "application/octet-stream", big.clone()).await, 413);
    assert_ne!(status(&app, "POST", "/v1/logs", "text/plain", big).await, 413);
    assert_eq!(status(&app, "POST", "/v1/logs", "text/plain", vec![b'x'; (1 << 20) + 1]).await, 413);
}

#[tokio::test]
async fn crash_reports_take_up_to_256_kib_of_text() {
    let app = app();
    let text = "x".repeat(200 << 10);
    let body = format!("{{\"text\":\"{text}\"}}").into_bytes();
    assert_ne!(status(&app, "POST", "/v1/worlds/w1/crash-report", "application/json", body).await, 413);
}
