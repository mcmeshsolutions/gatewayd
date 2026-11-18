use axum::{body::Body, http::Request, Router};
use base64::Engine;
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn cas_dir() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    std::env::temp_dir().join(format!("mcmesh-skin-test-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}

fn app() -> Router {
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w1", "Test World", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-alice", "alice", "dev-alice", Role::Admin).unwrap();
    g.add_token("dev-alice", "tok-alice").unwrap();
    router(AppState::new(g))
}

fn dummy_png(w: u32, h: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    b.extend_from_slice(&13u32.to_be_bytes());
    b.extend_from_slice(b"IHDR");
    b.extend_from_slice(&w.to_be_bytes());
    b.extend_from_slice(&h.to_be_bytes());
    b.extend_from_slice(&[8, 6, 0, 0, 0]);
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(b"IEND");
    b.extend_from_slice(&[0xae, 0x42, 0x60, 0x82]);
    b
}

#[tokio::test]
async fn skin_upload_and_fetch_flow() {
    let app = app();
    let png = dummy_png(64, 64);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png);

    // 1. Upload via JSON base64
    let req = Request::post("/v1/skins")
        .header("content-type", "application/json")
        .header("authorization", "Bearer tok-alice")
        .body(Body::from(json!({ "png_base64": b64 }).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap();
    let hash = v["hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert_eq!(v["url"].as_str().unwrap(), format!("/v1/skins/{hash}"));

    // 2. Fetch raw PNG
    let req = Request::get(format!("/v1/skins/{hash}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/png");
    let fetched_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(fetched_bytes.as_ref(), png.as_slice());

    // 3. Query user skin
    let req = Request::get("/v1/users/u-alice/skin")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["player_uuid"].as_str().unwrap(), "u-alice");
    assert_eq!(v["skin_hash"].as_str().unwrap(), hash);

    // 4. Raw PNG upload
    let req = Request::post("/v1/skins")
        .header("content-type", "image/png")
        .header("authorization", "Bearer tok-alice")
        .body(Body::from(png.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // 5. Rejects bad dimensions
    let bad_png = dummy_png(100, 100);
    let req = Request::post("/v1/skins")
        .header("content-type", "image/png")
        .header("authorization", "Bearer tok-alice")
        .body(Body::from(bad_png))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 400);

    // 6. Unknown user skin is 404
    let req = Request::get("/v1/users/u-nobody/skin")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}
