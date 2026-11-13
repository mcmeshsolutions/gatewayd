use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use tower::ServiceExt;

fn cas_dir() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    std::env::temp_dir().join(format!("mcmesh-export-test-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}

fn app() -> Router {
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w1", "Create Full Stack", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    router(AppState::new(g))
}

/// Returns status, content type, content-disposition and body bytes.
async fn get_export(app: &Router, tok: Option<&str>, path: &str, pack: Option<&str>) -> (u16, Option<String>, Option<String>, Vec<u8>) {
    let mut r = Request::get(path);
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    if let Some(p) = pack {
        r = r.header("x-mesh-pack", p);
    }
    let resp = app.clone().oneshot(r.body(Body::empty()).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
    let cd = resp.headers().get("content-disposition").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (code, ct, cd, body)
}

#[tokio::test]
async fn owner_downloads_world_zip() {
    let app = app();
    let (c, ct, cd, body) = get_export(&app, Some("tok-a"), "/v1/worlds/w1/export.zip", None).await;
    assert_eq!(c, 200);
    assert_eq!(ct.as_deref(), Some("application/zip"));
    assert_eq!(cd.as_deref(), Some("attachment; filename=\"w1.zip\""));
    assert!(body.starts_with(b"PK"));
}

#[tokio::test]
async fn non_owner_member_is_refused() {
    let app = app();
    let (c, _, _, body) = get_export(&app, Some("tok-b"), "/v1/worlds/w1/export.zip", None).await;
    assert_eq!(c, 403);
    assert!(String::from_utf8_lossy(&body).contains("OWNER_ONLY"));
}

#[tokio::test]
async fn unauthenticated_is_refused() {
    let app = app();
    let (c, _, _, _) = get_export(&app, None, "/v1/worlds/w1/export.zip", None).await;
    assert_eq!(c, 401);
}

#[tokio::test]
async fn unknown_world_is_not_found() {
    let app = app();
    let (c, _, _, body) = get_export(&app, Some("tok-a"), "/v1/worlds/nope/export.zip", None).await;
    assert_eq!(c, 404);
    assert!(String::from_utf8_lossy(&body).contains("NO_SUCH_WORLD"));
}

#[tokio::test]
async fn wrong_pack_is_refused() {
    let app = app();
    let (c, _, _, body) = get_export(&app, Some("tok-a"), "/v1/worlds/w1/export.zip", Some("other")).await;
    assert_eq!(c, 403);
    assert!(String::from_utf8_lossy(&body).contains("PACK_MISMATCH"));
}
