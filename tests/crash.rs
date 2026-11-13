use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-crash-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_member("w1", "u-c", "cara", "dev-c", Role::ClientOnly).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    g.add_token("dev-c", "tok-c").unwrap();
    router(AppState::new(g))
}

async fn send(app: &Router, method: &str, tok: Option<&str>, path: &str, body: Option<Value>) -> (u16, Value) {
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
async fn a_host_uploads_once_per_minute_and_the_owner_reads_it() {
    let app = app();
    let (c, v) = send(&app, "POST", Some("tok-b"), "/v1/worlds/w1/crash-report", Some(json!({ "text": "java.lang.OutOfMemoryError\n at x" }))).await;
    assert_eq!((c, v["stored"].as_bool()), (200, Some(true)));
    let (c, v) = send(&app, "POST", Some("tok-b"), "/v1/worlds/w1/crash-report", Some(json!({ "text": "again" }))).await;
    assert_eq!((c, v["stored"].as_bool(), v["reason"].as_str()), (200, Some(false), Some("rate_limited")));
    let (c, v) = send(&app, "GET", Some("tok-a"), "/v1/worlds/w1/crash-reports", None).await;
    assert_eq!(c, 200);
    let rows = v["reports"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["head"].as_str().unwrap().starts_with("java.lang.OutOfMemoryError"));
    assert_eq!(rows[0]["device"], "dev-b");
}

#[tokio::test]
async fn size_membership_and_auth_are_enforced() {
    let app = app();
    let big = "x".repeat(256 * 1024 + 1);
    let (c, v) = send(&app, "POST", Some("tok-b"), "/v1/worlds/w1/crash-report", Some(json!({ "text": big }))).await;
    assert_eq!((c, v["error"].as_str()), (400, Some("CRASH_REPORT_SIZE")));
    let (c, _) = send(&app, "POST", Some("tok-b"), "/v1/worlds/w1/crash-report", Some(json!({ "text": "" }))).await;
    assert_eq!(c, 400);
    let (c, v) = send(&app, "POST", Some("tok-c"), "/v1/worlds/w1/crash-report", Some(json!({ "text": "t" }))).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("NOT_MEMBER")));
    let (c, _) = send(&app, "POST", None, "/v1/worlds/w1/crash-report", Some(json!({ "text": "t" }))).await;
    assert_eq!(c, 401);
    let (c, _) = send(&app, "POST", Some("tok-b"), "/v1/worlds/nope/crash-report", Some(json!({ "text": "t" }))).await;
    assert_eq!(c, 404);
}

#[tokio::test]
async fn only_the_owner_or_an_admin_can_read_reports() {
    let app = app();
    send(&app, "POST", Some("tok-b"), "/v1/worlds/w1/crash-report", Some(json!({ "text": "boom" }))).await;
    let (c, v) = send(&app, "GET", Some("tok-b"), "/v1/worlds/w1/crash-reports", None).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("OWNER_ONLY")));
    let (c, _) = send(&app, "GET", None, "/v1/worlds/w1/crash-reports", None).await;
    assert_eq!(c, 401);
}
