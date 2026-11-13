use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-pv-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.ops_init().unwrap();
    g.create_world("w1", "World", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_member("w1", "u-c", "carol", "dev-c", Role::HostEligible).unwrap();
    for d in ["a", "b", "c"] {
        g.add_token(&format!("dev-{d}"), &format!("tok-{d}")).unwrap();
    }
    router(AppState::new(g))
}

async fn call(app: &Router, method: &str, tok: &str, path: &str, ver: Option<&str>, body: Option<Value>) -> Value {
    let mut r = Request::builder().method(method).uri(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}"));
    if let Some(v) = ver {
        r = r.header("x-mesh-pack-version", v);
    }
    let body = body.map_or(Body::empty(), |b| Body::from(b.to_string()));
    let resp = app.clone().oneshot(r.body(body).unwrap()).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn join(app: &Router, tok: &str, ver: Option<&str>) -> Value {
    call(app, "POST", tok, "/v1/worlds/w1/join", ver, Some(json!({ "hw": { "tier": 2, "score": 5.0 } }))).await
}

async fn listed(app: &Router) -> Value {
    call(app, "GET", "tok-c", "/v1/worlds", None, None).await["worlds"][0]["pack_version"].clone()
}

#[tokio::test]
async fn host_records_pack_version_and_listing_shows_it() {
    let app = app();
    assert_eq!(listed(&app).await, Value::Null, "unknown until a host reports one");
    assert_eq!(join(&app, "tok-a", Some("1.4.0")).await["decision"], "HOST");
    assert_eq!(listed(&app).await, "1.4.0");
}

#[tokio::test]
async fn missing_invalid_and_guest_versions_leave_it_alone() {
    let app = app();
    join(&app, "tok-a", Some("1.4.0")).await;
    // same host rejoins without the header, then with junk
    assert_eq!(join(&app, "tok-a", None).await["decision"], "HOST");
    assert_eq!(join(&app, "tok-a", Some("1.x; drop")).await["decision"], "HOST");
    assert_eq!(join(&app, "tok-a", Some("1.2.3.4.5")).await["decision"], "HOST");
    assert_eq!(join(&app, "tok-a", Some(&"1".repeat(40))).await["decision"], "HOST");
    assert_eq!(listed(&app).await, "1.4.0");
    // a guest never changes it
    assert_eq!(join(&app, "tok-b", Some("9.9.9")).await["decision"], "GUEST");
    assert_eq!(listed(&app).await, "1.4.0");
}
