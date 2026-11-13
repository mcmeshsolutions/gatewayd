use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-rb-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    router(AppState::new(g))
}

async fn post(app: &Router, tok: &str, path: &str, body: Value) -> (u16, Value) {
    let r = Request::post(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn region(rev: &str) -> Value {
    json!({ "revision": rev, "min_cx": 0, "min_cz": 0, "max_cx": 10, "max_cz": 10 })
}

#[tokio::test]
async fn only_the_owner_can_roll_back_a_region_and_errors_use_the_documented_codes() {
    let app = app();
    let (c, v) = post(&app, "tok-b", "/v1/worlds/w1/rollback", region("w1:R_0000")).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("OWNER_ONLY")));
    let (c, v) = post(&app, "tok-a", "/v1/worlds/w1/rollback", region("nope")).await;
    assert_eq!((c, v["error"].as_str()), (404, Some("NO_SUCH_REVISION")));
    let mut bad = region("w1:R_0000");
    bad["min_cx"] = json!(50);
    let (c, v) = post(&app, "tok-a", "/v1/worlds/w1/rollback", bad).await;
    assert_eq!((c, v["error"].as_str()), (400, Some("BAD_REGION")));
    let (c, v) = post(&app, "tok-a", "/v1/worlds/w1/rollback", region("w1:R_0000")).await;
    assert_eq!((c, v["error"].as_str()), (409, Some("NOTHING_TO_ROLLBACK")), "the head already equals that revision");
    let (c, _) = post(&app, "tok-a", "/v1/worlds/w1/rollback", json!({ "revision": "w1:R_0000" })).await;
    assert_eq!(c, 422, "the rectangle is required");
}
