use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-vote-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.create_world("w2", "y", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_member("w2", "u-z", "zed", "dev-z", Role::Admin).unwrap();
    for (d, t) in [("dev-a", "tok-a"), ("dev-b", "tok-b"), ("dev-z", "tok-z")] {
        g.add_token(d, t).unwrap();
    }
    router(AppState::new(g))
}

async fn call(app: &Router, method: &str, tok: &str, path: &str, body: Value) -> (u16, Value) {
    let r = Request::builder().method(method).uri(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_vote_is_off_until_the_owner_switches_it_on() {
    let app = app();
    let (c, v) = call(&app, "GET", "tok-b", "/v1/worlds/w1/handover-vote", Value::Null).await;
    assert_eq!((c, v["enabled"].as_bool(), v["round"].clone()), (200, Some(false), Value::Null));
    let (c, v) = call(&app, "POST", "tok-b", "/v1/worlds/w1/handover-vote/propose", json!({ "tier": 1, "score": 50.0 })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("VOTE_DISABLED")));

    let (c, v) = call(&app, "PUT", "tok-b", "/v1/worlds/w1/vote-policy", json!({ "enabled": true })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("OWNER_ONLY")), "a plain member cannot switch it on");
    let (c, v) = call(&app, "PUT", "tok-a", "/v1/worlds/w1/vote-policy", json!({ "enabled": true })).await;
    assert_eq!((c, v["handover_vote"].as_bool()), (200, Some(true)));
    let (_, v) = call(&app, "GET", "tok-b", "/v1/worlds/w1/handover-vote", Value::Null).await;
    assert_eq!(v["enabled"], true);
    let (_, v) = call(&app, "GET", "tok-a", "/v1/worlds/w1/policy", Value::Null).await;
    assert_eq!(v["handover_vote"], true);
}

#[tokio::test]
async fn errors_follow_the_documented_codes() {
    let app = app();
    call(&app, "PUT", "tok-a", "/v1/worlds/w1/vote-policy", json!({ "enabled": true })).await;
    let (c, v) = call(&app, "POST", "tok-b", "/v1/worlds/w1/handover-vote/propose", json!({ "tier": 1, "score": 50.0 })).await;
    assert_eq!((c, v["error"].as_str()), (409, Some("NO_LIVE_HOST")), "nobody is hosting");
    let (c, v) = call(&app, "POST", "tok-b", "/v1/worlds/w1/handover-vote", json!({ "yes": true })).await;
    assert_eq!((c, v["error"].as_str()), (404, Some("NO_ROUND")));
    let (c, v) = call(&app, "GET", "tok-z", "/v1/worlds/w1/handover-vote", Value::Null).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("NOT_MEMBER")));
    let (c, v) = call(&app, "POST", "tok-b", "/v1/worlds/w1/handover-vote/propose", json!({ "score": -1.0 })).await;
    assert_eq!((c, v["error"].as_str()), (400, Some("BAD_SCORE")));
}
