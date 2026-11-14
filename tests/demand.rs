use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    let dir = std::env::temp_dir().join(format!("mcmesh-demand-{}", std::process::id()));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.create_world("w2", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    router(AppState::new(g))
}

async fn call(app: &Router, method: &str, tok: &str, path: &str, body: Value) -> (u16, Value) {
    let r = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn join_body(wants_host: bool) -> Value {
    json!({ "hw": { "tier": 1, "score": 1.0, "wants_host": wants_host }, "fresh": true })
}

#[tokio::test]
async fn an_unwanted_world_reports_nothing() {
    let app = app();
    let (c, v) = call(&app, "GET", "tok-a", "/v1/worlds/w1/demand", Value::Null).await;
    assert_eq!(c, 200);
    assert!(v["wanted_s_ago"].is_null(), "nobody has asked for it yet: {v}");
    assert_eq!(v["hosted"], json!(false));
    assert_eq!(v["live"], json!(false));
}

#[tokio::test]
async fn a_guest_who_cannot_get_in_marks_the_world_as_wanted() {
    let app = app();
    // bob asks to play without wanting to host: there is no host, so the world is wanted
    let (c, v) = call(&app, "POST", "tok-b", "/v1/worlds/w1/join", join_body(false)).await;
    assert_eq!(c, 200, "{v}");
    assert_ne!(v["decision"], json!("HOST"), "a client that does not want to host must not be made one: {v}");

    let (c, v) = call(&app, "GET", "tok-b", "/v1/worlds/w1/demand", Value::Null).await;
    assert_eq!(c, 200);
    assert_eq!(v["wanted_s_ago"].as_u64(), Some(0), "asked for just now: {v}");
    assert_eq!(v["hosted"], json!(false), "wanting a world does not host it");
}

#[tokio::test]
async fn taking_the_lease_shows_up_as_hosted_and_does_not_mark_demand() {
    let app = app();
    let (c, v) = call(&app, "POST", "tok-b", "/v1/worlds/w1/join", join_body(true)).await;
    assert_eq!((c, &v["decision"]), (200, &json!("HOST")), "{v}");
    let (_, v) = call(&app, "GET", "tok-b", "/v1/worlds/w1/demand", Value::Null).await;
    assert!(v["wanted_s_ago"].is_null(), "the host itself is not unmet demand: {v}");
    assert_eq!(v["hosted"], json!(true));
    assert_eq!(v["live"], json!(false), "live means a relay tunnel, which this test has no host for");
}

#[tokio::test]
async fn demand_is_per_world_and_members_only() {
    let app = app();
    call(&app, "POST", "tok-b", "/v1/worlds/w1/join", join_body(false)).await;
    let (_, v) = call(&app, "GET", "tok-a", "/v1/worlds/w1/demand", Value::Null).await;
    assert_eq!(v["wanted_s_ago"].as_u64(), Some(0));
    // w2 has no members at all, so even an admin of w1 is not a member of it
    let (c, v) = call(&app, "GET", "tok-a", "/v1/worlds/w2/demand", Value::Null).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("NOT_MEMBER")), "{v}");
    let (c, _) = call(&app, "GET", "nope", "/v1/worlds/w1/demand", Value::Null).await;
    assert_eq!(c, 401);
}
