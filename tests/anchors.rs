use axum::{body::Body, http::Request, Router};
use gatewayd::admin::anchor_profile;
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    let dir = std::env::temp_dir().join(format!("mcmesh-anchors-{}", std::process::id()));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "anchor1", "dev-b", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    g.set_anchor("dev-b", true).unwrap();
    let cfg = gatewayd::auth::AuthCfg { admins: vec!["u-a".into()], ..Default::default() };
    router(AppState::with_auth(g, cfg))
}

async fn call(app: &Router, method: &str, tok: &str, path: &str, body: Value) -> (u16, Value) {
    let r = Request::builder().method(method).uri(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[test]
fn profiles_follow_memory() {
    assert_eq!(anchor_profile(None), "unknown");
    assert_eq!(
        [2048, 4096, 7000, 8192, 12000, 16384, 65536].map(|m| anchor_profile(Some(m))),
        ["s", "m", "m", "l", "l", "xl", "xl"]
    );
}

#[tokio::test]
async fn only_a_flagged_device_registers_and_admins_see_the_fleet() {
    let app = app();
    let (c, v) = call(&app, "POST", "tok-a", "/v1/anchors/register", json!({ "ram_mb": 8192 })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("NOT_AN_ANCHOR")), "registering never makes a device an anchor");
    assert_eq!(call(&app, "POST", "tok-b", "/v1/anchors/register", json!({ "ram_mb": 10 })).await.0, 400);
    let (c, v) = call(&app, "POST", "tok-b", "/v1/anchors/register", json!({ "ram_mb": 8192, "cores": 4 })).await;
    assert_eq!((c, v["profile"].as_str()), (200, Some("l")));
    let (c, v) = call(&app, "GET", "tok-b", "/v1/admin/anchors", Value::Null).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("ADMIN_ONLY")));
    let (c, v) = call(&app, "GET", "tok-a", "/v1/admin/anchors", Value::Null).await;
    assert_eq!(c, 200);
    assert_eq!((v["anchors"][0]["device"].as_str(), v["anchors"][0]["ram_mb"].as_i64(), v["anchors"][0]["profile"].as_str()), (Some("dev-b"), Some(8192), Some("l")));
    assert!(v["anchors"][0]["hosting"].is_null());
    call(&app, "POST", "tok-b", "/v1/worlds/w1/join", json!({ "hw": { "tier": 2, "score": 5.0 } })).await;
    let (_, v) = call(&app, "GET", "tok-a", "/v1/admin/anchors", Value::Null).await;
    assert_eq!(v["anchors"][0]["hosting"], "w1");
}
