use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::quota::{Limits, Scope};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::Value;
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-usage-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "First", "1.21.1", "neoforge").unwrap();
    g.create_world("w2", "Second", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w2", "u-b", "bob", "dev-b", Role::Admin).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    g.set_limits(Scope::World, "w1", &Limits { storage_bytes: Some(1 << 30), max_guests: Some(8), ..Default::default() }).unwrap();
    let cfg = gatewayd::auth::AuthCfg { admins: vec!["u-a".into()], ..Default::default() };
    router(AppState::with_auth(g, cfg))
}

async fn get(app: &Router, tok: Option<&str>) -> (u16, Value) {
    let mut r = Request::get("/v1/admin/usage");
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(r.body(Body::empty()).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn admins_see_usage_next_to_limits_and_others_are_refused() {
    let app = app();
    let (c, v) = get(&app, Some("tok-a")).await;
    assert_eq!(c, 200);
    assert_eq!(v["total_worlds"], 2);
    let w1 = v["worlds"].as_array().unwrap().iter().find(|w| w["id"] == "w1").unwrap();
    assert_eq!(w1["owner"], "alice");
    assert_eq!(w1["limits"]["storage_bytes"], 1u64 << 30);
    assert_eq!(w1["limits"]["max_guests"], 8);
    assert_eq!(w1["limits"]["keep_days"], Value::Null);
    assert_eq!(w1["storage_bytes"], 0);
    assert_eq!(v["users"].as_array().unwrap().len(), 2);
    assert_eq!(v["month"].as_str().unwrap().len(), 6);

    let (c, v) = get(&app, Some("tok-b")).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("ADMIN_ONLY")));
    assert_eq!(get(&app, None).await.0, 401);
}

#[tokio::test]
async fn usage_reports_live_lease_state_host_and_candidates() {
    let app = app();
    let join = Request::post("/v1/worlds/w1/join")
        .header("authorization", "Bearer tok-a")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({ "hw": { "tier": 2, "score": 5.0 } })).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(join).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let (c, v) = get(&app, Some("tok-a")).await;
    assert_eq!(c, 200);
    let w1 = v["worlds"].as_array().unwrap().iter().find(|w| w["id"] == "w1").unwrap();
    assert_eq!(w1["state"], "LOCKED");
    assert_eq!(w1["host"], "alice");
    assert!(w1["candidates"].as_u64().unwrap() >= 1);
    let w2 = v["worlds"].as_array().unwrap().iter().find(|w| w["id"] == "w2").unwrap();
    assert_eq!(w2["state"], "IDLE");
    assert_eq!(w2["host"], Value::Null);
}
