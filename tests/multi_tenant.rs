use axum::{body::Body, http::Request, Router};
use gatewayd::auth::AuthCfg;
use gatewayd::lease::{Gateway, Role};
use gatewayd::quota::{Limits, Scope};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn tmp(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    std::env::temp_dir().join(format!("mcmesh-multitenant-{tag}-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}

fn gateway(conn: Connection) -> Gateway {
    let mut g = Gateway::open(conn, gatewayd::cas::Cas::open(tmp("cas")).unwrap(), 0).unwrap();
    g.create_world("w1", "Alice World", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-alice", "alice", "dev-alice", Role::Admin).unwrap();
    g.add_member("w1", "u-bob", "bob", "dev-bob", Role::HostEligible).unwrap();
    g.add_token("dev-alice", "tok-alice").unwrap();
    g.add_token("dev-bob", "tok-bob").unwrap();

    // Mark alice as world owner
    g.db().execute("UPDATE worlds SET owner_uuid='u-alice' WHERE id='w1'", []).unwrap();

    // Setup gateway root admin
    g.create_world("w-admin", "Admin World", "1.21.1", "neoforge").unwrap();
    g.add_member("w-admin", "u-root", "root", "dev-root", Role::Admin).unwrap();
    g.add_token("dev-root", "tok-root").unwrap();
    g
}

fn cfg() -> AuthCfg {
    AuthCfg { admins: vec!["u-root".into()], allow_create: true, ..Default::default() }
}

fn app() -> Router {
    router(AppState::with_auth(gateway(Connection::open_in_memory().unwrap()), cfg()))
}

async fn req(app: &Router, method: &str, tok: Option<&str>, path: &str, body: Option<Value>) -> (u16, Value) {
    let mut r = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(r.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn call(app: &Router, method: &str, tok: &str, path: &str, body: Value) -> (u16, Value) {
    req(app, method, Some(tok), path, Some(body)).await
}

async fn get(app: &Router, tok: &str, path: &str) -> (u16, Value) {
    req(app, "GET", Some(tok), path, None).await
}

#[tokio::test]
async fn world_quotas_retrieval_and_update_within_ceiling() {
    let mut gw = gateway(Connection::open_in_memory().unwrap());
    // Configure global admin ceiling
    gw.set_limits(Scope::World, "*", &Limits {
        storage_bytes: Some(10_u64 * 1024 * 1024 * 1024), // 10 GB
        world_count: None,
        keep_revisions: Some(50),
        keep_days: Some(30),
        max_guests: Some(20),
        relay_bytes_month: Some(100_u64 * 1024 * 1024 * 1024), // 100 GB
    }).unwrap();
    let app = router(AppState::with_auth(gw, cfg()));

    // 1. World owner gets quotas
    let (c, v) = get(&app, "tok-alice", "/v1/worlds/w1/quotas").await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["world_id"], "w1");
    assert_eq!(v["owner_uuid"], "u-alice");
    assert_eq!(v["admin_ceiling"]["storage_bytes"], 10_u64 * 1024 * 1024 * 1024);
    assert_eq!(v["admin_ceiling"]["max_guests"], 20);

    // 2. World owner updates quotas within ceiling
    let (c, v) = call(&app, "PUT", "tok-alice", "/v1/worlds/w1/quotas", json!({
        "storage_bytes": 5_u64 * 1024 * 1024 * 1024,
        "max_guests": 10,
        "keep_revisions": 20,
        "keep_days": 14,
        "relay_bytes_month": 50_u64 * 1024 * 1024 * 1024
    })).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["ok"], true);
    assert_eq!(v["limits"]["storage_bytes"], 5_u64 * 1024 * 1024 * 1024);
    assert_eq!(v["limits"]["max_guests"], 10);

    // 3. Verify changes persist
    let (c, v) = get(&app, "tok-alice", "/v1/worlds/w1/quotas").await;
    assert_eq!(c, 200);
    assert_eq!(v["limits"]["storage_bytes"], 5_u64 * 1024 * 1024 * 1024);
    assert_eq!(v["limits"]["max_guests"], 10);
    assert_eq!(v["limits"]["keep_revisions"], 20);
}

#[tokio::test]
async fn world_quotas_enforces_admin_ceilings() {
    let mut gw = gateway(Connection::open_in_memory().unwrap());
    gw.set_limits(Scope::World, "*", &Limits {
        storage_bytes: Some(10_u64 * 1024 * 1024 * 1024),
        world_count: None,
        keep_revisions: Some(50),
        keep_days: Some(30),
        max_guests: Some(15),
        relay_bytes_month: Some(100_u64 * 1024 * 1024 * 1024),
    }).unwrap();
    let app = router(AppState::with_auth(gw, cfg()));

    // 1. Exceeding storage ceiling
    let (c, v) = call(&app, "PUT", "tok-alice", "/v1/worlds/w1/quotas", json!({
        "storage_bytes": 20_u64 * 1024 * 1024 * 1024
    })).await;
    assert_eq!(c, 400);
    assert_eq!(v["error"], "EXCEEDS_STORAGE_CEILING");

    // 2. Exceeding guests ceiling
    let (c, v) = call(&app, "PUT", "tok-alice", "/v1/worlds/w1/quotas", json!({
        "max_guests": 25
    })).await;
    assert_eq!(c, 400);
    assert_eq!(v["error"], "EXCEEDS_GUESTS_CEILING");

    // 3. Exceeding relay ceiling
    let (c, v) = call(&app, "PUT", "tok-alice", "/v1/worlds/w1/quotas", json!({
        "relay_bytes_month": 200_u64 * 1024 * 1024 * 1024
    })).await;
    assert_eq!(c, 400);
    assert_eq!(v["error"], "EXCEEDS_RELAY_CEILING");

    // 4. Gateway root admin can bypass ceiling
    let (c, v) = call(&app, "PUT", "tok-root", "/v1/worlds/w1/quotas", json!({
        "storage_bytes": 50_u64 * 1024 * 1024 * 1024,
        "max_guests": 100
    })).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["limits"]["storage_bytes"], 50_u64 * 1024 * 1024 * 1024);
    assert_eq!(v["limits"]["max_guests"], 100);
}

#[tokio::test]
async fn non_owner_rejected_from_quotas_and_tokens() {
    let app = app();

    // Bob is a member but not world owner
    let (c, _) = get(&app, "tok-bob", "/v1/worlds/w1/quotas").await;
    assert_eq!(c, 403);

    let (c, _) = call(&app, "PUT", "tok-bob", "/v1/worlds/w1/quotas", json!({ "max_guests": 5 })).await;
    assert_eq!(c, 403);

    let (c, _) = get(&app, "tok-bob", "/v1/worlds/w1/tokens").await;
    assert_eq!(c, 403);

    let (c, _) = call(&app, "POST", "tok-bob", "/v1/worlds/w1/tokens", json!({ "label": "test" })).await;
    assert_eq!(c, 403);
}

#[tokio::test]
async fn self_service_world_owner_tokens_lifecycle() {
    let app = app();

    // 1. Initial list of tokens is empty
    let (c, v) = get(&app, "tok-alice", "/v1/worlds/w1/tokens").await;
    assert_eq!(c, 200);
    assert_eq!(v["tokens"].as_array().unwrap().len(), 0);

    // 2. Create world token
    let (c, v) = call(&app, "POST", "tok-alice", "/v1/worlds/w1/tokens", json!({
        "label": "ci-backup",
        "expiry_days": 30
    })).await;
    assert_eq!(c, 200, "{v}");
    let token_id = v["token_id"].as_str().unwrap().to_string();
    let raw_token = v["token"].as_str().unwrap().to_string();
    assert!(raw_token.starts_with("mcmesh_wot_"));

    // 3. List tokens contains newly created token
    let (c, v) = get(&app, "tok-alice", "/v1/worlds/w1/tokens").await;
    assert_eq!(c, 200);
    let list = v["tokens"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], token_id);
    assert_eq!(list[0]["label"], "ci-backup");
    assert!(list[0]["expires_at"].as_i64().is_some());

    // 4. Authenticate using the generated world token to read world quotas
    let (c, v) = get(&app, &raw_token, "/v1/worlds/w1/quotas").await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["world_id"], "w1");

    // 5. Revoke the token
    let (c, v) = call(&app, "DELETE", "tok-alice", &format!("/v1/worlds/w1/tokens/{token_id}"), json!({})).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["revoked"], token_id);

    // 6. Token is no longer listed
    let (c, v) = get(&app, "tok-alice", "/v1/worlds/w1/tokens").await;
    assert_eq!(c, 200);
    assert_eq!(v["tokens"].as_array().unwrap().len(), 0);

    // 7. Revoked token can no longer authenticate
    let (c, _) = get(&app, &raw_token, "/v1/worlds/w1/quotas").await;
    assert_eq!(c, 401);
}
