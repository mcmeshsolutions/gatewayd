use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-keys-it-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
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

async fn make_key(app: &Router, name: &str, scopes: Value) -> (i64, String) {
    let (c, v) = call(app, "POST", "tok-a", "/v1/admin/api-keys", json!({ "name": name, "scopes": scopes })).await;
    assert_eq!(c, 200, "{v}");
    (v["id"].as_i64().unwrap(), v["key"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn a_read_key_reads_status_but_cannot_change_anything() {
    let app = app();
    let (_, key) = make_key(&app, "grafana", json!(["read:status"])).await;
    assert_eq!(call(&app, "GET", &key, "/v1/admin/usage", Value::Null).await.0, 200);
    assert_eq!(call(&app, "GET", &key, "/v1/admin/audit", Value::Null).await.0, 200);
    assert_eq!(call(&app, "GET", &key, "/v1/admin/maintenance", Value::Null).await.0, 200);
    let (c, v) = call(&app, "PUT", &key, "/v1/admin/maintenance", json!({ "on": true })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("SCOPE_DENIED")));
    let (c, v) = call(&app, "GET", &key, "/v1/admin/users/bob", Value::Null).await;
    assert_eq!((c, v["error"].as_str()), (401, Some("UNAUTHORIZED")), "routes outside the scopes do not recognise keys at all");
    let (c, _) = call(&app, "POST", &key, "/v1/admin/api-keys", json!({ "name": "x", "scopes": ["read:status"] })).await;
    assert_eq!(c, 401, "a key can never mint keys");
    assert_eq!(call(&app, "GET", "mcmesh_sk_made_up", "/v1/admin/usage", Value::Null).await.0, 401);
}

#[tokio::test]
async fn a_lifecycle_key_can_end_maintenance_it_started_and_the_audit_names_the_key() {
    let app = app();
    let (id, key) = make_key(&app, "deploy-bot", json!(["op:lifecycle"])).await;
    let (c, v) = call(&app, "PUT", &key, "/v1/admin/maintenance", json!({ "on": true, "message": "deploying" })).await;
    assert_eq!((c, v["on"].as_bool()), (200, Some(true)));
    let (c, v) = call(&app, "PUT", &key, "/v1/admin/maintenance", json!({ "on": false })).await;
    assert_eq!((c, v["on"].as_bool()), (200, Some(false)), "maintenance mode does not lock the key out");
    let (_, audit) = call(&app, "GET", "tok-a", "/v1/admin/audit?action=maintenance.on", Value::Null).await;
    let entry = &audit["entries"][0];
    assert_eq!(entry["actor_name"], "deploy-bot");
    assert_eq!(entry["actor"], format!("apikey:{id}"));
}

#[tokio::test]
async fn only_admins_manage_keys_secrets_are_shown_once_and_revoking_works() {
    let app = app();
    let (c, v) = call(&app, "POST", "tok-b", "/v1/admin/api-keys", json!({ "name": "x", "scopes": ["read:status"] })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("ADMIN_ONLY")));
    let (c, v) = call(&app, "POST", "tok-a", "/v1/admin/api-keys", json!({ "name": "x", "scopes": ["admin:everything"] })).await;
    assert_eq!((c, v["error"].as_str()), (400, Some("BAD_SCOPE")));
    let (id, key) = make_key(&app, "bot", json!(["read:status"])).await;
    let (_, list) = call(&app, "GET", "tok-a", "/v1/admin/api-keys", Value::Null).await;
    assert!(!list.to_string().contains(&key), "the list never shows the secret");
    assert_eq!(list["keys"][0]["name"], "bot");
    assert_eq!(call(&app, "DELETE", "tok-a", &format!("/v1/admin/api-keys/{id}"), Value::Null).await.0, 200);
    assert_eq!(call(&app, "GET", &key, "/v1/admin/usage", Value::Null).await.0, 401, "a revoked key stops working at once");
    assert_eq!(call(&app, "DELETE", "tok-a", &format!("/v1/admin/api-keys/{id}"), Value::Null).await.0, 404);
}
