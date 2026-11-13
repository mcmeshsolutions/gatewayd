use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::Value;
use tower::ServiceExt;

fn app(min_client: u32) -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-cg-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    let cfg = gatewayd::auth::AuthCfg { min_client, admins: vec!["u-a".into()], ..Default::default() };
    router(AppState::with_auth(g, cfg))
}

async fn get(app: &Router, path: &str, bearer: Option<&str>, level: Option<&str>) -> (u16, Value) {
    let mut r = Request::get(path);
    if let Some(t) = bearer {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    if let Some(l) = level {
        r = r.header("x-mesh-client", l);
    }
    let resp = app.clone().oneshot(r.body(Body::empty()).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn by_default_nobody_is_turned_away() {
    let app = app(0);
    assert_eq!(get(&app, "/v1/worlds", Some("tok-a"), None).await.0, 200, "an old mod sends no header and still works");
}

#[tokio::test]
async fn builds_below_the_minimum_get_a_plain_upgrade_message() {
    let app = app(1);
    for level in [None, Some("0"), Some("garbage")] {
        let (c, v) = get(&app, "/v1/worlds", Some("tok-a"), level).await;
        assert_eq!((c, v["error"].as_str(), v["min_client"].as_u64()), (426, Some("CLIENT_TOO_OLD"), Some(1)), "{level:?}");
        assert!(v["message"].as_str().unwrap().contains("newer version"));
    }
    assert_eq!(get(&app, "/v1/worlds", Some("tok-a"), Some("1")).await.0, 200, "the current level passes");
    assert_eq!(get(&app, "/v1/worlds", Some("tok-a"), Some("7")).await.0, 200, "a newer one too");
}

#[tokio::test]
async fn operators_bots_and_public_pages_are_never_locked_out() {
    let app = app(5);
    assert_eq!(get(&app, "/v1/status", None, None).await.0, 200);
    assert_eq!(get(&app, "/status", None, None).await.0, 200);
    assert_eq!(get(&app, "/.well-known/mcmesh-gateway.json", None, None).await.0, 200);
    assert_eq!(get(&app, "/v1/admin/usage", Some("tok-a"), None).await.0, 200, "admin routes ignore the gate");
    assert_ne!(get(&app, "/v1/admin/usage", Some("mcmesh_sk_not_a_real_key"), None).await.0, 426, "an api key is judged by its own rules");
    let (_, doc) = get(&app, "/.well-known/mcmesh-gateway.json", None, None).await;
    assert_eq!(doc["min_client"], 5, "launchers can read the requirement");
}
