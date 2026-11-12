use axum::{body::Body, extract::Query, http::Request, routing::get, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use gatewayd::auth::AuthCfg;
use gatewayd::lease::Gateway;
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use tower::ServiceExt;

async fn mock_mojang() -> String {
    async fn has_joined(Query(q): Query<HashMap<String, String>>) -> axum::response::Response {
        use axum::response::IntoResponse;
        if q.get("serverId").map_or(true, |s| s.is_empty()) {
            return axum::http::StatusCode::NO_CONTENT.into_response();
        }
        match q.get("username").map(String::as_str) {
            Some("Notch") => axum::Json(json!({"id":"069a79f444e94726a5befca90e38aaf5","name":"Notch"})).into_response(),
            _ => axum::http::StatusCode::NO_CONTENT.into_response(),
        }
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let app = Router::new().route("/session/minecraft/hasJoined", get(has_joined));
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

fn app(cfg: AuthCfg) -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-auth-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "W", "1.21.1", "neoforge").unwrap();
    router(AppState::with_auth(g, cfg))
}

async fn call(app: &Router, tok: Option<&str>, path: &str, body: Value) -> (u16, Value) {
    let mut r = Request::post(path).header("content-type", "application/json");
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn challenge(app: &Router) -> String {
    call(app, None, "/v1/auth/challenge", json!({})).await.1["challenge"].as_str().unwrap().to_string()
}

async fn key_login(app: &Router, seed: u8, name: &str) -> (u16, Value) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let c = challenge(app).await;
    let mut msg = b"mcmesh-auth-v1\0".to_vec();
    msg.extend_from_slice(c.as_bytes());
    let sig = sk.sign(&msg);
    call(app, None, "/v1/auth/key", json!({
        "challenge": c, "name": name,
        "pubkey": B64.encode(sk.verifying_key().to_bytes()), "sig": B64.encode(sig.to_bytes()),
    })).await
}

async fn mojang_login(app: &Router, name: &str) -> (u16, Value) {
    let c = challenge(app).await;
    call(app, None, "/v1/auth/mojang", json!({ "challenge": c, "name": name })).await
}

#[tokio::test]
async fn key_login_gives_a_working_token_and_stable_uuid() {
    let app = app(AuthCfg::default());
    let (c, v) = key_login(&app, 7, "Cracked_Bob").await;
    assert_eq!(c, 200);
    let tok = v["token"].as_str().unwrap().to_string();
    let uuid = v["uuid"].as_str().unwrap().to_string();
    let (c, v) = call(&app, Some(&tok), "/v1/worlds/w1/join", json!({"hw":{"tier":2,"score":1.0}})).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("NOT_MEMBER")));
    let (c, _) = call(&app, Some("nope"), "/v1/worlds/w1/join", json!({"hw":{"tier":2,"score":1.0}})).await;
    assert_eq!(c, 401);
    let (_, v) = key_login(&app, 7, "Cracked_Bob").await;
    assert_eq!(v["uuid"].as_str().unwrap(), uuid);
}

#[tokio::test]
async fn challenges_are_single_use_and_signatures_checked() {
    let app = app(AuthCfg::default());
    let sk = SigningKey::from_bytes(&[9; 32]);
    let c = challenge(&app).await;
    let mut msg = b"mcmesh-auth-v1\0".to_vec();
    msg.extend_from_slice(c.as_bytes());
    let body = json!({"challenge": c, "name": "Eve_x", "pubkey": B64.encode(sk.verifying_key().to_bytes()),
        "sig": B64.encode(sk.sign(&msg).to_bytes())});
    assert_eq!(call(&app, None, "/v1/auth/key", body.clone()).await.0, 200);
    assert_eq!(call(&app, None, "/v1/auth/key", body).await.1["error"], "BAD_CHALLENGE");

    let c = challenge(&app).await;
    let forged = SigningKey::from_bytes(&[1; 32]).sign(b"something else");
    let (code, _) = call(&app, None, "/v1/auth/key", json!({"challenge": c, "name": "Mallory",
        "pubkey": B64.encode(sk.verifying_key().to_bytes()), "sig": B64.encode(forged.to_bytes())})).await;
    assert_eq!(code, 401);
}

#[tokio::test]
async fn names_cannot_be_hijacked_and_premium_outranks_a_claim() {
    let url = mock_mojang().await;
    let app = app(AuthCfg { session_url: url, mojang: true, key: true, require_ticket: true, ..Default::default() });
    assert_eq!(key_login(&app, 1, "Notch").await.0, 200);
    assert_eq!(key_login(&app, 2, "Notch").await.1["error"], "NAME_TAKEN");

    let (c, v) = mojang_login(&app, "Notch").await;
    assert_eq!(c, 200);
    assert_eq!(v["uuid"], "069a79f4-44e9-4726-a5be-fca90e38aaf5");
    assert_eq!(key_login(&app, 1, "Notch").await.1["error"], "NAME_TAKEN");
    assert_eq!(key_login(&app, 1, "Notch_key").await.0, 200);

    assert_eq!(mojang_login(&app, "Nobody").await.0, 401);
    assert_eq!(key_login(&app, 3, "x").await.1["error"], "BAD_NAME");
}

#[tokio::test]
async fn modes_can_be_disabled() {
    let app = app(AuthCfg { session_url: "http://127.0.0.1:1".into(), mojang: false, key: false, require_ticket: true, ..Default::default() });
    assert_eq!(key_login(&app, 4, "Someone").await.1["error"], "AUTH_DISABLED");
    assert_eq!(mojang_login(&app, "Notch").await.1["error"], "AUTH_DISABLED");
}
