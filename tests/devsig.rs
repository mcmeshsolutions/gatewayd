use axum::{body::Body, http::Request, Router};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use gatewayd::devsig::{commit_message, device_key_message};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn app(require_signed: bool) -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-devsig-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    let cfg = gatewayd::auth::AuthCfg { require_signed, ..Default::default() };
    router(AppState::with_auth(g, cfg))
}

async fn post(app: &Router, path: &str, body: Value) -> (u16, Value) {
    let r = Request::post(path).header("content-type", "application/json").header("authorization", "Bearer tok-a");
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

struct Host {
    lease: String,
    base: String,
}

async fn join(app: &Router) -> Host {
    let (_, v) = post(app, "/v1/worlds/w1/join", json!({ "hw": { "tier": 2, "score": 5.0 } })).await;
    Host { lease: v["lease"]["id"].as_str().unwrap().into(), base: v["lease"]["base_rev"].as_str().unwrap().into() }
}

async fn register(app: &Router, sk: &SigningKey) -> (u16, Value) {
    let pk = sk.verifying_key().to_bytes();
    let sig = sk.sign(&device_key_message("dev-a", &pk)).to_bytes();
    post(app, "/v1/devices/key", json!({ "pubkey": b64(&pk), "sig": b64(&sig) })).await
}

fn commit_body(h: &Host, kind: &str, last: bool, sig: Option<[u8; 64]>) -> Value {
    let mut b = json!({ "epoch": 1, "base_rev": h.base, "kind": kind, "final": last });
    if let Some(s) = sig {
        b["sig"] = json!(b64(&s));
    }
    b
}

#[tokio::test]
async fn key_registration_needs_proof_and_first_key_wins() {
    let app = app(false);
    let sk = SigningKey::from_bytes(&[5u8; 32]);
    assert_eq!(register(&app, &sk).await.0, 200);
    assert_eq!(register(&app, &sk).await.0, 200, "the same key again is fine");
    let (c, v) = register(&app, &SigningKey::from_bytes(&[6u8; 32])).await;
    assert_eq!((c, v["error"].as_str()), (409, Some("DEVICE_KEY_SET")));

    let app2 = self::app(false);
    let pk = sk.verifying_key().to_bytes();
    let stolen = SigningKey::from_bytes(&[7u8; 32]).sign(&device_key_message("dev-a", &pk)).to_bytes();
    let (c, v) = post(&app2, "/v1/devices/key", json!({ "pubkey": b64(&pk), "sig": b64(&stolen) })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("BAD_SIGNATURE")), "no proof of possession, no key");
    let (c, _) = post(&app2, "/v1/devices/key", json!({ "pubkey": "AAAA", "sig": "AAAA" })).await;
    assert_eq!(c, 400);
}

#[tokio::test]
async fn signed_commits_are_checked_and_unsigned_ones_still_work_by_default() {
    let app = app(false);
    let h = join(&app).await;
    let sk = SigningKey::from_bytes(&[5u8; 32]);
    let sign = |kind: &str, last: bool, barrier: i64| sk.sign(&commit_message("w1", &h.lease, 1, &h.base, kind, last, barrier)).to_bytes();
    let path = format!("/v1/leases/{}/commit", h.lease);

    let (c, v) = post(&app, &path, commit_body(&h, "AUTOSAVE", false, Some(sign("AUTOSAVE", false, -1)))).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("NO_DEVICE_KEY")));
    assert_eq!(register(&app, &sk).await.0, 200);
    let (c, v) = post(&app, &path, commit_body(&h, "AUTOSAVE", false, Some(sign("AUTOSAVE", false, 4)))).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("BAD_SIGNATURE")), "the host's barrier differs from the gateway's view");
    let (c, v) = post(&app, &path, json!({ "epoch": 1, "base_rev": h.base, "kind": "AUTOSAVE", "sig": "not base64!" })).await;
    assert_eq!((c, v["error"].as_str()), (400, Some("BAD_SIG")));
    let (c, v) = post(&app, &path, commit_body(&h, "AUTOSAVE", false, Some(sign("AUTOSAVE", false, -1)))).await;
    assert_eq!((c, v["rev_id"].is_string()), (200, true));
}

#[tokio::test]
async fn require_signed_refuses_unsigned_commits_and_accepts_signed_ones() {
    let app = app(true);
    let h = join(&app).await;
    let sk = SigningKey::from_bytes(&[5u8; 32]);
    let path = format!("/v1/leases/{}/commit", h.lease);
    let (c, v) = post(&app, &path, commit_body(&h, "AUTOSAVE", false, None)).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("SIGNATURE_REQUIRED")));
    assert_eq!(register(&app, &sk).await.0, 200);
    let sig = sk.sign(&commit_message("w1", &h.lease, 1, &h.base, "AUTOSAVE", false, -1)).to_bytes();
    assert_eq!(post(&app, &path, commit_body(&h, "AUTOSAVE", false, Some(sig))).await.0, 200);
}

async fn put(app: &Router, path: &str, tok: &str, body: Value) -> (u16, Value) {
    let r = Request::put(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_owner_can_require_signatures_for_one_world() {
    let app = app(false);
    let h = join(&app).await;
    let path = format!("/v1/leases/{}/commit", h.lease);
    let (c, v) = put(&app, "/v1/worlds/w1/signing", "tok-a", json!({ "require_signed": true })).await;
    assert_eq!((c, v["require_signed"].as_bool()), (200, Some(true)));
    let (c, v) = post(&app, &path, commit_body(&h, "AUTOSAVE", false, None)).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("SIGNATURE_REQUIRED")));
    let sk = SigningKey::from_bytes(&[5u8; 32]);
    assert_eq!(register(&app, &sk).await.0, 200);
    let sig = sk.sign(&commit_message("w1", &h.lease, 1, &h.base, "AUTOSAVE", false, -1)).to_bytes();
    assert_eq!(post(&app, &path, commit_body(&h, "AUTOSAVE", false, Some(sig))).await.0, 200);
    let (c, _) = put(&app, "/v1/worlds/w1/signing", "tok-a", json!({ "require_signed": false })).await;
    assert_eq!(c, 200);
    let (_, v) = {
        let r = Request::get("/v1/worlds/w1/policy").header("authorization", "Bearer tok-a");
        let resp = app.clone().oneshot(r.body(Body::empty()).unwrap()).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (0, serde_json::from_slice::<Value>(&bytes).unwrap())
    };
    assert_eq!(v["require_signed"].as_bool(), Some(false));
}

#[tokio::test]
async fn only_an_owner_or_admin_can_change_the_signing_requirement() {
    let app = app(false);
    let (c, v) = put(&app, "/v1/worlds/w1/signing", "tok-nobody", json!({ "require_signed": true })).await;
    assert_eq!((c, v["error"].as_str()), (401, Some("UNAUTHORIZED")));
}
