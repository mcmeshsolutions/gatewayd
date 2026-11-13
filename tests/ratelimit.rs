use axum::{body::Body, http::Request, Router};
use gatewayd::lease::Gateway;
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::Value;
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-rate-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    router(AppState::new(g))
}

async fn hit(app: &Router, method: &str, path: &str, token: Option<&str>) -> (u16, Option<String>, Value) {
    let mut r = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(t) = token {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(r.body(Body::from("{}")).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let retry = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).map(str::to_string);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, retry, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn login_routes_are_cut_after_a_burst_of_sixty() {
    let app = app();
    for _ in 0..60 {
        assert_ne!(hit(&app, "POST", "/v1/auth/challenge", None).await.0, 429);
    }
    let (c, retry, body) = hit(&app, "POST", "/v1/auth/challenge", None).await;
    assert_eq!((c, body["error"].as_str()), (429, Some("RATE_LIMITED")));
    assert!(retry.unwrap().parse::<u64>().unwrap() >= 1);
}

#[tokio::test]
async fn unauthenticated_public_routes_are_limited_too() {
    let app = app();
    let mut cut = 0;
    for _ in 0..150 {
        if hit(&app, "GET", "/status", None).await.0 == 429 {
            cut += 1;
        }
    }
    assert!(cut >= 40, "100 burst, the rest refused: {cut}");
}

#[tokio::test]
async fn one_token_hitting_the_limit_does_not_block_another() {
    let app = app();
    for _ in 0..100 {
        hit(&app, "GET", "/v1/worlds", Some("tok-a")).await;
    }
    assert_eq!(hit(&app, "GET", "/v1/worlds", Some("tok-a")).await.0, 429);
    assert_ne!(hit(&app, "GET", "/v1/worlds", Some("tok-b")).await.0, 429);
}

#[tokio::test]
async fn lease_traffic_has_its_own_much_bigger_budget() {
    let app = app();
    for i in 0..600 {
        let (c, _, _) = hit(&app, "POST", "/v1/leases/l1/heartbeat", Some("host")).await;
        assert_ne!(c, 429, "request {i}");
    }
}
