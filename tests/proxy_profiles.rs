use axum::{body::Body, http::Request, Router};
use gatewayd::lease::Gateway;
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::Value;
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-proxytest-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    router(AppState::new(g))
}

async fn req_with_headers(app: &Router, headers: &[(&str, &str)]) -> (u16, Value) {
    let mut builder = Request::builder().method("GET").uri("/v1/proxy/test");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let resp = app.clone().oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn caddy_reverse_proxy_headers_detected() {
    let app = app();
    let headers = [
        ("host", "mesh.example.com"),
        ("x-forwarded-for", "198.51.100.42"),
        ("x-forwarded-proto", "https"),
    ];
    let (c, v) = req_with_headers(&app, &headers).await;
    assert_eq!(c, 200);
    assert_eq!(v["ok"], true);
    assert_eq!(v["client_ip"], "198.51.100.42");
    assert_eq!(v["proto"], "https");
    assert_eq!(v["host"], "mesh.example.com");
    assert_eq!(v["proxy_type"], "caddy");
    assert!(v["warnings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn nginx_headers_with_websocket_upgrade_detected() {
    let app = app();
    let headers = [
        ("host", "mc.company.org"),
        ("x-real-ip", "203.0.113.1"),
        ("x-forwarded-for", "203.0.113.1, 10.0.0.1"),
        ("x-forwarded-proto", "https"),
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
    ];
    let (c, v) = req_with_headers(&app, &headers).await;
    assert_eq!(c, 200);
    assert_eq!(v["ok"], true);
    assert_eq!(v["client_ip"], "203.0.113.1");
    assert_eq!(v["proto"], "https");
    assert_eq!(v["proxy_type"], "nginx");
    assert_eq!(v["websocket_ready"], true);
    assert!(v["warnings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn cloudflare_tunnel_headers_detected() {
    let app = app();
    let headers = [
        ("host", "smp.cloud.io"),
        ("cf-connecting-ip", "192.0.2.77"),
        ("cf-ray", "8e1a2b3c4d5e-FRA"),
        ("cf-visitor", "{\"scheme\":\"https\"}"),
    ];
    let (c, v) = req_with_headers(&app, &headers).await;
    assert_eq!(c, 200);
    assert_eq!(v["ok"], true);
    assert_eq!(v["client_ip"], "192.0.2.77");
    assert_eq!(v["proto"], "https");
    assert_eq!(v["proxy_type"], "cloudflare");
    assert!(v["warnings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn insecure_or_missing_headers_trigger_warnings() {
    let app = app();
    // 1. Plaintext direct request with no proxy headers
    let (c, v) = req_with_headers(&app, &[]).await;
    assert_eq!(c, 200);
    assert_eq!(v["ok"], false);
    assert_eq!(v["proto"], "http");
    let warnings = v["warnings"].as_array().unwrap();
    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("No client IP forwarding headers")));

    // 2. HTTP proxy forwarding without HTTPS
    let headers = [
        ("x-forwarded-for", "203.0.113.50"),
        ("x-forwarded-proto", "http"),
        ("host", "localhost:8080"),
    ];
    let (c, v) = req_with_headers(&app, &headers).await;
    assert_eq!(c, 200);
    assert_eq!(v["ok"], false);
    let warnings = v["warnings"].as_array().unwrap();
    assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("plaintext HTTP")));
}
