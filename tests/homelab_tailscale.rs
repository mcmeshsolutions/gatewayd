use gatewayd::cas::Cas;
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use gatewayd::tailscale::{is_tailnet_ip, parse_tailscale_status_json};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[test]
fn test_tailnet_ip_detection_and_status_parser() {
    assert!(is_tailnet_ip("100.64.0.1".parse().unwrap()));
    assert!(is_tailnet_ip("100.101.202.55".parse().unwrap()));
    assert!(is_tailnet_ip("100.127.255.254".parse().unwrap()));
    assert!(!is_tailnet_ip("100.128.0.1".parse().unwrap()));
    assert!(!is_tailnet_ip("192.168.1.10".parse().unwrap()));

    assert!(is_tailnet_ip("fd7a:115c:a1e0::1234".parse().unwrap()));
    assert!(!is_tailnet_ip("2001:db8::1".parse().unwrap()));

    let sample_json = r#"{
        "BackendState": "Running",
        "Self": {
            "DNSName": "mcmesh-gateway.tail1234.ts.net.",
            "TailscaleIPs": ["100.88.42.10", "fd7a:115c:a1e0::abcd"]
        },
        "Peer": {
            "nodekey:1": { "Online": true },
            "nodekey:2": { "Online": false },
            "nodekey:3": { "Online": true }
        }
    }"#;

    let (dns, v4, v6, peers, running) =
        parse_tailscale_status_json(sample_json).expect("valid tailscale json");
    assert!(running);
    assert_eq!(dns.as_deref(), Some("mcmesh-gateway.tail1234.ts.net"));
    assert_eq!(v4.as_deref(), Some("100.88.42.10"));
    assert_eq!(v6.as_deref(), Some("fd7a:115c:a1e0::abcd"));
    assert_eq!(peers, 2);
}

#[tokio::test]
async fn test_tailscale_admin_endpoints() {
    let temp = std::env::temp_dir().join(format!("mcmesh-test-ts-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();

    let cas = Cas::open(temp.join("cas")).unwrap();
    let mut g =
        Gateway::open(rusqlite::Connection::open(temp.join("mcmesh.db")).unwrap(), cas, 0).unwrap();
    g.admin_init().unwrap();
    g.create_world("w1", "World 1", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-admin", "admin", "d-admin", Role::Admin).unwrap();
    g.set_gateway_admin("u-admin", true, "test").unwrap();
    let admin_tok = "ts-admin-token";
    g.add_token("d-admin", admin_tok).unwrap();

    let auth_cfg = gatewayd::auth::AuthCfg {
        key: true,
        ..Default::default()
    };
    let app = AppState::with_auth(g, auth_cfg);
    let r = router(app);

    // 1. POST /v1/admin/tailscale/up
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/admin/tailscale/up")
        .header("authorization", format!("Bearer {admin_tok}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&serde_json::json!({
                "hostname": "homelab-mc",
                "magic_dns": "homelab-mc.tail99.ts.net",
                "tailnet_ip": "100.99.1.5",
                "funnel": false
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let up_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(up_json["ok"], true);
    assert_eq!(up_json["status"]["enabled"], true);
    assert_eq!(up_json["status"]["online"], true);
    assert_eq!(up_json["status"]["advertise_addr"], "homelab-mc.tail99.ts.net:25565");

    // 2. GET /v1/admin/tailscale/status
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/admin/tailscale/status")
        .header("authorization", format!("Bearer {admin_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let st_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(st_json["status"]["tailnet_ip"], "100.99.1.5");
    assert_eq!(st_json["status"]["zero_port_cgnat"], true);

    let _ = std::fs::remove_dir_all(&temp);
}
