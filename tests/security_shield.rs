use axum::extract::ConnectInfo;
use gatewayd::cas::Cas;
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use gatewayd::shield::{CidrNet, SecurityShield, ShieldConfig};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use tower::ServiceExt;

#[test]
fn test_cidr_ipv4_and_ipv6_matching() {
    let v4 = CidrNet::parse("198.51.100.0/24").expect("valid v4 cidr");
    assert!(v4.contains("198.51.100.1".parse().unwrap()));
    assert!(v4.contains("198.51.100.254".parse().unwrap()));
    assert!(!v4.contains("198.51.101.1".parse().unwrap()));

    let v6 = CidrNet::parse("2001:db8:abcd::/48").expect("valid v6 cidr");
    assert!(v6.contains("2001:db8:abcd::1".parse().unwrap()));
    assert!(v6.contains("2001:db8:abcd:ffff::99".parse().unwrap()));
    assert!(!v6.contains("2001:db8:9999::1".parse().unwrap()));

    assert!(CidrNet::parse("198.51.100.1/33").is_none());
    assert!(CidrNet::parse("not-a-cidr").is_none());
}

#[test]
fn test_fail2ban_auto_jail_and_clear() {
    let shield = SecurityShield::new(ShieldConfig {
        max_failures: 3,
        findtime_s: 300,
        bantime_s: 600,
    });

    assert!(shield.check_request("203.0.113.50", None, None).is_none());

    // First two failures do not trigger jail
    assert!(shield.record_failed_auth("203.0.113.50", "/v1/auth/mojang", "bad token").is_none());
    assert!(shield.record_failed_auth("203.0.113.50", "/v1/auth/mojang", "bad token").is_none());
    assert!(shield.check_request("203.0.113.50", None, None).is_none());

    // Third failure triggers auto-jail
    let jail_ban = shield
        .record_failed_auth("203.0.113.50", "/v1/auth/mojang", "bad token")
        .expect("auto-jailed on 3rd failure");
    assert_eq!(jail_ban.target, "203.0.113.50");
    assert_eq!(jail_ban.created_by, "fail2ban");

    // Subsequent requests are blocked
    let blocked = shield.check_request("203.0.113.50", None, None).expect("blocked");
    assert_eq!(blocked.id, jail_ban.id);
    assert_eq!(shield.total_blocked(), 1);

    // Clear auto-jail releases the IP
    let cleared = shield.clear_jail();
    assert_eq!(cleared, 1);
    assert!(shield.check_request("203.0.113.50", None, None).is_none());
}

#[tokio::test]
async fn test_security_shield_http_endpoints_and_middleware() {
    let temp = std::env::temp_dir().join(format!("mcmesh-test-shield-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();

    let cas = Cas::open(temp.join("cas")).unwrap();
    let mut g = Gateway::open(rusqlite::Connection::open(temp.join("mcmesh.db")).unwrap(), cas, 0).unwrap();
    g.admin_init().unwrap();
    g.create_world("w1", "World 1", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-admin", "admin", "d-admin", Role::Admin).unwrap();
    g.set_gateway_admin("u-admin", true, "test").unwrap();
    let admin_tok = "shield-admin-token";
    g.add_token("d-admin", admin_tok).unwrap();

    let auth_cfg = gatewayd::auth::AuthCfg {
        key: true,
        ..Default::default()
    };
    let app = AppState::with_auth(g, auth_cfg);
    let r = router(app.clone());

    // 1. Create a CIDR ban on 192.0.2.0/24 via POST /v1/admin/security/bans
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/admin/security/bans")
        .header("authorization", format!("Bearer {admin_tok}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&serde_json::json!({
                "target": "192.0.2.0/24",
                "kind": "cidr",
                "reason": "Blocked botnet subnet",
                "duration_s": 3600
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let ban_res: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ban_res["ok"], true);
    let ban_id = ban_res["ban"]["id"].as_str().unwrap().to_string();

    // 2. Request from an IP inside 192.0.2.0/24 is rejected with 403 SHIELD_BANNED
    let mut blocked_req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/worlds")
        .header("authorization", format!("Bearer {admin_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();
    blocked_req
        .extensions_mut()
        .insert(ConnectInfo("192.0.2.88:54321".parse::<SocketAddr>().unwrap()));

    let resp = r.clone().oneshot(blocked_req).await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["error"], "SHIELD_BANNED");

    // 3. GET /v1/admin/security/shield shows active ban and total_blocked == 1
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/admin/security/shield")
        .header("authorization", format!("Bearer {admin_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let shield_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(shield_json["stats"]["total_blocked"], 1);
    assert_eq!(shield_json["stats"]["active_bans"], 1);

    // 4. Delete the CIDR ban via DELETE /v1/admin/security/bans/:id
    let req = axum::http::Request::builder()
        .method("DELETE")
        .uri(format!("/v1/admin/security/bans/{ban_id}"))
        .header("authorization", format!("Bearer {admin_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // 5. Request from 192.0.2.88 now succeeds
    let mut unblocked_req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/worlds")
        .header("authorization", format!("Bearer {admin_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();
    unblocked_req
        .extensions_mut()
        .insert(ConnectInfo("192.0.2.88:54321".parse::<SocketAddr>().unwrap()));
    let resp = r.clone().oneshot(unblocked_req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let _ = std::fs::remove_dir_all(&temp);
}
