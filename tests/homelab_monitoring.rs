use gatewayd::cas::Cas;
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn test_healthz_and_homeassistant_discovery() {
    let temp = std::env::temp_dir().join(format!("mcmesh-test-mon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();

    let cas = Cas::open(temp.join("cas")).unwrap();
    let mut g =
        Gateway::open(rusqlite::Connection::open(temp.join("mcmesh.db")).unwrap(), cas, 0).unwrap();
    g.create_world("w1", "World 1", "1.21.1", "neoforge").unwrap();
    g.create_world("w2", "World 2", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-alice", "alice", "d-alice", Role::Admin).unwrap();

    let app = AppState::new(g);
    let r = router(app);

    // 1. GET /healthz
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let hz: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(hz["ok"], true);
    assert_eq!(hz["status"], "healthy");
    assert_eq!(hz["worlds_total"], 2);
    assert_eq!(hz["maintenance"], false);

    // 2. GET /v1/monitoring/homeassistant
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/monitoring/homeassistant")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let ha: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ha["ok"], true);
    assert_eq!(ha["discovery_prefix"], "homeassistant");
    assert_eq!(ha["state_topic"], "mcmesh/gateway/state");
    assert_eq!(ha["state"]["online"], "ON");
    assert_eq!(ha["state"]["worlds_total"], 2);
    assert_eq!(ha["state"]["players_registered"], 1);
    let configs = ha["discovery_configs"].as_array().unwrap();
    assert_eq!(configs.len(), 7);
    assert_eq!(
        configs[0]["topic"],
        "homeassistant/binary_sensor/mcmesh_gateway_online/config"
    );

    // 3. GET /v1/widget/homelab
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/widget/homelab")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let w: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(w["ok"], true);
    assert_eq!(w["status"], "online");
    assert_eq!(w["worlds_total"], 2);
    assert_eq!(w["worlds_active"], 0);
    assert_eq!(w["players_registered"], 1);
    assert_eq!(w["revisions_total"], 2);

    let _ = std::fs::remove_dir_all(&temp);
}
