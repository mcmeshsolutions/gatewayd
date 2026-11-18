use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-p2pmeter-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "P2P World", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::ClientOnly).unwrap();
    for (d, t) in [("dev-a", "tok-a"), ("dev-b", "tok-b")] {
        g.add_token(d, t).unwrap();
    }
    router(AppState::new(g))
}

async fn call(app: &Router, method: &str, tok: &str, path: &str, body: Value) -> (u16, Value) {
    let r = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn p2p_bandwidth_meter_tracks_offload_and_cloud_savings() {
    let app = app();

    // 1. Initial state before any traffic
    let (c, v) = call(&app, "GET", "tok-a", "/v1/worlds/w1/p2p-meter", Value::Null).await;
    assert_eq!(c, 200);
    assert_eq!(v["world_id"], "w1");
    assert_eq!(v["p2p_direct_bytes"], 0);
    assert_eq!(v["central_relay_total_bytes"], 0);
    assert_eq!(v["total_traffic_bytes"], 0);
    assert_eq!(v["p2p_offload_rate_percent"], 0.0);
    assert_eq!(v["cloud_cost_savings_usd"], 0.0);

    // 2. Host joins world w1
    let (c, join_res) = call(&app, "POST", "tok-a", "/v1/worlds/w1/join", json!({
        "hw": {
            "tier": 2,
            "score": 90.0,
            "wants_host": true,
            "takeover": false
        }
    })).await;
    assert_eq!(c, 200);
    let lease_id = join_res["lease"]["id"].as_str().unwrap().to_string();

    // 3. Host reports 1 GB of direct P2P traffic via heartbeat
    let one_gb: u64 = 1024 * 1024 * 1024;
    let (c, hb_res) = call(&app, "POST", "tok-a", &format!("/v1/leases/{lease_id}/heartbeat"), json!({
        "epoch": 1,
        "players": 2,
        "tps": 20.0,
        "p2p_direct_bytes": one_gb
    })).await;
    assert_eq!(c, 200);
    assert_eq!(hb_res["ok"], true);

    // 4. Verify /v1/worlds/w1/p2p-meter calculates offload and cost savings ($0.09 for 1 GB)
    let (c, meter) = call(&app, "GET", "tok-a", "/v1/worlds/w1/p2p-meter", Value::Null).await;
    assert_eq!(c, 200);
    assert_eq!(meter["p2p_direct_bytes"], one_gb);
    assert_eq!(meter["total_traffic_bytes"], one_gb);
    assert_eq!(meter["p2p_offload_rate_percent"], 100.0);
    assert_eq!(meter["cloud_cost_savings_usd"], 0.09);

    // 5. Verify live pulse also embeds the P2P scorecard
    let (c, pulse) = call(&app, "GET", "tok-a", "/v1/worlds/w1/pulse", Value::Null).await;
    assert_eq!(c, 200);
    assert_eq!(pulse["p2p_scorecard"]["p2p_direct_bytes"], one_gb);
    assert_eq!(pulse["p2p_scorecard"]["p2p_offload_rate_percent"], 100.0);
    assert_eq!(pulse["p2p_scorecard"]["cloud_cost_savings_usd"], 0.09);

    // 6. Unauthorized / non-member check
    let (c, _) = call(&app, "GET", "unknown-token", "/v1/worlds/w1/p2p-meter", Value::Null).await;
    assert!(c == 401 || c == 403);
}
