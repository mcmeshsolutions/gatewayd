use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-pulse-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "Pulse World", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_member("w1", "u-c", "charlie", "dev-c", Role::ClientOnly).unwrap();
    for (d, t) in [("dev-a", "tok-a"), ("dev-b", "tok-b"), ("dev-c", "tok-c")] {
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
async fn live_pulse_reports_idle_and_active_telemetry_correctly() {
    let app = app();

    // 1. Idle state
    let (c, v) = call(&app, "GET", "tok-a", "/v1/worlds/w1/pulse", Value::Null).await;
    assert_eq!(c, 200);
    assert_eq!(v["world_state"], "IDLE");
    assert!(v["host"].is_null());
    assert_eq!(v["failover"]["ready"], false);
    assert_eq!(v["frozen"], false);

    // 2. Alice becomes host
    let (c, join_res) = call(&app, "POST", "tok-a", "/v1/worlds/w1/join", json!({
        "hw": {
            "tier": 2,
            "score": 88.5,
            "wants_host": true,
            "takeover": false,
            "bench": { "cores": 16, "cpu": "AMD Ryzen 9", "heap_mb": 16384, "os": "Linux" }
        }
    })).await;
    assert_eq!(c, 200);
    let lease_id = join_res["lease"]["id"].as_str().unwrap().to_string();

    // Alice sends heartbeat with TPS and load
    let (c, hb_resp) = call(&app, "POST", "tok-a", &format!("/v1/leases/{lease_id}/heartbeat"), json!({
        "epoch": 1,
        "players": 4,
        "load": 0,
        "tps": 19.9
    })).await;
    assert_eq!(c, 200);
    assert_eq!(hb_resp["ok"], true);

    // 3. Bob joins as backup candidate
    let (c, _) = call(&app, "POST", "tok-b", "/v1/worlds/w1/join", json!({
        "hw": {
            "tier": 2,
            "score": 92.0,
            "wants_host": true,
            "takeover": false,
            "bench": { "cores": 8, "cpu": "Intel i7", "heap_mb": 8192, "os": "Windows" }
        }
    })).await;
    assert_eq!(c, 200);

    // 4. Query live pulse from client charlie
    let (c, v) = call(&app, "GET", "tok-c", "/v1/worlds/w1/pulse", Value::Null).await;
    assert_eq!(c, 200);
    assert_eq!(v["world_state"], "LOCKED");
    assert_eq!(v["host"]["player_name"], "alice");
    assert_eq!(v["host"]["hw_score"], 88.5);
    assert_eq!(v["host"]["tps"], 19.9);
    assert_eq!(v["host"]["health"], "OPTIMAL");
    assert_eq!(v["host"]["players_online"], 4);
    assert_eq!(v["host"]["hw_info"]["cpu"], "AMD Ryzen 9");

    // Failover readiness
    assert_eq!(v["failover"]["ready"], true);
    assert_eq!(v["failover"]["candidate_count"], 1);
    assert_eq!(v["failover"]["best_candidate"]["player_name"], "bob");
    assert_eq!(v["failover"]["best_candidate"]["score"], 92.0);
    assert_eq!(v["controls"]["can_handover"], true);
    assert_eq!(v["controls"]["can_flush"], true);
}

#[tokio::test]
async fn zero_ssh_remote_controls_execute_and_deliver_directives() {
    let app = app();

    // Setup host and candidate via HTTP
    let (_, join_res) = call(&app, "POST", "tok-a", "/v1/worlds/w1/join", json!({
        "hw": { "tier": 2, "score": 70.0, "wants_host": true, "takeover": false }
    })).await;
    let lease_id = join_res["lease"]["id"].as_str().unwrap().to_string();

    let _ = call(&app, "POST", "tok-b", "/v1/worlds/w1/join", json!({
        "hw": { "tier": 2, "score": 85.0, "wants_host": true, "takeover": false }
    })).await;

    // 1. Non-admin cannot trigger remote controls
    let (c, _) = call(&app, "POST", "tok-c", "/v1/worlds/w1/pulse/flush", Value::Null).await;
    assert_eq!(c, 403);
    let (c, _) = call(&app, "POST", "tok-c", "/v1/worlds/w1/pulse/freeze", json!({ "frozen": true })).await;
    assert_eq!(c, 403);
    let (c, _) = call(&app, "POST", "tok-c", "/v1/worlds/w1/pulse/handover", json!({})).await;
    assert_eq!(c, 403);

    // 2. Admin triggers WAL barrier flush
    let (c, v) = call(&app, "POST", "tok-a", "/v1/worlds/w1/pulse/flush", Value::Null).await;
    assert_eq!(c, 200);
    assert_eq!(v["barrier_pending"], true);

    // 3. Admin toggles Lag Freeze
    let (c, v) = call(&app, "POST", "tok-a", "/v1/worlds/w1/pulse/freeze", json!({ "frozen": true })).await;
    assert_eq!(c, 200);
    assert_eq!(v["frozen"], true);

    // Pulse reflects freeze and pending barrier
    let (_, v) = call(&app, "GET", "tok-a", "/v1/worlds/w1/pulse", Value::Null).await;
    assert_eq!(v["frozen"], true);
    assert_eq!(v["controls"]["barrier_pending"], true);

    // 4. Admin triggers Handover
    let (c, v) = call(&app, "POST", "tok-a", "/v1/worlds/w1/pulse/handover", json!({ "target_device": "dev-b" })).await;
    assert_eq!(c, 200);
    assert_eq!(v["handover_initiated"], true);
    assert_eq!(v["target_device"], "dev-b");

    // 5. Host heartbeats and receives all 3 directives!
    let (c, v) = call(&app, "POST", "tok-a", &format!("/v1/leases/{lease_id}/heartbeat"), json!({
        "epoch": 1,
        "players": 2,
        "load": 0,
        "tps": 20.0
    })).await;
    assert_eq!(c, 200);
    let dirs = v["directives"].as_array().unwrap();
    let types: Vec<&str> = dirs.iter().map(|d| d["type"].as_str().unwrap()).collect();
    assert!(types.contains(&"FLUSH_BARRIER"), "expected FLUSH_BARRIER directive: {dirs:?}");
    assert!(types.contains(&"LAG_FREEZE"), "expected LAG_FREEZE directive: {dirs:?}");
    assert!(types.contains(&"MIGRATE_PREPARE"), "expected MIGRATE_PREPARE directive: {dirs:?}");
}
