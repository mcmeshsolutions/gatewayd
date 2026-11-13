use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-events-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.create_world("w2", "y", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_member("w1", "u-c", "cara", "dev-c", Role::ClientOnly).unwrap();
    g.add_member("w2", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    for (d, t) in [("dev-a", "tok-a"), ("dev-b", "tok-b"), ("dev-c", "tok-c")] {
        g.add_token(d, t).unwrap();
    }
    router(AppState::new(g))
}

async fn call(app: &Router, method: &str, tok: Option<&str>, path: &str, body: Value) -> (u16, Value) {
    let mut r = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn host(app: &Router, tok: &str, world: &str) -> String {
    let (_, v) = call(app, "POST", Some(tok), &format!("/v1/worlds/{world}/join"), json!({ "hw": { "tier": 2, "score": 5.0 } })).await;
    v["lease"]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn a_member_reads_only_the_events_of_their_world_in_order() {
    let app = app();
    host(&app, "tok-a", "w1").await;
    host(&app, "tok-b", "w2").await;
    let (c, v) = call(&app, "GET", Some("tok-c"), "/v1/worlds/w1/events", Value::Null).await;
    assert_eq!(c, 200);
    let ev = v["events"].as_array().unwrap();
    assert_eq!(ev.len(), 1, "{v}");
    assert_eq!(ev[0]["event"], "host.started");
    let next = v["next"].as_u64().unwrap();
    assert!(next >= 1);
    let (_, again) = call(&app, "GET", Some("tok-c"), &format!("/v1/worlds/w1/events?after={next}"), Value::Null).await;
    assert!(again["events"].as_array().unwrap().is_empty());
    assert_eq!(again["next"].as_u64(), Some(next), "an empty page keeps the cursor");

    let (c, v) = call(&app, "GET", Some("tok-c"), "/v1/worlds/w2/events", Value::Null).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("NOT_MEMBER")));
    assert_eq!(call(&app, "GET", None, "/v1/worlds/w1/events", Value::Null).await.0, 401);
    assert_eq!(call(&app, "GET", Some("tok-c"), "/v1/worlds/w1/events?after=x", Value::Null).await.0, 400);
}

#[tokio::test]
async fn a_long_poll_returns_as_soon_as_something_happens() {
    let app = app();
    let lease = host(&app, "tok-a", "w1").await;
    let (_, first) = call(&app, "GET", Some("tok-c"), "/v1/worlds/w1/events", Value::Null).await;
    let next = first["next"].as_u64().unwrap();
    let waiter = {
        let app = app.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let (_, v) = call(&app, "GET", Some("tok-c"), &format!("/v1/worlds/w1/events?after={next}&wait=10"), Value::Null).await;
            (started.elapsed(), v)
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (c, _) = call(&app, "POST", Some("tok-a"), &format!("/v1/leases/{lease}/release"), json!({ "epoch": 1 })).await;
    assert_eq!(c, 200);
    let (took, v) = tokio::time::timeout(Duration::from_secs(8), waiter).await.expect("woken in time").unwrap();
    assert!(took < Duration::from_secs(5), "returned on the event, not at the timeout: {took:?}");
    assert_eq!(v["events"][0]["event"], "host.released");
}

#[tokio::test]
async fn an_idle_long_poll_times_out_empty_and_a_restart_is_reported() {
    let app = app();
    host(&app, "tok-a", "w1").await;
    let started = Instant::now();
    let (_, v) = call(&app, "GET", Some("tok-c"), "/v1/worlds/w1/events?after=999&wait=1", Value::Null).await;
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert!(v["events"].as_array().unwrap().is_empty());
    let boot = v["boot"].as_u64().unwrap();
    let (_, r) = call(&app, "GET", Some("tok-c"), &format!("/v1/worlds/w1/events?after=999&boot={}", boot + 1), Value::Null).await;
    assert_eq!(r["reset"], true);
    assert_eq!(r["events"].as_array().unwrap().len(), 1, "a stale cursor from before a restart replays the current log");
}

#[tokio::test]
async fn the_world_list_shows_the_hosts_reported_load_and_players() {
    let app = app();
    let lease = host(&app, "tok-a", "w1").await;
    let find = |v: &Value| v["worlds"].as_array().unwrap().iter().find(|w| w["id"] == "w1").cloned().unwrap();
    let (_, v) = call(&app, "GET", Some("tok-c"), "/v1/worlds", Value::Null).await;
    assert_eq!((find(&v)["host_load"].clone(), find(&v)["host_players"].clone()), (Value::Null, Value::Null), "unknown until the host reports");
    let (c, _) = call(&app, "POST", Some("tok-a"), &format!("/v1/leases/{lease}/heartbeat"), json!({ "epoch": 1, "players": 3, "load": 2 })).await;
    assert_eq!(c, 200);
    let (_, v) = call(&app, "GET", Some("tok-c"), "/v1/worlds", Value::Null).await;
    assert_eq!((find(&v)["host_load"].as_u64(), find(&v)["host_players"].as_u64()), (Some(2), Some(3)));
}
