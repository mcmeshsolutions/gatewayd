use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tower::ServiceExt;

fn app() -> Router {
    app_state().0
}

fn app_state() -> (Router, std::sync::Arc<AppState>) {
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
    let state = AppState::new(g);
    (router(state.clone()), state)
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

#[tokio::test]
async fn the_discovery_document_is_public_and_lists_features_without_secrets() {
    let app = app();
    let resp = app.clone().oneshot(Request::get("/.well-known/mcmesh-gateway.json").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["gateway"], "mcmesh");
    assert_eq!(v["api"], "/v1");
    assert!(v["auth"].as_array().unwrap().iter().any(|a| a == "key"));
    assert!(v["features"].as_array().unwrap().iter().any(|f| f == "handover_vote"));
    assert_eq!(v["relay"], Value::Null, "no relay address is advertised in this test setup");
    let text = String::from_utf8_lossy(&bytes).to_lowercase();
    assert!(!text.contains("token") && !text.contains("secret"), "nothing sensitive: {text}");
}

#[tokio::test]
async fn a_player_who_cannot_host_an_idle_world_raises_world_wanted_once() {
    let app = app();
    let join = |tok: &'static str| {
        let app = app.clone();
        async move { call(&app, "POST", Some(tok), "/v1/worlds/w1/join", json!({ "hw": { "tier": 2, "score": 5.0 } })).await }
    };
    let (c, v) = join("tok-c").await;
    assert_eq!(c, 200);
    assert_ne!(v["decision"], "HOST", "a client-only member never hosts");
    join("tok-c").await;
    let (_, ev) = call(&app, "GET", Some("tok-c"), "/v1/worlds/w1/events", Value::Null).await;
    let wanted: Vec<_> = ev["events"].as_array().unwrap().iter().filter(|e| e["event"] == "world.wanted").collect();
    assert_eq!(wanted.len(), 1, "a retrying joiner must not flood the log: {ev}");
    assert_eq!(wanted[0]["data"]["player"], "cara");
    host(&app, "tok-a", "w1").await;
    join("tok-c").await;
    let (_, ev) = call(&app, "GET", Some("tok-c"), "/v1/worlds/w1/events", Value::Null).await;
    let n = ev["events"].as_array().unwrap().iter().filter(|e| e["event"] == "world.wanted").count();
    assert_eq!(n, 1, "no event while a host is live");
}

#[tokio::test]
async fn only_a_fresh_join_replaces_the_lease_the_same_device_still_holds() {
    let app = app();
    let first = host(&app, "tok-a", "w1").await;
    let join = |body: Value| {
        let app = app.clone();
        async move { call(&app, "POST", Some("tok-a"), "/v1/worlds/w1/join", body).await.1 }
    };
    let retry = join(json!({ "hw": { "tier": 2, "score": 5.0 } })).await;
    assert_eq!(retry["lease"]["id"], first.as_str(), "a retried join gets the same lease back");
    let fresh = join(json!({ "hw": { "tier": 2, "score": 5.0 }, "fresh": true })).await;
    assert_eq!(fresh["decision"], "HOST");
    assert_ne!(fresh["lease"]["id"], first.as_str(), "a restarted host process gets a new lease");
    assert_eq!(fresh["lease"]["epoch"], 2);
    let guest_only = join(json!({ "hw": { "tier": 2, "score": 5.0, "wants_host": false }, "fresh": true })).await;
    assert_eq!(guest_only["lease"]["id"], fresh["lease"]["id"], "a join that does not want to host never drops a lease");
}

async fn read_frames(body: &mut Body, want: &str, within: Duration) -> String {
    let mut seen = String::new();
    let end = Instant::now() + within;
    while !seen.contains(want) && Instant::now() < end {
        match tokio::time::timeout(Duration::from_millis(300), body.frame()).await {
            Ok(Some(Ok(f))) => {
                if let Some(d) = f.data_ref() {
                    seen.push_str(&String::from_utf8_lossy(d));
                }
            }
            Ok(_) => break,
            Err(_) => {}
        }
    }
    seen
}

#[tokio::test]
async fn the_stream_delivers_backlog_then_live_events_and_resumes_from_the_last_id() {
    let app = app();
    let lease = host(&app, "tok-a", "w1").await;
    let req = |tok: &str, path: &str, last: Option<&str>| {
        let mut r = Request::builder().uri(path).header("authorization", format!("Bearer {tok}"));
        if let Some(l) = last {
            r = r.header("last-event-id", l);
        }
        r.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req("tok-c", "/v1/worlds/w1/events/stream", None)).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers()["content-type"].to_str().unwrap().starts_with("text/event-stream"));
    let mut body = resp.into_body();
    let seen = read_frames(&mut body, "host.started", Duration::from_secs(5)).await;
    assert!(seen.contains("event: host.started") && seen.contains("id: 1"), "backlog first: {seen}");

    let (c, _) = call(&app, "POST", Some("tok-a"), &format!("/v1/leases/{lease}/release"), json!({ "epoch": 1 })).await;
    assert_eq!(c, 200);
    let seen = read_frames(&mut body, "host.released", Duration::from_secs(5)).await;
    assert!(seen.contains("event: host.released"), "a live event arrives on the open stream: {seen}");

    let resp = app.clone().oneshot(req("tok-c", "/v1/worlds/w1/events/stream", Some("1"))).await.unwrap();
    let mut body = resp.into_body();
    let seen = read_frames(&mut body, "NEVER", Duration::from_millis(800)).await;
    assert!(!seen.contains("id: 1\n"), "nothing at or before Last-Event-ID is sent again: {seen}");

    assert_eq!(app.clone().oneshot(req("tok-c", "/v1/worlds/w2/events/stream", None)).await.unwrap().status(), 403, "members of other worlds are refused");
    assert_eq!(app.clone().oneshot(Request::builder().uri("/v1/worlds/w1/events/stream").body(Body::empty()).unwrap()).await.unwrap().status(), 401);
}
