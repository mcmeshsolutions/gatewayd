use axum::{body::Body, http::Request, Router};
use gatewayd::auth::AuthCfg;
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn gateway() -> Gateway {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-ops-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.ops_init().unwrap();
    g.create_world("w1", "Create <Full> Stack", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_member("w1", "u-c", "carol", "dev-c", Role::ClientOnly).unwrap();
    g.create_world("w2", "Other", "1.21.1", "neoforge").unwrap();
    g.add_member("w2", "u-c", "carol", "dev-c", Role::HostEligible).unwrap();
    for d in ["a", "b", "c"] {
        g.add_token(&format!("dev-{d}"), &format!("tok-{d}")).unwrap();
    }
    g
}

async fn send(app: &Router, method: &str, tok: Option<&str>, path: &str, body: Option<Value>) -> (u16, String) {
    let mut r = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let body = body.map_or(Body::empty(), |b| Body::from(b.to_string()));
    let resp = app.clone().oneshot(r.body(body).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    (code, String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned())
}

async fn post(app: &Router, tok: &str, path: &str, body: Value) -> (u16, Value) {
    let (c, b) = send(app, "POST", Some(tok), path, Some(body)).await;
    (c, serde_json::from_str(&b).unwrap_or(Value::Null))
}

fn hw() -> Value {
    json!({ "hw": { "tier": 2, "score": 5.0 } })
}

#[tokio::test]
async fn metrics_need_the_operator_token_and_count_per_world() {
    let off = router(AppState::new(gateway()));
    assert_eq!(send(&off, "GET", Some("tok-a"), "/metrics", None).await.0, 404, "no token configured, no endpoint");

    let app = router(AppState::with_auth(gateway(), AuthCfg { metrics_token: Some("scrape".into()), ..Default::default() }));
    assert_eq!(send(&app, "GET", None, "/metrics", None).await.0, 401);
    assert_eq!(send(&app, "GET", Some("tok-a"), "/metrics", None).await.0, 401, "player tokens are not operator tokens");

    let (_, v) = post(&app, "tok-a", "/v1/worlds/w1/join", hw()).await;
    let lease = v["lease"]["id"].as_str().unwrap().to_string();
    let base = v["lease"]["base_rev"].as_str().unwrap().to_string();
    post(&app, "tok-b", "/v1/worlds/w1/join", hw()).await;
    post(&app, "tok-c", "/v1/worlds/w2/join", hw()).await;
    let (c, _) = post(&app, "tok-a", &format!("/v1/leases/{lease}/commit"), json!({"epoch": 1, "base_rev": base, "kind": "AUTOSAVE"})).await;
    assert_eq!(c, 200);
    let data = b"chunk bytes".to_vec();
    let path = format!("/v1/blobs/{}", gatewayd::cas::hex(&gatewayd::cas::sha256(&data)));
    let r = Request::put(&path).header("authorization", "Bearer tok-a").body(Body::from(data.clone())).unwrap();
    assert_eq!(app.clone().oneshot(r).await.unwrap().status().as_u16(), 200);
    assert_eq!(send(&app, "GET", Some("tok-b"), &path, None).await.0, 200);
    let missing = format!("/v1/blobs/{}/exists", "0".repeat(64));
    assert_eq!(send(&app, "GET", Some("tok-b"), &missing, None).await.0, 200);
    assert_eq!(send(&app, "GET", Some("tok-b"), &format!("{path}/exists"), None).await.0, 200);

    let (c, text) = send(&app, "GET", Some("scrape"), "/metrics", None).await;
    assert_eq!(c, 200);
    for line in [
        "mcmesh_up 1",
        "mcmesh_live_leases 2",
        "mcmesh_worlds{state=\"LOCKED\"} 2",
        "# TYPE mcmesh_joins_total counter",
        "mcmesh_joins_total{world=\"w1\"} 2",
        "mcmesh_joins_total{world=\"w2\"} 1",
        "mcmesh_host_grants_total{world=\"w1\"} 1",
        "mcmesh_commits_total{world=\"w1\"} 1",
        "mcmesh_blob_put_bytes_total{world=\"w1\"} 11",
        "mcmesh_blob_get_bytes_total{world=\"w1\"} 11",
        "mcmesh_blob_checks_total 2",
        "mcmesh_blob_check_hits_total 1",
    ] {
        assert!(text.lines().any(|l| l == line), "missing {line:?} in\n{text}");
    }
    assert_eq!(text.matches("# TYPE mcmesh_joins_total").count(), 1);
}

#[tokio::test]
async fn relayed_bytes_reach_the_counters_on_tick() {
    let state = AppState::with_auth(gateway(), AuthCfg { metrics_token: Some("scrape".into()), ..Default::default() });
    state.relay_meter("w1", 100, 7);
    state.relay_meter("w1", 50, 0);
    state.tick();
    state.tick();
    let (_, text) = send(&router(state), "GET", Some("scrape"), "/metrics", None).await;
    assert!(text.contains("mcmesh_relay_to_host_bytes_total{world=\"w1\"} 150"), "{text}");
    assert!(text.contains("mcmesh_relay_to_guest_bytes_total{world=\"w1\"} 7"), "{text}");
}

#[tokio::test]
async fn public_status_shows_totals_and_no_world_names() {
    let app = router(AppState::new(gateway()));
    post(&app, "tok-a", "/v1/worlds/w1/join", hw()).await;
    let (c, body) = send(&app, "GET", None, "/v1/status", None).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((c, v["status"].as_str(), v["worlds"].as_i64(), v["hosted"].as_i64()), (200, Some("ok"), Some(2), Some(1)));
    assert!(v["last_save_age_s"].as_i64().unwrap() < 60, "world creation writes the first revision");
    let (c, html) = send(&app, "GET", None, "/status", None).await;
    assert_eq!(c, 200);
    assert!(html.contains("Operational") && !html.contains("{{") && !html.contains("Stack"), "{html}");
}

#[tokio::test]
async fn invites_expire_and_have_a_link_page() {
    let mut g = gateway();
    let stale = g.create_invite("dev-a", "w1", Role::ClientOnly).unwrap();
    g.set_invite_expiry(&stale, Some(1)).unwrap();
    let app = router(AppState::new(g));

    let (c, v) = post(&app, "tok-c", "/v1/invites/redeem", json!({ "code": stale })).await;
    assert_eq!((c, v["error"].as_str()), (410, Some("INVITE_EXPIRED")));
    let (c, _) = post(&app, "tok-c", "/v1/invites/redeem", json!({ "code": stale })).await;
    assert_eq!(c, 404, "an expired code is gone after the first refusal");

    let (c, _) = post(&app, "tok-a", "/v1/worlds/w1/invite", json!({ "expires_in_s": -5 })).await;
    assert_eq!(c, 400);
    let (c, _) = post(&app, "tok-a", "/v1/worlds/w1/invite", json!({ "expires_in_s": 91 * 86_400 })).await;
    assert_eq!(c, 400);
    let (_, v) = post(&app, "tok-a", "/v1/worlds/w1/invite", json!({ "expires_in_s": 0 })).await;
    assert!(v["expires_at"].is_null(), "0 means no expiry");

    let (c, v) = post(&app, "tok-a", "/v1/worlds/w2/invite", json!({})).await;
    assert_eq!(c, 403, "{v}");
    let (c, v) = post(&app, "tok-a", "/v1/worlds/w1/invite", json!({ "role": "HOST_ELIGIBLE" })).await;
    assert_eq!(c, 200);
    let code = v["code"].as_str().unwrap().to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let left = v["expires_at"].as_i64().unwrap() - now;
    assert!((7 * 86_400 - 5..=7 * 86_400).contains(&left), "default is 7 days, got {left}");
    assert_eq!(v["link"].as_str().unwrap(), format!("/invite/{code}"));

    let (c, html) = send(&app, "GET", None, &format!("/invite/{}", code.to_lowercase()), None).await;
    assert_eq!(c, 200);
    assert!(html.contains(&code) && html.contains("Create &lt;Full&gt; Stack") && html.contains("Expires in "), "{html}");
    let (c, html) = send(&app, "GET", None, "/invite/NOPE", None).await;
    assert!(c == 404 && html.contains("Invite not valid"));

    let (c, _) = post(&app, "tok-c", "/v1/invites/redeem", json!({ "code": code })).await;
    assert_eq!(c, 200, "viewing the page does not consume the code");
    assert_eq!(send(&app, "GET", None, &format!("/invite/{code}"), None).await.0, 404);
}

/// Accepts `n` HTTP requests and hands back (headers, body) of each.
fn sink(n: usize) -> (String, std::sync::mpsc::Receiver<(String, String)>) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hook", l.local_addr().unwrap());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for _ in 0..n {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head, body) = loop {
                let k = s.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..k]);
                let text = String::from_utf8_lossy(&buf).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let len: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    if body.len() >= len || k == 0 {
                        break (head.to_ascii_lowercase(), body.to_string());
                    }
                }
            };
            s.write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n").unwrap();
            tx.send((head, body)).unwrap();
        }
    });
    (url, rx)
}

#[tokio::test]
async fn webhooks_deliver_signed_events() {
    let (url, rx) = sink(2);
    let cfg = AuthCfg { webhooks: vec![url], webhook_secret: Some("s3cret".into()), ..Default::default() };
    let app = router(AppState::with_auth(gateway(), cfg));
    let (_, v) = post(&app, "tok-a", "/v1/worlds/w1/join", hw()).await;
    let lease = v["lease"]["id"].as_str().unwrap().to_string();
    post(&app, "tok-b", "/v1/worlds/w1/join", hw()).await;
    post(&app, "tok-a", &format!("/v1/leases/{lease}/release"), json!({"epoch": 1})).await;

    let wait = std::time::Duration::from_secs(10);
    let (head, body) = rx.recv_timeout(wait).unwrap();
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((v["event"].as_str(), v["world"].as_str(), v["data"]["player"].as_str()), (Some("host.started"), Some("w1"), Some("alice")));
    assert!(v["ts"].as_i64().unwrap() > 1_700_000_000);
    assert!(head.contains(&format!("x-mesh-signature: {}", gatewayd::ops::sign("s3cret", &body))), "{head}");
    let (_, body) = rx.recv_timeout(wait).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["event"], "host.released", "guest joins emit nothing");
}

#[test]
fn status_cli_lines_include_totals_and_counters() {
    let g = gateway();
    g.meter("w1", "joins", 3);
    g.meter("w1", "joins", 2);
    g.meter("", "logins", 1);
    let lines = g.ops_status().unwrap();
    assert!(lines[0].starts_with("totals worlds=2 live_leases=0 players=3 revisions="), "{lines:?}");
    assert!(lines.contains(&"meter joins world=w1 5".to_string()) && lines.contains(&"meter logins world=- 1".to_string()), "{lines:?}");
}

#[tokio::test]
async fn an_invite_redeems_once() {
    let app = router(AppState::new(gateway()));
    let (_, v) = post(&app, "tok-a", "/v1/worlds/w1/invite", json!({ "expires_in_s": 3600 })).await;
    let code = v["code"].as_str().unwrap().to_string();
    let (c, _) = post(&app, "tok-c", "/v1/invites/redeem", json!({ "code": code })).await;
    assert_eq!(c, 200);
    let (c, _) = post(&app, "tok-b", "/v1/invites/redeem", json!({ "code": code })).await;
    assert!(c == 404 || c == 409, "reuse must be refused, got {c}");
}

#[tokio::test]
async fn a_dead_webhook_endpoint_does_not_stall_requests() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hook", l.local_addr().unwrap());
    let cfg = AuthCfg { webhooks: vec![url], ..Default::default() };
    let app = router(AppState::with_auth(gateway(), cfg));
    let t = std::time::Instant::now();
    for _ in 0..3 {
        let (c, _) = post(&app, "tok-a", "/v1/worlds", json!({ "name": "x", "mc_version": "1.21.1", "loader": "neoforge" })).await;
        assert!(c == 200 || c == 403, "{c}");
    }
    post(&app, "tok-a", "/v1/worlds/w1/join", hw()).await;
    assert!(t.elapsed() < std::time::Duration::from_secs(2), "requests waited on the hook: {:?}", t.elapsed());
    drop(l);
}

#[test]
fn status_binary_exits_zero_on_a_healthy_store() {
    let dir = std::env::temp_dir().join(format!("mcmesh-ops-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_gatewayd"))
            .args(args)
            .env("MCMESH_DB", dir.join("t.db"))
            .env("MCMESH_CAS", dir.join("cas"))
            .output()
            .unwrap()
    };
    assert!(run(&["create-world", "w1", "Tmp", "1.21.1", "neoforge"]).status.success());
    let out = run(&["status"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("totals worlds=1"));
    let _ = std::fs::remove_dir_all(&dir);
}
