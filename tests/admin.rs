use axum::{body::Body, http::Request, Router};
use gatewayd::auth::AuthCfg;
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn tmp(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    std::env::temp_dir().join(format!("mcmesh-admin-{tag}-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}

/// w1: alice (owner), dave (second world admin), bob, carol. root is a gateway admin from config.
fn gateway(conn: Connection) -> Gateway {
    let mut g = Gateway::open(conn, gatewayd::cas::Cas::open(tmp("cas")).unwrap(), 0).unwrap();
    g.create_world("w1", "Main", "1.21.1", "neoforge").unwrap();
    for (w, u, n, d, r) in [
        ("w1", "u-alice", "alice", "dev-alice", Role::Admin),
        ("w1", "u-dave", "dave", "dev-dave", Role::Admin),
        ("w1", "u-bob", "bob", "dev-bob", Role::HostEligible),
        ("w1", "u-carol", "carol", "dev-carol", Role::HostEligible),
    ] {
        g.add_member(w, u, n, d, r).unwrap();
        g.add_token(d, &format!("tok-{n}")).unwrap();
    }
    g.create_world("w2", "Other", "1.21.1", "neoforge").unwrap();
    g.add_member("w2", "u-root", "root", "dev-root", Role::Admin).unwrap();
    g.add_token("dev-root", "tok-root").unwrap();
    g
}

fn cfg() -> AuthCfg {
    AuthCfg { admins: vec!["u-root".into()], allow_create: true, ..Default::default() }
}

fn app() -> Router {
    router(AppState::with_auth(gateway(Connection::open_in_memory().unwrap()), cfg()))
}

async fn req(app: &Router, method: &str, tok: Option<&str>, path: &str, body: Option<Value>) -> (u16, axum::http::HeaderMap, Value) {
    let mut r = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(r.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default())).unwrap()).await.unwrap();
    let (code, headers) = (resp.status().as_u16(), resp.headers().clone());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn call(app: &Router, method: &str, tok: &str, path: &str, body: Value) -> (u16, Value) {
    let (c, _, v) = req(app, method, Some(tok), path, Some(body)).await;
    (c, v)
}

async fn get(app: &Router, tok: &str, path: &str) -> (u16, Value) {
    let (c, _, v) = req(app, "GET", Some(tok), path, None).await;
    (c, v)
}

fn hw() -> Value {
    json!({ "hw": { "tier": 2, "score": 5.0 } })
}

fn err(r: &(u16, Value)) -> (u16, &str) {
    (r.0, r.1["error"].as_str().unwrap_or(""))
}

async fn host(app: &Router, tok: &str) -> (String, String) {
    let (c, v) = call(app, "POST", tok, "/v1/worlds/w1/join", hw()).await;
    assert_eq!((c, v["decision"].as_str()), (200, Some("HOST")), "{v}");
    (v["lease"]["id"].as_str().unwrap().into(), v["lease"]["base_rev"].as_str().unwrap().into())
}

// audit log

#[tokio::test]
async fn audit_records_actions_and_is_admin_only() {
    let app = app();
    let (c, v) = call(&app, "POST", "tok-alice", "/v1/worlds", json!({"name": "New", "mc_version": "1.21.1", "loader": "neoforge"})).await;
    assert_eq!(c, 200);
    let new = v["id"].as_str().unwrap().to_string();
    let (c, v) = call(&app, "POST", "tok-alice", "/v1/worlds/w1/invite", json!({})).await;
    assert_eq!(c, 200);
    let code = v["code"].as_str().unwrap().to_string();
    call(&app, "POST", "tok-bob", "/v1/invites/redeem", json!({"code": code})).await;
    host(&app, "tok-alice").await;

    let (c, v) = get(&app, "tok-root", "/v1/admin/audit").await;
    assert_eq!(c, 200);
    let acts: Vec<&str> = v["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    for a in ["world.create", "invite.create", "invite.redeem", "host.grant"] {
        assert!(acts.contains(&a), "{a} missing from {acts:?}");
    }
    let e = v["entries"].as_array().unwrap().iter().find(|e| e["action"] == "world.create").unwrap();
    assert_eq!((e["actor"].as_str(), e["actor_name"].as_str(), e["world"].as_str()), (Some("u-alice"), Some("alice"), Some(new.as_str())));
    assert!(e["ts"].as_i64().unwrap() > 0);

    for tok in ["tok-alice", "tok-bob"] {
        assert_eq!(err(&get(&app, tok, "/v1/admin/audit").await), (403, "ADMIN_ONLY"));
    }
    assert_eq!(req(&app, "GET", None, "/v1/admin/audit", None).await.0, 401);
}

#[tokio::test]
async fn audit_pages_and_filters() {
    let app = app();
    for i in 0..5 {
        call(&app, "POST", "tok-alice", "/v1/worlds/w1/invite", json!({"expires_in_s": 100 + i})).await;
    }
    let (_, p1) = get(&app, "tok-root", "/v1/admin/audit?limit=2&action=invite.create").await;
    assert_eq!(p1["entries"].as_array().unwrap().len(), 2);
    let next = p1["next_before"].as_i64().unwrap();
    let (_, p2) = get(&app, "tok-root", &format!("/v1/admin/audit?limit=2&action=invite.create&before={next}")).await;
    let ids: Vec<i64> = p1["entries"].as_array().unwrap().iter().chain(p2["entries"].as_array().unwrap()).map(|e| e["id"].as_i64().unwrap()).collect();
    assert!(ids.windows(2).all(|w| w[0] > w[1]), "newest first, no overlap: {ids:?}");
    let (_, p3) = get(&app, "tok-root", &format!("/v1/admin/audit?limit=2&action=invite.create&before={}", p2["next_before"])).await;
    assert_eq!(p3["entries"].as_array().unwrap().len(), 1);
    assert!(p3["next_before"].is_null());
    for bad in ["limit=0", "limit=999", "limit=x", "before=x"] {
        assert_eq!(err(&get(&app, "tok-root", &format!("/v1/admin/audit?{bad}")).await), (400, "BAD_PAGE"), "{bad}");
    }
}

#[tokio::test]
async fn world_audit_is_visible_to_its_owner_only() {
    let app = app();
    call(&app, "POST", "tok-alice", "/v1/worlds/w1/invite", json!({})).await;
    let (c, v) = get(&app, "tok-alice", "/v1/worlds/w1/audit").await;
    assert_eq!(c, 200);
    assert!(v["entries"].as_array().unwrap().iter().all(|e| e["world"] == "w1") && !v["entries"].as_array().unwrap().is_empty());
    assert_eq!(get(&app, "tok-root", "/v1/worlds/w1/audit").await.0, 200);
    // a second world admin and a plain member are not the owner
    for tok in ["tok-dave", "tok-bob"] {
        assert_eq!(err(&get(&app, tok, "/v1/worlds/w1/audit").await), (403, "OWNER_ONLY"));
    }
    // another world's owner cannot read w1, and unknown worlds look the same
    assert_eq!(err(&get(&app, "tok-bob", "/v1/worlds/w2/audit").await), (403, "OWNER_ONLY"));
    assert_eq!(err(&get(&app, "tok-bob", "/v1/worlds/nope/audit").await), (403, "OWNER_ONLY"));
    assert_eq!(err(&get(&app, "tok-root", "/v1/worlds/nope/audit").await), (404, "NO_SUCH_WORLD"));
}

#[tokio::test]
async fn audit_log_cannot_be_changed() {
    let app = app();
    for m in ["POST", "PUT", "PATCH", "DELETE"] {
        let (c, _, _) = req(&app, m, Some("tok-root"), "/v1/admin/audit", Some(json!({}))).await;
        assert_eq!(c, 405, "{m}");
    }
    // the table itself refuses edits, whoever holds the file
    let path = tmp("db");
    let g = gateway(Connection::open(&path).unwrap());
    let state = AppState::with_auth(g, cfg());
    let app = router(state);
    call(&app, "POST", "tok-alice", "/v1/worlds/w1/invite", json!({})).await;
    let raw = Connection::open(&path).unwrap();
    let before: i64 = raw.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0)).unwrap();
    assert!(before > 0);
    assert!(raw.execute("UPDATE audit_log SET action='x'", []).is_err());
    assert!(raw.execute("DELETE FROM audit_log", []).is_err());
    assert_eq!(raw.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get::<_, i64>(0)).unwrap(), before);
}

// suspend and ban

#[tokio::test]
async fn suspend_ban_and_restore() {
    let app = app();
    let put = |tok: &'static str, name: &'static str, status: &'static str| {
        let app = app.clone();
        async move { call(&app, "PUT", tok, &format!("/v1/admin/users/{name}/status"), json!({"status": status, "reason": "test"})).await }
    };
    assert_eq!(put("tok-root", "bob", "SUSPENDED").await.0, 200);
    assert_eq!(err(&call(&app, "POST", "tok-bob", "/v1/worlds/w1/join", hw()).await), (403, "ACCOUNT_SUSPENDED"));
    assert_eq!(err(&get(&app, "tok-bob", "/v1/worlds").await), (403, "ACCOUNT_SUSPENDED"));
    // others are unaffected
    assert_eq!(get(&app, "tok-alice", "/v1/worlds").await.0, 200);

    assert_eq!(put("tok-root", "bob", "BANNED").await.0, 200);
    assert_eq!(err(&get(&app, "tok-bob", "/v1/worlds").await), (403, "ACCOUNT_BANNED"));
    let (_, u) = get(&app, "tok-root", "/v1/admin/users/bob").await;
    assert_eq!((u["status"].as_str(), u["reason"].as_str()), (Some("BANNED"), Some("test")));

    assert_eq!(put("tok-root", "bob", "ACTIVE").await.0, 200);
    assert_eq!(get(&app, "tok-bob", "/v1/worlds").await.0, 200);
    let (_, u) = get(&app, "tok-root", "/v1/admin/users/bob").await;
    assert_eq!(u["status"], "ACTIVE");

    let (_, a) = get(&app, "tok-root", "/v1/admin/audit?action=user.ban").await;
    assert_eq!(a["entries"][0]["target"], "bob");
    for act in ["user.suspend", "user.restore"] {
        assert_eq!(get(&app, "tok-root", &format!("/v1/admin/audit?action={act}")).await.1["entries"].as_array().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn status_changes_are_admin_only_and_validated() {
    let app = app();
    for tok in ["tok-alice", "tok-bob"] {
        assert_eq!(err(&call(&app, "PUT", tok, "/v1/admin/users/carol/status", json!({"status": "BANNED"})).await), (403, "ADMIN_ONLY"));
        assert_eq!(err(&get(&app, tok, "/v1/admin/users/carol").await), (403, "ADMIN_ONLY"));
    }
    assert_eq!(get(&app, "tok-carol", "/v1/worlds").await.0, 200, "the refused ban did not apply");
    assert_eq!(err(&call(&app, "PUT", "tok-root", "/v1/admin/users/carol/status", json!({"status": "MUTED"})).await), (400, "BAD_STATUS"));
    assert_eq!(err(&call(&app, "PUT", "tok-root", "/v1/admin/users/nobody/status", json!({"status": "BANNED"})).await), (404, "NO_SUCH_USER"));
    assert_eq!(err(&call(&app, "PUT", "tok-root", "/v1/admin/users/root/status", json!({"status": "BANNED"})).await), (409, "CANNOT_TARGET_SELF"));
    let long = "x".repeat(300);
    assert_eq!(err(&call(&app, "PUT", "tok-root", "/v1/admin/users/carol/status", json!({"status": "BANNED", "reason": long})).await), (400, "BAD_REASON"));
}

#[tokio::test]
async fn banned_host_can_only_wind_down() {
    let app = app();
    let (lease, base) = host(&app, "tok-alice").await;
    let hb = format!("/v1/leases/{lease}/heartbeat");
    let commit = format!("/v1/leases/{lease}/commit");
    assert_eq!(call(&app, "PUT", "tok-root", "/v1/admin/users/alice/status", json!({"status": "BANNED"})).await.0, 200);

    let auto = json!({"epoch": 1, "base_rev": base, "kind": "AUTOSAVE"});
    assert_eq!(err(&call(&app, "POST", "tok-alice", &commit, auto).await), (403, "ACCOUNT_BANNED"));
    assert_eq!(call(&app, "POST", "tok-alice", &hb, json!({"epoch": 1})).await.0, 200, "inside the grace window");
    assert_eq!(err(&call(&app, "POST", "tok-alice", "/v1/worlds/w1/join", hw()).await), (403, "ACCOUNT_BANNED"));
    let last = json!({"epoch": 1, "base_rev": base, "kind": "SHUTDOWN", "final": true});
    let (c, v) = call(&app, "POST", "tok-alice", &commit, last).await;
    assert_eq!((c, v["seq"].as_i64()), (200, Some(1)), "{v}");
    // the world is free again for someone else
    let (c, v) = call(&app, "POST", "tok-bob", "/v1/worlds/w1/join", hw()).await;
    assert_eq!((c, v["decision"].as_str()), (200, Some("HOST")));
}

#[tokio::test]
async fn banned_host_loses_the_lease_after_the_grace_window() {
    let cfg = AuthCfg { ban_grace_s: 0, ..cfg() };
    let app = router(AppState::with_auth(gateway(Connection::open_in_memory().unwrap()), cfg));
    let (lease, base) = host(&app, "tok-alice").await;
    call(&app, "PUT", "tok-root", "/v1/admin/users/alice/status", json!({"status": "BANNED"})).await;
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(err(&call(&app, "POST", "tok-alice", &format!("/v1/leases/{lease}/heartbeat"), json!({"epoch": 1})).await), (403, "ACCOUNT_BANNED"));
    let last = json!({"epoch": 1, "base_rev": base, "kind": "SHUTDOWN", "final": true});
    assert_eq!(call(&app, "POST", "tok-alice", &format!("/v1/leases/{lease}/commit"), last).await.0, 200, "final commit is never refused");
}

// maintenance

#[tokio::test]
async fn maintenance_blocks_non_admin_writes() {
    let app = app();
    let (lease, base) = host(&app, "tok-alice").await;
    let (c, v) = call(&app, "PUT", "tok-root", "/v1/admin/maintenance", json!({"on": true, "retry_after_s": 120, "message": "db move"})).await;
    assert_eq!((c, v["on"].as_bool()), (200, Some(true)));
    assert_eq!(get(&app, "tok-root", "/v1/admin/maintenance").await.1["retry_after_s"], 120);

    let (c, h, v) = req(&app, "POST", Some("tok-bob"), "/v1/worlds/w1/invite", Some(json!({}))).await;
    assert_eq!((c, v["error"].as_str()), (503, Some("MAINTENANCE")));
    assert_eq!(h.get("retry-after").unwrap(), "120");
    assert_eq!(v["message"], "db move");
    let (c, h, _) = req(&app, "POST", Some("tok-carol"), "/v1/worlds/w1/join", Some(hw())).await;
    assert_eq!((c, h.get("retry-after").map(|v| v.to_str().unwrap())), (503, Some("120")));
    let new = json!({"name": "N", "mc_version": "1.21.1", "loader": "neoforge"});
    assert_eq!(call(&app, "POST", "tok-carol", "/v1/worlds", new.clone()).await.0, 503);

    // reads still work
    assert_eq!(get(&app, "tok-bob", "/v1/worlds").await.0, 200);
    assert_eq!(get(&app, "tok-bob", "/v1/worlds/w1/revisions").await.0, 200);
    // a live host keeps its lease, but autosaves wait and the final commit goes through
    assert_eq!(call(&app, "POST", "tok-alice", &format!("/v1/leases/{lease}/heartbeat"), json!({"epoch": 1})).await.0, 200);
    let auto = json!({"epoch": 1, "base_rev": base, "kind": "AUTOSAVE"});
    let (c, h, v) = req(&app, "POST", Some("tok-alice"), &format!("/v1/leases/{lease}/commit"), Some(auto)).await;
    assert_eq!((c, v["error"].as_str(), h.contains_key("retry-after")), (503, Some("MAINTENANCE"), true));
    let last = json!({"epoch": 1, "base_rev": base, "kind": "SHUTDOWN", "final": true});
    assert_eq!(call(&app, "POST", "tok-alice", &format!("/v1/leases/{lease}/commit"), last).await.0, 200);

    // admins keep working
    assert_eq!(call(&app, "POST", "tok-root", "/v1/worlds", new.clone()).await.0, 200);
    // and the switch turns off
    assert_eq!(call(&app, "PUT", "tok-root", "/v1/admin/maintenance", json!({"on": false})).await.0, 200);
    assert_eq!(call(&app, "POST", "tok-carol", "/v1/worlds", new).await.0, 200);
    assert_eq!(get(&app, "tok-root", "/v1/admin/maintenance").await.1["on"], false);
    let (_, a) = get(&app, "tok-root", "/v1/admin/audit?action=maintenance.on").await;
    assert_eq!(a["entries"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn maintenance_toggle_is_admin_only_and_validated() {
    let app = app();
    for tok in ["tok-alice", "tok-bob"] {
        assert_eq!(err(&call(&app, "PUT", tok, "/v1/admin/maintenance", json!({"on": true})).await), (403, "ADMIN_ONLY"));
        assert_eq!(err(&get(&app, tok, "/v1/admin/maintenance").await), (403, "ADMIN_ONLY"));
    }
    assert_eq!(get(&app, "tok-root", "/v1/admin/maintenance").await.1["on"], false);
    for bad in [json!({"on": true, "retry_after_s": 0}), json!({"on": true, "retry_after_s": 999999})] {
        assert_eq!(err(&call(&app, "PUT", "tok-root", "/v1/admin/maintenance", bad).await), (400, "BAD_MAINTENANCE"));
    }
}

#[tokio::test]
async fn maintenance_leaves_public_routes_alone() {
    let app = app();
    call(&app, "PUT", "tok-root", "/v1/admin/maintenance", json!({"on": true})).await;
    assert_eq!(req(&app, "GET", None, "/v1/status", None).await.0, 200);
    assert_eq!(req(&app, "POST", None, "/v1/auth/challenge", Some(json!({}))).await.0, 200);
    assert_eq!(req(&app, "POST", Some("tok-bob"), "/v1/auth/challenge", Some(json!({}))).await.0, 200);
}

// roles

#[tokio::test]
async fn only_admins_change_gateway_roles() {
    let app = app();
    for tok in ["tok-alice", "tok-bob"] {
        assert_eq!(err(&call(&app, "PUT", tok, "/v1/admin/users/bob/role", json!({"role": "admin"})).await), (403, "ADMIN_ONLY"));
    }
    assert_eq!(err(&get(&app, "tok-bob", "/v1/admin/audit").await), (403, "ADMIN_ONLY"));
    assert_eq!(call(&app, "PUT", "tok-root", "/v1/admin/users/bob/role", json!({"role": "admin"})).await.0, 200);
    assert_eq!(get(&app, "tok-bob", "/v1/admin/audit").await.0, 200, "bob is an admin now");
    assert_eq!(get(&app, "tok-root", "/v1/admin/users/bob").await.1["role"], "admin");
    // a database admin can promote and demote others
    assert_eq!(call(&app, "PUT", "tok-bob", "/v1/admin/users/carol/role", json!({"role": "admin"})).await.0, 200);
    assert_eq!(call(&app, "PUT", "tok-bob", "/v1/admin/users/carol/role", json!({"role": "user"})).await.0, 200);
    assert_eq!(err(&get(&app, "tok-carol", "/v1/admin/audit").await), (403, "ADMIN_ONLY"));
    assert_eq!(err(&call(&app, "PUT", "tok-bob", "/v1/admin/users/bob/role", json!({"role": "user"})).await), (409, "CANNOT_TARGET_SELF"));
    assert_eq!(err(&call(&app, "PUT", "tok-bob", "/v1/admin/users/root/role", json!({"role": "user"})).await), (409, "ADMIN_FROM_CONFIG"));
    assert_eq!(err(&call(&app, "PUT", "tok-root", "/v1/admin/users/bob/role", json!({"role": "root"})).await), (400, "BAD_ROLE"));
    assert_eq!(err(&call(&app, "PUT", "tok-root", "/v1/admin/users/zed/role", json!({"role": "admin"})).await), (404, "NO_SUCH_USER"));
    let (_, a) = get(&app, "tok-root", "/v1/admin/audit?action=role.gateway").await;
    assert_eq!(a["entries"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn only_owner_or_admin_changes_world_members() {
    let app = app();
    let path = "/v1/worlds/w1/members";
    // dave is a world ADMIN but not the owner
    assert_eq!(err(&call(&app, "PUT", "tok-dave", path, json!({"name": "bob", "role": "CLIENT_ONLY"})).await), (403, "OWNER_ONLY"));
    assert_eq!(err(&call(&app, "PUT", "tok-bob", path, json!({"name": "carol", "role": "ADMIN"})).await), (403, "OWNER_ONLY"));
    assert_eq!(call(&app, "PUT", "tok-alice", path, json!({"name": "bob", "role": "CLIENT_ONLY"})).await.0, 200);
    assert_eq!(call(&app, "PUT", "tok-root", path, json!({"name": "bob", "role": "HOST_ELIGIBLE"})).await.0, 200, "gateway admin override");
    assert_eq!(err(&call(&app, "PUT", "tok-alice", path, json!({"name": "alice", "role": "CLIENT_ONLY"})).await), (409, "OWNER_IMMUTABLE"));
    assert_eq!(err(&call(&app, "PUT", "tok-alice", path, json!({"name": "alice"})).await), (409, "OWNER_IMMUTABLE"));
    assert_eq!(err(&call(&app, "PUT", "tok-root", "/v1/worlds/nope/members", json!({"name": "bob"})).await), (404, "NO_SUCH_WORLD"));
    let (_, a) = get(&app, "tok-root", "/v1/admin/audit?action=role.world").await;
    assert_eq!(a["entries"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn creator_of_a_world_is_its_owner() {
    let app = app();
    let (_, v) = call(&app, "POST", "tok-bob", "/v1/worlds", json!({"name": "Bobs", "mc_version": "1.21.1", "loader": "neoforge"})).await;
    let id = v["id"].as_str().unwrap();
    call(&app, "PUT", "tok-bob", &format!("/v1/worlds/{id}/members"), json!({"name": "carol", "role": "ADMIN"})).await;
    // carol is a world admin, bob stays the owner
    assert_eq!(get(&app, "tok-bob", &format!("/v1/worlds/{id}/policy")).await.1["owner"], "bob");
    assert_eq!(err(&call(&app, "PUT", "tok-carol", &format!("/v1/worlds/{id}/policy"), json!({"policy": "OWNER"})).await), (403, "OWNER_ONLY"));
}

// host policy

async fn set_policy(app: &Router, tok: &str, body: Value) -> (u16, Value) {
    call(app, "PUT", tok, "/v1/worlds/w1/policy", body).await
}

#[tokio::test]
async fn members_policy_is_the_default() {
    let app = app();
    let (_, p) = get(&app, "tok-bob", "/v1/worlds/w1/policy").await;
    assert_eq!((p["policy"].as_str(), p["owner"].as_str()), (Some("MEMBERS"), Some("alice")));
    let (c, v) = call(&app, "POST", "tok-bob", "/v1/worlds/w1/join", hw()).await;
    assert_eq!((c, v["decision"].as_str(), v["host_allowed"].as_bool()), (200, Some("HOST"), Some(true)));
}

#[tokio::test]
async fn owner_only_policy_keeps_others_off_the_lease() {
    let app = app();
    assert_eq!(set_policy(&app, "tok-alice", json!({"policy": "OWNER"})).await.0, 200);
    let (c, v) = call(&app, "POST", "tok-bob", "/v1/worlds/w1/join", hw()).await;
    assert_eq!((c, v["decision"].as_str(), v["phase"].as_str(), v["host_allowed"].as_bool()), (200, Some("WAIT"), Some("NO_HOST"), Some(false)));
    let (c, v) = call(&app, "POST", "tok-alice", "/v1/worlds/w1/join", hw()).await;
    assert_eq!((c, v["decision"].as_str()), (200, Some("HOST")));
    // with the owner hosting, bob still joins as a guest and cannot take over
    let (_, v) = call(&app, "POST", "tok-bob", "/v1/worlds/w1/join", json!({"hw": {"tier": 1, "score": 500.0, "takeover": true}})).await;
    assert_eq!((v["decision"].as_str(), v["host_allowed"].as_bool()), (Some("GUEST"), Some(false)));
    let (_, l) = get(&app, "tok-bob", "/v1/worlds?tier=1&score=500").await;
    assert!(l["worlds"][0]["takeover_in_s"].is_null());
}

#[tokio::test]
async fn allowlist_policy_admits_listed_members_and_the_owner() {
    let app = app();
    let r = set_policy(&app, "tok-alice", json!({"policy": "ALLOWLIST", "allow": ["bob"]})).await;
    assert_eq!(r.0, 200);
    let (_, p) = get(&app, "tok-carol", "/v1/worlds/w1/policy").await;
    assert_eq!((p["policy"].as_str(), p["allow"].clone()), (Some("ALLOWLIST"), json!(["bob"])));
    let (_, v) = call(&app, "POST", "tok-carol", "/v1/worlds/w1/join", hw()).await;
    assert_eq!((v["decision"].as_str(), v["host_allowed"].as_bool()), (Some("WAIT"), Some(false)));
    let (_, v) = call(&app, "POST", "tok-dave", "/v1/worlds/w1/join", hw()).await;
    assert_eq!(v["host_allowed"].as_bool(), Some(false), "a world admin who is not listed is not allowed");
    let (_, v) = call(&app, "POST", "tok-bob", "/v1/worlds/w1/join", hw()).await;
    assert_eq!(v["decision"], "HOST");
    // omitting allow keeps the list; an empty list clears it
    set_policy(&app, "tok-alice", json!({"policy": "ALLOWLIST"})).await;
    assert_eq!(get(&app, "tok-alice", "/v1/worlds/w1/policy").await.1["allow"], json!(["bob"]));
    set_policy(&app, "tok-alice", json!({"policy": "ALLOWLIST", "allow": []})).await;
    assert_eq!(get(&app, "tok-alice", "/v1/worlds/w1/policy").await.1["allow"], json!([]));
    // back to members
    set_policy(&app, "tok-root", json!({"policy": "MEMBERS"})).await;
    let (_, v) = call(&app, "POST", "tok-carol", "/v1/worlds/w1/join", hw()).await;
    assert_eq!(v["host_allowed"].as_bool(), Some(true));
}

#[tokio::test]
async fn policy_changes_are_owner_or_admin_only_and_validated() {
    let app = app();
    for tok in ["tok-dave", "tok-bob"] {
        assert_eq!(err(&set_policy(&app, tok, json!({"policy": "OWNER"})).await), (403, "OWNER_ONLY"));
    }
    assert_eq!(get(&app, "tok-bob", "/v1/worlds/w1/policy").await.1["policy"], "MEMBERS", "the refused change did not apply");
    assert_eq!(err(&set_policy(&app, "tok-alice", json!({"policy": "EVERYONE"})).await), (400, "BAD_POLICY"));
    assert_eq!(err(&set_policy(&app, "tok-alice", json!({"policy": "ALLOWLIST", "allow": ["nobody"]})).await), (404, "NO_SUCH_MEMBER"));
    // a registered player who is not in this world cannot be allowlisted
    assert_eq!(err(&set_policy(&app, "tok-alice", json!({"policy": "ALLOWLIST", "allow": ["root"]})).await), (404, "NO_SUCH_MEMBER"));
    assert_eq!(err(&get(&app, "tok-root", "/v1/worlds/w1/policy").await), (403, "NOT_MEMBER"), "reading needs membership");
    let (_, a) = get(&app, "tok-root", "/v1/admin/audit?action=policy.host").await;
    assert_eq!(a["entries"].as_array().unwrap().len(), 0, "refused changes are not logged as done");
}

// login

async fn key_login(app: &Router, seed: u8, name: &str) -> (u16, Value) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let c = req(app, "POST", None, "/v1/auth/challenge", Some(json!({}))).await.2["challenge"].as_str().unwrap().to_string();
    let mut msg = b"mcmesh-auth-v1\0".to_vec();
    msg.extend_from_slice(c.as_bytes());
    let body = json!({
        "challenge": c, "name": name,
        "pubkey": B64.encode(sk.verifying_key().to_bytes()), "sig": B64.encode(sk.sign(&msg).to_bytes()),
    });
    let (code, _, v) = req(app, "POST", None, "/v1/auth/key", Some(body)).await;
    (code, v)
}

#[tokio::test]
async fn login_is_audited_and_refused_for_restricted_accounts() {
    let app = app();
    let (c, v) = key_login(&app, 7, "zed").await;
    assert_eq!(c, 200, "{v}");
    let (_, a) = get(&app, "tok-root", "/v1/admin/audit?action=login").await;
    assert_eq!((a["entries"][0]["actor_name"].as_str(), a["entries"][0]["detail"]["method"].as_str()), (Some("zed"), Some("key")));

    for (status, code) in [("SUSPENDED", "ACCOUNT_SUSPENDED"), ("BANNED", "ACCOUNT_BANNED")] {
        call(&app, "PUT", "tok-root", "/v1/admin/users/zed/status", json!({"status": status})).await;
        assert_eq!(err(&key_login(&app, 7, "zed").await), (403, code));
    }
    assert_eq!(get(&app, "tok-root", "/v1/admin/audit?action=login").await.1["entries"].as_array().unwrap().len(), 1, "refused logins are not logins");
    call(&app, "PUT", "tok-root", "/v1/admin/users/zed/status", json!({"status": "ACTIVE"})).await;
    assert_eq!(key_login(&app, 7, "zed").await.0, 200);
}

// device id

#[tokio::test]
async fn devices_me_returns_the_callers_device() {
    let app = app();
    for (tok, dev) in [("tok-alice", "dev-alice"), ("tok-bob", "dev-bob")] {
        let (c, v) = get(&app, tok, "/v1/devices/me").await;
        assert_eq!((c, v["device"].as_str()), (200, Some(dev)));
    }
    assert_eq!(req(&app, "GET", None, "/v1/devices/me", None).await.0, 401);
    assert_eq!(get(&app, "bad", "/v1/devices/me").await.0, 401);
    call(&app, "PUT", "tok-root", "/v1/admin/users/bob/status", json!({"status": "BANNED"})).await;
    assert_eq!(err(&get(&app, "tok-bob", "/v1/devices/me").await), (403, "ACCOUNT_BANNED"));
    // the id a key login gets is the one the endpoint reports
    let (_, t) = key_login(&app, 3, "newbie").await;
    let tok = t["token"].as_str().unwrap();
    let id = get(&app, tok, "/v1/devices/me").await.1["device"].as_str().unwrap().to_string();
    assert!(id.starts_with("d_") && id.len() == 18, "{id}");
}

#[tokio::test]
async fn sso_superadmin_and_account_linking_drive_the_dashboard() {
    let app = app();
    let (c, h, v) = req(&app, "POST", None, "/v1/auth/sso/register", Some(json!({"email": "boss@example.com", "password": "correct horse battery"}))).await;
    assert_eq!((c, v["superadmin"].as_bool()), (200, Some(true)));
    let cookie = h.get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();

    let sso_call = |method: &str, path: &str, body: Option<Value>| {
        let app = app.clone();
        let cookie = cookie.clone();
        let method = method.to_string();
        let path = path.to_string();
        async move {
            let r = Request::builder()
                .method(method.as_str())
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                .unwrap();
            let resp = app.oneshot(r).await.unwrap();
            let code = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (code, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
        }
    };

    // superadmin without a linked Minecraft player can still inspect all worlds, usage, quotas, activity, and MOTD
    let (c, me) = sso_call("GET", "/v1/sso/me", None).await;
    assert_eq!((c, me["mode"].as_str(), me["superadmin"].as_bool()), (200, Some("sso"), Some(true)));
    let (c, w) = sso_call("GET", "/v1/worlds?all=1", None).await;
    assert_eq!((c, w["worlds"].as_array().unwrap().len()), (200, 2));
    let (c, u) = sso_call("GET", "/v1/admin/usage", None).await;
    assert_eq!((c, u["total_worlds"].as_u64()), (200, Some(2)));
    assert!(u["defaults"]["world"].is_object());
    let (c, q) = sso_call("PUT", "/v1/admin/quotas", Some(json!({"scope": "world", "id": "w1", "storage_bytes": 104857600, "max_guests": 8}))).await;
    assert_eq!((c, q["limits"]["max_guests"].as_u64()), (200, Some(8)));
    let (c, _) = sso_call("PUT", "/v1/admin/motd", Some(json!({"motd": "&aHello &lMesh"}))).await;
    assert_eq!(c, 200);
    assert_eq!(req(&app, "GET", None, "/v1/motd", None).await.2["motd"].as_str(), Some("\u{00a7}aHello \u{00a7}lMesh"));
    let (c, act) = sso_call("GET", "/v1/worlds/w1/activity", None).await;
    assert_eq!(c, 200, "{act}");
    let (c, mem) = sso_call("GET", "/v1/worlds/w1/members", None).await;
    assert_eq!(c, 200, "{mem}");

    // link alice's Minecraft account to the SSO account using a link code, then mint a device link code via SSO
    let (_, lc) = call(&app, "POST", "tok-alice", "/v1/auth/link-code", json!({})).await;
    let code = lc["code"].as_str().unwrap();
    let (c, lk) = sso_call("POST", "/v1/sso/link", Some(json!({"code": code}))).await;
    assert_eq!((c, lk["player"].as_str()), (200, Some("alice")));
    let (_, me2) = sso_call("GET", "/v1/sso/me", None).await;
    assert_eq!(me2["player"].as_str(), Some("alice"));
    let (c, dc) = sso_call("POST", "/v1/auth/link-code", Some(json!({}))).await;
    assert_eq!(c, 200);
    assert_eq!(dc["code"].as_str().unwrap().len(), 12);
}
