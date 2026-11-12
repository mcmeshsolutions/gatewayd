use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn cas_dir() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    std::env::temp_dir().join(format!("mcmesh-api-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)))
}

fn app() -> Router {
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w1", "Create Full Stack", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    g.create_world("w2", "Other", "1.21.1", "neoforge").unwrap();
    g.add_member("w2", "u-c", "carol", "dev-c", Role::HostEligible).unwrap();
    g.add_token("dev-c", "tok-c").unwrap();
    router(AppState::new(g))
}

async fn call(app: &Router, tok: Option<&str>, path: &str, body: Value) -> (u16, Value) {
    let mut r = Request::post(path).header("content-type", "application/json");
    if let Some(t) = tok {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn hw() -> Value {
    json!({ "hw": { "tier": 2, "score": 5.0 } })
}

#[tokio::test]
async fn full_host_guest_commit_flow() {
    let app = app();
    let (c, v) = call(&app, Some("tok-a"), "/v1/worlds/w1/join", hw()).await;
    assert_eq!((c, v["decision"].as_str()), (200, Some("HOST")));
    let lease = v["lease"]["id"].as_str().unwrap().to_string();
    let base = v["lease"]["base_rev"].as_str().unwrap().to_string();
    assert_eq!(v["lease"]["epoch"], 1);

    let (c, v) = call(&app, Some("tok-b"), "/v1/worlds/w1/join", hw()).await;
    assert_eq!((c, v["decision"].as_str()), (200, Some("GUEST")));

    let (c, v) = call(&app, Some("tok-a"), &format!("/v1/leases/{lease}/heartbeat"), json!({"epoch": 1})).await;
    assert_eq!((c, v["ok"].as_bool()), (200, Some(true)));

    let body = json!({"epoch": 1, "base_rev": base, "kind": "AUTOSAVE"});
    let (c, v) = call(&app, Some("tok-a"), &format!("/v1/leases/{lease}/commit"), body.clone()).await;
    assert_eq!((c, v["seq"].as_i64()), (200, Some(1)));
    let (c, v) = call(&app, Some("tok-a"), &format!("/v1/leases/{lease}/commit"), body).await;
    assert_eq!((c, v["error"].as_str()), (409, Some("HEAD_MOVED")));
}

#[tokio::test]
async fn auth_and_ownership_are_enforced() {
    let app = app();
    let (c, _) = call(&app, None, "/v1/worlds/w1/join", hw()).await;
    assert_eq!(c, 401);
    let (c, _) = call(&app, Some("nope"), "/v1/worlds/w1/join", hw()).await;
    assert_eq!(c, 401);
    let (_, v) = call(&app, Some("tok-a"), "/v1/worlds/w1/join", hw()).await;
    let lease = v["lease"]["id"].as_str().unwrap().to_string();
    let (c, v) = call(&app, Some("tok-b"), &format!("/v1/leases/{lease}/heartbeat"), json!({"epoch": 1})).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("NOT_LEASE_HOLDER")));
    let (c, v) = call(&app, Some("tok-a"), &format!("/v1/leases/{lease}/heartbeat"), json!({"epoch": 7})).await;
    assert_eq!((c, v["error"].as_str()), (409, Some("STALE_EPOCH")));
    let (c, _) = call(&app, Some("tok-a"), "/v1/worlds/nope/join", hw()).await;
    assert_eq!(c, 403, "unknown worlds look like non-membership");
}

#[tokio::test]
async fn bad_commit_inputs_are_rejected() {
    let app = app();
    let (_, v) = call(&app, Some("tok-a"), "/v1/worlds/w1/join", hw()).await;
    let lease = v["lease"]["id"].as_str().unwrap().to_string();
    let p = format!("/v1/leases/{lease}/commit");
    let (c, _) = call(&app, Some("tok-a"), &p, json!({"epoch":1,"base_rev":"x","kind":"NOPE"})).await;
    assert_eq!(c, 400);
    let (c, _) = call(&app, Some("tok-a"), &p, json!({"epoch":1,"base_rev":"x","kind":"AUTOSAVE"})).await;
    assert_eq!(c, 409, "unknown base rev is a head mismatch");
}

async fn raw(app: &Router, method: &str, tok: &str, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
    let r = Request::builder().method(method).uri(path).header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body)).unwrap()).await.unwrap();
    (resp.status().as_u16(), resp.into_body().collect().await.unwrap().to_bytes().to_vec())
}

#[tokio::test]
async fn blobs_need_a_lease_and_a_matching_hash() {
    let app = app();
    let data = b"some chunk nbt".to_vec();
    let h = gatewayd::cas::hex(&gatewayd::cas::sha256(&data));
    let path = format!("/v1/blobs/{h}");
    let (c, _) = raw(&app, "PUT", "tok-a", &path, data.clone()).await;
    assert_eq!(c, 403, "only a lease holder may upload");
    call(&app, Some("tok-a"), "/v1/worlds/w1/join", hw()).await;
    let (c, _) = raw(&app, "PUT", "tok-a", &path, b"other bytes".to_vec()).await;
    assert_eq!(c, 400, "body must hash to the name in the path");
    let (c, _) = raw(&app, "PUT", "tok-a", &path, data.clone()).await;
    assert_eq!(c, 200);
    let (c, body) = raw(&app, "GET", "tok-b", &path, vec![]).await;
    assert_eq!((c, body), (200, data));
    let (c, _) = raw(&app, "GET", "bad", &path, vec![]).await;
    assert_eq!(c, 401);
}

async fn get(app: &Router, tok: &str, path: &str) -> (u16, Value) {
    let r = Request::get(path).header("authorization", format!("Bearer {tok}")).body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(r).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn revision_files_lists_committed_leaves_for_members_only() {
    use gatewayd::chain::{next_mac, Entry};
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w1", "w", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    let h1 = g.cas().put(b"chunk").unwrap();
    let h2 = g.cas().put(b"level").unwrap();
    let app = router(AppState::new(g));

    let (_, v) = call(&app, Some("tok-a"), "/v1/worlds/w1/join", hw()).await;
    let lease = v["lease"]["id"].as_str().unwrap().to_string();
    let base = v["lease"]["base_rev"].as_str().unwrap().to_string();
    let key = hex_key(v["lease"]["hmac_key"].as_str().unwrap());
    let mut prev = [0u8; 32];
    let mut frames = vec![];
    for (seq, (op, dim, cx, cz, h)) in [
        ("put:region", "minecraft:overworld", 3, -4, h1),
        ("aux_put", "level.dat", 0, 0, h2),
        ("barrier", "", 0, 0, [0u8; 32]),
    ]
    .into_iter()
    .enumerate()
    {
        let e = Entry { seq: seq as u64, dim, kind: op, cx, cz, hash: &h };
        let mac = next_mac(&key, &prev, &e);
        prev = mac;
        frames.push(json!({"seq": seq, "op": op, "dim": dim, "cx": cx, "cz": cz, "hash": format!("sha256:{}", hex(&h)), "mac": hex(&mac)}));
    }
    let (c, v) = call(&app, Some("tok-a"), &format!("/v1/leases/{lease}/wal"), json!({"epoch": 1, "frames": frames})).await;
    assert_eq!(c, 200, "{v}");
    let (c, v) = call(&app, Some("tok-a"), &format!("/v1/leases/{lease}/commit"), json!({"epoch": 1, "base_rev": base, "kind": "AUTOSAVE"})).await;
    assert_eq!(c, 200, "{v}");
    let rev = v["rev_id"].as_str().unwrap().to_string();

    let (c, v) = get(&app, "tok-a", &format!("/v1/revisions/{rev}/files")).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["chunks"][0]["cx"], 3);
    assert_eq!(v["chunks"][0]["cz"], -4);
    assert_eq!(v["chunks"][0]["kind"], "region");
    assert_eq!(v["chunks"][0]["hash"], hex(&h1));
    assert_eq!(v["aux"][0]["path"], "level.dat");
    assert_eq!(v["aux"][0]["hash"], hex(&h2));

    let (c, _) = get(&app, "nope", &format!("/v1/revisions/{rev}/files")).await;
    assert_eq!(c, 401);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_key(s: &str) -> [u8; 32] {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(s).unwrap().try_into().unwrap()
}

#[tokio::test]
async fn blobs_are_readable_only_within_the_uploading_world() {
    let app = app();
    let data = b"private inventory".to_vec();
    let h = gatewayd::cas::hex(&gatewayd::cas::sha256(&data));
    let path = format!("/v1/blobs/{h}");
    call(&app, Some("tok-a"), "/v1/worlds/w1/join", hw()).await;
    raw(&app, "PUT", "tok-a", &path, data.clone()).await;
    let (c, _) = raw(&app, "GET", "tok-c", &path, vec![]).await;
    assert_eq!(c, 400, "a member of another world cannot read it");
    let (c, _) = raw(&app, "GET", "tok-b", &path, vec![]).await;
    assert_eq!(c, 200);
}

#[tokio::test]
async fn creating_a_world_is_gated_and_makes_the_caller_admin() {
    let body = json!({"name": "Survival", "mc_version": "1.21.1", "loader": "neoforge"});
    let off = app();
    let (c, _) = call(&off, Some("tok-a"), "/v1/worlds", body.clone()).await;
    assert_eq!(c, 403);

    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w0", "Seed", "1.21.1", "neoforge").unwrap();
    g.add_member("w0", "u-a", "alice", "dev-a", Role::ClientOnly).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    let cfg = gatewayd::auth::AuthCfg { allow_create: true, ..Default::default() };
    let on = router(AppState::with_auth(g, cfg));
    let (c, v) = call(&on, Some("tok-a"), "/v1/worlds", body).await;
    assert_eq!(c, 200);
    let id = v["id"].as_str().unwrap().to_string();
    let (c, v) = get(&on, "tok-a", "/v1/worlds").await;
    assert_eq!(c, 200);
    let mine = v["worlds"].as_array().unwrap().iter().find(|w| w["id"] == id.as_str()).unwrap();
    assert_eq!(mine["role"], "ADMIN");
}

#[tokio::test]
async fn invites_are_admin_issued_single_use_and_never_downgrade() {
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(cas_dir()).unwrap(), 0).unwrap();
    g.create_world("w0", "Seed", "1.21.1", "neoforge").unwrap();
    g.add_member("w0", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.create_world("w9", "Other", "1.21.1", "neoforge").unwrap();
    g.add_member("w9", "u-b", "bob", "dev-b", Role::ClientOnly).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    let app = router(AppState::new(g));

    let (c, _) = call(&app, Some("tok-b"), "/v1/worlds/w0/invite", json!({})).await;
    assert_eq!(c, 403);
    let (c, v) = call(&app, Some("tok-a"), "/v1/worlds/w0/invite", json!({"role": "HOST_ELIGIBLE"})).await;
    assert_eq!(c, 200);
    let code = v["code"].as_str().unwrap().to_string();
    let (c, v) = call(&app, Some("tok-b"), "/v1/invites/redeem", json!({"code": code})).await;
    assert_eq!(c, 200);
    assert_eq!(v["world_id"], "w0");
    let (c, _) = call(&app, Some("tok-b"), "/v1/invites/redeem", json!({"code": code})).await;
    assert_ne!(c, 200);
    let (_, v) = get(&app, "tok-b", "/v1/worlds").await;
    let w = v["worlds"].as_array().unwrap().iter().find(|w| w["id"] == "w0").unwrap();
    assert_eq!(w["role"], "HOST_ELIGIBLE");
    assert_eq!(w["state"], "IDLE");
}

#[tokio::test]
async fn pack_header_scopes_listing_and_join() {
    let app = app();
    let get = |tok: &'static str, pack: Option<&'static str>| {
        let app = app.clone();
        async move {
            let mut r = Request::get("/v1/worlds").header("authorization", format!("Bearer {tok}"));
            if let Some(p) = pack {
                r = r.header("x-mesh-pack", p);
            }
            let resp = app.oneshot(r.body(Body::empty()).unwrap()).await.unwrap();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        }
    };
    assert_eq!(get("tok-a", None).await["worlds"].as_array().unwrap().len(), 1);
    assert_eq!(get("tok-a", Some("other-pack")).await["worlds"].as_array().unwrap().len(), 0);
    let r = Request::post("/v1/worlds/w1/join")
        .header("content-type", "application/json")
        .header("authorization", "Bearer tok-a")
        .header("x-mesh-pack", "other-pack")
        .body(Body::from(hw().to_string()))
        .unwrap();
    let resp = app.clone().oneshot(r).await.unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    let r = Request::post("/v1/worlds/w1/join")
        .header("content-type", "application/json")
        .header("authorization", "Bearer tok-a")
        .header("x-mesh-pack", "bad pack!")
        .body(Body::from(hw().to_string()))
        .unwrap();
    assert_eq!(app.oneshot(r).await.unwrap().status().as_u16(), 400);
}
