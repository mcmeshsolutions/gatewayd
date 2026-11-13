use axum::{body::Body, http::Request, Router};
use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> Router {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-keys-it-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    g.add_token("dev-b", "tok-b").unwrap();
    let cfg = gatewayd::auth::AuthCfg { admins: vec!["u-a".into()], ..Default::default() };
    router(AppState::with_auth(g, cfg))
}

async fn call(app: &Router, method: &str, tok: &str, path: &str, body: Value) -> (u16, Value) {
    let r = Request::builder().method(method).uri(path).header("content-type", "application/json").header("authorization", format!("Bearer {tok}"));
    let resp = app.clone().oneshot(r.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let code = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn make_key(app: &Router, name: &str, scopes: Value) -> (i64, String) {
    let (c, v) = call(app, "POST", "tok-a", "/v1/admin/api-keys", json!({ "name": name, "scopes": scopes })).await;
    assert_eq!(c, 200, "{v}");
    (v["id"].as_i64().unwrap(), v["key"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn a_read_key_reads_status_but_cannot_change_anything() {
    let app = app();
    let (_, key) = make_key(&app, "grafana", json!(["read:status"])).await;
    assert_eq!(call(&app, "GET", &key, "/v1/admin/usage", Value::Null).await.0, 200);
    assert_eq!(call(&app, "GET", &key, "/v1/admin/audit", Value::Null).await.0, 200);
    assert_eq!(call(&app, "GET", &key, "/v1/admin/maintenance", Value::Null).await.0, 200);
    let (c, v) = call(&app, "PUT", &key, "/v1/admin/maintenance", json!({ "on": true })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("SCOPE_DENIED")));
    let (c, v) = call(&app, "GET", &key, "/v1/admin/users/bob", Value::Null).await;
    assert_eq!((c, v["error"].as_str()), (401, Some("UNAUTHORIZED")), "routes outside the scopes do not recognise keys at all");
    let (c, _) = call(&app, "POST", &key, "/v1/admin/api-keys", json!({ "name": "x", "scopes": ["read:status"] })).await;
    assert_eq!(c, 401, "a key can never mint keys");
    assert_eq!(call(&app, "GET", "mcmesh_sk_made_up", "/v1/admin/usage", Value::Null).await.0, 401);
}

#[tokio::test]
async fn a_lifecycle_key_can_end_maintenance_it_started_and_the_audit_names_the_key() {
    let app = app();
    let (id, key) = make_key(&app, "deploy-bot", json!(["op:lifecycle"])).await;
    let (c, v) = call(&app, "PUT", &key, "/v1/admin/maintenance", json!({ "on": true, "message": "deploying" })).await;
    assert_eq!((c, v["on"].as_bool()), (200, Some(true)));
    let (c, v) = call(&app, "PUT", &key, "/v1/admin/maintenance", json!({ "on": false })).await;
    assert_eq!((c, v["on"].as_bool()), (200, Some(false)), "maintenance mode does not lock the key out");
    let (_, audit) = call(&app, "GET", "tok-a", "/v1/admin/audit?action=maintenance.on", Value::Null).await;
    let entry = &audit["entries"][0];
    assert_eq!(entry["actor_name"], "deploy-bot");
    assert_eq!(entry["actor"], format!("apikey:{id}"));
}

#[tokio::test]
async fn only_admins_manage_keys_secrets_are_shown_once_and_revoking_works() {
    let app = app();
    let (c, v) = call(&app, "POST", "tok-b", "/v1/admin/api-keys", json!({ "name": "x", "scopes": ["read:status"] })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("ADMIN_ONLY")));
    let (c, v) = call(&app, "POST", "tok-a", "/v1/admin/api-keys", json!({ "name": "x", "scopes": ["admin:everything"] })).await;
    assert_eq!((c, v["error"].as_str()), (400, Some("BAD_SCOPE")));
    let (id, key) = make_key(&app, "bot", json!(["read:status"])).await;
    let (_, list) = call(&app, "GET", "tok-a", "/v1/admin/api-keys", Value::Null).await;
    assert!(!list.to_string().contains(&key), "the list never shows the secret");
    assert_eq!(list["keys"][0]["name"], "bot");
    assert_eq!(call(&app, "DELETE", "tok-a", &format!("/v1/admin/api-keys/{id}"), Value::Null).await.0, 200);
    assert_eq!(call(&app, "GET", &key, "/v1/admin/usage", Value::Null).await.0, 401, "a revoked key stops working at once");
    assert_eq!(call(&app, "DELETE", "tok-a", &format!("/v1/admin/api-keys/{id}"), Value::Null).await.0, 404);
}

fn app_with_chunks() -> (Router, String) {
    use gatewayd::chain::{next_mac, Entry};
    use gatewayd::lease::{CommitKind, Hw, Join};
    use gatewayd::wal::Frame;
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("mcmesh-cas-it-{}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), gatewayd::cas::Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "x", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_token("dev-a", "tok-a").unwrap();
    let Join::Host(a) = g.join("w1", "dev-a", Hw { tier: 2, score: 5.0, wants_host: true, takeover: true }, 0).unwrap() else { panic!("host") };
    let (c1, lv) = (g.cas().put(b"chunk1").unwrap(), g.cas().put(b"level").unwrap());
    let mut prev = [0u8; 32];
    let mut frames = Vec::new();
    for (seq, (op, dim, cx, cz, hash)) in [("put:region", "minecraft:overworld", 3, -4, c1), ("aux_put", "level.dat", 0, 0, lv), ("barrier", "", 0, 0, [0u8; 32])].into_iter().enumerate() {
        let e = Entry { seq: seq as u64, dim, kind: op, cx, cz, hash: &hash };
        prev = next_mac(&a.hmac_key, &prev, &e);
        frames.push(Frame { seq: e.seq, op: op.into(), dim: dim.into(), cx, cz, hash, mac: prev.to_vec() });
    }
    g.wal_append(&a.lease_id, a.epoch, &frames).unwrap();
    let rev = g.commit(&a.lease_id, a.epoch, &a.base_rev, CommitKind::Autosave, false, 100).unwrap();
    let cfg = gatewayd::auth::AuthCfg { admins: vec!["u-a".into()], ..Default::default() };
    (router(AppState::with_auth(g, cfg)), rev.id)
}

#[tokio::test]
async fn a_cas_key_lists_revisions_and_manifests_and_nothing_else() {
    let (app, rev) = app_with_chunks();
    let (_, key) = make_key(&app, "renderer", json!(["read:cas"])).await;
    let (c, v) = call(&app, "GET", &key, "/v1/admin/worlds/w1/revisions", Value::Null).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["head"], json!(rev));
    let (c, v) = call(&app, "GET", &key, &format!("/v1/admin/worlds/w1/revisions/{rev}/manifest"), Value::Null).await;
    assert_eq!(c, 200, "{v}");
    assert_eq!(v["total"], 2);
    let leaves = v["leaves"].as_array().unwrap();
    assert!(leaves.iter().any(|l| l["type"] == "aux" && l["path"] == "level.dat"));
    assert!(leaves.iter().any(|l| l["type"] == "chunk" && l["cx"] == 3 && l["cz"] == -4 && l["kind"] == "region" && l["hash"].as_str().unwrap().len() == 64));
    let (_, page) = call(&app, "GET", &key, &format!("/v1/admin/worlds/w1/revisions/{rev}/manifest?offset=1&limit=1"), Value::Null).await;
    assert_eq!((page["total"].as_u64(), page["leaves"].as_array().unwrap().len()), (Some(2), 1));

    let (c, _) = call(&app, "GET", &key, "/v1/admin/worlds/nope/revisions", Value::Null).await;
    assert_eq!(c, 404);
    let (c, v) = call(&app, "GET", &key, "/v1/admin/worlds/other/revisions/w1:R_0001/manifest", Value::Null).await;
    assert_eq!((c, v["error"].as_str()), (404, Some("NO_SUCH_REVISION")));
    assert_eq!(call(&app, "GET", &key, "/v1/admin/usage", Value::Null).await.0, 403);

    let (_, status_key) = make_key(&app, "grafana", json!(["read:status"])).await;
    let (c, v) = call(&app, "GET", &status_key, "/v1/admin/worlds/w1/revisions", Value::Null).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("SCOPE_DENIED")));
}

#[tokio::test]
async fn a_cas_key_downloads_a_blob_by_hash_from_a_manifest_leaf() {
    let (app, rev) = app_with_chunks();
    let (_, key) = make_key(&app, "renderer", json!(["read:cas"])).await;
    let (_, v) = call(&app, "GET", &key, &format!("/v1/admin/worlds/w1/revisions/{rev}/manifest"), Value::Null).await;
    let hash = v["leaves"].as_array().unwrap().iter().find(|l| l["type"] == "chunk").unwrap()["hash"].as_str().unwrap().to_string();
    let get = |tok: &str, h: &str| {
        let r = Request::builder().uri(format!("/v1/admin/blobs/{h}")).header("authorization", format!("Bearer {tok}"));
        let app = app.clone();
        let req = r.body(Body::empty()).unwrap();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            (resp.status().as_u16(), resp.into_body().collect().await.unwrap().to_bytes())
        }
    };
    let (c, body) = get(&key, &hash).await;
    assert_eq!((c, &body[..]), (200, &b"chunk1"[..]));
    assert_eq!(get(&key, "zz").await.0, 400);
    assert_eq!(get(&key, &"0".repeat(64)).await.0, 404);
    let (_, status_key) = make_key(&app, "grafana", json!(["read:status"])).await;
    assert_eq!(get(&status_key, &hash).await.0, 403);
}

#[tokio::test]
async fn an_owner_hands_a_world_to_a_member_and_loses_owner_only_rights() {
    let app = app();
    let (c, v) = call(&app, "POST", "tok-a", "/v1/worlds/w1/transfer", json!({ "to": "nobody" })).await;
    assert_eq!((c, v["error"].as_str()), (404, Some("NO_SUCH_PLAYER")));
    let (c, v) = call(&app, "POST", "tok-a", "/v1/worlds/w1/transfer", json!({ "to": "alice" })).await;
    assert_eq!((c, v["error"].as_str()), (409, Some("ALREADY_OWNER")));
    let (c, v) = call(&app, "POST", "tok-b", "/v1/worlds/w1/transfer", json!({ "to": "bob" })).await;
    assert_eq!((c, v["error"].as_str()), (403, Some("OWNER_ONLY")), "a plain member cannot give themselves the world");
    let (c, v) = call(&app, "POST", "tok-a", "/v1/worlds/w1/transfer", json!({ "to": "bob" })).await;
    assert_eq!((c, v["owner"].as_str()), (200, Some("bob")), "{v}");
    let (c, v) = call(&app, "GET", "tok-a", "/v1/admin/audit", Value::Null).await;
    assert_eq!(c, 200);
    assert!(v.to_string().contains("world.transfer"));
    let (c, _) = call(&app, "POST", "tok-b", "/v1/worlds/w1/transfer", json!({ "to": "alice" })).await;
    assert_eq!(c, 200, "bob is the owner now and can hand it back");
}

#[tokio::test]
async fn a_fork_starts_from_an_old_revision_and_shares_its_blobs() {
    let (app, rev) = app_with_chunks();
    let (c, v) = call(&app, "POST", "tok-a", "/v1/worlds/w1/fork", json!({ "rev": "w1:R_0099", "name": "copy" })).await;
    assert_eq!((c, v["error"].as_str()), (404, Some("NO_SUCH_REVISION")));
    let (c, _) = call(&app, "POST", "tok-a", "/v1/worlds/nope/fork", json!({ "rev": rev, "name": "copy" })).await;
    assert_eq!(c, 404);
    let (c, v) = call(&app, "POST", "tok-a", "/v1/worlds/w1/fork", json!({ "rev": rev, "name": "copy" })).await;
    assert_eq!(c, 200, "{v}");
    let fork = v["id"].as_str().unwrap().to_string();

    let (_, key) = make_key(&app, "renderer", json!(["read:cas"])).await;
    let (c, v) = call(&app, "GET", &key, &format!("/v1/admin/worlds/{fork}/revisions"), Value::Null).await;
    assert_eq!(c, 200, "{v}");
    let head = v["head"].as_str().unwrap().to_string();
    assert_eq!(head, format!("{fork}:R_0000"));
    let (_, forked) = call(&app, "GET", &key, &format!("/v1/admin/worlds/{fork}/revisions/{head}/manifest"), Value::Null).await;
    let (_, source) = call(&app, "GET", &key, &format!("/v1/admin/worlds/w1/revisions/{rev}/manifest"), Value::Null).await;
    assert_eq!(forked["leaves"], source["leaves"], "same content");
    assert_eq!(forked["total"], 2);

    let (_, usage) = call(&app, "GET", "tok-a", "/v1/admin/usage", Value::Null).await;
    let bytes = |id: &str| usage["worlds"].as_array().unwrap().iter().find(|w| w["id"] == id).map(|w| w["storage_bytes"].as_u64().unwrap());
    assert!(bytes(&fork).unwrap() > 0, "the fork's owner is charged for the shared blobs");
    let (_, after) = call(&app, "GET", &key, "/v1/admin/worlds/w1/revisions", Value::Null).await;
    assert_eq!(after["head"], json!(rev), "the source world is untouched");
}

#[tokio::test]
async fn a_listed_template_can_be_forked_by_anyone_logged_in_and_only_then() {
    let app = app();
    let (c, v) = call(&app, "POST", "tok-b", "/v1/templates/w1/fork", json!({ "name": "mine" })).await;
    assert_eq!((c, v["error"].as_str()), (404, Some("NO_SUCH_TEMPLATE")), "not listed yet");
    let (c, _) = call(&app, "PUT", "tok-b", "/v1/worlds/w1/template", json!({ "on": true })).await;
    assert_eq!(c, 403, "only the owner or an admin lists a template");
    let (c, _) = call(&app, "PUT", "tok-a", "/v1/worlds/w1/template", json!({ "on": true, "description": "spawn town" })).await;
    assert_eq!(c, 200);
    let (c, v) = call(&app, "GET", "tok-b", "/v1/templates", Value::Null).await;
    assert_eq!((c, v["templates"][0]["description"].as_str()), (200, Some("spawn town")));
    let (c, v) = call(&app, "POST", "tok-b", "/v1/templates/w1/fork", json!({ "name": "mine" })).await;
    assert_eq!(c, 200, "{v}");
    let (c, v2) = call(&app, "GET", "tok-b", "/v1/worlds", Value::Null).await;
    assert_eq!(c, 200);
    assert!(v2.to_string().contains(v["id"].as_str().unwrap()), "bob owns the fork");
    let (c, _) = call(&app, "PUT", "tok-a", "/v1/worlds/w1/template", json!({ "on": false })).await;
    assert_eq!(c, 200);
    assert_eq!(call(&app, "POST", "tok-b", "/v1/templates/w1/fork", json!({ "name": "again" })).await.0, 404);
}

#[tokio::test]
async fn a_cas_key_fetches_several_blobs_in_one_framed_response() {
    let (app, rev) = app_with_chunks();
    let (_, key) = make_key(&app, "renderer", json!(["read:cas"])).await;
    let (_, v) = call(&app, "GET", &key, &format!("/v1/admin/worlds/w1/revisions/{rev}/manifest"), Value::Null).await;
    let hash = v["leaves"].as_array().unwrap().iter().find(|l| l["type"] == "chunk").unwrap()["hash"].as_str().unwrap().to_string();
    let post = |tok: &str, hashes: Vec<String>| {
        let r = Request::builder().method("POST").uri("/v1/admin/blobs/batch").header("content-type", "application/json").header("authorization", format!("Bearer {tok}"));
        let req = r.body(Body::from(json!({ "hashes": hashes }).to_string())).unwrap();
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            (resp.status().as_u16(), resp.into_body().collect().await.unwrap().to_bytes())
        }
    };
    let (c, body) = post(&key, vec![hash.clone(), "0".repeat(64)]).await;
    assert_eq!(c, 200);
    assert_eq!(body[32], 1);
    assert_eq!(&body[33..37], &6u32.to_be_bytes());
    assert_eq!(&body[37..43], b"chunk1");
    assert_eq!(&body[43 + 32..], &[0u8][..], "the unknown hash is reported missing");
    assert_eq!(post(&key, vec!["zz".into()]).await.0, 400);
    assert_eq!(post(&key, vec![hash.clone(); 257]).await.0, 400);
    let (_, status_key) = make_key(&app, "grafana", json!(["read:status"])).await;
    assert_eq!(post(&status_key, vec![hash]).await.0, 403);
}
