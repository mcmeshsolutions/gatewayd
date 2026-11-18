use gatewayd::cas::Cas;
use gatewayd::lease::{Error, Gateway, Role};
use rusqlite::Connection;
use serde_json::json;

fn setup() -> Gateway {
    let dir = std::env::temp_dir().join(format!("mcmesh-panel-{}", std::process::id()));
    let mut g = Gateway::open(Connection::open_in_memory().unwrap(), Cas::open(dir).unwrap(), 0).unwrap();
    g.create_world("w1", "w", "1.21.1", "neoforge").unwrap();
    g.add_member("w1", "u-a", "alice", "dev-a", Role::Admin).unwrap();
    g.add_member("w1", "u-b", "bob", "dev-b", Role::HostEligible).unwrap();
    g
}

#[test]
fn mods_doc_is_admin_only_and_defaults_empty() {
    let mut g = setup();
    assert_eq!(g.world_mods("w1").unwrap(), json!({}));
    let doc = json!({ "allow": [{ "id": "create", "hash": "ab" }], "ignore": ["jei"] });
    assert!(matches!(g.set_world_mods("dev-b", "w1", &doc), Err(Error::NotMember)));
    g.set_world_mods("dev-a", "w1", &doc).unwrap();
    assert_eq!(g.world_mods("w1").unwrap(), doc);
}

#[test]
fn member_edits_are_admin_only_and_keep_one_admin() {
    let mut g = setup();
    assert!(g.set_member("dev-b", "w1", "alice", None).is_err());
    assert!(!g.set_member("dev-a", "w1", "alice", Some(Role::ClientOnly)).unwrap());
    assert!(!g.set_member("dev-a", "w1", "alice", None).unwrap());
    assert!(g.set_member("dev-a", "w1", "bob", Some(Role::Admin)).unwrap());
    assert!(g.set_member("dev-a", "w1", "alice", None).unwrap());
    assert!(!g.set_member("dev-b", "w1", "nobody", Some(Role::ClientOnly)).unwrap());
    let names: Vec<_> = g.members("w1").unwrap().into_iter().map(|m| m.0).collect();
    assert_eq!(names, ["bob"]);
}

#[tokio::test]
async fn setup_wizard_bootstraps_gateway_and_generates_discord_card() {
    let dir = std::env::temp_dir().join(format!("mcmesh-setup-{}", std::process::id()));
    let g = Gateway::open(Connection::open_in_memory().unwrap(), Cas::open(dir).unwrap(), 0).unwrap();
    let app = gatewayd::server::router(gatewayd::server::AppState::new(g));

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    // 1. Initial status is unconfigured
    let req = Request::get("/v1/setup/status").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["configured"], false);

    // 2. POST /v1/setup
    let setup_body = serde_json::json!({
        "admin_name": "SetupAdmin",
        "community_name": "Test SMP",
        "pack_name": "Test Pack",
        "motd": "Welcome to test!",
        "initial_world_id": "world-1",
        "initial_world_name": "First World"
    });
    let req = Request::post("/v1/setup")
        .header("content-type", "application/json")
        .body(Body::from(setup_body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["admin_name"], "SetupAdmin");
    assert!(!v["admin_token"].as_str().unwrap().is_empty());
    assert!(!v["invite_url"].as_str().unwrap().is_empty());

    // 3. Status now configured
    let req = Request::get("/v1/setup/status").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["configured"], true);
    assert_eq!(v["community_name"], "Test SMP");
    assert_eq!(v["pack_name"], "Test Pack");

    // 4. GET /v1/setup/discord-card returns SVG
    let req = Request::get("/v1/setup/discord-card").body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/svg+xml");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let svg = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(svg.contains("<svg"));
    assert!(svg.contains("Test SMP"));
    assert!(svg.contains("Test Pack"));
}
