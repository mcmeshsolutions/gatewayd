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
