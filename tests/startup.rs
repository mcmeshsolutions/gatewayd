use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_gatewayd"))
}

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("mcmesh-startup-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn strict_mode_refuses_to_serve_on_an_empty_volume_and_creates_nothing() {
    let d = dir("strict");
    let out = bin()
        .arg("serve")
        .env("MCMESH_STRICT_DATA", "1")
        .env("MCMESH_DB", d.join("m.db"))
        .env("MCMESH_CAS", d.join("cas"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("MCMESH_STRICT_DATA"));
    assert!(!d.join("m.db").exists() && !d.join("cas").exists(), "a refused start must not create an empty gateway");
}

#[test]
fn init_creates_the_database_and_cas_on_purpose() {
    let d = dir("init");
    let out = bin().arg("init").env("MCMESH_STRICT_DATA", "1").env("MCMESH_DB", d.join("m.db")).env("MCMESH_CAS", d.join("cas")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(d.join("m.db").is_file() && d.join("cas").is_dir());
}
