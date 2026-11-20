use gatewayd::cas::Cas;
use gatewayd::lease::Gateway;
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use tower::ServiceExt;

#[tokio::test]
async fn test_forward_auth_and_oidc_flow() {
    // Start a mock OIDC token & userinfo server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();

    std::thread::spawn(move || {
        for _ in 0..1000 {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_nonblocking(false);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                let _ = reader.read_line(&mut req_line);
                let mut clen = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if line.to_lowercase().starts_with("content-length:") {
                        clen = line.split(':').nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; clen];
                if clen > 0 {
                    let _ = reader.read_exact(&mut body);
                }

                if req_line.starts_with("POST /token") {
                    let json_body = r#"{"access_token":"mock-access-tok","token_type":"Bearer"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        json_body.len(),
                        json_body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req_line.starts_with("GET /userinfo") {
                    let json_body = r#"{"sub":"oidc-user-1","email":"authentik@homelab.local","groups":["users","mcmesh-admins"]}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        json_body.len(),
                        json_body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    });

    let issuer = format!("http://127.0.0.1:{port}");
    std::env::set_var("MCMESH_FORWARD_AUTH", "1");
    std::env::set_var("MCMESH_OIDC_ISSUER", &issuer);
    std::env::set_var("MCMESH_OIDC_CLIENT_ID", "mcmesh-homelab");
    std::env::set_var("MCMESH_OIDC_CLIENT_SECRET", "super-secret");

    let temp = std::env::temp_dir().join(format!("mcmesh-test-homelab-sso-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();

    let cas = Cas::open(temp.join("cas")).unwrap();
    let g = Gateway::open(rusqlite::Connection::open(temp.join("mcmesh.db")).unwrap(), cas, 0).unwrap();
    let app = AppState::new(g);
    let r = router(app);

    // 1. Test /v1/auth/sso/providers discovery
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/auth/sso/providers")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let prov: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(prov["forward_auth"], true);
    assert_eq!(prov["oidc_enabled"], true);
    assert_eq!(prov["oidc_issuer"], issuer);

    // 2. Test Forward-Auth header login (Authelia / Authentik Remote-User & Remote-Groups)
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/sso/me")
        .header("remote-user", "authelia-operator")
        .header("remote-email", "operator@authelia.local")
        .header("remote-groups", "homelab,mcmesh-admins")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let me: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(me["mode"], "sso");
    assert_eq!(me["email"], "operator@authelia.local");
    assert_eq!(me["superadmin"], true);

    // 3. Test OIDC login redirect (/v1/auth/oidc/login) and callback (/v1/auth/oidc/callback)
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/auth/oidc/login")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = r.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 302);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(loc.starts_with(&format!("{issuer}/authorize?")));
    let state = loc.split("state=").nth(1).unwrap().to_string();

    let cb_req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/v1/auth/oidc/callback?code=mock-code-123&state={state}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let cb_resp = r.clone().oneshot(cb_req).await.unwrap();
    assert_eq!(cb_resp.status(), 302);
    assert_eq!(cb_resp.headers().get("location").unwrap(), "/panel");
    let cookie = cb_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("mcmesh_sso="));

    // Verify the minted OIDC session cookie works on /v1/sso/me
    let me_req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/sso/me")
        .header("cookie", &cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let me_resp = r.clone().oneshot(me_req).await.unwrap();
    assert_eq!(me_resp.status(), 200);
    let body = me_resp.into_body().collect().await.unwrap().to_bytes();
    let me_oidc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(me_oidc["email"], "authentik@homelab.local");
    assert_eq!(me_oidc["superadmin"], true);

    std::env::remove_var("MCMESH_FORWARD_AUTH");
    std::env::remove_var("MCMESH_OIDC_ISSUER");
    std::env::remove_var("MCMESH_OIDC_CLIENT_ID");
    std::env::remove_var("MCMESH_OIDC_CLIENT_SECRET");
    let _ = std::fs::remove_dir_all(&temp);
}
