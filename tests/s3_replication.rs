use gatewayd::cas::Cas;
use gatewayd::lease::{Gateway, Role};
use gatewayd::s3::{
    format_datetime, parse_list_objects_xml, sha256_hex, url_encode, S3Config,
    S3Replicator,
};
use gatewayd::server::{router, AppState};
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tower::ServiceExt;

#[test]
fn test_sigv4_utilities() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1731916800); // 2024-11-18 08:00:00 UTC
    let (amz_date, date_stamp) = format_datetime(now);
    assert_eq!(amz_date, "20241118T080000Z");
    assert_eq!(date_stamp, "20241118");

    let encoded = url_encode("prefix/with spaces & symbols.db");
    assert_eq!(encoded, "prefix%2Fwith%20spaces%20%26%20symbols.db");

    let hash = sha256_hex(b"hello world");
    assert_eq!(
        hash,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn test_xml_list_objects_parser() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>my-bucket</Name>
    <Prefix>cas/</Prefix>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>cas/ab/cd/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890</Key>
        <LastModified>2026-11-18T06:00:00.000Z</LastModified>
        <ETag>"1234567890abcdef"</ETag>
        <Size>4096</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
    <Contents>
        <Key>cas/ef/01/ef01234567890abcdef1234567890abcdef1234567890abcdef1234567890</Key>
        <Size>8192</Size>
    </Contents>
</ListBucketResult>"#;

    let objs = parse_list_objects_xml(xml);
    assert_eq!(objs.len(), 2);
    assert_eq!(
        objs[0].key,
        "cas/ab/cd/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );
    assert_eq!(objs[0].size, 4096);
    assert_eq!(
        objs[1].key,
        "cas/ef/01/ef01234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    );
    assert_eq!(objs[1].size, 8192);
}

/// Simple in-memory mock S3 server simulating PUT, GET, HEAD, DELETE, LIST
struct MockS3Server {
    objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    port: u16,
    shutdown: Arc<Mutex<bool>>,
}

impl MockS3Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock s3");
        let port = listener.local_addr().unwrap().port();
        let objects = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let objs_clone = objects.clone();
        let shutdown_clone = shutdown.clone();

        listener.set_nonblocking(true).unwrap();

        std::thread::spawn(move || {
            loop {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let objs = objs_clone.clone();
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut request_line = String::new();
                        if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
                            continue;
                        }

                        let parts: Vec<&str> = request_line.split_whitespace().collect();
                        if parts.len() < 2 {
                            continue;
                        }
                        let method = parts[0].to_string();
                        let uri = parts[1].to_string();

                        let mut content_length = 0usize;
                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                                break;
                            }
                            let lower = line.to_lowercase();
                            if lower.starts_with("content-length:") {
                                if let Some(val) = line.split(':').nth(1) {
                                    content_length = val.trim().parse().unwrap_or(0);
                                }
                            }
                        }

                        let mut body = vec![0u8; content_length];
                        if content_length > 0 {
                            let _ = reader.read_exact(&mut body);
                        }

                        // Path style: /bucket/key or /bucket/?list-type=2...
                        let path_part = uri.split('?').next().unwrap_or(&uri);
                        let query_part = if uri.contains('?') {
                            uri.split('?').nth(1).unwrap_or("")
                        } else {
                            ""
                        };

                        let key = if let Some(stripped) = path_part.strip_prefix("/test-bucket/") {
                            stripped.to_string()
                        } else if path_part == "/test-bucket" || path_part == "/test-bucket/" {
                            "".to_string()
                        } else {
                            path_part.trim_start_matches('/').to_string()
                        };

                        if method == "PUT" {
                            objs.lock().unwrap().insert(key, body);
                            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        } else if method == "GET" && query_part.contains("list-type=2") {
                            let prefix = if let Some(p) = query_part.split('&').find(|s| s.starts_with("prefix=")) {
                                p.strip_prefix("prefix=")
                                    .unwrap_or("")
                                    .replace("%2F", "/")
                                    .replace("%20", " ")
                            } else {
                                "".to_string()
                            };

                            let map = objs.lock().unwrap();
                            let mut keys: Vec<String> = map.keys().cloned().collect();
                            keys.sort();

                            let mut items = Vec::new();
                            for k in keys {
                                if k.starts_with(&prefix) {
                                    let size = map.get(&k).map(|v| v.len()).unwrap_or(0);
                                    items.push(format!("<Contents><Key>{}</Key><Size>{}</Size></Contents>", k, size));
                                }
                            }
                            let xml = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult>{}</ListBucketResult>", items.join(""));
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                                xml.len(),
                                xml
                            );
                            let _ = stream.write_all(resp.as_bytes());
                        } else if method == "GET" {
                            let map = objs.lock().unwrap();
                            if let Some(val) = map.get(&key) {
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                                    val.len()
                                );
                                let _ = stream.write_all(resp.as_bytes());
                                let _ = stream.write_all(val);
                            } else {
                                let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                                let _ = stream.write_all(not_found.as_bytes());
                            }
                        } else if method == "HEAD" {
                            let map = objs.lock().unwrap();
                            if map.contains_key(&key) {
                                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                                let _ = stream.write_all(resp.as_bytes());
                            } else {
                                let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                                let _ = stream.write_all(not_found.as_bytes());
                            }
                        } else if method == "DELETE" {
                            objs.lock().unwrap().remove(&key);
                            let resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        } else {
                            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            objects,
            port,
            shutdown,
        }
    }
}

impl Drop for MockS3Server {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
    }
}

#[tokio::test]
async fn test_s3_replication_and_fresh_restore() {
    let server = MockS3Server::start();
    let endpoint = format!("http://127.0.0.1:{}", server.port);

    let config = S3Config {
        endpoint: endpoint.clone(),
        bucket: "test-bucket".to_string(),
        region: "us-east-1".to_string(),
        access_key: "test-access".to_string(),
        secret_key: "test-secret".to_string(),
        prefix: "gw1/".to_string(),
        sync_interval_s: 300,
        keep_snapshots: 5,
        path_style: true,
    };

    let replicator = S3Replicator::new(Some(config.clone()));

    // 1. Verify S3 connectivity test
    let latency = replicator.test_connection().expect("test_connection");
    println!("Mock S3 latency: {latency}ms");

    // 2. Set up local Gateway dataset with database & CAS blobs
    let temp_root = std::env::temp_dir().join(format!("mcmesh-test-s3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_root);
    std::fs::create_dir_all(&temp_root).unwrap();

    let cas_dir = temp_root.join("cas");
    let cas = Cas::open(&cas_dir).unwrap();

    let db_path = temp_root.join("mcmesh.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let mut gw = Gateway::open(conn, cas, 0).unwrap();
    gw.create_world("s3-world", "S3 World", "1.21.1", "neoforge").unwrap();
    gw.add_member("s3-world", "u-alice", "alice", "d-alice", Role::Admin).unwrap();

    // Write sample CAS blob files into cas directory
    let blob1_data = b"chunk data blob 1 - diamond ore";
    let blob2_data = b"chunk data blob 2 - redstone comparator";
    let hash1 = sha256_hex(blob1_data);
    let hash2 = sha256_hex(blob2_data);

    let p1 = cas_dir.join(&hash1[..2]).join(&hash1[2..4]).join(&hash1);
    let p2 = cas_dir.join(&hash2[..2]).join(&hash2[2..4]).join(&hash2);
    std::fs::create_dir_all(p1.parent().unwrap()).unwrap();
    std::fs::create_dir_all(p2.parent().unwrap()).unwrap();
    std::fs::write(&p1, blob1_data).unwrap();
    std::fs::write(&p2, blob2_data).unwrap();

    // 3. Trigger initial S3 replication sync (1 revision root blob + 2 custom chunk blobs = 3 blobs)
    let sync_report = replicator.sync_all(gw.db(), &cas_dir).expect("sync_all");
    assert_eq!(sync_report.uploaded_blobs, 3);
    assert_eq!(sync_report.skipped_blobs, 0);
    assert!(sync_report.uploaded_bytes >= blob1_data.len() as u64 + blob2_data.len() as u64);
    assert!(sync_report.snapshot.contains("gw1/db/mcmesh-"));

    // Verify objects in mock S3
    {
        let objs = server.objects.lock().unwrap();
        assert!(objs.contains_key("gw1/db/latest.db"), "latest.db missing");
        assert!(objs.contains_key("gw1/db/manifest.json"), "manifest.json missing");
        let k1 = format!("gw1/cas/{}/{}/{}", &hash1[..2], &hash1[2..4], &hash1);
        let k2 = format!("gw1/cas/{}/{}/{}", &hash2[..2], &hash2[2..4], &hash2);
        assert!(objs.contains_key(&k1), "blob 1 missing in S3: {k1}");
        assert!(objs.contains_key(&k2), "blob 2 missing in S3: {k2}");
    }

    // 4. Trigger second sync - must be incremental (0 uploaded blobs, 3 skipped)
    let sync_report2 = replicator.sync_all(gw.db(), &cas_dir).expect("sync_all incremental");
    assert_eq!(sync_report2.uploaded_blobs, 0);
    assert_eq!(sync_report2.skipped_blobs, 3);

    // 5. Test 1-Command Fresh Disaster Restore into a new empty directory
    let restore_dir = temp_root.join("fresh_restore");
    let restore_report = replicator.restore_fresh(&restore_dir, None).expect("restore_fresh");
    assert_eq!(restore_report.restored_blobs, 3);
    assert!(restore_dir.join("mcmesh.db").is_file());
    assert!(restore_dir.join("cas").is_dir());

    // Verify restored database integrity and tables
    let restored_conn = rusqlite::Connection::open(restore_dir.join("mcmesh.db")).unwrap();
    let integrity: String = restored_conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");

    let world_name: String = restored_conn
        .query_row("SELECT name FROM worlds WHERE id='s3-world'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(world_name, "S3 World");

    // Verify restored CAS blobs match exactly
    let restored_p1 = restore_dir.join("cas").join(&hash1[..2]).join(&hash1[2..4]).join(&hash1);
    let restored_p2 = restore_dir.join("cas").join(&hash2[..2]).join(&hash2[2..4]).join(&hash2);
    assert_eq!(std::fs::read(&restored_p1).unwrap(), blob1_data);
    assert_eq!(std::fs::read(&restored_p2).unwrap(), blob2_data);

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn test_s3_admin_routes() {
    let server = MockS3Server::start();
    let endpoint = format!("http://127.0.0.1:{}", server.port);

    std::env::set_var("MCMESH_S3_BUCKET", "test-bucket");
    std::env::set_var("MCMESH_S3_ENDPOINT", &endpoint);
    std::env::set_var("MCMESH_S3_ACCESS_KEY", "key");
    std::env::set_var("MCMESH_S3_SECRET_KEY", "secret");

    let temp = std::env::temp_dir().join(format!("mcmesh-test-s3-admin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();

    let cas = Cas::open(temp.join("cas")).unwrap();
    let mut g = Gateway::open(rusqlite::Connection::open(temp.join("mcmesh.db")).unwrap(), cas, 0).unwrap();
    g.admin_init().unwrap();
    g.create_world("w", "w", "1.21.1", "neoforge").unwrap();
    g.add_member("w", "u-admin", "admin", "d-admin", Role::Admin).unwrap();
    g.set_gateway_admin("u-admin", true, "test").unwrap();
    let admin_tok = "s3admintoken123";
    g.add_token("d-admin", admin_tok).unwrap();

    let auth_cfg = gatewayd::auth::AuthCfg {
        key: true,
        ..Default::default()
    };
    let app = AppState::with_auth(g, auth_cfg);
    let app_router = router(app);

    // 1. GET /v1/admin/s3/status
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/admin/s3/status")
        .header("authorization", format!("Bearer {admin_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app_router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["status"]["enabled"], true);
    assert_eq!(json["status"]["bucket"], "test-bucket");

    // 2. POST /v1/admin/s3/test
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/admin/s3/test")
        .header("authorization", format!("Bearer {admin_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app_router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["bucket"], "test-bucket");

    // 3. POST /v1/admin/s3/sync
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/admin/s3/sync")
        .header("authorization", format!("Bearer {admin_tok}"))
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app_router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["status"], "SYNC_COMPLETE");

    // Clean up
    let _ = std::fs::remove_dir_all(&temp);
}
