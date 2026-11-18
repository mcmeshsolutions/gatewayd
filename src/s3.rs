//! Automated S3 / Cloudflare R2 Off-Site Disaster Replication & Fresh Restore.
//! Provides asynchronous CAS blob and WAL SQLite snapshot sync to S3-compatible object storage
//! (AWS S3, Cloudflare R2, MinIO, Wasabi, Garage) and 1-command fresh disaster restore.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub prefix: String,
    pub sync_interval_s: u64,
    pub keep_snapshots: usize,
    pub path_style: bool,
}

impl S3Config {
    pub fn from_env() -> Option<Self> {
        let bucket = std::env::var("MCMESH_S3_BUCKET").ok()?.trim().to_string();
        if bucket.is_empty() {
            return None;
        }

        let endpoint = std::env::var("MCMESH_S3_ENDPOINT")
            .unwrap_or_else(|_| "https://s3.amazonaws.com".to_string())
            .trim()
            .trim_end_matches('/')
            .to_string();

        let region = std::env::var("MCMESH_S3_REGION")
            .unwrap_or_else(|_| "us-east-1".to_string())
            .trim()
            .to_string();

        let access_key = std::env::var("MCMESH_S3_ACCESS_KEY")
            .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let secret_key = std::env::var("MCMESH_S3_SECRET_KEY")
            .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let mut prefix = std::env::var("MCMESH_S3_PREFIX").unwrap_or_default().trim().to_string();
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        if prefix.starts_with('/') {
            prefix = prefix.trim_start_matches('/').to_string();
        }

        let sync_interval_s = std::env::var("MCMESH_S3_SYNC_INTERVAL_S")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300)
            .max(30);

        let keep_snapshots = std::env::var("MCMESH_S3_KEEP_SNAPSHOTS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(14);

        let path_style = match std::env::var("MCMESH_S3_PATH_STYLE").as_deref() {
            Ok("0" | "false" | "FALSE") => false,
            Ok("1" | "true" | "TRUE") => true,
            _ => {
                endpoint.contains("localhost")
                    || endpoint.contains("127.0.0.1")
                    || endpoint.contains("r2.cloudflarestorage.com")
                    || endpoint.contains(":9000")
            }
        };

        Some(S3Config {
            endpoint,
            bucket,
            region,
            access_key,
            secret_key,
            prefix,
            sync_interval_s,
            keep_snapshots,
            path_style,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Status {
    pub enabled: bool,
    pub bucket: String,
    pub endpoint: String,
    pub region: String,
    pub prefix: String,
    pub last_sync_at: Option<u64>,
    pub last_error: Option<String>,
    pub last_snapshot: Option<String>,
    pub total_synced_blobs: u64,
    pub total_synced_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Object {
    pub key: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3SyncReport {
    pub uploaded_blobs: u64,
    pub uploaded_bytes: u64,
    pub skipped_blobs: u64,
    pub snapshot: String,
    pub db_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3RestoreReport {
    pub db_snapshot: String,
    pub restored_blobs: u64,
    pub restored_bytes: u64,
}

#[derive(Clone)]
pub struct S3Client {
    pub config: S3Config,
}

impl S3Client {
    pub fn new(config: S3Config) -> Self {
        Self { config }
    }

    fn url_and_host(&self, key: &str) -> (String, String, String) {
        let trimmed_key = key.trim_start_matches('/');
        let endpoint = &self.config.endpoint;

        let (scheme, after_scheme) = if let Some(stripped) = endpoint.strip_prefix("https://") {
            ("https", stripped)
        } else if let Some(stripped) = endpoint.strip_prefix("http://") {
            ("http", stripped)
        } else {
            ("https", endpoint.as_str())
        };

        let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);

        if self.config.path_style {
            let url = format!("{}/{}/{}", endpoint, self.config.bucket, trimmed_key);
            let canonical_uri = format!("/{}/{}", self.config.bucket, trimmed_key);
            let host_hdr = host_port.to_string();
            (url, host_hdr, canonical_uri)
        } else {
            let virtual_host = format!("{}.{}", self.config.bucket, host_port);
            let url = format!("{}://{}/{}", scheme, virtual_host, trimmed_key);
            let canonical_uri = format!("/{}", trimmed_key);
            (url, virtual_host, canonical_uri)
        }
    }

    pub fn put_object(&self, key: &str, data: &[u8], content_type: &str) -> Result<(), String> {
        let (url, host_hdr, canonical_uri) = self.url_and_host(key);
        let (amz_date, date_stamp) = format_datetime(SystemTime::now());
        let payload_sha256 = sha256_hex(data);

        let mut headers = vec![
            ("content-type", content_type),
            ("host", host_hdr.as_str()),
            ("x-amz-content-sha256", payload_sha256.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        headers.sort_by_key(|h| h.0);

        let auth_hdr = sign_request(
            "PUT",
            &canonical_uri,
            "",
            &headers,
            &payload_sha256,
            &self.config,
            &amz_date,
            &date_stamp,
        );

        let agent = ureq::builder().timeout(Duration::from_secs(60)).build();
        let req = agent.put(&url)
            .set("host", &host_hdr)
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &payload_sha256)
            .set("content-type", content_type)
            .set("authorization", &auth_hdr);

        match req.send_bytes(data) {
            Ok(resp) => {
                if resp.status() >= 200 && resp.status() < 300 {
                    Ok(())
                } else {
                    Err(format!("S3 PUT {} failed with status {}", key, resp.status()))
                }
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(format!("S3 PUT {} failed HTTP {}: {}", key, code, body))
            }
            Err(e) => Err(format!("S3 PUT {} network error: {}", key, e)),
        }
    }

    pub fn get_object(&self, key: &str) -> Result<Vec<u8>, String> {
        let (url, host_hdr, canonical_uri) = self.url_and_host(key);
        let (amz_date, date_stamp) = format_datetime(SystemTime::now());
        let empty_payload_sha256 = sha256_hex(b"");

        let mut headers = vec![
            ("host", host_hdr.as_str()),
            ("x-amz-content-sha256", empty_payload_sha256.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        headers.sort_by_key(|h| h.0);

        let auth_hdr = sign_request(
            "GET",
            &canonical_uri,
            "",
            &headers,
            &empty_payload_sha256,
            &self.config,
            &amz_date,
            &date_stamp,
        );

        let agent = ureq::builder().timeout(Duration::from_secs(120)).build();
        let req = agent.get(&url)
            .set("host", &host_hdr)
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &empty_payload_sha256)
            .set("authorization", &auth_hdr);

        match req.call() {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut buf)
                    .map_err(|e| format!("Failed reading response: {e}"))?;
                Ok(buf)
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(format!("S3 GET {} failed HTTP {}: {}", key, code, body))
            }
            Err(e) => Err(format!("S3 GET {} network error: {}", key, e)),
        }
    }

    pub fn head_object(&self, key: &str) -> Result<bool, String> {
        let (url, host_hdr, canonical_uri) = self.url_and_host(key);
        let (amz_date, date_stamp) = format_datetime(SystemTime::now());
        let empty_payload_sha256 = sha256_hex(b"");

        let mut headers = vec![
            ("host", host_hdr.as_str()),
            ("x-amz-content-sha256", empty_payload_sha256.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        headers.sort_by_key(|h| h.0);

        let auth_hdr = sign_request(
            "HEAD",
            &canonical_uri,
            "",
            &headers,
            &empty_payload_sha256,
            &self.config,
            &amz_date,
            &date_stamp,
        );

        let agent = ureq::builder().timeout(Duration::from_secs(15)).build();
        let req = agent.request("HEAD", &url)
            .set("host", &host_hdr)
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &empty_payload_sha256)
            .set("authorization", &auth_hdr);

        match req.call() {
            Ok(resp) => Ok(resp.status() == 200),
            Err(ureq::Error::Status(404, _)) => Ok(false),
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(format!("S3 HEAD {} failed HTTP {}: {}", key, code, body))
            }
            Err(e) => Err(format!("S3 HEAD {} network error: {}", key, e)),
        }
    }

    pub fn delete_object(&self, key: &str) -> Result<(), String> {
        let (url, host_hdr, canonical_uri) = self.url_and_host(key);
        let (amz_date, date_stamp) = format_datetime(SystemTime::now());
        let empty_payload_sha256 = sha256_hex(b"");

        let mut headers = vec![
            ("host", host_hdr.as_str()),
            ("x-amz-content-sha256", empty_payload_sha256.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        headers.sort_by_key(|h| h.0);

        let auth_hdr = sign_request(
            "DELETE",
            &canonical_uri,
            "",
            &headers,
            &empty_payload_sha256,
            &self.config,
            &amz_date,
            &date_stamp,
        );

        let agent = ureq::builder().timeout(Duration::from_secs(15)).build();
        let req = agent.delete(&url)
            .set("host", &host_hdr)
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &empty_payload_sha256)
            .set("authorization", &auth_hdr);

        match req.call() {
            Ok(_) | Err(ureq::Error::Status(404, _)) => Ok(()),
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(format!("S3 DELETE {} failed HTTP {}: {}", key, code, body))
            }
            Err(e) => Err(format!("S3 DELETE {} network error: {}", key, e)),
        }
    }

    pub fn list_objects(&self, prefix: &str) -> Result<Vec<S3Object>, String> {
        let (url_base, host_hdr, canonical_uri) = self.url_and_host("");
        let (amz_date, date_stamp) = format_datetime(SystemTime::now());
        let empty_payload_sha256 = sha256_hex(b"");

        let query_str = if prefix.is_empty() {
            "list-type=2".to_string()
        } else {
            format!("list-type=2&prefix={}", url_encode(prefix))
        };

        let mut headers = vec![
            ("host", host_hdr.as_str()),
            ("x-amz-content-sha256", empty_payload_sha256.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        headers.sort_by_key(|h| h.0);

        let auth_hdr = sign_request(
            "GET",
            &canonical_uri,
            &query_str,
            &headers,
            &empty_payload_sha256,
            &self.config,
            &amz_date,
            &date_stamp,
        );

        let full_url = format!("{}?{}", url_base, query_str);
        let agent = ureq::builder().timeout(Duration::from_secs(30)).build();
        let req = agent.get(&full_url)
            .set("host", &host_hdr)
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &empty_payload_sha256)
            .set("authorization", &auth_hdr);

        match req.call() {
            Ok(resp) => {
                let xml = resp.into_string().map_err(|e| format!("XML read error: {e}"))?;
                Ok(parse_list_objects_xml(&xml))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(format!("S3 LIST prefix '{}' failed HTTP {}: {}", prefix, code, body))
            }
            Err(e) => Err(format!("S3 LIST prefix '{}' network error: {}", prefix, e)),
        }
    }
}

pub struct S3Replicator {
    client: Option<S3Client>,
    status: Arc<RwLock<S3Status>>,
}

impl S3Replicator {
    pub fn from_env() -> Self {
        let config = S3Config::from_env();
        Self::new(config)
    }

    pub fn new(config: Option<S3Config>) -> Self {
        let initial_status = match &config {
            Some(c) => S3Status {
                enabled: true,
                bucket: c.bucket.clone(),
                endpoint: c.endpoint.clone(),
                region: c.region.clone(),
                prefix: c.prefix.clone(),
                last_sync_at: None,
                last_error: None,
                last_snapshot: None,
                total_synced_blobs: 0,
                total_synced_bytes: 0,
            },
            None => S3Status {
                enabled: false,
                bucket: String::new(),
                endpoint: String::new(),
                region: String::new(),
                prefix: String::new(),
                last_sync_at: None,
                last_error: None,
                last_snapshot: None,
                total_synced_blobs: 0,
                total_synced_bytes: 0,
            },
        };

        let client = config.map(S3Client::new);
        Self {
            client,
            status: Arc::new(RwLock::new(initial_status)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.client.is_some()
    }

    pub fn config(&self) -> Option<S3Config> {
        self.client.as_ref().map(|c| c.config.clone())
    }

    pub fn status(&self) -> S3Status {
        self.status.read().unwrap().clone()
    }

    pub fn test_connection(&self) -> Result<u64, String> {
        let client = self.client.as_ref().ok_or_else(|| "S3 not configured".to_string())?;
        let start = SystemTime::now();

        let test_key = format!("{}.mcmesh_s3_test_{}", client.config.prefix, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis());
        let test_payload = b"mcmesh-s3-connectivity-check";

        client.put_object(&test_key, test_payload, "text/plain")?;
        let read_back = client.get_object(&test_key)?;
        let _ = client.delete_object(&test_key);

        if read_back != test_payload {
            return Err("S3 test payload readback mismatch".to_string());
        }

        let elapsed = start.elapsed().map(|d| d.as_millis() as u64).unwrap_or(0);
        Ok(elapsed)
    }

    pub fn take_snapshot(conn: &rusqlite::Connection) -> Result<(Vec<u8>, String), String> {
        let tmp_db = std::env::temp_dir().join(format!("mcmesh-s3snap-{}-{}.tmp", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let tmp_str = tmp_db.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&tmp_db);

        let snap_res = (|| -> Result<(Vec<u8>, String), String> {
            conn.execute("VACUUM INTO ?", [&tmp_str]).map_err(|e| format!("VACUUM INTO failed: {e}"))?;
            let bytes = std::fs::read(&tmp_db).map_err(|e| format!("Read temp snapshot failed: {e}"))?;
            let hash = sha256_hex(&bytes);
            Ok((bytes, hash))
        })();

        let _ = std::fs::remove_file(&tmp_db);
        snap_res
    }

    pub fn sync_all(&self, conn: &rusqlite::Connection, cas_dir: &Path) -> Result<S3SyncReport, String> {
        let (db_bytes, db_hash) = match Self::take_snapshot(conn) {
            Ok(v) => v,
            Err(e) => {
                let mut st = self.status.write().unwrap();
                st.last_error = Some(e.clone());
                return Err(e);
            }
        };
        self.sync_snapshot_and_blobs(&db_bytes, &db_hash, cas_dir)
    }

    pub fn sync_snapshot_and_blobs(&self, db_bytes: &[u8], db_hash: &str, cas_dir: &Path) -> Result<S3SyncReport, String> {
        let client = self.client.as_ref().ok_or_else(|| "S3 replication not configured".to_string())?;

        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let snap_key = format!("{}db/mcmesh-{}-{}.db", client.config.prefix, ts, &db_hash[..8.min(db_hash.len())]);
        let latest_key = format!("{}db/latest.db", client.config.prefix);

        if let Err(e) = client.put_object(&snap_key, db_bytes, "application/x-sqlite3") {
            let mut st = self.status.write().unwrap();
            st.last_error = Some(e.clone());
            return Err(e);
        }
        let _ = client.put_object(&latest_key, db_bytes, "application/x-sqlite3");

        // 2. Discover remote CAS blobs and sync missing local blobs
        let cas_prefix = format!("{}cas/", client.config.prefix);
        let remote_objects = client.list_objects(&cas_prefix).unwrap_or_default();
        let mut remote_keys: HashSet<String> = remote_objects.into_iter().map(|o| o.key).collect();

        let mut uploaded_blobs = 0u64;
        let mut uploaded_bytes = 0u64;
        let mut skipped_blobs = 0u64;

        let local_blobs = crate::maintenance::blob_files(cas_dir).map_err(|e| e.to_string())?;
        for p in local_blobs {
            let rel = p.strip_prefix(cas_dir).map_err(|e| e.to_string())?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let key = format!("{}cas/{}", client.config.prefix, rel_str);

            if remote_keys.contains(&key) {
                skipped_blobs += 1;
                continue;
            }

            match std::fs::read(&p) {
                Ok(data) => {
                    if let Err(e) = client.put_object(&key, &data, "application/octet-stream") {
                        let mut st = self.status.write().unwrap();
                        st.last_error = Some(e.clone());
                        return Err(e);
                    }
                    remote_keys.insert(key);
                    uploaded_blobs += 1;
                    uploaded_bytes += data.len() as u64;
                }
                Err(e) => {
                    eprintln!("Warning: skipping unreadable local blob {}: {e}", p.display());
                }
            }
        }

        // 3. Write manifest.json
        let manifest = serde_json::json!({
            "timestamp": ts,
            "latest_snapshot": snap_key,
            "db_sha256": db_hash,
            "db_size_bytes": db_bytes.len(),
            "total_blobs": remote_keys.len(),
            "gateway_version": env!("CARGO_PKG_VERSION")
        });
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
        let manifest_key = format!("{}db/manifest.json", client.config.prefix);
        let _ = client.put_object(&manifest_key, &manifest_bytes, "application/json");

        // 4. Prune older snapshots beyond retention limit
        let db_prefix = format!("{}db/", client.config.prefix);
        if let Ok(db_objs) = client.list_objects(&db_prefix) {
            let mut snap_keys: Vec<String> = db_objs
                .into_iter()
                .map(|o| o.key)
                .filter(|k| k.contains("mcmesh-") && k.ends_with(".db"))
                .collect();
            snap_keys.sort();
            if snap_keys.len() > client.config.keep_snapshots {
                let to_remove = snap_keys.len() - client.config.keep_snapshots;
                for k in snap_keys.iter().take(to_remove) {
                    let _ = client.delete_object(k);
                }
            }
        }

        // 5. Update live state
        {
            let mut st = self.status.write().unwrap();
            st.last_sync_at = Some(ts);
            st.last_snapshot = Some(snap_key.clone());
            st.total_synced_blobs += uploaded_blobs;
            st.total_synced_bytes += uploaded_bytes + db_bytes.len() as u64;
            st.last_error = None;
        }

        Ok(S3SyncReport {
            uploaded_blobs,
            uploaded_bytes,
            skipped_blobs,
            snapshot: snap_key,
            db_size: db_bytes.len() as u64,
        })
    }

    pub fn restore_fresh(&self, target_dir: &Path, specific_snapshot: Option<&str>) -> Result<S3RestoreReport, String> {
        let client = self.client.as_ref().ok_or_else(|| "S3 not configured".to_string())?;

        std::fs::create_dir_all(target_dir).map_err(|e| format!("Failed to create target dir: {e}"))?;

        // 1. Determine which DB snapshot to fetch
        let db_key = match specific_snapshot {
            Some(s) if s.contains('/') => s.to_string(),
            Some(s) => format!("{}db/{}", client.config.prefix, s),
            None => format!("{}db/latest.db", client.config.prefix),
        };

        let db_bytes = client.get_object(&db_key)?;
        let tmp_db = target_dir.join("mcmesh.db.tmp");
        std::fs::write(&tmp_db, &db_bytes).map_err(|e| format!("Failed to write tmp db: {e}"))?;

        // Verify SQLite integrity
        {
            let conn = rusqlite::Connection::open(&tmp_db).map_err(|e| format!("Corrupt restored SQLite db: {e}"))?;
            let integrity: String = conn.query_row("PRAGMA integrity_check;", [], |r| r.get(0))
                .map_err(|e| format!("PRAGMA integrity_check error: {e}"))?;
            if integrity != "ok" {
                let _ = std::fs::remove_file(&tmp_db);
                return Err(format!("Restored db failed integrity check: {integrity}"));
            }
        }

        std::fs::rename(&tmp_db, target_dir.join("mcmesh.db"))
            .map_err(|e| format!("Failed to move restored mcmesh.db: {e}"))?;

        // 2. Fetch CAS blobs
        let cas_dir = target_dir.join("cas");
        std::fs::create_dir_all(&cas_dir).map_err(|e| format!("Failed to create cas dir: {e}"))?;

        let cas_prefix = format!("{}cas/", client.config.prefix);
        let objects = client.list_objects(&cas_prefix)?;

        let mut restored_blobs = 0u64;
        let mut restored_bytes = 0u64;

        for obj in objects {
            let rel = obj.key.strip_prefix(&cas_prefix).unwrap_or(&obj.key);
            if rel.is_empty() {
                continue;
            }
            let target_blob = cas_dir.join(rel);
            if target_blob.exists() {
                continue;
            }

            if let Some(parent) = target_blob.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create blob dir: {e}"))?;
            }

            let data = client.get_object(&obj.key)?;
            let tmp_blob = target_blob.with_extension("tmp");
            std::fs::write(&tmp_blob, &data).map_err(|e| format!("Failed to write blob {}: {e}", obj.key))?;
            std::fs::rename(&tmp_blob, &target_blob).map_err(|e| format!("Failed to finalize blob {}: {e}", obj.key))?;

            restored_blobs += 1;
            restored_bytes += data.len() as u64;
        }

        Ok(S3RestoreReport {
            db_snapshot: db_key,
            restored_blobs,
            restored_bytes,
        })
    }
}

// ---------------------------------------------------------------------------
// AWS SigV4 Signer & XML Parser Utilities
// ---------------------------------------------------------------------------

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC supports any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn format_datetime(t: SystemTime) -> (String, String) {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = (secs / 86400) as i64;

    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mth <= 2 { y + 1 } else { y };

    let amz_date = format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", yr, mth, d, h, m, s);
    let date_stamp = format!("{:04}{:02}{:02}", yr, mth, d);
    (amz_date, date_stamp)
}

pub fn sign_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(&str, &str)],
    payload_sha256: &str,
    cfg: &S3Config,
    amz_date: &str,
    date_stamp: &str,
) -> String {
    let mut can_headers = String::new();
    let mut signed_headers_vec = Vec::new();

    for (k, v) in headers {
        can_headers.push_str(&format!("{}:{}\n", k, v.trim()));
        signed_headers_vec.push(*k);
    }
    let signed_headers = signed_headers_vec.join(";");

    let can_req = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        canonical_uri,
        canonical_query,
        can_headers,
        signed_headers,
        payload_sha256
    );
    let can_req_hash = sha256_hex(can_req.as_bytes());

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, cfg.region);
    let str_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        can_req_hash
    );

    let k_secret = format!("AWS4{}", cfg.secret_key);
    let k_date = hmac(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac(&k_date, cfg.region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");

    let sig = hex_encode(&hmac(&k_signing, str_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        cfg.access_key, scope, signed_headers, sig
    )
}

pub fn parse_list_objects_xml(xml: &str) -> Vec<S3Object> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start_idx) = rest.find("<Contents>") {
        rest = &rest[start_idx + "<Contents>".len()..];
        let end_idx = match rest.find("</Contents>") {
            Some(i) => i,
            None => break,
        };
        let content_block = &rest[..end_idx];
        rest = &rest[end_idx + "</Contents>".len()..];

        let key = if let Some(k_start) = content_block.find("<Key>") {
            let after = &content_block[k_start + "<Key>".len()..];
            if let Some(k_end) = after.find("</Key>") {
                after[..k_end].to_string()
            } else {
                continue;
            }
        } else {
            continue;
        };

        let size: u64 = if let Some(s_start) = content_block.find("<Size>") {
            let after = &content_block[s_start + "<Size>".len()..];
            if let Some(s_end) = after.find("</Size>") {
                after[..s_end].trim().parse().unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        out.push(S3Object { key, size });
    }
    out
}
