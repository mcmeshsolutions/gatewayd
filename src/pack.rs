//! Modpack Creator CLI and packaging toolkit for mcmesh.
//! Provides `pack init`, `pack sign`, and `pack check` functionality.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DOMAIN: &[u8] = b"mcmesh-pack-v1\0";
const MANIFEST_MAX_BYTES: usize = 1 << 20; // 1 MB limit

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub pack: String,
    pub version: String,
    pub files: Vec<FileEntry>,
    #[serde(default)]
    pub remove: Vec<String>,
}

pub struct PackInitResult {
    pub pack_id: String,
    pub public_key: String,
    pub config_path: PathBuf,
    pub key_path: PathBuf,
}

pub struct PackSignResult {
    pub pack_id: String,
    pub version: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub public_key: String,
    pub manifest_path: PathBuf,
    pub signature_path: PathBuf,
}

pub struct PackCheckResult {
    pub pack_id: String,
    pub version: String,
    pub file_count: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub valid_signature: Option<bool>,
}

/// Initializes a new modpack workspace with author signing keys and starter mcmesh configuration.
pub fn init(dir: &Path, pack_id: Option<&str>, pack_name: Option<&str>) -> Result<PackInitResult, String> {
    fs::create_dir_all(dir.join("mods")).map_err(|e| format!("create mods dir: {e}"))?;
    fs::create_dir_all(dir.join("config")).map_err(|e| format!("create config dir: {e}"))?;

    let id = pack_id.unwrap_or("my-pack");
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) || id.is_empty() || id.len() > 64 {
        return Err("pack id must be 1 to 64 characters of letters, digits, dot, dash, underscore".into());
    }

    let key_path = dir.join("author.key");
    let signing_key = if key_path.exists() {
        let bytes = fs::read(&key_path).map_err(|e| format!("read existing author.key: {e}"))?;
        if bytes.len() != 32 {
            return Err("author.key must be exactly 32 bytes".into());
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);
        SigningKey::from_bytes(&raw)
    } else {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|e| format!("generate random key: {e}"))?;
        fs::write(&key_path, &raw).map_err(|e| format!("write author.key: {e}"))?;
        SigningKey::from_bytes(&raw)
    };

    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pubkey_b64 = URL_SAFE_NO_PAD.encode(pubkey_bytes);

    let config_path = dir.join("config").join("mcmesh-common.toml");
    let name_comment = pack_name.map_or(String::new(), |n| format!("# Community Pack: {n}\n"));
    let toml_content = format!(
        "{name_comment}packId = \"{id}\"\npackVersion = \"1.0.0\"\npackAuthorKey = \"{pubkey_b64}\"\npackAutoUpdate = true\n"
    );
    fs::write(&config_path, toml_content).map_err(|e| format!("write mcmesh-common.toml: {e}"))?;

    Ok(PackInitResult {
        pack_id: id.to_string(),
        public_key: pubkey_b64,
        config_path,
        key_path,
    })
}

/// Hashes and signs modpack files into a verified manifest.json and manifest.json.sig.
pub fn sign(
    dir: &Path,
    pack_id: Option<&str>,
    version: Option<&str>,
    out_dir: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<PackSignResult, String> {
    let id = pack_id.unwrap_or("my-pack");
    let ver = version.unwrap_or("1.0.0");

    if !id.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) || id.is_empty() || id.len() > 64 {
        return Err("pack id must be 1 to 64 characters of letters, digits, dot, dash, underscore".into());
    }

    let default_key = dir.join("author.key");
    let key_file = key_path.unwrap_or(&default_key);
    if !key_file.exists() {
        return Err(format!("Author key not found at {}. Run 'gatewayd pack init' first.", key_file.display()));
    }
    let key_bytes = fs::read(key_file).map_err(|e| format!("read key file: {e}"))?;
    if key_bytes.len() != 32 {
        return Err("author.key must be 32 bytes".into());
    }
    let mut raw_key = [0u8; 32];
    raw_key.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&raw_key);
    let pubkey = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());

    let default_out = dir.join("dist");
    let out = out_dir.unwrap_or(&default_out);
    fs::create_dir_all(out.join("files")).map_err(|e| format!("create dist files dir: {e}"))?;

    let mut entries = Vec::new();
    let mut total_bytes = 0u64;

    for folder in &["mods", "config"] {
        let base = dir.join(folder);
        if !base.is_dir() {
            continue;
        }
        collect_files(&base, dir, &mut entries, &mut total_bytes, out)?;
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = json!({
        "pack": id,
        "version": ver,
        "files": entries,
        "remove": []
    });

    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| format!("serialize manifest: {e}"))?;
    if manifest_bytes.len() > MANIFEST_MAX_BYTES {
        return Err(format!("Manifest size exceeds limit ({} > {})", manifest_bytes.len(), MANIFEST_MAX_BYTES));
    }

    let mut message = Vec::with_capacity(DOMAIN.len() + manifest_bytes.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&manifest_bytes);

    let signature = signing_key.sign(&message);
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let manifest_path = out.join("manifest.json");
    let sig_path = out.join("manifest.json.sig");

    fs::write(&manifest_path, &manifest_bytes).map_err(|e| format!("write manifest.json: {e}"))?;
    fs::write(&sig_path, format!("{signature_b64}\n")).map_err(|e| format!("write manifest.json.sig: {e}"))?;

    Ok(PackSignResult {
        pack_id: id.to_string(),
        version: ver.to_string(),
        file_count: entries.len(),
        total_bytes,
        public_key: pubkey,
        manifest_path,
        signature_path: sig_path,
    })
}

fn collect_files(
    current: &Path,
    root: &Path,
    entries: &mut Vec<FileEntry>,
    total_bytes: &mut u64,
    out: &Path,
) -> Result<(), String> {
    for entry in fs::read_dir(current).map_err(|e| format!("read dir {}: {e}", current.display()))? {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') {
            continue;
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("metadata {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("Symbolic links are disallowed in packs: {}", path.display()));
        }

        if meta.is_dir() {
            collect_files(&path, root, entries, total_bytes, out)?;
        } else if meta.is_file() {
            let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");

            let size = meta.len();
            *total_bytes += size;

            let sha = hash_file(&path)?;

            // Copy to out/files/<rel>
            let dest = out.join("files").join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("create dest parent {}: {e}", parent.display()))?;
            }
            fs::copy(&path, &dest).map_err(|e| format!("copy {} to {}: {e}", path.display(), dest.display()))?;

            entries.push(FileEntry {
                path: rel_str.clone(),
                sha256: sha,
                size,
                url: format!("files/{rel_str}"),
            });
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Validates manifest syntax, cryptographic signature, file checksums, and mod compatibility.
pub fn check(path: &Path) -> Result<PackCheckResult, String> {
    let manifest_file = if path.is_file() {
        path.to_path_buf()
    } else if path.join("dist").join("manifest.json").exists() {
        path.join("dist").join("manifest.json")
    } else if path.join("manifest.json").exists() {
        path.join("manifest.json")
    } else {
        return Err(format!("manifest.json not found in {}", path.display()));
    };

    let manifest_bytes = fs::read(&manifest_file).map_err(|e| format!("read manifest: {e}"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|e| format!("parse JSON: {e}"))?;

    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    let pack_id = manifest["pack"].as_str().unwrap_or("").to_string();
    let version = manifest["version"].as_str().unwrap_or("").to_string();

    if pack_id.is_empty() || !pack_id.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
        errors.push("Invalid pack identifier format".into());
    }
    if version.is_empty() {
        errors.push("Missing pack version".into());
    }

    let files = manifest["files"].as_array().ok_or("manifest missing 'files' array")?;
    let files_root = manifest_file.parent().map(|p| p.join("files"));

    // Check for client-only rendering mods that commonly break headless servers
    let client_only_mods = [
        "sodium", "rubidium", "embeddium", "oculus", "iris", "colorwheel", "entityculling", "distanthorizons",
    ];

    for f in files {
        let p = f["path"].as_str().unwrap_or("");
        if p.contains("..") || p.starts_with('/') || p.starts_with('\\') {
            errors.push(format!("Unsafe file path in manifest: {p}"));
        }

        let p_lower = p.to_lowercase();
        for m in &client_only_mods {
            if p_lower.contains(m) {
                warnings.push(format!("Client rendering mod detected ({m} in {p}). May cause crashes on headless anchor servers if not marked client-only."));
            }
        }

        if let Some(ref root) = files_root {
            let actual_path = root.join(p);
            if actual_path.exists() {
                if let Ok(actual_hash) = hash_file(&actual_path) {
                    if let Some(expected_hash) = f["sha256"].as_str() {
                        if actual_hash != expected_hash {
                            errors.push(format!("SHA256 mismatch for {p}: expected {expected_hash}, got {actual_hash}"));
                        }
                    }
                }
            }
        }
    }

    // Verify signature if signature file exists
    let sig_file = manifest_file.with_extension("json.sig");
    let mut valid_signature = None;
    if sig_file.exists() {
        if let Ok(sig_str) = fs::read_to_string(&sig_file) {
            let sig_clean = sig_str.trim();
            if let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(sig_clean) {
                if sig_bytes.len() == 64 {
                    // Try to verify with author.key if present
                    let author_key = manifest_file.parent().and_then(|p| p.parent()).map(|p| p.join("author.key"));
                    if let Some(ref key_path) = author_key {
                        if key_path.exists() {
                            if let Ok(kb) = fs::read(key_path) {
                                if kb.len() == 32 {
                                    let mut raw = [0u8; 32];
                                    raw.copy_from_slice(&kb);
                                    let sk = SigningKey::from_bytes(&raw);
                                    let vk = sk.verifying_key();
                                    let mut msg = Vec::with_capacity(DOMAIN.len() + manifest_bytes.len());
                                    msg.extend_from_slice(DOMAIN);
                                    msg.extend_from_slice(&manifest_bytes);
                                    if let Ok(sig_obj) = ed25519_dalek::Signature::from_slice(&sig_bytes) {
                                        let ok = vk.verify_strict(&msg, &sig_obj).is_ok();
                                        valid_signature = Some(ok);
                                        if !ok {
                                            errors.push("Cryptographic signature verification failed!".into());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(PackCheckResult {
        pack_id,
        version,
        file_count: files.len(),
        warnings,
        errors,
        valid_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_init_sign_check_lifecycle() {
        let dir = std::env::temp_dir().join(format!("mcmesh-pack-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        // 1. Init
        let init_res = init(&dir, Some("test-pack"), Some("Test Pack")).unwrap();
        assert_eq!(init_res.pack_id, "test-pack");
        assert!(init_res.config_path.exists());
        assert!(init_res.key_path.exists());

        // Add a mock mod and config
        fs::write(dir.join("mods").join("sample-mod.jar"), b"fake jar content").unwrap();
        fs::write(dir.join("config").join("sample.toml"), b"key = 1").unwrap();

        // 2. Sign
        let sign_res = sign(&dir, Some("test-pack"), Some("1.0.0"), None, None).unwrap();
        assert_eq!(sign_res.file_count, 3); // sample-mod.jar, sample.toml, mcmesh-common.toml
        assert!(sign_res.manifest_path.exists());
        assert!(sign_res.signature_path.exists());

        // 3. Check
        let check_res = check(&dir).unwrap();
        assert_eq!(check_res.pack_id, "test-pack");
        assert_eq!(check_res.version, "1.0.0");
        assert_eq!(check_res.valid_signature, Some(true));
        assert!(check_res.errors.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }
}
