//! Self-host diagnostic doctor for gatewayd.
//! Automated connectivity, storage, and permissions diagnostics with actionable fix suggestions.
use crate::lease::Gateway;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: String, // "pass", "warn", "fail"
    pub message: String,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub status: String, // "ok", "degraded", "error"
    pub checks: Vec<DoctorCheck>,
}

/// Runs full gateway diagnostics suite.
pub fn run_doctor(gw: &Gateway) -> DoctorReport {
    let mut checks = Vec::new();

    // 1. Database check
    checks.push(check_database(gw));

    // 2. CAS Storage check
    let cas_dir = std::env::var("MCMESH_CAS").unwrap_or_else(|_| "cas".into());
    checks.push(check_cas_storage(Path::new(&cas_dir)));

    // 3. Network Ports check
    checks.push(check_ports());

    // 4. Reverse Proxy config check
    checks.push(check_reverse_proxy());

    // 5. Upstream Auth / Internet connectivity
    checks.push(check_upstream_auth());

    let has_fail = checks.iter().any(|c| c.status == "fail");
    let has_warn = checks.iter().any(|c| c.status == "warn");

    let overall_status = if has_fail {
        "error"
    } else if has_warn {
        "degraded"
    } else {
        "ok"
    };

    DoctorReport {
        status: overall_status.to_string(),
        checks,
    }
}

fn check_database(gw: &Gateway) -> DoctorCheck {
    let integrity: Result<String, rusqlite::Error> = gw
        .db()
        .query_row("PRAGMA quick_check;", [], |r| r.get(0));

    let table_count: Result<i64, rusqlite::Error> = gw
        .db()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table';",
            [],
            |r| r.get(0),
        );

    match (integrity, table_count) {
        (Ok(ref res), Ok(count)) if res == "ok" => DoctorCheck {
            name: "database".to_string(),
            status: "pass".to_string(),
            message: format!("SQLite database connection ok, integrity verified (tables: {count})."),
            fix: None,
        },
        (Ok(ref res), _) => DoctorCheck {
            name: "database".to_string(),
            status: "fail".to_string(),
            message: format!("SQLite database integrity check reported issues: {res}."),
            fix: Some("Run 'gatewayd recover <world> --apply' or restore database from backup.".to_string()),
        },
        (Err(e), _) => DoctorCheck {
            name: "database".to_string(),
            status: "fail".to_string(),
            message: format!("SQLite database query error: {e}."),
            fix: Some("Check file permissions on MCMESH_DB and verify the SQLite file is valid.".to_string()),
        },
    }
}

fn check_cas_storage(cas_path: &Path) -> DoctorCheck {
    if let Err(e) = std::fs::create_dir_all(cas_path) {
        return DoctorCheck {
            name: "cas_storage".to_string(),
            status: "fail".to_string(),
            message: format!("Cannot create CAS directory {}: {e}", cas_path.display()),
            fix: Some("Check filesystem permissions (e.g. chown -R 10001:10001 or chmod 700).".to_string()),
        };
    }

    let probe_file = cas_path.join(".doctor_probe");
    if let Err(e) = std::fs::write(&probe_file, b"mcmesh-doctor-probe") {
        return DoctorCheck {
            name: "cas_storage".to_string(),
            status: "fail".to_string(),
            message: format!("CAS directory {} is not writable: {e}", cas_path.display()),
            fix: Some("Grant write permissions to the gatewayd process on the CAS directory.".to_string()),
        };
    }
    let _ = std::fs::remove_file(&probe_file);

    let count = match std::fs::read_dir(cas_path) {
        Ok(entries) => entries.filter_map(|e| e.ok()).count(),
        Err(_) => 0,
    };

    DoctorCheck {
        name: "cas_storage".to_string(),
        status: "pass".to_string(),
        message: format!("CAS storage directory {} is writable (contains {count} entries).", cas_path.display()),
        fix: None,
    }
}

fn check_ports() -> DoctorCheck {
    let api_addr = std::env::var("MCMESH_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let relay_addr = std::env::var("MCMESH_RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:9000".into());
    let public_addr = std::env::var("MCMESH_PUBLIC_ADDR").unwrap_or_else(|_| "0.0.0.0:25565".into());
    let voice_addr = std::env::var("MCMESH_VOICE_ADDR").unwrap_or_else(|_| "0.0.0.0:24454".into());

    let mut issues = Vec::new();

    // Check TCP listener availability
    for (name, addr_str) in [("API (MCMESH_ADDR)", &api_addr), ("Relay (MCMESH_RELAY_ADDR)", &relay_addr), ("Minecraft (MCMESH_PUBLIC_ADDR)", &public_addr)] {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            match TcpListener::bind(addr) {
                Ok(_) => {}, // successfully bound
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    // Port in use is expected if gatewayd is currently running
                },
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    issues.push(format!("{name} on {addr_str}: permission denied (port < 1024 requires root or CAP_NET_BIND_SERVICE)"));
                },
                Err(e) => {
                    issues.push(format!("{name} on {addr_str}: {e}"));
                }
            }
        }
    }

    // Check UDP voice port
    if let Ok(addr) = voice_addr.parse::<SocketAddr>() {
        match UdpSocket::bind(addr) {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {},
            Err(e) => {
                issues.push(format!("Voice (MCMESH_VOICE_ADDR) on {voice_addr}: {e}"));
            }
        }
    }

    if issues.is_empty() {
        DoctorCheck {
            name: "network_ports".to_string(),
            status: "pass".to_string(),
            message: format!("Configured listener addresses ready: API {api_addr}, Relay {relay_addr}, MC {public_addr}, Voice {voice_addr}."),
            fix: None,
        }
    } else {
        DoctorCheck {
            name: "network_ports".to_string(),
            status: "fail".to_string(),
            message: issues.join("; "),
            fix: Some("Check port conflicts or grant required permissions in your firewall/container configuration.".to_string()),
        }
    }
}

fn check_reverse_proxy() -> DoctorCheck {
    let trust_proxy = std::env::var("MCMESH_TRUST_PROXY").unwrap_or_default();
    if trust_proxy == "1" || trust_proxy.eq_ignore_ascii_case("true") {
        DoctorCheck {
            name: "reverse_proxy".to_string(),
            status: "pass".to_string(),
            message: "MCMESH_TRUST_PROXY is active; client IP is securely derived from X-Forwarded-For.".to_string(),
            fix: None,
        }
    } else {
        DoctorCheck {
            name: "reverse_proxy".to_string(),
            status: "pass".to_string(),
            message: "Direct IP listener mode (MCMESH_TRUST_PROXY=0). If operating behind Caddy/Nginx, enable MCMESH_TRUST_PROXY=1 for accurate rate limiting.".to_string(),
            fix: None,
        }
    }
}

fn check_upstream_auth() -> DoctorCheck {
    let target = "sessionserver.mojang.com:443";
    let reachable = target
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok());

    if reachable.is_some() {
        DoctorCheck {
            name: "upstream_auth".to_string(),
            status: "pass".to_string(),
            message: "Mojang session servers reachable (sessionserver.mojang.com:443 connected).".to_string(),
            fix: None,
        }
    } else {
        DoctorCheck {
            name: "upstream_auth".to_string(),
            status: "warn".to_string(),
            message: "Could not reach sessionserver.mojang.com:443 within 2 seconds. Mojang online player auth may fail.".to_string(),
            fix: Some("Verify outbound internet connectivity and DNS resolution on the gateway host.".to_string()),
        }
    }
}

/// Formats and prints the doctor report to stdout in a terminal-friendly view.
/// Returns true if all checks passed or warned (no fatal failures), false otherwise.
pub fn print_cli_report(report: &DoctorReport) -> bool {
    println!("\n======================================================================");
    println!("  MCMesh Gateway Diagnostic Doctor");
    println!("======================================================================");

    for check in &report.checks {
        let tag = match check.status.as_str() {
            "pass" => "\x1b[1;32m[PASS]\x1b[0m",
            "warn" => "\x1b[1;33m[WARN]\x1b[0m",
            _ => "\x1b[1;31m[FAIL]\x1b[0m",
        };
        println!(" {tag} {}: {}", check.name, check.message);
        if let Some(ref fix) = check.fix {
            println!("        \x1b[1;36mFix suggestion:\x1b[0m {fix}");
        }
    }

    println!("----------------------------------------------------------------------");
    let ok = report.status != "error";
    if ok {
        println!(" Verdict: \x1b[1;32mHEALTHY\x1b[0m (status: {})", report.status);
    } else {
        println!(" Verdict: \x1b[1;31mISSUES DETECTED\x1b[0m (status: {})", report.status);
    }
    println!("======================================================================\n");
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cas::Cas;
    use crate::lease::Gateway;
    use rusqlite::Connection;

    #[test]
    fn doctor_runs_and_verifies_healthy_gateway() {
        let dir = std::env::temp_dir().join(format!("mcmesh-doc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cas = Cas::open(&dir).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        let gw = Gateway::open(conn, cas, 0).unwrap();
        gw.ops_init().unwrap();

        std::env::set_var("MCMESH_CAS", dir.to_str().unwrap());
        let report = run_doctor(&gw);
        assert!(!report.checks.is_empty());
        assert!(report.checks.iter().any(|c| c.name == "database" && c.status == "pass"));
        assert!(report.checks.iter().any(|c| c.name == "cas_storage" && c.status == "pass"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
