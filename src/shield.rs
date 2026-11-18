//! Security Shield & Automated Threat Jail.
//! Provides Fail2Ban-style sliding-window failed auth tracking, automated IP blacklisting,
//! live failed authentication logs, and 1-click IP / CIDR / token key bans.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LOG_ENTRIES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    pub max_failures: u32,
    pub findtime_s: u64,
    pub bantime_s: u64,
}

impl ShieldConfig {
    pub fn from_env() -> Self {
        let max_failures = std::env::var("MCMESH_SHIELD_MAX_FAILURES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v >= 1)
            .unwrap_or(10);

        let findtime_s = std::env::var("MCMESH_SHIELD_FINDTIME_S")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= 5)
            .unwrap_or(300);

        let bantime_s = std::env::var("MCMESH_SHIELD_BANTIME_S")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v >= 5)
            .unwrap_or(900);

        Self {
            max_failures,
            findtime_s,
            bantime_s,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBan {
    pub id: String,
    pub target: String,
    pub kind: String, // "ip" | "cidr" | "key"
    pub reason: String,
    pub created_by: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedAuthEvent {
    pub ts: u64,
    pub ip: String,
    pub path: String,
    pub detail: String,
    pub auto_jailed: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum CidrNet {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl CidrNet {
    pub fn parse(s: &str) -> Option<Self> {
        let (ip_part, prefix_part) = s.split_once('/')?;
        let ip: IpAddr = ip_part.trim().parse().ok()?;
        let prefix: u32 = prefix_part.trim().parse().ok()?;

        match ip {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return None;
                }
                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                let net = u32::from(v4) & mask;
                Some(CidrNet::V4 { net, mask })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return None;
                }
                let mask = if prefix == 0 { 0 } else { !0u128 << (128 - prefix) };
                let net = u128::from(v6) & mask;
                Some(CidrNet::V6 { net, mask })
            }
        }
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (*self, addr) {
            (CidrNet::V4 { net, mask }, IpAddr::V4(v4)) => (u32::from(v4) & mask) == net,
            (CidrNet::V6 { net, mask }, IpAddr::V6(v6)) => (u128::from(v6) & mask) == net,
            _ => false,
        }
    }
}

pub struct SecurityShield {
    config: ShieldConfig,
    bans: RwLock<Vec<(SecurityBan, Option<CidrNet>)>>,
    failures: RwLock<HashMap<String, Vec<u64>>>,
    failed_log: RwLock<VecDeque<FailedAuthEvent>>,
    total_blocked: AtomicU64,
    seq: AtomicU64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl SecurityShield {
    pub fn from_env() -> Self {
        Self::new(ShieldConfig::from_env())
    }

    pub fn new(config: ShieldConfig) -> Self {
        Self {
            config,
            bans: RwLock::new(Vec::new()),
            failures: RwLock::new(HashMap::new()),
            failed_log: RwLock::new(VecDeque::new()),
            total_blocked: AtomicU64::new(0),
            seq: AtomicU64::new(1),
        }
    }

    pub fn config(&self) -> &ShieldConfig {
        &self.config
    }

    pub fn total_blocked(&self) -> u64 {
        self.total_blocked.load(Ordering::Relaxed)
    }

    pub fn load_from_db(&self, conn: &rusqlite::Connection) {
        let now = unix_now() as i64;
        let _ = conn.execute(
            "DELETE FROM security_bans WHERE expires_at IS NOT NULL AND expires_at <= ?",
            [now],
        );

        let Ok(mut stmt) = conn.prepare(
            "SELECT id, target, kind, reason, created_by, created_at, expires_at FROM security_bans ORDER BY created_at DESC",
        ) else {
            return;
        };

        let Ok(rows) = stmt.query_map([], |r| {
            Ok(SecurityBan {
                id: r.get(0)?,
                target: r.get::<_, String>(1)?,
                kind: r.get::<_, String>(2)?,
                reason: r.get::<_, String>(3)?,
                created_by: r.get::<_, String>(4)?,
                created_at: r.get::<_, i64>(5)? as u64,
                expires_at: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
            })
        }) else {
            return;
        };

        let mut list = self.bans.write().unwrap();
        list.clear();
        for ban in rows.flatten() {
            let cidr = if ban.kind == "cidr" {
                CidrNet::parse(&ban.target)
            } else {
                None
            };
            list.push((ban, cidr));
        }
    }

    /// Checks if the request IP or token key is currently banned.
    /// Returns `Some(SecurityBan)` if blocked.
    pub fn check_request(&self, ip: &str, token_key: Option<&str>, raw_bearer: Option<&str>) -> Option<SecurityBan> {
        let now = unix_now();
        let parsed_ip: Option<IpAddr> = ip.parse().ok();

        let bans = self.bans.read().unwrap();
        for (ban, cidr) in bans.iter() {
            if let Some(exp) = ban.expires_at {
                if now >= exp {
                    continue;
                }
            }
            match ban.kind.as_str() {
                "ip" => {
                    if ban.target == ip {
                        self.total_blocked.fetch_add(1, Ordering::Relaxed);
                        return Some(ban.clone());
                    }
                }
                "cidr" => {
                    if let (Some(net), Some(addr)) = (cidr, parsed_ip) {
                        if net.contains(addr) {
                            self.total_blocked.fetch_add(1, Ordering::Relaxed);
                            return Some(ban.clone());
                        }
                    }
                }
                "key" => {
                    if let Some(tk) = token_key {
                        if ban.target == tk {
                            self.total_blocked.fetch_add(1, Ordering::Relaxed);
                            return Some(ban.clone());
                        }
                    }
                    if let Some(raw) = raw_bearer {
                        if ban.target == raw || raw.starts_with(&ban.target) {
                            self.total_blocked.fetch_add(1, Ordering::Relaxed);
                            return Some(ban.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Records a failed authentication attempt and triggers Fail2Ban auto-jail if threshold is reached.
    pub fn record_failed_auth(&self, ip: &str, path: &str, detail: &str) -> Option<SecurityBan> {
        let now = unix_now();
        let cutoff = now.saturating_sub(self.config.findtime_s);

        let mut jailed_ban: Option<SecurityBan> = None;

        if !ip.is_empty() && ip != "unknown" {
            let mut map = self.failures.write().unwrap();
            let entry = map.entry(ip.to_string()).or_default();
            entry.retain(|&ts| ts >= cutoff);
            entry.push(now);

            if entry.len() >= self.config.max_failures as usize {
                entry.clear();
                drop(map);

                let n = self.seq.fetch_add(1, Ordering::Relaxed);
                let ban = SecurityBan {
                    id: format!("sb_jail_{now}_{n}"),
                    target: ip.to_string(),
                    kind: "ip".to_string(),
                    reason: format!(
                        "Fail2Ban auto-jail: {} failed auth attempts within {}s",
                        self.config.max_failures, self.config.findtime_s
                    ),
                    created_by: "fail2ban".to_string(),
                    created_at: now,
                    expires_at: Some(now + self.config.bantime_s),
                };

                let mut bans = self.bans.write().unwrap();
                bans.retain(|(b, _)| !(b.kind == "ip" && b.target == ip));
                bans.insert(0, (ban.clone(), None));
                jailed_ban = Some(ban);
            }
        }

        let mut log = self.failed_log.write().unwrap();
        if log.len() >= MAX_LOG_ENTRIES {
            log.pop_back();
        }
        log.push_front(FailedAuthEvent {
            ts: now,
            ip: ip.to_string(),
            path: path.to_string(),
            detail: detail.to_string(),
            auto_jailed: jailed_ban.is_some(),
        });

        jailed_ban
    }

    pub fn add_ban(
        &self,
        target: &str,
        kind: &str,
        reason: &str,
        created_by: &str,
        duration_s: Option<u64>,
    ) -> Result<SecurityBan, &'static str> {
        let target = target.trim();
        if target.is_empty() || target.len() > 128 {
            return Err("BAD_TARGET");
        }

        let cidr = match kind {
            "ip" => {
                if target.parse::<IpAddr>().is_err() {
                    return Err("BAD_IP");
                }
                None
            }
            "cidr" => {
                let Some(c) = CidrNet::parse(target) else {
                    return Err("BAD_CIDR");
                };
                Some(c)
            }
            "key" => None,
            _ => return Err("BAD_BAN_KIND"),
        };

        let now = unix_now();
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("sb_{now}_{n}");
        let expires_at = duration_s.filter(|&d| d > 0).map(|d| now + d);

        let ban = SecurityBan {
            id,
            target: target.to_string(),
            kind: kind.to_string(),
            reason: if reason.trim().is_empty() {
                "Manual security block".to_string()
            } else {
                reason.trim().to_string()
            },
            created_by: created_by.to_string(),
            created_at: now,
            expires_at,
        };

        let mut bans = self.bans.write().unwrap();
        bans.retain(|(b, _)| !(b.kind == kind && b.target == target));
        bans.insert(0, (ban.clone(), cidr));

        Ok(ban)
    }

    pub fn remove_ban(&self, id: &str) -> bool {
        let mut bans = self.bans.write().unwrap();
        let before = bans.len();
        bans.retain(|(b, _)| b.id != id);
        bans.len() < before
    }

    pub fn clear_jail(&self) -> usize {
        self.failures.write().unwrap().clear();
        let mut bans = self.bans.write().unwrap();
        let before = bans.len();
        bans.retain(|(b, _)| b.created_by != "fail2ban");
        before - bans.len()
    }

    pub fn active_bans(&self) -> Vec<SecurityBan> {
        let now = unix_now();
        let mut bans = self.bans.write().unwrap();
        bans.retain(|(b, _)| b.expires_at.map_or(true, |exp| now < exp));
        bans.iter().map(|(b, _)| b.clone()).collect()
    }

    pub fn recent_failed_log(&self, limit: usize) -> Vec<FailedAuthEvent> {
        let log = self.failed_log.read().unwrap();
        log.iter().take(limit).cloned().collect()
    }
}
