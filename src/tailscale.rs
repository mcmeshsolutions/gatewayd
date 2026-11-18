//! Native Tailscale Tailnet Integration (`MCMESH_TAILSCALE=1`).
//! Enables zero-port-forwarding CGNAT mesh connectivity across private Tailscale tailnets,
//! automatic MagicDNS / `100.64.0.0/10` endpoint discovery, and Tailscale Funnel / Serve support.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleConfig {
    pub enabled: bool,
    pub hostname: String,
    pub auth_key_configured: bool,
    pub state_dir: String,
    pub funnel_enabled: bool,
}

impl TailscaleConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("MCMESH_TAILSCALE")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let hostname = std::env::var("MCMESH_TS_HOSTNAME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "mcmesh-gateway".to_string());
        let auth_key_configured = std::env::var("MCMESH_TS_AUTHKEY")
            .or_else(|_| std::env::var("TS_AUTHKEY"))
            .is_ok_and(|v| !v.trim().is_empty());
        let state_dir = std::env::var("MCMESH_TS_STATE_DIR")
            .unwrap_or_else(|_| "/data/tailscale".to_string());
        let funnel_enabled = std::env::var("MCMESH_TS_FUNNEL")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

        Self {
            enabled,
            hostname,
            auth_key_configured,
            state_dir,
            funnel_enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleStatus {
    pub enabled: bool,
    pub online: bool,
    pub hostname: String,
    pub tailnet_ip: Option<String>,
    pub tailnet_ipv6: Option<String>,
    pub magic_dns: Option<String>,
    pub advertise_addr: Option<String>,
    pub peers_online: usize,
    pub funnel_enabled: bool,
    pub zero_port_cgnat: bool,
}

/// Checks if an IP address belongs to the Tailscale WireGuard range:
/// - IPv4 `100.64.0.0/10` (`100.64.0.0` .. `100.127.255.255`)
/// - IPv6 `fd7a:115c:a1e0::/48`
pub fn is_tailnet_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (octets[1] & 0b1100_0000) == 64
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            segs[0] == 0xfd7a && segs[1] == 0x115c && segs[2] == 0xa1e0
        }
    }
}

/// Parses `tailscale status --json` output into `(dns_name, ipv4, ipv6, online_peers, running)`.
pub fn parse_tailscale_status_json(
    raw: &str,
) -> Option<(Option<String>, Option<String>, Option<String>, usize, bool)> {
    let val: serde_json::Value = serde_json::from_str(raw).ok()?;
    let running = val
        .get("BackendState")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "Running");

    let self_node = val.get("Self")?;
    let dns_name = self_node
        .get("DNSName")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty());

    let mut ipv4 = None;
    let mut ipv6 = None;
    if let Some(ips) = self_node.get("TailscaleIPs").and_then(|v| v.as_array()) {
        for ip_val in ips {
            if let Some(s) = ip_val.as_str() {
                if s.contains(':') && ipv6.is_none() {
                    ipv6 = Some(s.to_string());
                } else if s.contains('.') && ipv4.is_none() {
                    ipv4 = Some(s.to_string());
                }
            }
        }
    }

    let mut peers_online = 0usize;
    if let Some(peers) = val.get("Peer").and_then(|v| v.as_object()) {
        for (_, p) in peers {
            if p.get("Online").and_then(|v| v.as_bool()).unwrap_or(false) {
                peers_online += 1;
            }
        }
    }

    Some((dns_name, ipv4, ipv6, peers_online, running))
}

pub struct TailscaleManager {
    state: RwLock<TailscaleStatus>,
}

impl TailscaleManager {
    pub fn from_env() -> Self {
        let cfg = TailscaleConfig::from_env();
        let mut status = TailscaleStatus {
            enabled: cfg.enabled,
            online: false,
            hostname: cfg.hostname.clone(),
            tailnet_ip: std::env::var("MCMESH_TS_IP").ok().filter(|s| !s.is_empty()),
            tailnet_ipv6: None,
            magic_dns: std::env::var("MCMESH_TS_MAGICDNS").ok().filter(|s| !s.is_empty()),
            advertise_addr: None,
            peers_online: 0,
            funnel_enabled: cfg.funnel_enabled,
            zero_port_cgnat: true,
        };

        if cfg.enabled {
            Self::probe_cli(&mut status);
            Self::recompute_advertise(&mut status);
        }

        Self {
            state: RwLock::new(status),
        }
    }

    fn probe_cli(status: &mut TailscaleStatus) {
        if let Ok(out) = Command::new("tailscale").args(["status", "--json"]).output() {
            if out.status.success() {
                if let Ok(txt) = String::from_utf8(out.stdout) {
                    if let Some((dns, v4, v6, peers, running)) = parse_tailscale_status_json(&txt) {
                        status.online = running;
                        if dns.is_some() {
                            status.magic_dns = dns;
                        }
                        if v4.is_some() {
                            status.tailnet_ip = v4;
                        }
                        if v6.is_some() {
                            status.tailnet_ipv6 = v6;
                        }
                        status.peers_online = peers;
                    }
                }
            }
        }
        if status.tailnet_ip.is_some() || status.magic_dns.is_some() {
            status.online = true;
        }
    }

    fn recompute_advertise(status: &mut TailscaleStatus) {
        let port = std::env::var("MCMESH_PUBLIC_ADDR")
            .ok()
            .and_then(|a| a.rsplit_once(':').map(|(_, p)| p.to_string()))
            .unwrap_or_else(|| "25565".to_string());

        if let Some(ref dns) = status.magic_dns {
            status.advertise_addr = Some(format!("{dns}:{port}"));
        } else if let Some(ref ip) = status.tailnet_ip {
            status.advertise_addr = Some(format!("{ip}:{port}"));
        }
    }

    pub fn status(&self) -> TailscaleStatus {
        self.state.read().unwrap().clone()
    }

    pub fn up(
        &self,
        hostname: Option<String>,
        magic_dns: Option<String>,
        tailnet_ip: Option<String>,
        funnel: Option<bool>,
    ) -> TailscaleStatus {
        let mut st = self.state.write().unwrap();
        st.enabled = true;
        Self::probe_cli(&mut st);
        if let Some(h) = hostname.filter(|s| !s.trim().is_empty()) {
            st.hostname = h.trim().to_string();
        }
        if let Some(d) = magic_dns.filter(|s| !s.trim().is_empty()) {
            st.magic_dns = Some(d.trim().trim_end_matches('.').to_string());
        }
        if let Some(ip) = tailnet_ip.filter(|s| !s.trim().is_empty()) {
            st.tailnet_ip = Some(ip.trim().to_string());
        }
        if let Some(f) = funnel {
            st.funnel_enabled = f;
        }
        st.online = true;
        Self::recompute_advertise(&mut st);
        st.clone()
    }
}
