//! One limiter for everything that reaches the gateway: every HTTP route goes through `layer`, the relay asks `allow` directly.
//! Token buckets per (class, key). Defaults are far above what a real host or guest does; `MCMESH_RATE_SCALE` tunes them and
//! `MCMESH_RATE=off` disables the whole thing.

use crate::server::AppState;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Class {
    /// every HTTP request from one address, whatever the token
    Ip,
    /// login and one-shot codes, keyed by address
    Auth,
    /// creating things and log or crash ingestion, keyed by token
    Create,
    /// lease traffic: heartbeat, WAL, blobs, commits
    Bulk,
    Default,
    /// new relay TCP connections per address
    Handshake,
    /// relay UDP datagrams per address
    Udp,
}

/// (refill per second, burst)
fn spec(c: Class) -> (f64, f64) {
    match c {
        Class::Ip => (200.0, 2000.0),
        Class::Auth => (1.0, 60.0),
        Class::Create => (0.5, 20.0),
        Class::Bulk => (100.0, 1000.0),
        Class::Default => (20.0, 100.0),
        Class::Handshake => (5.0, 50.0),
        Class::Udp => (2000.0, 4000.0),
    }
}

const MAX_KEYS: usize = 100_000;
const IDLE_S: f64 = 600.0;
const OVERFLOW_KEY: &str = "~overflow";

struct Bucket {
    tokens: f64,
    at: f64,
}

pub struct Limiter {
    start: Instant,
    enabled: bool,
    scale: f64,
    /// extra factor for the relay classes, for forwarders that hide the real address of UDP traffic
    relay_scale: f64,
    trust_proxy: bool,
    map: Mutex<HashMap<(Class, String), Bucket>>,
}

impl Limiter {
    pub fn from_env() -> Self {
        let scale = std::env::var("MCMESH_RATE_SCALE").ok().and_then(|v| v.parse::<f64>().ok()).filter(|v| *v > 0.0).unwrap_or(1.0);
        let relay_scale = std::env::var("MCMESH_RELAY_RATE_SCALE").ok().and_then(|v| v.parse::<f64>().ok()).filter(|v| *v > 0.0).unwrap_or(1.0);
        Limiter {
            start: Instant::now(),
            enabled: std::env::var("MCMESH_RATE").map_or(true, |v| v != "off"),
            scale,
            relay_scale,
            trust_proxy: std::env::var("MCMESH_TRUST_PROXY").is_ok_and(|v| v == "1"),
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, class: Class, key: &str) -> Result<(), u64> {
        if !self.enabled {
            return Ok(());
        }
        self.allow_at(class, key, self.start.elapsed().as_secs_f64())
    }

    /// Err carries the seconds to wait.
    fn allow_at(&self, class: Class, key: &str, now: f64) -> Result<(), u64> {
        let (rate, burst) = spec(class);
        let factor = self.scale * if matches!(class, Class::Handshake | Class::Udp) { self.relay_scale } else { 1.0 };
        let (rate, burst) = (rate * factor, burst * factor);
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let k = if map.len() >= MAX_KEYS && !map.contains_key(&(class, key.to_string())) { OVERFLOW_KEY } else { key };
        let b = map.entry((class, k.to_string())).or_insert(Bucket { tokens: burst, at: now });
        b.tokens = (b.tokens + (now - b.at).max(0.0) * rate).min(burst);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err((((1.0 - b.tokens) / rate).ceil() as u64).max(1))
        }
    }

    /// Drops buckets that have been idle long enough to be full again anyway.
    pub fn sweep(&self) {
        let now = self.start.elapsed().as_secs_f64();
        self.map.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, b| now - b.at < IDLE_S);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

fn classify(method: &Method, path: &str) -> Class {
    if path.starts_with("/v1/auth/") || path == "/v1/panel/code" || path == "/v1/panel/login" || path == "/v1/invites/redeem" {
        return Class::Auth;
    }
    if path.starts_with("/v1/blobs/") || path.starts_with("/v1/leases/") {
        return Class::Bulk;
    }
    if method == Method::POST && (path == "/v1/worlds" || path == "/v1/logs" || path == "/v1/bandwidth" || path.ends_with("/invite") || path.ends_with("/crash-report")) {
        return Class::Create;
    }
    Class::Default
}

fn token_key(req: &Request, ip: &str) -> String {
    match req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        Some(v) if !v.is_empty() => {
            let mut h = DefaultHasher::new();
            v.hash(&mut h);
            format!("t{:x}", h.finish())
        }
        _ => ip.to_string(),
    }
}

fn client_ip(req: &Request, trust_proxy: bool) -> String {
    if trust_proxy {
        let fwd = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|v| v.rsplit(',').next()).map(str::trim);
        let real = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()).map(str::trim);
        if let Some(ip) = fwd.or(real).filter(|s| s.parse::<IpAddr>().is_ok()) {
            return ip.to_string();
        }
    }
    req.extensions().get::<ConnectInfo<SocketAddr>>().map_or_else(|| "unknown".into(), |c| c.0.ip().to_string())
}

fn refuse(retry: u64) -> Response {
    (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, retry.to_string())], Json(json!({ "error": "RATE_LIMITED", "retry_after_s": retry }))).into_response()
}

/// Outermost layer: runs before auth, body parsing and every handler, so no route can opt out.
pub async fn layer(State(s): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let lim = &s.limiter;
    let ip = client_ip(&req, lim.trust_proxy);
    let tkey = token_key(&req, &ip);
    let raw_bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v).trim().to_string());

    if let Some(ban) = s.shield.check_request(&ip, Some(&tkey), raw_bearer.as_deref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "SHIELD_BANNED",
                "reason": ban.reason,
                "ban_id": ban.id,
                "expires_at": ban.expires_at,
            })),
        )
            .into_response();
    }

    if lim.enabled {
        if let Err(retry) = lim.allow(Class::Ip, &ip) {
            return refuse(retry);
        }
        let class = classify(req.method(), req.uri().path());
        let key = if class == Class::Auth { ip.clone() } else { tkey };
        if let Err(retry) = lim.allow(class, &key) {
            return refuse(retry);
        }
    }

    let path = req.uri().path().to_string();
    let resp = next.run(req).await;
    if lim.enabled && resp.status() == StatusCode::UNAUTHORIZED {
        s.shield.record_failed_auth(&ip, &path, "HTTP 401 UNAUTHORIZED");
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limiter {
        Limiter { start: Instant::now(), enabled: true, scale: 1.0, relay_scale: 1.0, trust_proxy: false, map: Mutex::new(HashMap::new()) }
    }

    #[test]
    fn burst_then_refusal_then_refill() {
        let l = lim();
        for _ in 0..60 {
            l.allow_at(Class::Auth, "1.2.3.4", 0.0).unwrap();
        }
        assert_eq!(l.allow_at(Class::Auth, "1.2.3.4", 0.0), Err(1));
        assert_eq!(l.allow_at(Class::Auth, "1.2.3.4", 0.5), Err(1));
        l.allow_at(Class::Auth, "1.2.3.4", 1.0).unwrap();
        assert!(l.allow_at(Class::Auth, "1.2.3.4", 1.0).is_err());
        let slow = Limiter { scale: 0.1, ..lim() };
        for _ in 0..6 {
            slow.allow_at(Class::Auth, "x", 0.0).unwrap();
        }
        assert_eq!(slow.allow_at(Class::Auth, "x", 0.0), Err(10), "scale 0.1 means 0.1 per second");
    }

    #[test]
    fn relay_scale_only_touches_the_relay_classes() {
        let l = Limiter { relay_scale: 10.0, ..lim() };
        for _ in 0..500 {
            l.allow_at(Class::Handshake, "vps", 0.0).unwrap();
        }
        assert!(l.allow_at(Class::Handshake, "vps", 0.0).is_err());
        for _ in 0..60 {
            l.allow_at(Class::Auth, "vps", 0.0).unwrap();
        }
        assert!(l.allow_at(Class::Auth, "vps", 0.0).is_err(), "http classes keep their normal budget");
    }

    #[test]
    fn keys_and_classes_are_independent() {
        let l = lim();
        for _ in 0..60 {
            l.allow_at(Class::Auth, "a", 0.0).unwrap();
        }
        assert!(l.allow_at(Class::Auth, "a", 0.0).is_err());
        l.allow_at(Class::Auth, "b", 0.0).unwrap();
        l.allow_at(Class::Default, "a", 0.0).unwrap();
    }

    #[test]
    fn a_pause_never_banks_more_than_the_burst() {
        let l = lim();
        for _ in 0..100 {
            l.allow_at(Class::Default, "k", 0.0).unwrap();
        }
        assert!(l.allow_at(Class::Default, "k", 0.0).is_err());
        let mut ok = 0;
        while l.allow_at(Class::Default, "k", 10_000.0).is_ok() {
            ok += 1;
        }
        assert_eq!(ok, 100);
    }

    #[test]
    fn normal_host_traffic_is_nowhere_near_the_limits() {
        let l = lim();
        // an autosave: 500 blobs and a wal batch within one second, then heartbeats
        for i in 0..600 {
            l.allow_at(Class::Bulk, "host", i as f64 / 600.0).unwrap();
        }
        for i in 0..60 {
            l.allow_at(Class::Bulk, "host", 1.0 + i as f64).unwrap();
        }
    }

    #[test]
    fn sweep_drops_idle_buckets_and_overflow_is_bounded() {
        let l = lim();
        l.allow_at(Class::Default, "old", 0.0).unwrap();
        assert_eq!(l.len(), 1);
        {
            let mut m = l.map.lock().unwrap();
            for i in 0..MAX_KEYS {
                m.insert((Class::Default, format!("k{i}")), Bucket { tokens: 1.0, at: 1.0e9 });
            }
        }
        l.allow_at(Class::Default, "new-attacker-key", 1.0e9).unwrap();
        assert!(l.len() <= MAX_KEYS + 2, "new keys fall into one shared bucket once the table is full");
    }

    #[test]
    fn classes() {
        let post = Method::POST;
        assert_eq!(classify(&post, "/v1/auth/mojang"), Class::Auth);
        assert_eq!(classify(&post, "/v1/panel/login"), Class::Auth);
        assert_eq!(classify(&Method::PUT, "/v1/blobs/abc"), Class::Bulk);
        assert_eq!(classify(&post, "/v1/leases/l1/heartbeat"), Class::Bulk);
        assert_eq!(classify(&post, "/v1/worlds"), Class::Create);
        assert_eq!(classify(&post, "/v1/logs"), Class::Create);
        assert_eq!(classify(&post, "/v1/bandwidth"), Class::Create, "a megabyte per call is not a heartbeat");
        assert_eq!(classify(&post, "/v1/worlds/w1/invite"), Class::Create);
        assert_eq!(classify(&Method::GET, "/v1/worlds"), Class::Default);
        assert_eq!(classify(&Method::GET, "/metrics"), Class::Default);
    }

    fn req_with(headers: &[(&str, &str)]) -> Request {
        let mut b = Request::builder().uri("/x");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn client_address_comes_from_the_socket_unless_a_proxy_is_trusted() {
        let mut r = req_with(&[("x-forwarded-for", "9.9.9.9")]);
        assert_eq!(client_ip(&r, false), "unknown");
        r.extensions_mut().insert(ConnectInfo("10.1.2.3:555".parse::<SocketAddr>().unwrap()));
        assert_eq!(client_ip(&r, false), "10.1.2.3", "a forwarded header is ignored without MCMESH_TRUST_PROXY");
        assert_eq!(client_ip(&r, true), "9.9.9.9");
    }

    #[test]
    fn the_proxy_appended_address_wins_and_garbage_is_ignored() {
        assert_eq!(client_ip(&req_with(&[("x-forwarded-for", "6.6.6.6, 1.1.1.1")]), true), "1.1.1.1", "the client cannot choose the last hop");
        assert_eq!(client_ip(&req_with(&[("x-forwarded-for", "not-an-ip")]), true), "unknown");
        assert_eq!(client_ip(&req_with(&[("x-real-ip", "2.2.2.2")]), true), "2.2.2.2");
    }

    #[test]
    fn a_bearer_token_is_never_kept_in_clear() {
        let k = token_key(&req_with(&[("authorization", "Bearer secret-token")]), "1.1.1.1");
        assert!(k.starts_with('t') && !k.contains("secret"));
        assert_eq!(token_key(&req_with(&[]), "1.1.1.1"), "1.1.1.1");
    }
}
