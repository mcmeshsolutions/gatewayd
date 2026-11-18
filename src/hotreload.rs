//! Zero-Downtime Hot Reload & Rolling Gateway Upgrades:
//! Unix socket handoff with SO_REUSEPORT and Virtual Limbo buffering.

use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpListener;

/// Binds a TCP listener with SO_REUSEADDR and SO_REUSEPORT (on Unix/Linux).
/// Allows multiple gateway processes to bind concurrently during rolling upgrades.
pub fn bind_reuseport(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

#[derive(Debug, Clone)]
pub struct LimboPacket {
    pub received_at: Instant,
    pub data: Vec<u8>,
}

/// Virtual Limbo buffering state:
/// Keeps guest connections alive and buffers packets in memory while a gateway
/// reloads or a host handover is taking place, preventing player disconnects.
pub struct VirtualLimbo {
    is_active: AtomicBool,
    drain_mode: AtomicBool,
    deadline_epoch_s: AtomicU64,
    /// Per-stream packet buffer: stream_id -> queue of packets
    streams: Mutex<HashMap<u32, VecDeque<LimboPacket>>>,
    total_buffered_bytes: AtomicU64,
    max_stream_buffer_bytes: usize,
}

impl Default for VirtualLimbo {
    fn default() -> Self {
        Self {
            is_active: AtomicBool::new(false),
            drain_mode: AtomicBool::new(false),
            deadline_epoch_s: AtomicU64::new(0),
            streams: Mutex::new(HashMap::new()),
            total_buffered_bytes: AtomicU64::new(0),
            max_stream_buffer_bytes: 2 * 1024 * 1024, // 2MB cap per guest stream
        }
    }
}

impl VirtualLimbo {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Engages limbo buffering for up to `timeout_s` seconds.
    pub fn engage(&self, timeout_s: u64) {
        let deadline = crate::lease::wall_s() as u64 + timeout_s;
        self.deadline_epoch_s.store(deadline, Ordering::Release);
        self.is_active.store(true, Ordering::Release);
    }

    /// Checks if limbo buffering is currently engaged and unexpired.
    pub fn is_limbo_active(&self) -> bool {
        if !self.is_active.load(Ordering::Acquire) {
            return false;
        }
        let now = crate::lease::wall_s() as u64;
        let deadline = self.deadline_epoch_s.load(Ordering::Acquire);
        if now > deadline {
            self.is_active.store(false, Ordering::Release);
            false
        } else {
            true
        }
    }

    /// Sets drain mode (old process winding down, not accepting new sessions).
    pub fn set_drain(&self, drain: bool) {
        self.drain_mode.store(drain, Ordering::Release);
    }

    pub fn is_draining(&self) -> bool {
        self.drain_mode.load(Ordering::Acquire)
    }

    /// Buffers a packet for a guest stream while in limbo.
    /// Returns true if buffered, false if buffer full or not active.
    pub fn buffer_packet(&self, stream_id: u32, data: Vec<u8>) -> bool {
        if !self.is_limbo_active() {
            return false;
        }
        let len = data.len();
        let mut map = self.streams.lock().unwrap();
        let queue = map.entry(stream_id).or_default();
        let current_bytes: usize = queue.iter().map(|p| p.data.len()).sum();
        if current_bytes + len > self.max_stream_buffer_bytes {
            return false;
        }
        queue.push_back(LimboPacket {
            received_at: Instant::now(),
            data,
        });
        self.total_buffered_bytes.fetch_add(len as u64, Ordering::Relaxed);
        true
    }

    /// Drains all buffered packets for a stream once a host tunnel re-attaches.
    pub fn drain_stream(&self, stream_id: u32) -> Vec<Vec<u8>> {
        let mut map = self.streams.lock().unwrap();
        if let Some(queue) = map.remove(&stream_id) {
            let drained: Vec<Vec<u8>> = queue.into_iter().map(|p| p.data).collect();
            let freed: u64 = drained.iter().map(|d| d.len() as u64).sum();
            self.total_buffered_bytes.fetch_sub(freed, Ordering::Relaxed);
            drained
        } else {
            Vec::new()
        }
    }

    /// Clears and resets all limbo buffers.
    pub fn clear(&self) {
        self.is_active.store(false, Ordering::Release);
        let mut map = self.streams.lock().unwrap();
        map.clear();
        self.total_buffered_bytes.store(0, Ordering::Relaxed);
    }

    pub fn stats(&self) -> VirtualLimboStats {
        let map = self.streams.lock().unwrap();
        let stream_count = map.len();
        let packet_count: usize = map.values().map(|q| q.len()).sum();
        let bytes = self.total_buffered_bytes.load(Ordering::Relaxed);
        let active = self.is_limbo_active();
        let draining = self.is_draining();
        let deadline = self.deadline_epoch_s.load(Ordering::Acquire);
        VirtualLimboStats {
            active,
            draining,
            deadline_epoch_s: deadline,
            buffered_streams: stream_count,
            buffered_packets: packet_count,
            buffered_bytes: bytes,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VirtualLimboStats {
    pub active: bool,
    pub draining: bool,
    pub deadline_epoch_s: u64,
    pub buffered_streams: usize,
    pub buffered_packets: usize,
    pub buffered_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limbo_lifecycle_and_buffering() {
        let limbo = VirtualLimbo::new();
        assert!(!limbo.is_limbo_active());

        // Engage for 60 seconds
        limbo.engage(60);
        assert!(limbo.is_limbo_active());

        // Buffer packets for stream 1 and 2
        assert!(limbo.buffer_packet(1, b"packet-1a".to_vec()));
        assert!(limbo.buffer_packet(1, b"packet-1b".to_vec()));
        assert!(limbo.buffer_packet(2, b"packet-2a".to_vec()));

        let stats = limbo.stats();
        assert_eq!(stats.buffered_streams, 2);
        assert_eq!(stats.buffered_packets, 3);
        assert!(stats.buffered_bytes > 0);

        // Drain stream 1
        let drained1 = limbo.drain_stream(1);
        assert_eq!(drained1, vec![b"packet-1a".to_vec(), b"packet-1b".to_vec()]);

        let stats2 = limbo.stats();
        assert_eq!(stats2.buffered_streams, 1);
        assert_eq!(stats2.buffered_packets, 1);

        // Clear resets all
        limbo.clear();
        assert!(!limbo.is_limbo_active());
        assert_eq!(limbo.stats().buffered_packets, 0);
    }
}
