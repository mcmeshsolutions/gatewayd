//! PROXY protocol v1 and v2 headers, so a forwarder in front of the relay (haproxy, nginx stream, a VPS) can pass the real
//! client address. Only enable it when the listener is reachable through that forwarder alone: anyone who can connect
//! directly could otherwise claim any address.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

const SIG_V2: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const MAX_V1: usize = 107;

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Reads exactly one header from the start of a connection. Ok(None) means "use the socket address" (LOCAL or UNKNOWN).
pub async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
    let mut first = [0u8; 12];
    r.read_exact(&mut first[..6]).await?;
    if &first[..6] == b"PROXY " {
        let mut line = Vec::with_capacity(MAX_V1);
        loop {
            let b = r.read_u8().await?;
            if b == b'\n' {
                break;
            }
            line.push(b);
            if line.len() + 6 > MAX_V1 {
                return Err(bad("proxy v1 header too long"));
            }
        }
        if line.last() != Some(&b'\r') {
            return Err(bad("proxy v1 header not terminated"));
        }
        line.pop();
        return parse_v1(std::str::from_utf8(&line).map_err(|_| bad("proxy v1 not text"))?);
    }
    r.read_exact(&mut first[6..]).await?;
    if first != SIG_V2 {
        return Err(bad("not a proxy header"));
    }
    let mut h = [0u8; 4];
    r.read_exact(&mut h).await?;
    let len = u16::from_be_bytes([h[2], h[3]]) as usize;
    if len > 512 {
        return Err(bad("proxy v2 header too long"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    parse_v2(h[0], h[1], &body)
}

fn parse_v1(rest: &str) -> io::Result<Option<SocketAddr>> {
    let p: Vec<&str> = rest.split(' ').collect();
    match p.as_slice() {
        ["UNKNOWN", ..] => Ok(None),
        [proto @ ("TCP4" | "TCP6"), src, _dst, sport, _dport] => {
            let ip: IpAddr = src.parse().map_err(|_| bad("proxy v1 bad address"))?;
            if (*proto == "TCP4") != ip.is_ipv4() {
                return Err(bad("proxy v1 family mismatch"));
            }
            Ok(Some(SocketAddr::new(ip, sport.parse().map_err(|_| bad("proxy v1 bad port"))?)))
        }
        _ => Err(bad("proxy v1 malformed")),
    }
}

fn parse_v2(ver_cmd: u8, fam_proto: u8, body: &[u8]) -> io::Result<Option<SocketAddr>> {
    if ver_cmd >> 4 != 2 {
        return Err(bad("proxy v2 bad version"));
    }
    match ver_cmd & 0x0f {
        0 => return Ok(None),
        1 => {}
        _ => return Err(bad("proxy v2 bad command")),
    }
    match (fam_proto, body.len()) {
        (0x11, n) if n >= 12 => Ok(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(body[0], body[1], body[2], body[3])), u16::from_be_bytes([body[8], body[9]])))),
        (0x21, n) if n >= 36 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&body[..16]);
            Ok(Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), u16::from_be_bytes([body[32], body[33]]))))
        }
        (0x00, _) => Ok(None),
        _ => Err(bad("proxy v2 unsupported family")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read(bytes: &[u8]) -> (io::Result<Option<SocketAddr>>, Vec<u8>) {
        let mut r = bytes;
        let res = read_header(&mut r).await;
        (res, r.to_vec())
    }

    #[tokio::test]
    async fn v1_tcp4_and_tcp6_leave_the_payload_untouched() {
        let (r, rest) = read(b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 25565\r\n\x10\x00hello").await;
        assert_eq!(r.unwrap(), Some("203.0.113.7:51234".parse().unwrap()));
        assert_eq!(rest, b"\x10\x00hello");
        let (r, _) = read(b"PROXY TCP6 2001:db8::1 2001:db8::2 4000 25565\r\n").await;
        assert_eq!(r.unwrap(), Some("[2001:db8::1]:4000".parse().unwrap()));
    }

    #[tokio::test]
    async fn v1_unknown_means_use_the_socket_address() {
        assert_eq!(read(b"PROXY UNKNOWN\r\nabc").await.0.unwrap(), None);
    }

    #[tokio::test]
    async fn v1_garbage_is_refused() {
        for bad in [
            &b"PROXY TCP4 not-an-ip 10.0.0.1 1 2\r\n"[..],
            b"PROXY TCP4 2001:db8::1 10.0.0.1 1 2\r\n",
            b"PROXY TCP4 1.2.3.4 10.0.0.1 99999 2\r\n",
            b"PROXY TCP4 1.2.3.4 10.0.0.1 1\r\n",
            b"PROXY TCP4 1.2.3.4 10.0.0.1 1 2\n",
            b"GET / HTTP/1.1\r\n\r\n",
        ] {
            assert!(read(bad).await.0.is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let long = format!("PROXY TCP4 {}\r\n", "1".repeat(200));
        assert!(read(long.as_bytes()).await.0.is_err());
    }

    fn v2(cmd: u8, fam: u8, body: &[u8]) -> Vec<u8> {
        let mut v = SIG_V2.to_vec();
        v.extend([0x20 | cmd, fam]);
        v.extend((body.len() as u16).to_be_bytes());
        v.extend(body);
        v
    }

    #[tokio::test]
    async fn v2_tcp4_tcp6_and_local() {
        let mut b = vec![198, 51, 100, 9, 10, 0, 0, 1];
        b.extend(40000u16.to_be_bytes());
        b.extend(25565u16.to_be_bytes());
        let mut msg = v2(1, 0x11, &b);
        msg.extend(b"payload");
        let (r, rest) = read(&msg).await;
        assert_eq!(r.unwrap(), Some("198.51.100.9:40000".parse().unwrap()));
        assert_eq!(rest, b"payload");

        let mut b6 = "2001:db8::5".parse::<Ipv6Addr>().unwrap().octets().to_vec();
        b6.extend([0u8; 16]);
        b6.extend(777u16.to_be_bytes());
        b6.extend(25565u16.to_be_bytes());
        assert_eq!(read(&v2(1, 0x21, &b6)).await.0.unwrap(), Some("[2001:db8::5]:777".parse().unwrap()));
        assert_eq!(read(&v2(0, 0x00, &[])).await.0.unwrap(), None);
    }

    #[tokio::test]
    async fn v2_truncated_or_bogus_is_refused() {
        assert!(read(&v2(1, 0x11, &[1, 2, 3])).await.0.is_err());
        assert!(read(&v2(2, 0x11, &[0; 12])).await.0.is_err());
        assert!(read(&v2(1, 0x31, &[0; 12])).await.0.is_err());
        let mut m = SIG_V2.to_vec();
        m.extend([0x21, 0x11, 0xff, 0xff]);
        assert!(read(&m).await.0.is_err(), "oversized length");
        assert!(read(&SIG_V2[..8]).await.0.is_err());
    }
}
