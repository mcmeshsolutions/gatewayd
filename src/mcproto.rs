//! Just enough of the Minecraft login protocol to gate guests: the handshake and Login Start.

pub const MAX_PACKET: usize = 2048;

pub fn read_varint(b: &[u8]) -> Option<(i32, usize)> {
    let mut v: u32 = 0;
    for i in 0..5 {
        let byte = *b.get(i)?;
        v |= ((byte & 0x7f) as u32) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v as i32, i + 1));
        }
    }
    None
}

pub fn write_varint(out: &mut Vec<u8>, v: i32) {
    let mut v = v as u32;
    loop {
        if v < 0x80 {
            out.push(v as u8);
            return;
        }
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
}

fn read_string(b: &[u8], max: usize) -> Option<(String, usize)> {
    let (len, n) = read_varint(b)?;
    let len = usize::try_from(len).ok().filter(|l| *l <= max)?;
    let s = std::str::from_utf8(b.get(n..n + len)?).ok()?;
    Some((s.to_string(), n + len))
}

/// Outcome of looking at the front of a buffer for one length-prefixed packet.
pub enum Frame<'a> {
    Need,
    Bad,
    Packet { body: &'a [u8], total: usize },
}

pub fn frame(buf: &[u8]) -> Frame<'_> {
    match read_varint(buf) {
        None if buf.len() < 5 => Frame::Need,
        None => Frame::Bad,
        Some((len, n)) => {
            let len = len as usize;
            if len == 0 || len > MAX_PACKET {
                Frame::Bad
            } else if buf.len() < n + len {
                Frame::Need
            } else {
                Frame::Packet { body: &buf[n..n + len], total: n + len }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Handshake {
    pub protocol: i32,
    pub address: String,
    pub port: u16,
    pub next: i32,
}

pub fn parse_handshake(body: &[u8]) -> Option<Handshake> {
    let (id, mut o) = read_varint(body)?;
    if id != 0 {
        return None;
    }
    let (protocol, n) = read_varint(&body[o..])?;
    o += n;
    let (address, n) = read_string(&body[o..], 1024)?;
    o += n;
    let port = u16::from_be_bytes([*body.get(o)?, *body.get(o + 1)?]);
    o += 2;
    let (next, n) = read_varint(&body[o..])?;
    (o + n == body.len()).then_some(Handshake { protocol, address, port, next })
}

pub fn build_handshake(h: &Handshake) -> Vec<u8> {
    let mut body = Vec::new();
    write_varint(&mut body, 0);
    write_varint(&mut body, h.protocol);
    write_varint(&mut body, h.address.len() as i32);
    body.extend_from_slice(h.address.as_bytes());
    body.extend_from_slice(&h.port.to_be_bytes());
    write_varint(&mut body, h.next);
    let mut out = Vec::new();
    write_varint(&mut out, body.len() as i32);
    out.extend_from_slice(&body);
    out
}

/// Login Start: packet id 0, then the player name.
pub fn parse_login_start(body: &[u8]) -> Option<String> {
    let (id, o) = read_varint(body)?;
    if id != 0 {
        return None;
    }
    read_string(&body[o..], 16).map(|(s, _)| s)
}

/// Status-state response packet (id 0) for the server list.
pub fn status_response(protocol: i32, motd: &str) -> Vec<u8> {
    let json = serde_json::json!({
        "version": { "name": "Host loading", "protocol": protocol },
        "players": { "max": 0, "online": 0 },
        "description": { "text": motd },
    })
    .to_string();
    let mut body = Vec::new();
    write_varint(&mut body, 0);
    write_varint(&mut body, json.len() as i32);
    body.extend_from_slice(json.as_bytes());
    let mut out = Vec::new();
    write_varint(&mut out, body.len() as i32);
    out.extend_from_slice(&body);
    out
}

/// Login-state Disconnect packet (id 0) carrying a plain text chat component.
pub fn login_disconnect(msg: &str) -> Vec<u8> {
    let json = format!("{{\"text\":{}}}", serde_json::to_string(msg).unwrap_or_else(|_| "\"\"".into()));
    let mut body = Vec::new();
    write_varint(&mut body, 0);
    write_varint(&mut body, json.len() as i32);
    body.extend_from_slice(json.as_bytes());
    let mut out = Vec::new();
    write_varint(&mut out, body.len() as i32);
    out.extend_from_slice(&body);
    out
}

const TAG: &str = "mesh=";

/// Splits the forge-style NUL separated address into the real host part and our ticket, if present.
pub fn split_ticket(address: &str) -> (String, Option<String>) {
    let mut ticket = None;
    let mut keep = Vec::new();
    for part in address.split('\0') {
        match part.strip_prefix(TAG) {
            Some(t) if ticket.is_none() => ticket = Some(t.to_string()),
            _ => keep.push(part),
        }
    }
    (keep.join("\0"), ticket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnect_packet_roundtrip() {
        let p = login_disconnect("host \"loading\"");
        let Frame::Packet { body, total } = frame(&p) else { panic!() };
        assert_eq!(total, p.len());
        let (id, o) = read_varint(body).unwrap();
        assert_eq!(id, 0);
        let (s, _) = read_string(&body[o..], 32767).unwrap();
        assert_eq!(s, "{\"text\":\"host \\\"loading\\\"\"}");
    }

    #[test]
    fn handshake_roundtrip_and_ticket_split() {
        let h = Handshake { protocol: 767, address: "play.example.org\0mesh=abc\0FORGE".into(), port: 25565, next: 2 };
        let bytes = build_handshake(&h);
        let Frame::Packet { body, total } = frame(&bytes) else { panic!() };
        assert_eq!(total, bytes.len());
        assert_eq!(parse_handshake(body).unwrap(), h);
        let (clean, t) = split_ticket(&h.address);
        assert_eq!((clean.as_str(), t.as_deref()), ("play.example.org\0FORGE", Some("abc")));
        assert!(matches!(frame(&bytes[..bytes.len() - 1]), Frame::Need));
        assert!(matches!(frame(&[0xff, 0xff, 0xff, 0xff, 0xff, 1]), Frame::Bad));
    }

    #[test]
    fn login_start_reads_name() {
        let mut body = vec![0];
        write_varint(&mut body, 3);
        body.extend_from_slice(b"Bob");
        body.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse_login_start(&body).as_deref(), Some("Bob"));
    }
}
