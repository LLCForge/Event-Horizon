//! Collector-independent flow sample plus a defensive IPv4 / IPv6 header
//! parser used for sFlow raw packet headers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One sampled flow, already scaled by the sampling rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowSample {
    pub dst: IpAddr,
    pub src: Option<IpAddr>,
    pub protocol: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    pub src_asn: Option<u32>,
    pub packets: u64,
    pub bytes: u64,
}

impl FlowSample {
    pub fn new(dst: IpAddr, packets: u64, bytes: u64) -> Self {
        Self {
            dst,
            src: None,
            protocol: None,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            src_asn: None,
            packets,
            bytes,
        }
    }
}

/// Addresses, protocol, ports and TCP flags of one IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<u8>,
}

fn l4(proto: u8, p: Option<&[u8]>) -> (Option<u16>, Option<u16>, Option<u8>) {
    let Some(p) = p else {
        return (None, None, None);
    };
    let port = |o: usize| p.get(o..o + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    match proto {
        6 => (port(0), port(2), p.get(13).copied()),
        17 => (port(0), port(2), None),
        _ => (None, None, None),
    }
}

pub fn parse_ipv4(p: &[u8]) -> Option<PacketInfo> {
    if p.first()? >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0F) * 4;
    let src: [u8; 4] = p.get(12..16)?.try_into().ok()?;
    let dst: [u8; 4] = p.get(16..20)?.try_into().ok()?;
    let proto = *p.get(9)?;
    let frag_off = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]) & 0x1FFF;
    // Only the first fragment carries the L4 header.
    let payload = if ihl >= 20 && frag_off == 0 {
        p.get(ihl..)
    } else {
        None
    };
    let (src_port, dst_port, tcp_flags) = l4(proto, payload);
    Some(PacketInfo {
        src: IpAddr::V4(Ipv4Addr::from(src)),
        dst: IpAddr::V4(Ipv4Addr::from(dst)),
        protocol: proto,
        src_port,
        dst_port,
        tcp_flags,
    })
}

/// shortcut: extension headers are not walked, so ports are only read when
/// the fixed header's next-header is TCP/UDP; upgrade if fragmented v6 floods matter.
pub fn parse_ipv6(p: &[u8]) -> Option<PacketInfo> {
    if p.first()? >> 4 != 6 {
        return None;
    }
    let src: [u8; 16] = p.get(8..24)?.try_into().ok()?;
    let dst: [u8; 16] = p.get(24..40)?.try_into().ok()?;
    let proto = *p.get(6)?;
    let (src_port, dst_port, tcp_flags) = l4(proto, p.get(40..));
    Some(PacketInfo {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        protocol: proto,
        src_port,
        dst_port,
        tcp_flags,
    })
}

/// Ethernet frame with up to two VLAN tags (802.1Q / 802.1ad).
pub fn parse_ethernet(frame: &[u8]) -> Option<PacketInfo> {
    let mut off = 12;
    let mut ethertype = u16::from_be_bytes([*frame.get(off)?, *frame.get(off + 1)?]);
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88A8 {
            off += 4;
            ethertype = u16::from_be_bytes([*frame.get(off)?, *frame.get(off + 1)?]);
        }
    }
    let payload = frame.get(off + 2..)?;
    match ethertype {
        0x0800 => parse_ipv4(payload),
        0x86DD => parse_ipv6(payload),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn ipv4_udp(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 203, 0, 113, 9];
        ip.extend_from_slice(&[198, 51, 100, 7]);
        ip.extend_from_slice(&src_port.to_be_bytes());
        ip.extend_from_slice(&dst_port.to_be_bytes());
        ip.extend_from_slice(&[0, 8, 0, 0]);
        ip
    }

    #[test]
    fn parses_udp_ports_and_tcp_flags() {
        let p = parse_ipv4(&ipv4_udp(53, 4444)).unwrap();
        assert_eq!(p.protocol, 17);
        assert_eq!((p.src_port, p.dst_port), (Some(53), Some(4444)));
        assert_eq!(p.src, "203.0.113.9".parse::<IpAddr>().unwrap());

        let mut tcp = vec![
            0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 203, 0, 113, 9, 198, 51, 100, 7,
        ];
        tcp.extend_from_slice(&[0x30, 0x39, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02]);
        let p = parse_ipv4(&tcp).unwrap();
        assert_eq!((p.dst_port, p.tcp_flags), (Some(80), Some(0x02)));
    }

    #[test]
    fn non_first_fragments_have_no_ports() {
        let mut f = ipv4_udp(53, 4444);
        f[7] = 0x10; // fragment offset != 0
        let p = parse_ipv4(&f).unwrap();
        assert_eq!(p.src_port, None);
        assert_eq!(p.protocol, 17);
    }

    #[test]
    fn short_headers_never_panic() {
        let full = ipv4_udp(53, 1);
        for cut in 0..full.len() {
            let _ = parse_ipv4(&full[..cut]);
        }
        assert!(parse_ipv4(&full[..19]).is_none());
        assert!(parse_ipv4(&full[..20]).unwrap().src_port.is_none());
        assert!(parse_ipv6(&[0x60; 39]).is_none());
        assert!(parse_ethernet(&[0u8; 13]).is_none());
        // IHL smaller than 5 words: addresses only.
        let mut bad = full.clone();
        bad[0] = 0x41;
        assert!(parse_ipv4(&bad).unwrap().src_port.is_none());
    }
}
