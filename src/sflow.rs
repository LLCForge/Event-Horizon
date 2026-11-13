//! sFlow v5 datagram parser: flow samples with raw packet header records and
//! the extended gateway record (source AS).
//!
//! Each flow sample stands for `sampling_rate` packets; the returned packet and
//! byte counts are already scaled. Counter samples and other record types are
//! skipped. Malformed input yields an error, never a panic.

use thiserror::Error;

use crate::flow::{parse_ethernet, parse_ipv4, parse_ipv6, FlowSample, PacketInfo};
use crate::wire::{Reader, Truncated};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SflowError {
    #[error("datagram truncated")]
    Truncated,
    #[error("unsupported sFlow version {0}")]
    Version(u32),
    #[error("unknown agent address type {0}")]
    AgentType(u32),
}

impl From<Truncated> for SflowError {
    fn from(_: Truncated) -> Self {
        SflowError::Truncated
    }
}

const FLOW_SAMPLE: u32 = 1;
const FLOW_SAMPLE_EXPANDED: u32 = 3;
const RAW_PACKET_HEADER: u32 = 1;
const EXTENDED_GATEWAY: u32 = 1003;

const PROTO_ETHERNET: u32 = 1;
const PROTO_IPV4: u32 = 11;
const PROTO_IPV6: u32 = 12;

pub fn parse_datagram(buf: &[u8]) -> Result<Vec<FlowSample>, SflowError> {
    let mut r = Reader::new(buf);
    let version = r.u32()?;
    if version != 5 {
        return Err(SflowError::Version(version));
    }
    match r.u32()? {
        1 => r.take(4)?,
        2 => r.take(16)?,
        t => return Err(SflowError::AgentType(t)),
    };
    let _sub_agent = r.u32()?;
    let _sequence = r.u32()?;
    let _uptime = r.u32()?;
    let n_samples = r.u32()?;

    let mut out = Vec::new();
    for _ in 0..n_samples {
        let format = r.u32()?;
        let len = r.u32()? as usize;
        let mut s = Reader::new(r.take(len)?);
        let (enterprise, kind) = (format >> 12, format & 0xFFF);
        if enterprise != 0 {
            continue;
        }
        let rate = match kind {
            FLOW_SAMPLE => {
                let _seq = s.u32()?;
                let _source = s.u32()?;
                let rate = s.u32()?;
                s.take(16)?; // pool, drops, input, output
                rate
            }
            FLOW_SAMPLE_EXPANDED => {
                let _seq = s.u32()?;
                s.take(8)?; // source id type + index
                let rate = s.u32()?;
                s.take(24)?; // pool, drops, input fmt/val, output fmt/val
                rate
            }
            _ => continue,
        };
        let n_records = s.u32()?;
        let first = out.len();
        let mut src_as = None;
        for _ in 0..n_records {
            let rformat = s.u32()?;
            let rlen = s.u32()? as usize;
            let rec = s.take(rlen)?;
            if rate == 0 {
                continue;
            }
            match rformat {
                RAW_PACKET_HEADER => {
                    if let Some((p, frame_len)) = parse_raw_header(rec)? {
                        let mut f = FlowSample::new(
                            p.dst,
                            u64::from(rate),
                            u64::from(frame_len).saturating_mul(u64::from(rate)),
                        );
                        f.src = Some(p.src);
                        f.protocol = Some(p.protocol);
                        f.src_port = p.src_port;
                        f.dst_port = p.dst_port;
                        f.tcp_flags = p.tcp_flags;
                        out.push(f);
                    }
                }
                EXTENDED_GATEWAY => src_as = parse_gateway_src_as(rec),
                _ => {}
            }
        }
        if let Some(asn) = src_as.filter(|a| *a != 0) {
            for f in &mut out[first..] {
                f.src_asn = Some(asn);
            }
        }
    }
    Ok(out)
}

/// `extended_gateway`: next hop address, router AS, source AS, ...
fn parse_gateway_src_as(rec: &[u8]) -> Option<u32> {
    let mut r = Reader::new(rec);
    match r.u32().ok()? {
        1 => r.take(4).ok()?,
        2 => r.take(16).ok()?,
        _ => return None,
    };
    let _router_as = r.u32().ok()?;
    r.u32().ok()
}

/// Returns `(packet, frame_length)` or `None` for non-IP / short headers.
fn parse_raw_header(rec: &[u8]) -> Result<Option<(PacketInfo, u32)>, SflowError> {
    let mut r = Reader::new(rec);
    let proto = r.u32()?;
    let frame_len = r.u32()?;
    let _stripped = r.u32()?;
    let hdr_len = r.u32()? as usize;
    let hdr = r.take(hdr_len)?;
    let p = match proto {
        PROTO_ETHERNET => parse_ethernet(hdr),
        PROTO_IPV4 => parse_ipv4(hdr),
        PROTO_IPV6 => parse_ipv6(hdr),
        _ => None,
    };
    Ok(p.map(|p| (p, frame_len)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    fn u32s(v: &mut Vec<u8>, xs: &[u32]) {
        for x in xs {
            v.extend_from_slice(&x.to_be_bytes());
        }
    }

    pub fn eth_ipv4(dst: [u8; 4], vlan: bool) -> Vec<u8> {
        eth_ipv4_udp(dst, vlan, 4444, 80)
    }

    pub fn eth_ipv4_udp(dst: [u8; 4], vlan: bool, sport: u16, dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        if vlan {
            f.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
        }
        f.extend_from_slice(&[0x08, 0x00]);
        let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0, 203, 0, 113, 9];
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&sport.to_be_bytes());
        ip.extend_from_slice(&dport.to_be_bytes());
        ip.extend_from_slice(&[0, 20, 0, 0]);
        f.extend_from_slice(&ip);
        f
    }

    fn eth_ipv6(dst: Ipv6Addr) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x86, 0xDD]);
        let mut ip = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        ip.extend_from_slice(&[0u8; 16]);
        ip.extend_from_slice(&dst.octets());
        f.extend_from_slice(&ip);
        f
    }

    fn record(format: u32, body: &[u8]) -> Vec<u8> {
        let mut rec = body.to_vec();
        while !rec.len().is_multiple_of(4) {
            rec.push(0);
        }
        let mut out = Vec::new();
        u32s(&mut out, &[format, rec.len() as u32]);
        out.extend_from_slice(&rec);
        out
    }

    pub fn raw_record(proto: u32, frame_len: u32, header: &[u8]) -> Vec<u8> {
        let mut rec = Vec::new();
        u32s(&mut rec, &[proto, frame_len, 0, header.len() as u32]);
        rec.extend_from_slice(header);
        record(RAW_PACKET_HEADER, &rec)
    }

    fn gateway_record(src_as: u32) -> Vec<u8> {
        let mut g = Vec::new();
        u32s(&mut g, &[1]);
        g.extend_from_slice(&[192, 0, 2, 1]);
        u32s(&mut g, &[64500, src_as, 64496, 0, 0, 0]);
        record(EXTENDED_GATEWAY, &g)
    }

    /// Builds a datagram with one flow sample per `(expanded, rate, records)`.
    pub fn datagram(samples: &[(bool, u32, Vec<Vec<u8>>)]) -> Vec<u8> {
        let mut d = Vec::new();
        u32s(
            &mut d,
            &[5, 1, 0xC000_0215, 0, 1, 1000, samples.len() as u32],
        );
        for (expanded, rate, records) in samples {
            let mut s = Vec::new();
            if *expanded {
                u32s(
                    &mut s,
                    &[1, 0, 3, *rate, 0, 0, 0, 1, 0, 2, records.len() as u32],
                );
            } else {
                u32s(&mut s, &[1, 3, *rate, 0, 0, 1, 2, records.len() as u32]);
            }
            for r in records {
                s.extend_from_slice(r);
            }
            u32s(&mut d, &[if *expanded { 3 } else { 1 }, s.len() as u32]);
            d.extend_from_slice(&s);
        }
        d
    }

    pub fn sample_v4(dst: [u8; 4], rate: u32, frame_len: u32) -> Vec<u8> {
        datagram(&[(
            false,
            rate,
            vec![raw_record(PROTO_ETHERNET, frame_len, &eth_ipv4(dst, false))],
        )])
    }

    #[test]
    fn parses_ethernet_ipv4_and_scales() {
        let d = sample_v4([198, 51, 100, 7], 1000, 1500);
        let s = parse_datagram(&d).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].dst, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!((s[0].packets, s[0].bytes), (1000, 1_500_000));
        assert_eq!(s[0].protocol, Some(17));
        assert_eq!((s[0].src_port, s[0].dst_port), (Some(4444), Some(80)));
        assert_eq!(s[0].src, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(s[0].src_asn, None);
    }

    #[test]
    fn extended_gateway_sets_source_as() {
        let d = datagram(&[(
            false,
            100,
            vec![
                gateway_record(64511),
                raw_record(
                    PROTO_ETHERNET,
                    100,
                    &eth_ipv4_udp([198, 51, 100, 7], false, 123, 5000),
                ),
            ],
        )]);
        let s = parse_datagram(&d).unwrap();
        assert_eq!(s[0].src_asn, Some(64511));
        assert_eq!(s[0].src_port, Some(123));
        assert_eq!(parse_gateway_src_as(&[0, 0, 0, 9]), None);
    }

    #[test]
    fn parses_vlan_ipv6_expanded_and_raw_ip() {
        let v6: Ipv6Addr = "2001:db8:100::7".parse().unwrap();
        let mut raw_ip4 = eth_ipv4([198, 51, 100, 8], false);
        raw_ip4.drain(..14);
        let d = datagram(&[
            (
                true,
                512,
                vec![
                    raw_record(PROTO_ETHERNET, 100, &eth_ipv4([198, 51, 100, 9], true)),
                    raw_record(PROTO_ETHERNET, 200, &eth_ipv6(v6)),
                ],
            ),
            (false, 10, vec![raw_record(PROTO_IPV4, 60, &raw_ip4)]),
        ]);
        let s = parse_datagram(&d).unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].dst, "198.51.100.9".parse::<IpAddr>().unwrap());
        assert_eq!(s[1].dst, IpAddr::V6(v6));
        assert_eq!(s[1].bytes, 200 * 512);
        assert_eq!(s[2].dst, "198.51.100.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn skips_non_ip_zero_rate_and_unknown_records() {
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06, 0, 1]);
        let mut other = Vec::new();
        u32s(&mut other, &[1001, 4, 0]); // extended switch record
        let d = datagram(&[
            (
                false,
                100,
                vec![raw_record(PROTO_ETHERNET, 60, &arp), other],
            ),
            (
                false,
                0,
                vec![raw_record(
                    PROTO_ETHERNET,
                    60,
                    &eth_ipv4([198, 51, 100, 7], false),
                )],
            ),
        ]);
        assert!(parse_datagram(&d).unwrap().is_empty());
    }

    #[test]
    fn rejects_wrong_version_and_agent_type() {
        let mut d = sample_v4([198, 51, 100, 7], 1, 64);
        d[3] = 4;
        assert_eq!(parse_datagram(&d), Err(SflowError::Version(4)));
        let mut d = sample_v4([198, 51, 100, 7], 1, 64);
        d[7] = 9;
        assert_eq!(parse_datagram(&d), Err(SflowError::AgentType(9)));
    }

    #[test]
    fn truncation_never_panics_and_is_reported() {
        let d = datagram(&[(
            true,
            64,
            vec![raw_record(
                PROTO_ETHERNET,
                64,
                &eth_ipv6("2001:db8:100::7".parse().unwrap()),
            )],
        )]);
        for cut in 0..d.len() {
            assert!(parse_datagram(&d[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn huge_counts_do_not_allocate_or_loop_forever() {
        let mut d = Vec::new();
        u32s(&mut d, &[5, 1, 0, 0, 0, 0, u32::MAX]);
        assert_eq!(parse_datagram(&d), Err(SflowError::Truncated));
        let mut d = Vec::new();
        u32s(&mut d, &[5, 1, 0, 0, 0, 0, 1, 1, u32::MAX]);
        assert_eq!(parse_datagram(&d), Err(SflowError::Truncated));
    }
}
