//! BGP FlowSpec (RFC 8955, IPv6 per RFC 8956): rule model, NLRI and
//! traffic-rate extended community encoding, and a defensive decoder used by
//! tests and `simulate`.
//!
//! Only the components Event Horizon emits are produced: destination prefix
//! (always a host prefix), IP protocol, destination port and source port, each
//! as a single equality match.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::message::*;
use crate::wire::Reader;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

const COMP_DST_PREFIX: u8 = 1;
const COMP_PROTOCOL: u8 = 3;
const COMP_DST_PORT: u8 = 5;
const COMP_SRC_PORT: u8 = 6;

/// Numeric operator: end-of-list bit, value length (1 or 2 bytes), equality.
const OP_END: u8 = 0x80;
const OP_LEN2: u8 = 0x10;
const OP_EQ: u8 = 0x01;

/// Transitive experimental extended community, sub-type traffic-rate-bytes (RFC 8955 §7.3).
const EXT_TRAFFIC_RATE: [u8; 2] = [0x80, 0x06];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FlowAction {
    /// traffic-rate 0: drop everything that matches.
    Discard,
    /// traffic-rate limit in kbit/s.
    RateLimit { kbps: u64 },
}

impl FlowAction {
    /// IEEE 754 bytes per second as carried in the extended community.
    pub fn bytes_per_sec(&self) -> f32 {
        match self {
            FlowAction::Discard => 0.0,
            FlowAction::RateLimit { kbps } => (*kbps as f64 * 1000.0 / 8.0) as f32,
        }
    }
}

impl fmt::Display for FlowAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowAction::Discard => f.write_str("discard"),
            FlowAction::RateLimit { kbps } => write!(f, "rate-limit {kbps} kbit/s"),
        }
    }
}

/// One FlowSpec rule against a single victim address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowRule {
    pub dst: IpAddr,
    pub protocol: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    pub action: FlowAction,
}

fn port_str(p: Option<u16>) -> String {
    p.map_or_else(|| "any".to_owned(), |p| p.to_string())
}

impl FlowRule {
    /// Stable, URL-safe identifier of the match (the action is not part of it).
    pub fn key(&self) -> String {
        format!(
            "{}-{}-s{}-d{}",
            self.dst,
            self.protocol,
            port_str(self.src_port),
            port_str(self.dst_port)
        )
    }

    pub fn nlri(&self) -> Vec<u8> {
        let mut c = Vec::with_capacity(32);
        c.push(COMP_DST_PREFIX);
        match self.dst {
            IpAddr::V4(a) => {
                c.push(32);
                c.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                c.extend_from_slice(&[128, 0]); // length, offset (RFC 8956)
                c.extend_from_slice(&a.octets());
            }
        }
        c.extend_from_slice(&[COMP_PROTOCOL, OP_END | OP_EQ, self.protocol]);
        for (kind, port) in [
            (COMP_DST_PORT, self.dst_port),
            (COMP_SRC_PORT, self.src_port),
        ] {
            if let Some(p) = port {
                c.extend_from_slice(&[kind, OP_END | OP_LEN2 | OP_EQ]);
                c.extend_from_slice(&p.to_be_bytes());
            }
        }
        // Length prefix: 1 byte below 240, else 0xF0nn (never reached for our rules).
        let mut out = Vec::with_capacity(c.len() + 2);
        if c.len() < 240 {
            out.push(c.len() as u8);
        } else {
            out.extend_from_slice(&(0xF000u16 | c.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(&c);
        out
    }

    fn afi(&self) -> u16 {
        if self.dst.is_ipv4() {
            AFI_IPV4
        } else {
            AFI_IPV6
        }
    }
}

impl fmt::Display for FlowRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dst {} proto {}", self.dst, self.protocol)?;
        if let Some(p) = self.src_port {
            write!(f, " src-port {p}")?;
        }
        if let Some(p) = self.dst_port {
            write!(f, " dst-port {p}")?;
        }
        write!(f, " -> {}", self.action)
    }
}

/// traffic-rate extended community for `action`; the AS field carries a
/// 2-octet `local_asn` or 0 for 4-octet ASNs (RFC 8955 §7.3).
pub fn traffic_rate_community(local_asn: u32, action: &FlowAction) -> [u8; 8] {
    let asn = u16::try_from(local_asn).unwrap_or(0);
    let mut c = [0u8; 8];
    c[..2].copy_from_slice(&EXT_TRAFFIC_RATE);
    c[2..4].copy_from_slice(&asn.to_be_bytes());
    c[4..].copy_from_slice(&action.bytes_per_sec().to_be_bytes());
    c
}

/// UPDATE announcing `rule` (MP_REACH_NLRI, SAFI 133, no next hop).
pub fn encode_flowspec_announce(rule: &FlowRule, local_asn: u32, four_octet_as: bool) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, FLAG_TRANSITIVE, ATTR_ORIGIN, &[0]);
    let mut path = vec![AS_SEQUENCE, 1];
    if four_octet_as {
        path.extend_from_slice(&local_asn.to_be_bytes());
    } else {
        path.extend_from_slice(&(local_asn as u16).to_be_bytes());
    }
    push_attr(&mut attrs, FLAG_TRANSITIVE, ATTR_AS_PATH, &path);
    let mut mp = rule.afi().to_be_bytes().to_vec();
    mp.extend_from_slice(&[SAFI_FLOWSPEC, 0, 0]); // next hop length 0, reserved
    mp.extend_from_slice(&rule.nlri());
    push_attr(&mut attrs, FLAG_OPTIONAL, ATTR_MP_REACH, &mp);
    push_attr(
        &mut attrs,
        FLAG_OPTIONAL | FLAG_TRANSITIVE,
        ATTR_EXT_COMMUNITIES,
        &traffic_rate_community(local_asn, &rule.action),
    );
    update(&[], &attrs, &[])
}

/// UPDATE withdrawing `rule` (MP_UNREACH_NLRI, SAFI 133).
pub fn encode_flowspec_withdraw(rule: &FlowRule) -> Vec<u8> {
    let mut mp = rule.afi().to_be_bytes().to_vec();
    mp.push(SAFI_FLOWSPEC);
    mp.extend_from_slice(&rule.nlri());
    let mut attrs = Vec::new();
    push_attr(&mut attrs, FLAG_OPTIONAL, ATTR_MP_UNREACH, &mp);
    update(&[], &attrs, &[])
}

/// Decoded FlowSpec match (any component we do not model is counted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowMatch {
    pub dst: Option<IpNet>,
    pub protocol: Option<u8>,
    pub dst_port: Option<u16>,
    pub src_port: Option<u16>,
    pub other_components: usize,
}

/// Decoded FlowSpec content of an UPDATE body.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FlowUpdate {
    pub announced: Vec<FlowMatch>,
    pub withdrawn: Vec<FlowMatch>,
    /// traffic-rate values (bytes/s) found in extended communities.
    pub rates: Vec<f32>,
}

fn read_value(r: &mut Reader<'_>, op: u8) -> Option<u64> {
    let len = 1usize << ((op >> 4) & 0x3);
    let b = r.take(len).ok()?;
    Some(b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

fn decode_match(buf: &[u8], v6: bool) -> Option<FlowMatch> {
    let mut r = Reader::new(buf);
    let mut m = FlowMatch::default();
    while !r.is_empty() {
        let t = r.u8().ok()?;
        match t {
            COMP_DST_PREFIX | 2 => {
                let len = r.u8().ok()?;
                if v6 {
                    let _offset = r.u8().ok()?;
                }
                if len > if v6 { 128 } else { 32 } {
                    return None;
                }
                let bytes = r.take(usize::from(len).div_ceil(8)).ok()?;
                let ip = if v6 {
                    let mut a = [0u8; 16];
                    a[..bytes.len()].copy_from_slice(bytes);
                    IpAddr::V6(Ipv6Addr::from(a))
                } else {
                    let mut a = [0u8; 4];
                    a[..bytes.len()].copy_from_slice(bytes);
                    IpAddr::V4(Ipv4Addr::from(a))
                };
                if t == COMP_DST_PREFIX {
                    m.dst = IpNet::new(ip, len).ok();
                } else {
                    m.other_components += 1;
                }
            }
            1..=13 => {
                // Numeric / bitmask operator lists; keep the first equality value.
                let mut first = None;
                loop {
                    let op = r.u8().ok()?;
                    let v = read_value(&mut r, op)?;
                    first.get_or_insert(v);
                    if op & OP_END != 0 {
                        break;
                    }
                }
                let v = first?;
                match t {
                    COMP_PROTOCOL => m.protocol = u8::try_from(v).ok(),
                    COMP_DST_PORT => m.dst_port = u16::try_from(v).ok(),
                    COMP_SRC_PORT => m.src_port = u16::try_from(v).ok(),
                    _ => m.other_components += 1,
                }
            }
            _ => return None,
        }
    }
    Some(m)
}

fn decode_nlri_list(buf: &[u8], v6: bool, out: &mut Vec<FlowMatch>) -> Option<()> {
    let mut r = Reader::new(buf);
    while !r.is_empty() {
        let first = r.u8().ok()?;
        let len = if first >= 0xF0 {
            (usize::from(first & 0x0F) << 8) | usize::from(r.u8().ok()?)
        } else {
            usize::from(first)
        };
        out.push(decode_match(r.take(len).ok()?, v6)?);
    }
    Some(())
}

/// Extracts FlowSpec NLRI and traffic-rate actions from an UPDATE body.
/// Returns `None` on malformed input; never panics.
pub fn decode_flowspec_update(body: &[u8]) -> Option<FlowUpdate> {
    let mut out = FlowUpdate::default();
    let mut r = Reader::new(body);
    let wlen = usize::from(r.u16().ok()?);
    r.take(wlen).ok()?;
    let alen = usize::from(r.u16().ok()?);
    let mut attrs = Reader::new(r.take(alen).ok()?);
    while !attrs.is_empty() {
        let flags = attrs.u8().ok()?;
        let code = attrs.u8().ok()?;
        let len = if flags & FLAG_EXTENDED != 0 {
            usize::from(attrs.u16().ok()?)
        } else {
            usize::from(attrs.u8().ok()?)
        };
        let mut a = Reader::new(attrs.take(len).ok()?);
        match code {
            ATTR_MP_REACH | ATTR_MP_UNREACH => {
                let afi = a.u16().ok()?;
                let safi = a.u8().ok()?;
                if safi != SAFI_FLOWSPEC {
                    continue;
                }
                let v6 = afi == AFI_IPV6;
                if code == ATTR_MP_REACH {
                    let nh = usize::from(a.u8().ok()?);
                    a.take(nh).ok()?;
                    a.u8().ok()?;
                    decode_nlri_list(a.rest(), v6, &mut out.announced)?;
                } else {
                    decode_nlri_list(a.rest(), v6, &mut out.withdrawn)?;
                }
            }
            ATTR_EXT_COMMUNITIES => {
                while !a.is_empty() {
                    let c = a.take(8).ok()?;
                    if c[..2] == EXT_TRAFFIC_RATE {
                        out.rates.push(f32::from_be_bytes([c[4], c[5], c[6], c[7]]));
                    }
                }
            }
            _ => {}
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> FlowRule {
        FlowRule {
            dst: "198.51.100.7".parse().unwrap(),
            protocol: PROTO_UDP,
            src_port: Some(53),
            dst_port: None,
            action: FlowAction::RateLimit { kbps: 8000 },
        }
    }

    fn body(msg: &[u8]) -> &[u8] {
        let (len, kind) = decode_header(msg).unwrap();
        assert_eq!((len, kind), (msg.len(), MSG_UPDATE));
        &msg[HEADER_LEN..]
    }

    #[test]
    fn nlri_exact_bytes_v4() {
        assert_eq!(
            rule().nlri(),
            vec![13, 1, 32, 198, 51, 100, 7, 3, 0x81, 17, 6, 0x91, 0, 53]
        );
    }

    #[test]
    fn nlri_v6_has_offset_byte() {
        let r = FlowRule {
            dst: "2001:db8:100::7".parse().unwrap(),
            protocol: PROTO_TCP,
            src_port: None,
            dst_port: Some(443),
            action: FlowAction::Discard,
        };
        let n = r.nlri();
        // prefix component 1+1+1+16, protocol 3, dst port 4
        assert_eq!(&n[..4], &[26, 1, 128, 0]);
        assert_eq!(&n[n.len() - 4..], &[5, 0x91, 0x01, 0xBB]);
    }

    #[test]
    fn traffic_rate_encoding() {
        let c = traffic_rate_community(64500, &FlowAction::RateLimit { kbps: 8000 });
        assert_eq!(&c[..4], &[0x80, 0x06, 0xFB, 0xF4]);
        assert_eq!(f32::from_be_bytes([c[4], c[5], c[6], c[7]]), 1_000_000.0);
        let d = traffic_rate_community(4_200_000_000, &FlowAction::Discard);
        assert_eq!(d, [0x80, 0x06, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn announce_and_withdraw_roundtrip() {
        for r in [
            rule(),
            FlowRule {
                dst: "2001:db8:100::7".parse().unwrap(),
                protocol: PROTO_ICMPV6,
                src_port: None,
                dst_port: None,
                action: FlowAction::Discard,
            },
        ] {
            let msg = encode_flowspec_announce(&r, 64500, true);
            let u = decode_flowspec_update(body(&msg)).unwrap();
            assert_eq!(u.announced.len(), 1);
            let m = &u.announced[0];
            assert_eq!(
                m.dst,
                Some(IpNet::new(r.dst, if r.dst.is_ipv4() { 32 } else { 128 }).unwrap())
            );
            assert_eq!(m.protocol, Some(r.protocol));
            assert_eq!(m.src_port, r.src_port);
            assert_eq!(m.dst_port, r.dst_port);
            assert_eq!(u.rates, vec![r.action.bytes_per_sec()]);
            // The unicast decoder still accepts the message (FlowSpec is counted as other).
            let plain = decode_update(body(&msg), true).unwrap();
            assert!(plain.nlri.is_empty());

            let w = encode_flowspec_withdraw(&r);
            let u = decode_flowspec_update(body(&w)).unwrap();
            assert_eq!(u.withdrawn.len(), 1);
            assert!(u.announced.is_empty());
        }
    }

    #[test]
    fn decoder_never_panics_on_truncation() {
        let msg = encode_flowspec_announce(&rule(), 64500, false);
        let b = body(&msg);
        for cut in 0..b.len() {
            let _ = decode_flowspec_update(&b[..cut]);
        }
        assert!(decode_match(&[1, 33, 1, 2, 3, 4, 5], false).is_none());
        assert!(decode_match(&[99, 1], false).is_none());
    }

    #[test]
    fn key_is_stable_and_url_safe() {
        assert_eq!(rule().key(), "198.51.100.7-17-s53-dany");
        let mut r = rule();
        r.action = FlowAction::Discard;
        assert_eq!(r.key(), rule().key());
        assert!(rule()
            .key()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-.:".contains(c)));
        assert_eq!(
            rule().to_string(),
            "dst 198.51.100.7 proto 17 src-port 53 -> rate-limit 8000 kbit/s"
        );
    }
}
