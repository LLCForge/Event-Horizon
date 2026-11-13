//! BGP-4 message encoding and decoding (RFC 4271, RFC 6793 4-octet AS,
//! RFC 4760 multiprotocol extensions, RFC 1997 communities).
//!
//! Only what an announce-only RTBH speaker needs is implemented. Decoders
//! never panic: every length is bounds-checked against the received buffer.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;
use serde::Deserialize;
use thiserror::Error;

use crate::wire::{Reader, Truncated};

pub const HEADER_LEN: usize = 19;
pub const MAX_MESSAGE_LEN: usize = 4096;

pub const MSG_OPEN: u8 = 1;
pub const MSG_UPDATE: u8 = 2;
pub const MSG_NOTIFICATION: u8 = 3;
pub const MSG_KEEPALIVE: u8 = 4;

pub const AS_TRANS: u32 = 23456;

pub const AFI_IPV4: u16 = 1;
pub const AFI_IPV6: u16 = 2;
pub const SAFI_UNICAST: u8 = 1;
/// RFC 8955 dissemination of flow specification rules.
pub const SAFI_FLOWSPEC: u8 = 133;

pub(crate) const ATTR_ORIGIN: u8 = 1;
pub(crate) const ATTR_AS_PATH: u8 = 2;
const ATTR_NEXT_HOP: u8 = 3;
const ATTR_COMMUNITIES: u8 = 8;
pub(crate) const ATTR_MP_REACH: u8 = 14;
pub(crate) const ATTR_MP_UNREACH: u8 = 15;
pub(crate) const ATTR_EXT_COMMUNITIES: u8 = 16;

pub(crate) const FLAG_OPTIONAL: u8 = 0x80;
pub(crate) const FLAG_TRANSITIVE: u8 = 0x40;
pub(crate) const FLAG_EXTENDED: u8 = 0x10;

const AS_SET: u8 = 1;
pub(crate) const AS_SEQUENCE: u8 = 2;

const CAP_MULTIPROTOCOL: u8 = 1;
const CAP_GRACEFUL_RESTART: u8 = 64;
const CAP_FOUR_OCTET_AS: u8 = 65;

/// A standard (RFC 1997) community, `high:low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Community(pub u32);

impl Community {
    /// BLACKHOLE, RFC 7999.
    pub const BLACKHOLE: Community = Community(0xFFFF_029A);
    /// NO_EXPORT, RFC 1997. RFC 7999 recommends attaching it to blackhole routes.
    pub const NO_EXPORT: Community = Community(0xFFFF_FF01);
}

impl FromStr for Community {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hi, lo) = s
            .split_once(':')
            .ok_or_else(|| format!("community {s:?} must look like 65535:666"))?;
        let hi: u16 = hi
            .trim()
            .parse()
            .map_err(|_| format!("community {s:?}: bad high part"))?;
        let lo: u16 = lo
            .trim()
            .parse()
            .map_err(|_| format!("community {s:?}: bad low part"))?;
        Ok(Community((u32::from(hi) << 16) | u32::from(lo)))
    }
}

impl TryFrom<String> for Community {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.0 >> 16, self.0 & 0xFFFF)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("message truncated")]
    Truncated,
    #[error("invalid marker")]
    BadMarker,
    #[error("invalid message length {0}")]
    BadLength(usize),
    #[error("unknown message type {0}")]
    BadType(u8),
    #[error("malformed {0}")]
    Malformed(&'static str),
}

impl From<Truncated> for DecodeError {
    fn from(_: Truncated) -> Self {
        DecodeError::Truncated
    }
}

/// Validates a 19-byte header and returns `(total_length, type)`.
pub fn decode_header(buf: &[u8]) -> Result<(usize, u8), DecodeError> {
    let mut r = Reader::new(buf);
    if r.take(16)?.iter().any(|b| *b != 0xFF) {
        return Err(DecodeError::BadMarker);
    }
    let len = usize::from(r.u16()?);
    let kind = r.u8()?;
    if !(HEADER_LEN..=MAX_MESSAGE_LEN).contains(&len) {
        return Err(DecodeError::BadLength(len));
    }
    if !(MSG_OPEN..=MSG_KEEPALIVE).contains(&kind) {
        return Err(DecodeError::BadType(kind));
    }
    let min = match kind {
        MSG_OPEN => 29,
        MSG_UPDATE => 23,
        MSG_NOTIFICATION => 21,
        _ => HEADER_LEN,
    };
    if len < min || (kind == MSG_KEEPALIVE && len != HEADER_LEN) {
        return Err(DecodeError::BadLength(len));
    }
    Ok((len, kind))
}

pub(crate) fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let len = HEADER_LEN + body.len();
    debug_assert!(len <= MAX_MESSAGE_LEN);
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&[0xFF; 16]);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    out
}

pub fn encode_keepalive() -> Vec<u8> {
    frame(MSG_KEEPALIVE, &[])
}

pub fn encode_notification(code: u8, subcode: u8, data: &[u8]) -> Vec<u8> {
    let mut body = vec![code, subcode];
    body.extend_from_slice(&data[..data.len().min(MAX_MESSAGE_LEN - HEADER_LEN - 2)]);
    frame(MSG_NOTIFICATION, &body)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub code: u8,
    pub subcode: u8,
}

pub fn decode_notification(body: &[u8]) -> Result<Notification, DecodeError> {
    let mut r = Reader::new(body);
    Ok(Notification {
        code: r.u8()?,
        subcode: r.u8()?,
    })
}

/// Optional capabilities for our OPEN.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenOptions {
    /// Advertise IPv4 and IPv6 FlowSpec (AFI 1/2, SAFI 133).
    pub flowspec: bool,
    /// RFC 4724 Graceful Restart: restart time in seconds and the Restart State bit.
    pub graceful_restart: Option<(u16, bool)>,
}

/// Encodes an OPEN advertising 4-octet AS and IPv4 + IPv6 unicast.
#[cfg(test)]
pub fn encode_open(local_asn: u32, hold_time: u16, router_id: Ipv4Addr) -> Vec<u8> {
    encode_open_with(local_asn, hold_time, router_id, &OpenOptions::default())
}

/// Encodes an OPEN with the optional capabilities in `opts`.
pub fn encode_open_with(
    local_asn: u32,
    hold_time: u16,
    router_id: Ipv4Addr,
    opts: &OpenOptions,
) -> Vec<u8> {
    let my_as = u16::try_from(local_asn).unwrap_or(AS_TRANS as u16);
    let mut families = vec![(AFI_IPV4, SAFI_UNICAST), (AFI_IPV6, SAFI_UNICAST)];
    if opts.flowspec {
        families.extend([(AFI_IPV4, SAFI_FLOWSPEC), (AFI_IPV6, SAFI_FLOWSPEC)]);
    }
    let mut caps = Vec::new();
    for (afi, safi) in &families {
        caps.extend_from_slice(&[CAP_MULTIPROTOCOL, 4]);
        caps.extend_from_slice(&afi.to_be_bytes());
        caps.extend_from_slice(&[0, *safi]);
    }
    if let Some((time, restarting)) = opts.graceful_restart {
        let flags = (if restarting { 0x8000u16 } else { 0 }) | time.min(4095);
        caps.extend_from_slice(&[CAP_GRACEFUL_RESTART, (2 + 4 * families.len()) as u8]);
        caps.extend_from_slice(&flags.to_be_bytes());
        for (afi, safi) in &families {
            caps.extend_from_slice(&afi.to_be_bytes());
            // F bit: the peer keeps our routes across a restart instead of flushing them.
            caps.extend_from_slice(&[*safi, 0x80]);
        }
    }
    caps.extend_from_slice(&[CAP_FOUR_OCTET_AS, 4]);
    caps.extend_from_slice(&local_asn.to_be_bytes());

    let mut body = vec![4];
    body.extend_from_slice(&my_as.to_be_bytes());
    body.extend_from_slice(&hold_time.to_be_bytes());
    body.extend_from_slice(&router_id.octets());
    body.push((caps.len() + 2) as u8);
    body.push(2); // optional parameter type: capabilities
    body.push(caps.len() as u8);
    body.extend_from_slice(&caps);
    frame(MSG_OPEN, &body)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub version: u8,
    /// Peer ASN, taken from the 4-octet AS capability when present.
    pub asn: u32,
    pub hold_time: u16,
    pub router_id: Ipv4Addr,
    pub four_octet_as: bool,
    pub any_multiprotocol: bool,
    pub ipv4_unicast: bool,
    pub ipv6_unicast: bool,
    pub ipv4_flowspec: bool,
    pub ipv6_flowspec: bool,
    /// Peer's Graceful Restart time when it advertised the capability.
    pub graceful_restart: Option<u16>,
}

impl Open {
    /// FlowSpec for the address family of `ip` was negotiated by the peer.
    pub fn supports_flowspec(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.ipv4_flowspec,
            IpAddr::V6(_) => self.ipv6_flowspec,
        }
    }

    /// RFC 4760: without any MP capability the session carries IPv4 unicast only.
    pub fn supports(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => !self.any_multiprotocol || self.ipv4_unicast,
            IpAddr::V6(_) => self.ipv6_unicast,
        }
    }
}

pub fn decode_open(body: &[u8]) -> Result<Open, DecodeError> {
    let mut r = Reader::new(body);
    let version = r.u8()?;
    let my_as = u32::from(r.u16()?);
    let hold_time = r.u16()?;
    let router_id = Ipv4Addr::from(r.u32()?);
    let opt_len = usize::from(r.u8()?);
    let mut params = Reader::new(r.take(opt_len)?);
    if !r.is_empty() {
        return Err(DecodeError::Malformed("OPEN trailing bytes"));
    }
    let mut open = Open {
        version,
        asn: my_as,
        hold_time,
        router_id,
        four_octet_as: false,
        any_multiprotocol: false,
        ipv4_unicast: false,
        ipv6_unicast: false,
        ipv4_flowspec: false,
        ipv6_flowspec: false,
        graceful_restart: None,
    };
    while !params.is_empty() {
        let ptype = params.u8()?;
        let plen = usize::from(params.u8()?);
        let pdata = params.take(plen)?;
        if ptype != 2 {
            continue;
        }
        let mut caps = Reader::new(pdata);
        while !caps.is_empty() {
            let code = caps.u8()?;
            let clen = usize::from(caps.u8()?);
            let mut c = Reader::new(caps.take(clen)?);
            match code {
                CAP_MULTIPROTOCOL if clen == 4 => {
                    let afi = c.u16()?;
                    let _reserved = c.u8()?;
                    let safi = c.u8()?;
                    open.any_multiprotocol = true;
                    match (afi, safi) {
                        (AFI_IPV4, SAFI_UNICAST) => open.ipv4_unicast = true,
                        (AFI_IPV6, SAFI_UNICAST) => open.ipv6_unicast = true,
                        (AFI_IPV4, SAFI_FLOWSPEC) => open.ipv4_flowspec = true,
                        (AFI_IPV6, SAFI_FLOWSPEC) => open.ipv6_flowspec = true,
                        _ => {}
                    }
                }
                CAP_GRACEFUL_RESTART if clen >= 2 && (clen - 2) % 4 == 0 => {
                    open.graceful_restart = Some(c.u16()? & 0x0FFF);
                }
                CAP_GRACEFUL_RESTART => {
                    return Err(DecodeError::Malformed("graceful restart capability length"))
                }
                CAP_FOUR_OCTET_AS if clen == 4 => {
                    open.four_octet_as = true;
                    open.asn = c.u32()?;
                }
                CAP_MULTIPROTOCOL | CAP_FOUR_OCTET_AS => {
                    return Err(DecodeError::Malformed("capability length"))
                }
                _ => {}
            }
        }
    }
    Ok(open)
}

/// Everything needed to build the announcement for one upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceParams {
    pub local_asn: u32,
    pub four_octet_as: bool,
    pub next_hop_v4: Ipv4Addr,
    pub next_hop_v6: Ipv6Addr,
    pub communities: Vec<Community>,
}

/// BLACKHOLE + NO_EXPORT first, then the upstream's own communities, deduplicated.
pub fn blackhole_communities(extra: &[Community]) -> Vec<Community> {
    dedup_onto(vec![Community::BLACKHOLE, Community::NO_EXPORT], extra)
}

/// Regional / selective blackholing: NO_EXPORT plus the provider's regional
/// communities only. The well-known BLACKHOLE community is left out on
/// purpose: most providers act on it globally, which would defeat the scope.
pub fn regional_communities(region: &[Community]) -> Vec<Community> {
    dedup_onto(vec![Community::NO_EXPORT], region)
}

fn dedup_onto(mut out: Vec<Community>, extra: &[Community]) -> Vec<Community> {
    for c in extra {
        if !out.contains(c) {
            out.push(*c);
        }
    }
    out
}

/// End-of-RIB marker (RFC 4724): an empty UPDATE for IPv4 unicast, an empty
/// MP_UNREACH_NLRI for every other AFI/SAFI.
pub fn encode_end_of_rib(afi: u16, safi: u8) -> Vec<u8> {
    if afi == AFI_IPV4 && safi == SAFI_UNICAST {
        return update(&[], &[], &[]);
    }
    let mut mp = afi.to_be_bytes().to_vec();
    mp.push(safi);
    let mut attrs = Vec::new();
    push_attr(&mut attrs, FLAG_OPTIONAL, ATTR_MP_UNREACH, &mp);
    update(&[], &attrs, &[])
}

pub fn host_prefix(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(_) => IpNet::new(ip, 32),
        IpAddr::V6(_) => IpNet::new(ip, 128),
    }
    .expect("host prefix length is always valid")
}

pub(crate) fn push_attr(out: &mut Vec<u8>, flags: u8, code: u8, data: &[u8]) {
    if data.len() > 255 {
        out.extend_from_slice(&[flags | FLAG_EXTENDED, code]);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        out.extend_from_slice(&[flags, code, data.len() as u8]);
    }
    out.extend_from_slice(data);
}

fn push_prefix(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(a) => {
            out.push(32);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(128);
            out.extend_from_slice(&a.octets());
        }
    }
}

pub(crate) fn update(withdrawn: &[u8], attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + withdrawn.len() + attrs.len() + nlri.len());
    body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    body.extend_from_slice(withdrawn);
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(attrs);
    body.extend_from_slice(nlri);
    frame(MSG_UPDATE, &body)
}

/// UPDATE announcing `ip` as a /32 or /128 blackhole host route.
pub fn encode_announce(ip: IpAddr, p: &AnnounceParams) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, FLAG_TRANSITIVE, ATTR_ORIGIN, &[0]); // IGP

    let mut path = vec![AS_SEQUENCE, 1];
    if p.four_octet_as {
        path.extend_from_slice(&p.local_asn.to_be_bytes());
    } else {
        // Callers refuse 2-octet peers when local_asn > 65535.
        path.extend_from_slice(&(p.local_asn as u16).to_be_bytes());
    }
    push_attr(&mut attrs, FLAG_TRANSITIVE, ATTR_AS_PATH, &path);

    let mut nlri = Vec::new();
    match ip {
        IpAddr::V4(_) => {
            push_attr(
                &mut attrs,
                FLAG_TRANSITIVE,
                ATTR_NEXT_HOP,
                &p.next_hop_v4.octets(),
            );
            push_prefix(&mut nlri, ip);
        }
        IpAddr::V6(_) => {
            let mut mp = Vec::new();
            mp.extend_from_slice(&AFI_IPV6.to_be_bytes());
            mp.push(SAFI_UNICAST);
            mp.push(16);
            mp.extend_from_slice(&p.next_hop_v6.octets());
            mp.push(0); // reserved
            push_prefix(&mut mp, ip);
            push_attr(&mut attrs, FLAG_OPTIONAL, ATTR_MP_REACH, &mp);
        }
    }

    let comm: Vec<u8> = p
        .communities
        .iter()
        .flat_map(|c| c.0.to_be_bytes())
        .collect();
    if !comm.is_empty() {
        push_attr(
            &mut attrs,
            FLAG_OPTIONAL | FLAG_TRANSITIVE,
            ATTR_COMMUNITIES,
            &comm,
        );
    }
    update(&[], &attrs, &nlri)
}

/// UPDATE withdrawing the /32 or /128 host route for `ip`.
pub fn encode_withdraw(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(_) => {
            let mut w = Vec::new();
            push_prefix(&mut w, ip);
            update(&w, &[], &[])
        }
        IpAddr::V6(_) => {
            let mut mp = Vec::new();
            mp.extend_from_slice(&AFI_IPV6.to_be_bytes());
            mp.push(SAFI_UNICAST);
            push_prefix(&mut mp, ip);
            let mut attrs = Vec::new();
            push_attr(&mut attrs, FLAG_OPTIONAL, ATTR_MP_UNREACH, &mp);
            update(&[], &attrs, &[])
        }
    }
}

/// Decoded view of an UPDATE. IPv6 routes from MP_(UN)REACH are folded into
/// `nlri` / `withdrawn`; the MP next hop goes into `next_hop`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Update {
    pub withdrawn: Vec<IpNet>,
    pub nlri: Vec<IpNet>,
    pub origin: Option<u8>,
    pub as_path: Vec<u32>,
    pub next_hop: Option<IpAddr>,
    pub communities: Vec<Community>,
    pub other_attributes: usize,
}

fn decode_prefixes(buf: &[u8], v6: bool, out: &mut Vec<IpNet>) -> Result<(), DecodeError> {
    let mut r = Reader::new(buf);
    let max = if v6 { 128 } else { 32 };
    while !r.is_empty() {
        let len = r.u8()?;
        if len > max {
            return Err(DecodeError::Malformed("prefix length"));
        }
        let bytes = r.take(usize::from(len).div_ceil(8))?;
        let ip = if v6 {
            let mut a = [0u8; 16];
            a[..bytes.len()].copy_from_slice(bytes);
            IpAddr::V6(Ipv6Addr::from(a))
        } else {
            let mut a = [0u8; 4];
            a[..bytes.len()].copy_from_slice(bytes);
            IpAddr::V4(Ipv4Addr::from(a))
        };
        out.push(IpNet::new(ip, len).map_err(|_| DecodeError::Malformed("prefix"))?);
    }
    Ok(())
}

fn afi_is_v6(afi: u16) -> Option<bool> {
    match afi {
        AFI_IPV4 => Some(false),
        AFI_IPV6 => Some(true),
        _ => None,
    }
}

/// Parses an UPDATE body (without the 19-byte header).
pub fn decode_update(body: &[u8], four_octet_as: bool) -> Result<Update, DecodeError> {
    let mut u = Update::default();
    let mut r = Reader::new(body);
    let wlen = usize::from(r.u16()?);
    decode_prefixes(r.take(wlen)?, false, &mut u.withdrawn)?;
    let alen = usize::from(r.u16()?);
    let mut attrs = Reader::new(r.take(alen)?);
    decode_prefixes(r.rest(), false, &mut u.nlri)?;

    while !attrs.is_empty() {
        let flags = attrs.u8()?;
        let code = attrs.u8()?;
        let len = if flags & FLAG_EXTENDED != 0 {
            usize::from(attrs.u16()?)
        } else {
            usize::from(attrs.u8()?)
        };
        let data = attrs.take(len)?;
        let mut a = Reader::new(data);
        match code {
            ATTR_ORIGIN => {
                if len != 1 {
                    return Err(DecodeError::Malformed("ORIGIN length"));
                }
                u.origin = Some(a.u8()?);
            }
            ATTR_AS_PATH => {
                let width = if four_octet_as { 4 } else { 2 };
                while !a.is_empty() {
                    let seg_type = a.u8()?;
                    if seg_type != AS_SET && seg_type != AS_SEQUENCE {
                        return Err(DecodeError::Malformed("AS_PATH segment type"));
                    }
                    let count = usize::from(a.u8()?);
                    for _ in 0..count {
                        let asn = if width == 4 {
                            a.u32()?
                        } else {
                            u32::from(a.u16()?)
                        };
                        u.as_path.push(asn);
                    }
                }
            }
            ATTR_NEXT_HOP => {
                if len != 4 {
                    return Err(DecodeError::Malformed("NEXT_HOP length"));
                }
                u.next_hop = Some(IpAddr::V4(Ipv4Addr::from(a.u32()?)));
            }
            ATTR_COMMUNITIES => {
                if len % 4 != 0 {
                    return Err(DecodeError::Malformed("COMMUNITIES length"));
                }
                while !a.is_empty() {
                    u.communities.push(Community(a.u32()?));
                }
            }
            ATTR_MP_REACH => {
                let afi = a.u16()?;
                let safi = a.u8()?;
                let nh_len = usize::from(a.u8()?);
                let nh = a.take(nh_len)?;
                let _reserved = a.u8()?;
                match (afi_is_v6(afi), safi) {
                    (Some(v6), SAFI_UNICAST) => {
                        u.next_hop = match (v6, nh_len) {
                            (true, 16 | 32) => {
                                let mut b = [0u8; 16];
                                b.copy_from_slice(&nh[..16]);
                                Some(IpAddr::V6(Ipv6Addr::from(b)))
                            }
                            (false, 4) => {
                                Some(IpAddr::V4(Ipv4Addr::new(nh[0], nh[1], nh[2], nh[3])))
                            }
                            _ => return Err(DecodeError::Malformed("MP_REACH next hop length")),
                        };
                        decode_prefixes(a.rest(), v6, &mut u.nlri)?;
                    }
                    _ => u.other_attributes += 1,
                }
            }
            ATTR_MP_UNREACH => {
                let afi = a.u16()?;
                let safi = a.u8()?;
                match (afi_is_v6(afi), safi) {
                    (Some(v6), SAFI_UNICAST) => decode_prefixes(a.rest(), v6, &mut u.withdrawn)?,
                    _ => u.other_attributes += 1,
                }
            }
            _ => u.other_attributes += 1,
        }
    }
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(four: bool) -> AnnounceParams {
        AnnounceParams {
            local_asn: 64500,
            four_octet_as: four,
            next_hop_v4: Ipv4Addr::new(192, 0, 2, 1),
            next_hop_v6: "100::1".parse().unwrap(),
            communities: blackhole_communities(&["64496:666".parse().unwrap()]),
        }
    }

    fn body(msg: &[u8]) -> &[u8] {
        let (len, _) = decode_header(msg).unwrap();
        assert_eq!(len, msg.len());
        &msg[HEADER_LEN..]
    }

    #[test]
    fn community_parse_and_display() {
        let c: Community = "65535:666".parse().unwrap();
        assert_eq!(c, Community::BLACKHOLE);
        assert_eq!(c.to_string(), "65535:666");
        assert!("65536:1".parse::<Community>().is_err());
        assert!("666".parse::<Community>().is_err());
        assert!("a:b".parse::<Community>().is_err());
    }

    #[test]
    fn communities_always_start_with_blackhole_and_dedupe() {
        let c = blackhole_communities(&[Community::BLACKHOLE, Community((64496 << 16) | 666)]);
        assert_eq!(
            c,
            vec![
                Community::BLACKHOLE,
                Community::NO_EXPORT,
                Community((64496 << 16) | 666)
            ]
        );
    }

    #[test]
    fn keepalive_is_exactly_a_header() {
        let k = encode_keepalive();
        assert_eq!(k.len(), 19);
        assert_eq!(decode_header(&k), Ok((19, MSG_KEEPALIVE)));
    }

    #[test]
    fn header_rejects_bad_input() {
        let mut k = encode_keepalive();
        k[0] = 0;
        assert_eq!(decode_header(&k), Err(DecodeError::BadMarker));
        let mut k = encode_keepalive();
        k[18] = 9;
        assert_eq!(decode_header(&k), Err(DecodeError::BadType(9)));
        let mut k = encode_keepalive();
        k[16] = 0x10; // length 4115
        assert!(matches!(decode_header(&k), Err(DecodeError::BadLength(_))));
        let mut k = encode_keepalive();
        k[17] = 18;
        assert!(matches!(decode_header(&k), Err(DecodeError::BadLength(18))));
        let mut k = encode_keepalive();
        k[17] = 20; // keepalive with a body
        assert!(matches!(decode_header(&k), Err(DecodeError::BadLength(20))));
        assert_eq!(decode_header(&[0xFF; 10]), Err(DecodeError::Truncated));
    }

    #[test]
    fn open_roundtrip_two_and_four_octet() {
        let msg = encode_open(64500, 90, Ipv4Addr::new(192, 0, 2, 10));
        let o = decode_open(body(&msg)).unwrap();
        assert_eq!(o.version, 4);
        assert_eq!(o.asn, 64500);
        assert_eq!(o.hold_time, 90);
        assert_eq!(o.router_id, Ipv4Addr::new(192, 0, 2, 10));
        assert!(o.four_octet_as && o.ipv4_unicast && o.ipv6_unicast);

        let msg = encode_open(65536, 90, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(&msg[20..22], &(AS_TRANS as u16).to_be_bytes());
        assert_eq!(decode_open(body(&msg)).unwrap().asn, 65536);
    }

    #[test]
    fn open_with_flowspec_and_graceful_restart() {
        let opts = OpenOptions {
            flowspec: true,
            graceful_restart: Some((120, true)),
        };
        let msg = encode_open_with(64500, 90, Ipv4Addr::new(192, 0, 2, 10), &opts);
        let o = decode_open(body(&msg)).unwrap();
        assert!(o.ipv4_flowspec && o.ipv6_flowspec && o.ipv4_unicast && o.ipv6_unicast);
        assert_eq!(o.graceful_restart, Some(120));
        assert!(o.supports_flowspec("198.51.100.7".parse().unwrap()));
        // Capability 64: R bit + 120 s, then four AFI/SAFI tuples with the F bit.
        let gr = [64u8, 18, 0x80, 120, 0, 1, 1, 0x80];
        assert!(msg.windows(gr.len()).any(|w| w == gr));
        let plain = encode_open(64500, 90, Ipv4Addr::new(192, 0, 2, 10));
        let plain = decode_open(body(&plain)).unwrap();
        assert!(!plain.ipv4_flowspec && plain.graceful_restart.is_none());
        // GR capability with a bad length is rejected.
        let bad = [4, 0xFB, 0xF4, 0, 90, 192, 0, 2, 1, 5, 2, 3, 64, 1, 0];
        assert!(decode_open(&bad).is_err());
    }

    #[test]
    fn end_of_rib_markers() {
        let v4 = encode_end_of_rib(AFI_IPV4, SAFI_UNICAST);
        assert_eq!(v4.len(), 23);
        let u = decode_update(body(&v4), true).unwrap();
        assert!(u.nlri.is_empty() && u.withdrawn.is_empty());
        let v6 = encode_end_of_rib(AFI_IPV6, SAFI_UNICAST);
        assert_eq!(&v6[HEADER_LEN..], &[0, 0, 0, 6, 0x80, 15, 3, 0, 2, 1]);
        assert!(decode_update(body(&v6), true).unwrap().withdrawn.is_empty());
    }

    #[test]
    fn regional_communities_skip_blackhole() {
        let c = regional_communities(&["64496:6661".parse().unwrap(), Community::NO_EXPORT]);
        assert_eq!(c, vec![Community::NO_EXPORT, "64496:6661".parse().unwrap()]);
    }

    #[test]
    fn open_without_capabilities_defaults_to_ipv4() {
        let body = [4, 0xFB, 0xF0, 0, 180, 192, 0, 2, 1, 0];
        let o = decode_open(&body).unwrap();
        assert_eq!(o.asn, 64496);
        assert!(!o.four_octet_as);
        assert!(o.supports("198.51.100.1".parse().unwrap()));
        assert!(!o.supports("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn open_rejects_truncated_and_bad_capabilities() {
        let msg = encode_open(64500, 90, Ipv4Addr::new(192, 0, 2, 10));
        let b = body(&msg);
        for cut in 0..b.len() {
            assert!(decode_open(&b[..cut]).is_err(), "cut at {cut}");
        }
        // 4-octet AS capability with length 2
        let bad = [4, 0xFB, 0xF4, 0, 90, 192, 0, 2, 1, 6, 2, 4, 65, 2, 0, 1];
        assert_eq!(
            decode_open(&bad),
            Err(DecodeError::Malformed("capability length"))
        );
        // trailing garbage
        let trailing = [4, 0xFB, 0xF4, 0, 90, 192, 0, 2, 1, 0, 0xAA];
        assert!(decode_open(&trailing).is_err());
    }

    #[test]
    fn announce_v4_exact_bytes() {
        let msg = encode_announce("198.51.100.7".parse().unwrap(), &params(true));
        let expected: Vec<u8> = [
            vec![0xFF; 16],
            vec![0x00, 0x3F, 0x02], // len 63, UPDATE
            vec![0x00, 0x00],       // no withdrawn
            vec![0x00, 0x23],       // 35 bytes of attributes
            vec![0x40, 0x01, 0x01, 0x00],
            vec![0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xFB, 0xF4],
            vec![0x40, 0x03, 0x04, 192, 0, 2, 1],
            vec![0xC0, 0x08, 0x0C],
            vec![
                0xFF, 0xFF, 0x02, 0x9A, 0xFF, 0xFF, 0xFF, 0x01, 0xFB, 0xF0, 0x02, 0x9A,
            ],
            vec![0x20, 198, 51, 100, 7],
        ]
        .concat();
        assert_eq!(msg, expected);
    }

    #[test]
    fn announce_v4_roundtrip() {
        let msg = encode_announce("198.51.100.7".parse().unwrap(), &params(true));
        let u = decode_update(body(&msg), true).unwrap();
        assert_eq!(u.origin, Some(0));
        assert_eq!(u.as_path, vec![64500]);
        assert_eq!(u.next_hop, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(u.nlri, vec!["198.51.100.7/32".parse::<IpNet>().unwrap()]);
        assert_eq!(u.communities.len(), 3);
        assert!(u.withdrawn.is_empty());
    }

    #[test]
    fn announce_two_octet_as_path() {
        let msg = encode_announce("198.51.100.7".parse().unwrap(), &params(false));
        let u = decode_update(body(&msg), false).unwrap();
        assert_eq!(u.as_path, vec![64500]);
    }

    #[test]
    fn announce_v6_uses_mp_reach() {
        let msg = encode_announce("2001:db8:100::7".parse().unwrap(), &params(true));
        let u = decode_update(body(&msg), true).unwrap();
        assert_eq!(u.next_hop, Some("100::1".parse().unwrap()));
        assert_eq!(
            u.nlri,
            vec!["2001:db8:100::7/128".parse::<IpNet>().unwrap()]
        );
        assert_eq!(u.communities[0], Community::BLACKHOLE);
    }

    #[test]
    fn withdraw_roundtrip_v4_and_v6() {
        let msg = encode_withdraw("198.51.100.7".parse().unwrap());
        assert_eq!(msg.len(), 28);
        let u = decode_update(body(&msg), true).unwrap();
        assert_eq!(
            u.withdrawn,
            vec!["198.51.100.7/32".parse::<IpNet>().unwrap()]
        );
        assert!(u.nlri.is_empty());

        let msg = encode_withdraw("2001:db8:100::7".parse().unwrap());
        let u = decode_update(body(&msg), true).unwrap();
        assert_eq!(
            u.withdrawn,
            vec!["2001:db8:100::7/128".parse::<IpNet>().unwrap()]
        );
    }

    #[test]
    fn update_decoder_never_panics_on_truncation() {
        for ip in ["198.51.100.7", "2001:db8:100::7"] {
            let msg = encode_announce(ip.parse().unwrap(), &params(true));
            let b = body(&msg);
            for cut in 0..b.len() {
                let _ = decode_update(&b[..cut], true);
                let _ = decode_update(&b[..cut], false);
            }
        }
    }

    #[test]
    fn update_decoder_rejects_malformed() {
        // withdrawn length larger than the body
        assert_eq!(decode_update(&[0, 9, 0], true), Err(DecodeError::Truncated));
        // prefix length 33
        assert_eq!(
            decode_update(&[0, 5, 33, 1, 2, 3, 4, 0, 0], true),
            Err(DecodeError::Malformed("prefix length"))
        );
        // ORIGIN with length 2
        assert_eq!(
            decode_update(&[0, 0, 0, 5, 0x40, 1, 2, 0, 0], true),
            Err(DecodeError::Malformed("ORIGIN length"))
        );
        // AS_PATH with segment type 9
        assert_eq!(
            decode_update(&[0, 0, 0, 5, 0x40, 2, 2, 9, 0], true),
            Err(DecodeError::Malformed("AS_PATH segment type"))
        );
        // COMMUNITIES with length 3
        assert_eq!(
            decode_update(&[0, 0, 0, 6, 0xC0, 8, 3, 0, 0, 0], true),
            Err(DecodeError::Malformed("COMMUNITIES length"))
        );
        // attribute length running past the attribute block
        assert_eq!(
            decode_update(&[0, 0, 0, 4, 0x40, 1, 9, 0], true),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn update_decoder_counts_unknown_attributes() {
        let u = decode_update(&[0, 0, 0, 5, 0xC0, 99, 2, 0xAB, 0xCD], true).unwrap();
        assert_eq!(u.other_attributes, 1);
    }

    #[test]
    fn notification_roundtrip_and_truncation() {
        let msg = encode_notification(6, 2, b"bye");
        let n = decode_notification(body(&msg)).unwrap();
        assert_eq!(
            n,
            Notification {
                code: 6,
                subcode: 2
            }
        );
        assert_eq!(decode_notification(&[6]), Err(DecodeError::Truncated));
    }
}
