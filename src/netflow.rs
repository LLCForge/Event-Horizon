//! NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) collector with template caching.
//!
//! Templates are cached per (exporter address, source id / observation
//! domain, version, template id), so exporters and domains can never overwrite
//! each other's templates. The cache is bounded; data sets whose template is
//! unknown are counted and skipped. Option templates are ignored; the sampling
//! rate comes from a per-record sampling interval field when present, else
//! from the configured `sampling_rate`. Malformed input yields an error, never
//! a panic.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::flow::FlowSample;
use crate::wire::{Reader, Truncated};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetflowError {
    #[error("datagram truncated")]
    Truncated,
    #[error("unsupported NetFlow version {0}")]
    Version(u16),
    #[error("malformed {0}")]
    Malformed(&'static str),
}

impl From<Truncated> for NetflowError {
    fn from(_: Truncated) -> Self {
        NetflowError::Truncated
    }
}

const MAX_FIELDS: usize = 256;
const VARIABLE: u16 = 65_535;

// Information elements (identical numbers in NetFlow v9 and IPFIX).
const IE_BYTES: u16 = 1;
const IE_PACKETS: u16 = 2;
const IE_PROTOCOL: u16 = 4;
const IE_TCP_FLAGS: u16 = 6;
const IE_SRC_PORT: u16 = 7;
const IE_SRC_V4: u16 = 8;
const IE_DST_PORT: u16 = 11;
const IE_DST_V4: u16 = 12;
const IE_SRC_AS: u16 = 16;
const IE_SRC_V6: u16 = 27;
const IE_DST_V6: u16 = 28;
const IE_SAMPLING_INTERVAL: u16 = 34;
const IE_OCTET_TOTAL: u16 = 85;
const IE_PACKET_TOTAL: u16 = 86;
const IE_SAMPLING_PACKET_INTERVAL: u16 = 305;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TemplateKey {
    exporter: IpAddr,
    domain: u32,
    version: u16,
    id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Field {
    id: u16,
    len: u16,
    enterprise: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Template {
    fields: Vec<Field>,
    /// Smallest possible record (variable-length fields count as one byte).
    min_len: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub samples: Vec<FlowSample>,
    pub missing_template: usize,
    pub rejected_templates: usize,
}

pub struct Collector {
    templates: HashMap<TemplateKey, Template>,
    max_templates: usize,
    sampling_rate: u32,
}

fn be(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0u64, |a, x| (a << 8) | u64::from(*x))
}

impl Collector {
    pub fn new(max_templates: usize, sampling_rate: u32) -> Self {
        Self {
            templates: HashMap::new(),
            max_templates,
            sampling_rate: sampling_rate.max(1),
        }
    }

    pub fn templates(&self) -> usize {
        self.templates.len()
    }

    pub fn parse(&mut self, exporter: IpAddr, buf: &[u8]) -> Result<Parsed, NetflowError> {
        let mut r = Reader::new(buf);
        let version = r.u16()?;
        match version {
            9 => {
                let _count = r.u16()?;
                r.take(12)?; // uptime, unix secs, sequence
                let domain = r.u32()?;
                self.sets(exporter, domain, 9, r.rest())
            }
            10 => {
                let len = usize::from(r.u16()?);
                if len < 16 || len > buf.len() {
                    return Err(NetflowError::Malformed("IPFIX message length"));
                }
                r.take(8)?; // export time, sequence
                let domain = r.u32()?;
                self.sets(exporter, domain, 10, &buf[16..len])
            }
            v => Err(NetflowError::Version(v)),
        }
    }

    fn sets(
        &mut self,
        exporter: IpAddr,
        domain: u32,
        version: u16,
        buf: &[u8],
    ) -> Result<Parsed, NetflowError> {
        let (tmpl_set, opt_set) = if version == 9 { (0, 1) } else { (2, 3) };
        let mut out = Parsed::default();
        let mut r = Reader::new(buf);
        // Trailing bytes shorter than a set header are padding.
        while r.remaining() >= 4 {
            let id = r.u16()?;
            let len = usize::from(r.u16()?);
            if len < 4 {
                return Err(NetflowError::Malformed("set length"));
            }
            let body = r.take(len - 4)?;
            let key = |id| TemplateKey {
                exporter,
                domain,
                version,
                id,
            };
            if id == tmpl_set {
                self.templates_set(body, version, &key, &mut out)?;
            } else if id == opt_set || id < 256 {
                continue;
            } else {
                match self.templates.get(&key(id)) {
                    Some(t) => self.data_set(body, t, &mut out.samples)?,
                    None => out.missing_template += 1,
                }
            }
        }
        Ok(out)
    }

    fn templates_set(
        &mut self,
        body: &[u8],
        version: u16,
        key: &dyn Fn(u16) -> TemplateKey,
        out: &mut Parsed,
    ) -> Result<(), NetflowError> {
        let mut r = Reader::new(body);
        while r.remaining() >= 4 {
            let tid = r.u16()?;
            let count = usize::from(r.u16()?);
            if tid < 256 {
                return Err(NetflowError::Malformed("template id"));
            }
            if count == 0 {
                // IPFIX template withdrawal.
                self.templates.remove(&key(tid));
                continue;
            }
            if count > MAX_FIELDS {
                return Err(NetflowError::Malformed("template field count"));
            }
            let mut fields = Vec::with_capacity(count);
            let mut min_len = 0usize;
            for _ in 0..count {
                let raw = r.u16()?;
                let len = r.u16()?;
                let enterprise = version == 10 && raw & 0x8000 != 0;
                if enterprise {
                    r.u32()?;
                }
                if len == 0 || (len == VARIABLE && version == 9) {
                    return Err(NetflowError::Malformed("template field length"));
                }
                min_len += if len == VARIABLE { 1 } else { usize::from(len) };
                fields.push(Field {
                    id: raw & 0x7FFF,
                    len,
                    enterprise,
                });
            }
            let k = key(tid);
            if !self.templates.contains_key(&k) && self.templates.len() >= self.max_templates {
                out.rejected_templates += 1;
                continue;
            }
            self.templates.insert(k, Template { fields, min_len });
        }
        Ok(())
    }

    fn data_set(
        &self,
        body: &[u8],
        t: &Template,
        out: &mut Vec<FlowSample>,
    ) -> Result<(), NetflowError> {
        let mut r = Reader::new(body);
        while r.remaining() >= t.min_len.max(1) {
            let mut v = Values::default();
            for f in &t.fields {
                let len = if f.len == VARIABLE {
                    match r.u8()? {
                        255 => usize::from(r.u16()?),
                        n => usize::from(n),
                    }
                } else {
                    usize::from(f.len)
                };
                let b = r.take(len)?;
                if !f.enterprise {
                    v.set(f.id, b);
                }
            }
            if let Some(s) = v.sample(self.sampling_rate) {
                out.push(s);
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Values {
    dst: Option<IpAddr>,
    src: Option<IpAddr>,
    bytes: Option<u64>,
    packets: Option<u64>,
    protocol: Option<u8>,
    tcp_flags: Option<u8>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    src_as: Option<u32>,
    sampling: Option<u64>,
}

fn v4(b: &[u8]) -> Option<IpAddr> {
    <[u8; 4]>::try_from(b)
        .ok()
        .map(|a| IpAddr::V4(Ipv4Addr::from(a)))
}

fn v6(b: &[u8]) -> Option<IpAddr> {
    <[u8; 16]>::try_from(b)
        .ok()
        .map(|a| IpAddr::V6(Ipv6Addr::from(a)))
}

impl Values {
    fn set(&mut self, id: u16, b: &[u8]) {
        match id {
            IE_BYTES => self.bytes = Some(be(b)),
            IE_OCTET_TOTAL => self.bytes = self.bytes.or(Some(be(b))),
            IE_PACKETS => self.packets = Some(be(b)),
            IE_PACKET_TOTAL => self.packets = self.packets.or(Some(be(b))),
            IE_PROTOCOL => self.protocol = Some(be(b) as u8),
            IE_TCP_FLAGS => self.tcp_flags = Some(be(b) as u8),
            IE_SRC_PORT => self.src_port = u16::try_from(be(b)).ok(),
            IE_DST_PORT => self.dst_port = u16::try_from(be(b)).ok(),
            IE_SRC_V4 => self.src = self.src.or(v4(b)),
            IE_DST_V4 => self.dst = self.dst.or(v4(b)),
            IE_SRC_V6 => self.src = self.src.or(v6(b)),
            IE_DST_V6 => self.dst = self.dst.or(v6(b)),
            IE_SRC_AS => self.src_as = u32::try_from(be(b)).ok().filter(|a| *a != 0),
            IE_SAMPLING_INTERVAL | IE_SAMPLING_PACKET_INTERVAL => {
                self.sampling = Some(be(b)).filter(|s| *s > 0)
            }
            _ => {}
        }
    }

    fn sample(self, default_rate: u32) -> Option<FlowSample> {
        let dst = self.dst?;
        let packets = self.packets.filter(|p| *p > 0)?;
        let rate = self
            .sampling
            .map_or(u64::from(default_rate), |s| s.min(1 << 24));
        let mut f = FlowSample::new(
            dst,
            packets.saturating_mul(rate),
            self.bytes.unwrap_or(0).saturating_mul(rate),
        );
        f.src = self.src;
        f.protocol = self.protocol;
        f.src_port = self.src_port;
        f.dst_port = self.dst_port;
        f.tcp_flags = self.tcp_flags;
        f.src_asn = self.src_as;
        Some(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXP: &str = "192.0.2.21";

    fn exp() -> IpAddr {
        EXP.parse().unwrap()
    }

    fn set(id: u16, body: &[u8]) -> Vec<u8> {
        let mut s = id.to_be_bytes().to_vec();
        s.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        s.extend_from_slice(body);
        s
    }

    fn v9(domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let mut d = vec![0, 9, 0, sets.len() as u8];
        d.extend_from_slice(&[0; 12]);
        d.extend_from_slice(&domain.to_be_bytes());
        for s in sets {
            d.extend_from_slice(s);
        }
        d
    }

    fn ipfix(domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = sets.concat();
        let mut d = vec![0, 10];
        d.extend_from_slice(&((16 + body.len()) as u16).to_be_bytes());
        d.extend_from_slice(&[0; 8]);
        d.extend_from_slice(&domain.to_be_bytes());
        d.extend_from_slice(&body);
        d
    }

    /// Template 256: src v4, dst v4, proto, sport, dport, packets (4), bytes (4), src AS (4).
    fn v4_template(set_id: u16) -> Vec<u8> {
        let fields: [(u16, u16); 8] = [
            (8, 4),
            (12, 4),
            (4, 1),
            (7, 2),
            (11, 2),
            (2, 4),
            (1, 4),
            (16, 4),
        ];
        let mut t = vec![1, 0, 0, fields.len() as u8];
        for (id, len) in fields {
            t.extend_from_slice(&id.to_be_bytes());
            t.extend_from_slice(&len.to_be_bytes());
        }
        set(set_id, &t)
    }

    fn v4_record(dst: [u8; 4], sport: u16, pkts: u32, bytes: u32) -> Vec<u8> {
        let mut r = vec![203, 0, 113, 9];
        r.extend_from_slice(&dst);
        r.push(17);
        r.extend_from_slice(&sport.to_be_bytes());
        r.extend_from_slice(&4444u16.to_be_bytes());
        r.extend_from_slice(&pkts.to_be_bytes());
        r.extend_from_slice(&bytes.to_be_bytes());
        r.extend_from_slice(&64511u32.to_be_bytes());
        r
    }

    #[test]
    fn v9_template_then_data_with_padding() {
        let mut c = Collector::new(16, 100);
        let mut data = [
            v4_record([198, 51, 100, 7], 53, 10, 15_000),
            v4_record([198, 51, 100, 8], 123, 2, 900),
        ]
        .concat();
        data.extend_from_slice(&[0, 0, 0]); // padding
        let p = c
            .parse(exp(), &v9(7, &[v4_template(0), set(256, &data)]))
            .unwrap();
        assert_eq!(p.samples.len(), 2);
        let s = p.samples[0];
        assert_eq!(s.dst, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!((s.packets, s.bytes), (1000, 1_500_000)); // scaled by sampling_rate
        assert_eq!(
            (s.protocol, s.src_port, s.src_asn),
            (Some(17), Some(53), Some(64511))
        );
        assert_eq!(c.templates(), 1);
    }

    #[test]
    fn data_before_template_is_counted_and_templates_are_per_domain() {
        let mut c = Collector::new(16, 1);
        let data = set(256, &v4_record([198, 51, 100, 7], 53, 1, 1));
        let p = c.parse(exp(), &v9(7, std::slice::from_ref(&data))).unwrap();
        assert_eq!((p.samples.len(), p.missing_template), (0, 1));
        c.parse(exp(), &v9(7, &[v4_template(0)])).unwrap();
        assert_eq!(
            c.parse(exp(), &v9(7, std::slice::from_ref(&data)))
                .unwrap()
                .samples
                .len(),
            1
        );
        // Same template id from another domain or exporter is a different template.
        assert_eq!(
            c.parse(exp(), &v9(8, std::slice::from_ref(&data)))
                .unwrap()
                .missing_template,
            1
        );
        let other: IpAddr = "192.0.2.22".parse().unwrap();
        assert_eq!(
            c.parse(other, &v9(7, std::slice::from_ref(&data)))
                .unwrap()
                .missing_template,
            1
        );
        // IPFIX with the same domain does not see the v9 template either.
        assert_eq!(
            c.parse(exp(), &ipfix(7, std::slice::from_ref(&data)))
                .unwrap()
                .missing_template,
            1
        );
    }

    #[test]
    fn ipfix_variable_length_enterprise_and_withdrawal() {
        let mut c = Collector::new(16, 1);
        // dst v6, packetDeltaCount (8), enterprise field (var len), samplingPacketInterval (4)
        let mut t = vec![1, 0, 0, 4];
        t.extend_from_slice(&[0, 28, 0, 16]);
        t.extend_from_slice(&[0, 2, 0, 8]);
        t.extend_from_slice(&[0x80, 1, 0xFF, 0xFF, 0, 0, 0x7F, 0xFF]);
        t.extend_from_slice(&[1, 49, 0, 4]); // IE 305
        let mut rec: Vec<u8> = "2001:db8:100::7"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec();
        rec.extend_from_slice(&5u64.to_be_bytes());
        rec.extend_from_slice(&[3, b'a', b'b', b'c']);
        rec.extend_from_slice(&512u32.to_be_bytes());
        let p = c
            .parse(exp(), &ipfix(1, &[set(2, &t), set(256, &rec)]))
            .unwrap();
        assert_eq!(p.samples.len(), 1);
        assert_eq!(
            p.samples[0].dst,
            "2001:db8:100::7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(p.samples[0].packets, 5 * 512);
        // Long variable-length encoding (255 + u16).
        let mut long = rec[..24].to_vec();
        long.extend_from_slice(&[255, 0, 3, b'x', b'y', b'z']);
        long.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            c.parse(exp(), &ipfix(1, &[set(256, &long)]))
                .unwrap()
                .samples[0]
                .packets,
            5
        );
        // Withdrawal (field count 0) removes it.
        c.parse(exp(), &ipfix(1, &[set(2, &[1, 0, 0, 0])])).unwrap();
        assert_eq!(c.templates(), 0);
    }

    #[test]
    fn template_cache_is_bounded() {
        let mut c = Collector::new(1, 1);
        c.parse(exp(), &v9(1, &[v4_template(0)])).unwrap();
        let p = c.parse(exp(), &v9(2, &[v4_template(0)])).unwrap();
        assert_eq!(p.rejected_templates, 1);
        assert_eq!(c.templates(), 1);
        // Refreshing an existing template is always allowed.
        assert_eq!(
            c.parse(exp(), &v9(1, &[v4_template(0)]))
                .unwrap()
                .rejected_templates,
            0
        );
    }

    #[test]
    fn rejects_bad_versions_lengths_and_templates() {
        let mut c = Collector::new(16, 1);
        assert_eq!(c.parse(exp(), &[0, 5, 0, 0]), Err(NetflowError::Version(5)));
        assert!(c
            .parse(exp(), &[0, 10, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .is_err());
        assert!(c.parse(exp(), &v9(1, &[vec![1, 0, 0, 2]])).is_err()); // set length 2
        assert!(c
            .parse(exp(), &v9(1, &[set(0, &[0, 1, 0, 1, 0, 8, 0, 4])]))
            .is_err()); // tid < 256
        assert!(c
            .parse(exp(), &v9(1, &[set(0, &[1, 0, 0, 1, 0, 8, 0, 0])]))
            .is_err()); // len 0
        assert!(c
            .parse(exp(), &v9(1, &[set(0, &[1, 0, 0, 1, 0, 8, 0xFF, 0xFF])]))
            .is_err()); // var in v9
        assert!(c.parse(exp(), &v9(1, &[set(0, &[1, 0, 1, 1])])).is_err()); // 257 fields
    }

    #[test]
    fn truncation_never_panics() {
        let mut c = Collector::new(16, 1);
        let full = v9(
            7,
            &[
                v4_template(0),
                set(256, &v4_record([198, 51, 100, 7], 53, 1, 1)),
            ],
        );
        for cut in 0..full.len() {
            let _ = Collector::new(16, 1).parse(exp(), &full[..cut]);
        }
        c.parse(exp(), &full).unwrap();
        let mut garbage = full.clone();
        for b in garbage.iter_mut().skip(20) {
            *b = 0xFF;
        }
        let _ = c.parse(exp(), &garbage);
    }
}
