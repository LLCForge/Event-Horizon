//! Bounds-checked big-endian reader shared by the BGP and sFlow parsers.
//! Every accessor returns `Err(Truncated)` instead of panicking on short input.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let end = self.pos.checked_add(n).ok_or(Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(Truncated)?;
        self.pos = end;
        Ok(out)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }

    pub fn u8(&mut self) -> Result<u8, Truncated> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Truncated> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, Truncated> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_rejects_short_input() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.u16(), Ok(0x0203));
        assert_eq!(r.u32(), Err(Truncated));
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.take(usize::MAX), Err(Truncated));
        assert_eq!(r.rest(), &[0x04, 0x05]);
        assert!(r.is_empty());
    }
}
