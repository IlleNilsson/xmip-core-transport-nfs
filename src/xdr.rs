//! XDR (RFC 4506): what ONC RPC and NFS say their bytes in. Big-endian
//! integers four and eight bytes wide, a boolean as a whole integer, opaque
//! data counted and padded to a multiple of four, a string as opaque
//! bytes. Nothing here knows which procedure is being spoken.

use transport::error::{Result, protocol_error};

/// A reader over one XDR-encoded buffer, moving forward and never past the
/// end.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// True once every byte has been taken.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    /// The bytes not yet taken.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at.min(self.bytes.len())..]
    }

    /// One unsigned 32-bit integer.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.fixed(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// One unsigned 64-bit integer.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn u64(&mut self) -> Result<u64> {
        let high = u64::from(self.u32()?);
        let low = u64::from(self.u32()?);
        Ok((high << 32) | low)
    }

    /// One boolean: zero is false, anything else true.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u32()? != 0)
    }

    /// Exactly `count` bytes, padded to four in the buffer.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn fixed(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| protocol_error("XDR data cut short"))?;
        let taken = &self.bytes[self.at..end];
        self.at = end + padding(count);
        Ok(taken)
    }

    /// Counted opaque bytes: a length, then that many bytes padded to four.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn opaque(&mut self) -> Result<&'a [u8]> {
        let count = self.u32()? as usize;
        self.fixed(count)
    }

    /// A string: counted opaque bytes read as UTF-8, lossily.
    ///
    /// # Errors
    /// Where the buffer ends first.
    pub fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.opaque()?).into_owned())
    }
}

/// The bytes that pad `count` to a multiple of four.
const fn padding(count: usize) -> usize {
    (4 - count % 4) % 4
}

/// Append one unsigned 32-bit integer.
pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Append one unsigned 64-bit integer.
pub fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Append one boolean.
pub fn put_bool(out: &mut Vec<u8>, value: bool) {
    put_u32(out, u32::from(value));
}

/// Append fixed-length bytes, padded to four.
pub fn put_fixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
    out.extend(std::iter::repeat_n(0, padding(bytes.len())));
}

/// Append counted opaque bytes: the length, then the bytes padded to four.
pub fn put_opaque(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    put_fixed(out, bytes);
}

/// Append a string as counted opaque bytes.
pub fn put_string(out: &mut Vec<u8>, text: &str) {
    put_opaque(out, text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_put_is_read_back_in_order_with_its_padding() {
        let mut out = Vec::new();
        put_u32(&mut out, 7);
        put_u64(&mut out, 1 << 40);
        put_bool(&mut out, true);
        put_opaque(&mut out, b"abcde");
        put_string(&mut out, "x");
        put_fixed(&mut out, &[1, 2, 3]);
        assert_eq!(out.len(), 4 + 8 + 4 + 12 + 8 + 4);
        let mut reader = Reader::new(&out);
        assert_eq!(reader.u32().expect("u32"), 7);
        assert_eq!(reader.u64().expect("u64"), 1 << 40);
        assert!(reader.bool().expect("bool"));
        assert_eq!(reader.opaque().expect("opaque"), b"abcde");
        assert_eq!(reader.string().expect("string"), "x");
        assert_eq!(reader.fixed(3).expect("fixed"), &[1, 2, 3]);
        assert!(reader.is_empty());
        assert!(reader.rest().is_empty());
    }

    #[test]
    fn a_buffer_that_ends_early_is_a_protocol_error() {
        let mut reader = Reader::new(&[0, 0, 0, 9, b'a']);
        let error = reader.opaque().expect_err("cut short");
        assert!(!error.retryable);
        assert!(Reader::new(&[0, 0]).u32().is_err());
        assert_eq!(padding(0), 0);
        assert_eq!(padding(5), 3);
    }
}
