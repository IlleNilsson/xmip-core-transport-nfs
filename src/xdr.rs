//! XDR (RFC 4506): what ONC RPC and NFS say their bytes in. Big-endian
//! integers four and eight bytes wide (codec's `u32_be` and `u64_be`), a
//! boolean as a whole integer, opaque data counted and padded to a multiple
//! of four, a string as opaque bytes. What is XDR's own is written here over
//! codec's cursor and writer; nothing here knows which procedure is being
//! spoken.

use codec::Result;
use codec::cursor::Cursor;
use codec::writer::ByteWriter;

/// Reading XDR's own fields off codec's cursor.
pub trait Xdr<'a> {
    /// One boolean: zero is false, anything else true.
    ///
    /// # Errors
    /// Where the buffer ends first.
    fn bool(&mut self) -> Result<bool>;

    /// Exactly `count` bytes and the padding that takes them to a multiple
    /// of four. A pad that is not there is refused, and the cursor does not
    /// move; what the pad bytes hold is not checked.
    ///
    /// # Errors
    /// Where the buffer ends before the bytes or their padding.
    fn fixed(&mut self, count: usize) -> Result<&'a [u8]>;

    /// Counted opaque bytes: a length, then that many bytes padded to four.
    ///
    /// # Errors
    /// Where the buffer ends first.
    fn opaque(&mut self) -> Result<&'a [u8]>;

    /// A string: counted opaque bytes read as UTF-8, lossily.
    ///
    /// # Errors
    /// Where the buffer ends first.
    fn string(&mut self) -> Result<String>;
}

impl<'a> Xdr<'a> for Cursor<'a> {
    fn bool(&mut self) -> Result<bool> {
        Ok(self.u32_be()? != 0)
    }

    fn fixed(&mut self, count: usize) -> Result<&'a [u8]> {
        let padded = count.saturating_add(padding(count));
        Ok(&self.take(padded)?[..count])
    }

    fn opaque(&mut self) -> Result<&'a [u8]> {
        let count = self.u32_be()? as usize;
        self.fixed(count)
    }

    fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.opaque()?).into_owned())
    }
}

/// Writing XDR's own fields beside codec's [`ByteWriter`].
pub trait XdrWrite {
    /// One boolean.
    fn bool(&mut self, value: bool) -> &mut Self;

    /// Fixed-length bytes, padded to four.
    fn fixed(&mut self, bytes: &[u8]) -> &mut Self;

    /// Counted opaque bytes: the length, then the bytes padded to four.
    fn opaque(&mut self, bytes: &[u8]) -> &mut Self;

    /// A string as counted opaque bytes.
    fn string(&mut self, text: &str) -> &mut Self;
}

impl XdrWrite for Vec<u8> {
    fn bool(&mut self, value: bool) -> &mut Self {
        self.u32_be(u32::from(value))
    }

    fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.extend_from_slice(bytes);
        self.extend(std::iter::repeat_n(0, padding(bytes.len())));
        self
    }

    fn opaque(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32_be(u32::try_from(bytes.len()).unwrap_or(u32::MAX))
            .fixed(bytes)
    }

    fn string(&mut self, text: &str) -> &mut Self {
        self.opaque(text.as_bytes())
    }
}

/// The bytes that pad `count` to a multiple of four.
const fn padding(count: usize) -> usize {
    (4 - count % 4) % 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_put_is_read_back_in_order_with_its_padding() {
        let mut out = Vec::new();
        out.u32_be(7)
            .u64_be(1 << 40)
            .bool(true)
            .opaque(b"abcde")
            .string("x")
            .fixed(&[1, 2, 3]);
        assert_eq!(out.len(), 4 + 8 + 4 + 12 + 8 + 4);
        let mut reader = Cursor::new(&out);
        assert_eq!(reader.u32_be().expect("u32"), 7);
        assert_eq!(reader.u64_be().expect("u64"), 1 << 40);
        assert!(reader.bool().expect("bool"));
        assert_eq!(reader.opaque().expect("opaque"), b"abcde");
        assert_eq!(reader.string().expect("string"), "x");
        assert_eq!(reader.fixed(3).expect("fixed"), &[1, 2, 3]);
        assert!(reader.is_empty());
        assert!(reader.remaining().is_empty());
    }

    #[test]
    fn a_buffer_that_ends_early_is_a_protocol_error() {
        let mut reader = Cursor::new(&[0, 0, 0, 9, b'a']);
        let error = transport::TransportError::from(reader.opaque().expect_err("cut short"));
        assert!(!error.retryable);
        assert!(error.message.contains("runs past"), "{error}");
        assert!(Cursor::new(&[0, 0]).u32_be().is_err());
        assert_eq!(padding(0), 0);
        assert_eq!(padding(5), 3);
    }

    #[test]
    fn a_missing_pad_is_refused_and_moves_nothing() {
        let mut reader = Cursor::new(&[1, 2, 3]);
        assert!(reader.fixed(3).is_err(), "three bytes with no pad");
        assert_eq!(reader.position(), 0);
        assert_eq!(
            Cursor::new(&[1, 2, 3, 0]).fixed(3).expect("padded"),
            &[1, 2, 3]
        );
    }
}
