//! `fattr3` (RFC 1813 section 2.6) as far as a Location reads it: the
//! length and modification time that say a file lies unchanged, carried
//! in the `post_op_attr` a `LOOKUP` answers with. Every other attribute is
//! written plainly by this crate's far end and read past by its client.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::Result;

use crate::xdr::{Xdr, XdrWrite};

/// `NF3REG`: a regular file.
const REGULAR: u32 = 1;
/// Where `size` and `mtime` lie in the eighty-four bytes of an `fattr3`.
const SIZE: usize = 20;
const MTIME: usize = 68;
/// How long an `fattr3` is.
const FATTR3: usize = 84;

/// What says a file is unchanged: its length, and its modification time in
/// seconds and nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp {
    pub length: u64,
    pub modified: (u32, u32),
}

/// A `post_op_attr`: the attributes of a regular file stamped `stamp`, or
/// none.
pub fn put(out: &mut Vec<u8>, stamp: Option<Stamp>) {
    out.bool(stamp.is_some());
    let Some(Stamp { length, modified }) = stamp else {
        return;
    };
    // Type, mode, links, owner and group.
    for field in [REGULAR, 0o644, 1, 0, 0] {
        out.u32_be(field);
    }
    // Size, space used, the device, the file system and the file id.
    out.u64_be(length)
        .u64_be(length)
        .u64_be(0)
        .u64_be(0)
        .u64_be(0);
    // Accessed, modified and changed at once.
    for _ in 0..3 {
        out.u32_be(modified.0).u32_be(modified.1);
    }
}

/// The stamp a `post_op_attr` carries, `None` where it carries none.
///
/// # Errors
/// Where the attributes are cut short.
pub fn take(reader: &mut Cursor<'_>) -> Result<Option<Stamp>> {
    if !reader.bool()? {
        return Ok(None);
    }
    let mut fattr = Cursor::new(reader.fixed(FATTR3)?);
    fattr.take(SIZE)?;
    let length = fattr.u64_be()?;
    fattr.take(MTIME - SIZE - 8)?;
    let modified = (fattr.u32_be()?, fattr.u32_be()?);
    Ok(Some(Stamp { length, modified }))
}

/// When each file on a far end's export was last written, each write
/// after the one before it, so a file written again lists as changed
/// however soon.
#[derive(Default)]
pub struct Written {
    at: BTreeMap<String, (u32, u32)>,
    newest: (u32, u32),
}

impl Written {
    /// Note `name` written now.
    pub fn touch(&mut self, name: &str) {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let now = (
            u32::try_from(since.as_secs()).unwrap_or(u32::MAX),
            since.subsec_nanos(),
        );
        let after = match self.newest {
            (seconds, 999_999_999) => (seconds.saturating_add(1), 0),
            (seconds, nanoseconds) => (seconds, nanoseconds + 1),
        };
        self.newest = now.max(after);
        self.at.insert(name.to_string(), self.newest);
    }

    /// Forget `name`, removed.
    pub fn forget(&mut self, name: &str) {
        self.at.remove(name);
    }

    /// When `name` was last written; never, for a file the export was
    /// given.
    #[must_use]
    pub fn at(&self, name: &str) -> (u32, u32) {
        self.at.get(name).copied().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stamp_reads_back_off_its_attributes_and_none_is_none() {
        let stamp = Stamp {
            length: (7 << 32) | 9,
            modified: (11, 13),
        };
        let mut out = Vec::new();
        put(&mut out, Some(stamp));
        put(&mut out, None);
        assert_eq!(out.len(), 4 + FATTR3 + 4);
        let mut reader = Cursor::new(&out);
        assert_eq!(take(&mut reader).expect("stamped"), Some(stamp));
        assert_eq!(take(&mut reader).expect("none"), None);
    }

    #[test]
    fn a_file_written_again_is_written_later_even_at_once() {
        let mut written = Written::default();
        written.touch("a.edi");
        let first = written.at("a.edi");
        assert!(first.0 > 0, "written now");
        written.touch("a.edi");
        assert!(written.at("a.edi") > first);
        written.forget("a.edi");
        assert_eq!(written.at("a.edi"), (0, 0));
    }
}
