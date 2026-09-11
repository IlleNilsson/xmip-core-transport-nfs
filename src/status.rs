//! `nfsstat3` (RFC 1813 section 2.6): the status that opens every result,
//! the few this crate answers with, and what each means to a caller —
//! including the one that means try again.

use transport::error::{Result, TransportError};

use crate::xdr::Reader;

/// `NFS3_OK`.
pub const OK: u32 = 0;
/// `NFS3ERR_NOENT`: no such file.
pub const NOENT: u32 = 2;
/// `NFS3ERR_ACCES`: not permitted.
pub const ACCES: u32 = 13;
/// `NFS3ERR_FBIG`: too big a file.
pub const FBIG: u32 = 27;
/// `NFS3ERR_STALE`: a handle to something gone.
pub const STALE: u32 = 70;
/// `NFS3ERR_JUKEBOX`: not now, later.
pub const JUKEBOX: u32 = 10008;

/// The failure a status names, for a message: retryable only where the
/// server said later.
#[must_use]
pub fn status_error(what: &str, status: u32) -> TransportError {
    let name = match status {
        1 => "not permitted",
        NOENT => "no such file or directory",
        5 => "an I/O error",
        ACCES => "access denied",
        17 => "it exists already",
        20 => "not a directory",
        21 => "a directory",
        FBIG => "too big a file",
        28 => "no space left",
        30 => "a read-only file system",
        STALE => "a stale file handle",
        10001 => "a bad file handle",
        10004 => "not supported",
        JUKEBOX => "try again later",
        _ => "an error",
    };
    let message = format!("{what}: NFS status {status}, {name}");
    if status == JUKEBOX {
        TransportError::retryable(message)
    } else {
        TransportError::permanent(message)
    }
}

/// Read the status that opens a result, and stop where it is not OK.
///
/// # Errors
/// The failure the status names.
pub fn expect_ok(reader: &mut Reader<'_>, what: &str) -> Result<()> {
    match reader.u32()? {
        OK => Ok(()),
        other => Err(status_error(what, other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_names_its_failure_and_only_the_jukebox_is_retryable() {
        let missing = status_error("reading", NOENT);
        assert_eq!(
            missing.message,
            "reading: NFS status 2, no such file or directory"
        );
        assert!(!missing.retryable);
        assert!(status_error("writing", JUKEBOX).retryable);
        assert!(status_error("x", 999).message.ends_with("an error"));
        expect_ok(&mut Reader::new(&[0, 0, 0, 0]), "ok").expect("ok");
        assert!(expect_ok(&mut Reader::new(&[0, 0, 0, 13]), "no").is_err());
    }
}
