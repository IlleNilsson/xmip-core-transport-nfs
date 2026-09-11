//! The mount program, version 3 (RFC 1813 appendix I): `MNT` hands out
//! the root handle of an export, `UMNT` says it is no longer in use.
//! Spoken on the same connection as NFS here.

use transport::error::Result;

use crate::procedure::Handle;
use crate::status::{OK, expect_ok};
use crate::xdr::{self, Reader};

/// `MOUNTPROC3_MNT`.
pub const MNT: u32 = 1;
/// `MOUNTPROC3_UMNT`.
pub const UMNT: u32 = 3;

/// `MNT` arguments and `UMNT` arguments: the export's path.
#[must_use]
pub fn args(export: &str) -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_string(&mut out, export);
    out
}

/// The path a `MNT` or `UMNT` names.
///
/// # Errors
/// Where the arguments are cut short.
pub fn take_args(arguments: &[u8]) -> Result<String> {
    Reader::new(arguments).string()
}

/// A successful `MNT` result: the root handle, `AUTH_UNIX` the one flavor.
#[must_use]
pub fn ok(root: &Handle) -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_u32(&mut out, OK);
    root.put(&mut out);
    xdr::put_u32(&mut out, 1);
    xdr::put_u32(&mut out, 1);
    out
}

/// A failed `MNT` result: the errno.
#[must_use]
pub fn failure(status: u32) -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_u32(&mut out, status);
    out
}

/// The root handle a `MNT` result carries.
///
/// # Errors
/// Where the mount was refused.
pub fn take(results: &[u8]) -> Result<Handle> {
    let mut reader = Reader::new(results);
    expect_ok(&mut reader, "mounting")?;
    Handle::take(&mut reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::ACCES;

    #[test]
    fn a_mount_names_its_export_and_answers_with_the_root_or_an_errno() {
        assert_eq!(take_args(&args("/orders")).expect("path"), "/orders");
        let root = Handle(vec![0]);
        assert_eq!(take(&ok(&root)).expect("root"), root);
        let error = take(&failure(ACCES)).expect_err("refused");
        assert!(error.message.contains("access denied"), "{error}");
        let mut long = Vec::new();
        xdr::put_u32(&mut long, OK);
        xdr::put_opaque(&mut long, &[1; 65]);
        assert!(take(&long).is_err(), "over sixty-four bytes");
    }
}
