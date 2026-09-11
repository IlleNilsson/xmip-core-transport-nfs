//! The NFS version 3 procedures this crate speaks (RFC 1813): the
//! arguments a client puts and a server takes, the results a server puts
//! and a client takes. Attributes are carried as the protocol allows —
//! absent — and skipped where a server sends them: what a Stream needs is
//! the bytes, a name and whether the read is at its end.

use transport::error::{Result, protocol_error};

use crate::status::{OK, expect_ok};
use crate::xdr::{self, Reader};

/// `NFSPROC3_NULL`.
pub const NULL: u32 = 0;
/// `NFSPROC3_LOOKUP`.
pub const LOOKUP: u32 = 3;
/// `NFSPROC3_READ`.
pub const READ: u32 = 6;
/// `NFSPROC3_WRITE`.
pub const WRITE: u32 = 7;
/// `NFSPROC3_CREATE`.
pub const CREATE: u32 = 8;
/// `NFSPROC3_REMOVE`.
pub const REMOVE: u32 = 12;
/// `NFSPROC3_READDIR`.
pub const READDIR: u32 = 16;
/// `NFSPROC3_COMMIT`.
pub const COMMIT: u32 = 21;

/// `FILE_SYNC`: the write is on disk before the reply.
pub const FILE_SYNC: u32 = 2;

/// A file handle: up to sixty-four opaque bytes the server knows.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Handle(pub Vec<u8>);

impl Handle {
    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        xdr::put_opaque(out, &self.0);
    }

    pub(crate) fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let bytes = reader.opaque()?;
        if bytes.len() > 64 {
            return Err(protocol_error("a file handle over sixty-four bytes"));
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// A `post_op_attr` that carries no attributes.
fn put_no_attributes(out: &mut Vec<u8>) {
    xdr::put_bool(out, false);
}

/// Past a `post_op_attr`, whether or not it carries the eighty-four bytes.
fn skip_attributes(reader: &mut Reader<'_>) -> Result<()> {
    if reader.bool()? {
        reader.fixed(84)?;
    }
    Ok(())
}

/// Past a `wcc_data`: the before, twenty-four bytes where present, and the
/// after.
fn skip_wcc(reader: &mut Reader<'_>) -> Result<()> {
    if reader.bool()? {
        reader.fixed(24)?;
    }
    skip_attributes(reader)
}

/// A failed result: the status and the attributes it carries, absent.
#[must_use]
pub fn put_failure(status: u32, procedure: u32) -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_u32(&mut out, status);
    let bools = match procedure {
        WRITE | CREATE | REMOVE | COMMIT => 2,
        _ => 1,
    };
    for _ in 0..bools {
        xdr::put_bool(&mut out, false);
    }
    out
}

/// `diropargs3`: a directory and a name in it — `LOOKUP`, `REMOVE` and
/// the `where` of `CREATE`.
#[must_use]
pub fn dir_args(dir: &Handle, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    dir.put(&mut out);
    xdr::put_string(&mut out, name);
    out
}

/// The directory and name `diropargs3` carry; `CREATE`'s `how` follows
/// and is not read.
///
/// # Errors
/// Where the arguments are cut short.
pub fn take_dir_args(arguments: &[u8]) -> Result<(Handle, String)> {
    let mut reader = Reader::new(arguments);
    Ok((Handle::take(&mut reader)?, reader.string()?))
}

/// `CREATE` arguments: the name, `UNCHECKED`, no attributes set.
#[must_use]
pub fn create_args(dir: &Handle, name: &str) -> Vec<u8> {
    let mut out = dir_args(dir, name);
    xdr::put_u32(&mut out, 0);
    for _ in 0..6 {
        xdr::put_bool(&mut out, false);
    }
    out
}

/// A successful `LOOKUP` or `CREATE` result: the handle, no attributes.
#[must_use]
pub fn handle_ok(handle: &Handle, procedure: u32) -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_u32(&mut out, OK);
    if procedure == CREATE {
        xdr::put_bool(&mut out, true);
    }
    handle.put(&mut out);
    put_no_attributes(&mut out);
    if procedure == CREATE {
        xdr::put_bool(&mut out, false);
    }
    put_no_attributes(&mut out);
    out
}

/// The handle a `LOOKUP` or `CREATE` result carries.
///
/// # Errors
/// Where the call failed, or a `CREATE` came back without a handle.
pub fn take_handle(results: &[u8], procedure: u32) -> Result<Handle> {
    let mut reader = Reader::new(results);
    expect_ok(&mut reader, "looking up")?;
    if procedure == CREATE && !reader.bool()? {
        return Err(protocol_error("the file was created without a handle"));
    }
    Handle::take(&mut reader)
}

/// `READ` arguments.
#[must_use]
pub fn read_args(file: &Handle, offset: u64, count: u32) -> Vec<u8> {
    let mut out = Vec::new();
    file.put(&mut out);
    xdr::put_u64(&mut out, offset);
    xdr::put_u32(&mut out, count);
    out
}

/// The file, offset and count a `READ` asks for.
///
/// # Errors
/// Where the arguments are cut short.
pub fn take_read_args(arguments: &[u8]) -> Result<(Handle, u64, u32)> {
    let mut reader = Reader::new(arguments);
    Ok((Handle::take(&mut reader)?, reader.u64()?, reader.u32()?))
}

/// A successful `READ` result: the bytes, and whether the file ends there.
#[must_use]
pub fn read_ok(data: &[u8], eof: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 24);
    xdr::put_u32(&mut out, OK);
    put_no_attributes(&mut out);
    xdr::put_u32(&mut out, u32::try_from(data.len()).unwrap_or(u32::MAX));
    xdr::put_bool(&mut out, eof);
    xdr::put_opaque(&mut out, data);
    out
}

/// The bytes a `READ` result carries, and whether the file ends there.
///
/// # Errors
/// Where the read failed.
pub fn take_read(results: &[u8]) -> Result<(Vec<u8>, bool)> {
    let mut reader = Reader::new(results);
    expect_ok(&mut reader, "reading")?;
    skip_attributes(&mut reader)?;
    reader.u32()?;
    let eof = reader.bool()?;
    Ok((reader.opaque()?.to_vec(), eof))
}

/// `WRITE` arguments: `data` at `offset`, `FILE_SYNC`.
#[must_use]
pub fn write_args(file: &Handle, offset: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 32);
    file.put(&mut out);
    xdr::put_u64(&mut out, offset);
    xdr::put_u32(&mut out, u32::try_from(data.len()).unwrap_or(u32::MAX));
    xdr::put_u32(&mut out, FILE_SYNC);
    xdr::put_opaque(&mut out, data);
    out
}

/// The file, offset and bytes a `WRITE` carries.
///
/// # Errors
/// Where the arguments are cut short.
pub fn take_write_args(arguments: &[u8]) -> Result<(Handle, u64, Vec<u8>)> {
    let mut reader = Reader::new(arguments);
    let file = Handle::take(&mut reader)?;
    let offset = reader.u64()?;
    reader.u32()?;
    reader.u32()?;
    Ok((file, offset, reader.opaque()?.to_vec()))
}

/// A successful `WRITE` result: `count` bytes, `FILE_SYNC`, this server's
/// verifier.
#[must_use]
pub fn write_ok(count: u32, verifier: [u8; 8]) -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_u32(&mut out, OK);
    xdr::put_bool(&mut out, false);
    put_no_attributes(&mut out);
    xdr::put_u32(&mut out, count);
    xdr::put_u32(&mut out, FILE_SYNC);
    xdr::put_fixed(&mut out, &verifier);
    out
}

/// The count a `WRITE` result carries.
///
/// # Errors
/// Where the write failed.
pub fn take_write(results: &[u8]) -> Result<u32> {
    let mut reader = Reader::new(results);
    expect_ok(&mut reader, "writing")?;
    skip_wcc(&mut reader)?;
    reader.u32()
}

/// `COMMIT` arguments: the whole file.
#[must_use]
pub fn commit_args(file: &Handle) -> Vec<u8> {
    let mut out = Vec::new();
    file.put(&mut out);
    xdr::put_u64(&mut out, 0);
    xdr::put_u32(&mut out, 0);
    out
}

/// The file a `COMMIT` names.
///
/// # Errors
/// Where the arguments are cut short.
pub fn take_commit_args(arguments: &[u8]) -> Result<Handle> {
    Handle::take(&mut Reader::new(arguments))
}

/// A successful `COMMIT` result: this server's verifier.
#[must_use]
pub fn commit_ok(verifier: [u8; 8]) -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_u32(&mut out, OK);
    xdr::put_bool(&mut out, false);
    put_no_attributes(&mut out);
    xdr::put_fixed(&mut out, &verifier);
    out
}

/// A successful `REMOVE` result.
#[must_use]
pub fn remove_ok() -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_u32(&mut out, OK);
    xdr::put_bool(&mut out, false);
    put_no_attributes(&mut out);
    out
}

/// That a `COMMIT` or `REMOVE` succeeded.
///
/// # Errors
/// Where it did not.
pub fn take_done(results: &[u8], what: &str) -> Result<()> {
    expect_ok(&mut Reader::new(results), what)
}

/// `READDIR` arguments from the start, `count` bytes at most.
#[must_use]
pub fn readdir_args(dir: &Handle, count: u32) -> Vec<u8> {
    let mut out = Vec::new();
    dir.put(&mut out);
    xdr::put_u64(&mut out, 0);
    xdr::put_fixed(&mut out, &[0; 8]);
    xdr::put_u32(&mut out, count);
    out
}

/// The directory a `READDIR` lists.
///
/// # Errors
/// Where the arguments are cut short.
pub fn take_readdir_args(arguments: &[u8]) -> Result<Handle> {
    Handle::take(&mut Reader::new(arguments))
}

/// A successful `READDIR` result listing every name, the whole directory.
#[must_use]
pub fn readdir_ok(names: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    xdr::put_u32(&mut out, OK);
    put_no_attributes(&mut out);
    xdr::put_fixed(&mut out, &[0; 8]);
    for (index, name) in names.iter().enumerate() {
        xdr::put_bool(&mut out, true);
        xdr::put_u64(&mut out, index as u64 + 2);
        xdr::put_string(&mut out, name);
        xdr::put_u64(&mut out, index as u64 + 1);
    }
    xdr::put_bool(&mut out, false);
    xdr::put_bool(&mut out, true);
    out
}

/// The names a `READDIR` result carries, `.` and `..` left out.
///
/// # Errors
/// Where the listing failed, or did not reach the end of the directory.
pub fn take_readdir(results: &[u8]) -> Result<Vec<String>> {
    let mut reader = Reader::new(results);
    expect_ok(&mut reader, "listing")?;
    skip_attributes(&mut reader)?;
    reader.fixed(8)?;
    let mut names = Vec::new();
    while reader.bool()? {
        reader.u64()?;
        let name = reader.string()?;
        reader.u64()?;
        if name != "." && name != ".." {
            names.push(name);
        }
    }
    if !reader.bool()? {
        return Err(protocol_error("a directory longer than one listing"));
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{JUKEBOX, NOENT, STALE};

    #[test]
    fn every_argument_reads_back_and_every_result_yields_what_it_carries() {
        let dir = Handle(vec![0]);
        let file = Handle(b"orders/1.edi".to_vec());
        assert_eq!(
            take_dir_args(&create_args(&dir, "a")).expect("create"),
            (dir.clone(), "a".to_string())
        );
        assert_eq!(
            take_handle(&handle_ok(&file, CREATE), CREATE).expect("created"),
            file
        );
        assert_eq!(
            take_handle(&handle_ok(&file, LOOKUP), LOOKUP).expect("found"),
            file
        );
        assert_eq!(
            take_read_args(&read_args(&file, 8, 16)).expect("read"),
            (file.clone(), 8, 16)
        );
        assert_eq!(
            take_read(&read_ok(b"abc", true)).expect("data"),
            (b"abc".to_vec(), true)
        );
        assert_eq!(
            take_write_args(&write_args(&file, 4, b"xy")).expect("write"),
            (file.clone(), 4, b"xy".to_vec())
        );
        assert_eq!(take_write(&write_ok(2, [7; 8])).expect("count"), 2);
        assert_eq!(take_commit_args(&commit_args(&file)).expect("commit"), file);
        take_done(&commit_ok([0; 8]), "committing").expect("committed");
        take_done(&remove_ok(), "removing").expect("removed");
        assert_eq!(
            take_readdir_args(&readdir_args(&dir, 4096)).expect("dir"),
            dir
        );
        let names = vec![".".to_string(), "b".to_string(), "a".to_string()];
        assert_eq!(
            take_readdir(&readdir_ok(&names)).expect("names"),
            ["b", "a"]
        );
    }

    #[test]
    fn a_failure_names_its_status_and_only_the_jukebox_is_retryable() {
        let error = take_handle(&put_failure(NOENT, LOOKUP), LOOKUP).expect_err("missing");
        assert!(error.message.contains("no such file"), "{error}");
        assert!(!error.retryable);
        assert!(
            take_write(&put_failure(JUKEBOX, WRITE))
                .expect_err("later")
                .retryable
        );
        assert!(
            take_handle(&[0, 0, 0, 0, 0, 0, 0, 0], CREATE).is_err(),
            "no handle"
        );
        assert_eq!(put_failure(STALE, READ).len(), 8);
        assert_eq!(put_failure(STALE, WRITE).len(), 12);
    }
}
