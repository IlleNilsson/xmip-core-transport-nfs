//! Xmip's side of one connection to an NFS server: mount an export, look
//! up, create, write, commit, read, list and remove — each one RPC call
//! and its reply, on one TCP connection that carries the mount program
//! and the NFS program alike.
//!
//! A server that keeps its mount daemon on another port answers the `MNT`
//! with a program-unavailable, and this client says so; the portmapper
//! that would find it is not spoken here.

use std::collections::BTreeMap;
use std::io::BufReader;
use std::net::TcpStream;
use std::time::Duration;

use net::MAX_BODY;
use transport::error::{Result, protocol_error};
use transport::pool::{Pooled, alive};
use transport::socket;

use crate::attributes::Stamp;
use crate::mount;
use crate::procedure::{self, Handle};
use crate::rpc::{self, Call, Reply, Unix};

/// The largest read or write in one call: what every server since
/// version 3 accepts without being asked through `FSINFO`.
pub const CHUNK: usize = 65_536;

/// The bytes a listing asks for at once, the whole of any drop directory.
const LISTING: u32 = 1 << 20;

/// One connection to a server, kept between sends while the server keeps
/// it open, and the root handle of each export mounted on it.
pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    credentials: Unix,
    next_xid: u32,
    mounted: BTreeMap<String, Handle>,
}

impl Client {
    /// Connect to `server`, presenting `credentials` on every call.
    ///
    /// # Errors
    /// Where the server could not be reached.
    pub fn connect(server: &str, credentials: Unix, timeout: Option<Duration>) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        Ok(Self {
            reader,
            writer,
            credentials,
            next_xid: 1,
            mounted: BTreeMap::new(),
        })
    }

    /// Mount `export` and take its root handle.
    ///
    /// # Errors
    /// Where the server refused the mount or does not serve it here.
    pub fn mount(&mut self, export: &str) -> Result<Handle> {
        let results = self.mount_call(mount::MNT, mount::args(export))?;
        mount::take(&results)
    }

    /// The root handle of `export`: mounted on the first ask on this
    /// connection, and kept for every ask after.
    ///
    /// # Errors
    /// Where the server refused the mount or does not serve it here.
    pub fn root(&mut self, export: &str) -> Result<Handle> {
        if let Some(root) = self.mounted.get(export) {
            return Ok(root.clone());
        }
        let root = self.mount(export)?;
        self.mounted.insert(export.to_string(), root.clone());
        Ok(root)
    }

    /// Say the export is no longer in use.
    ///
    /// # Errors
    /// Where the connection broke.
    pub fn unmount(&mut self, export: &str) -> Result<()> {
        self.mount_call(mount::UMNT, mount::args(export))
            .map(|_| ())
    }

    /// The handle of `name` in `dir`.
    ///
    /// # Errors
    /// Where there is no such name.
    pub fn lookup(&mut self, dir: &Handle, name: &str) -> Result<Handle> {
        self.looked_up(dir, name).map(|(handle, _)| handle)
    }

    /// The stamp of `name` in `dir` as it lies now, from the attributes a
    /// `LOOKUP` answers with; `None` where the server gave none.
    ///
    /// # Errors
    /// Where there is no such name.
    pub fn stamp(&mut self, dir: &Handle, name: &str) -> Result<Option<Stamp>> {
        self.looked_up(dir, name).map(|(_, stamp)| stamp)
    }

    fn looked_up(&mut self, dir: &Handle, name: &str) -> Result<(Handle, Option<Stamp>)> {
        let results = self.nfs_call(procedure::LOOKUP, procedure::dir_args(dir, name))?;
        procedure::take_handle(&results, procedure::LOOKUP)
    }

    /// Create `name` in `dir`, empty, and take its handle.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn create(&mut self, dir: &Handle, name: &str) -> Result<Handle> {
        let results = self.nfs_call(procedure::CREATE, procedure::create_args(dir, name))?;
        procedure::take_handle(&results, procedure::CREATE).map(|(handle, _)| handle)
    }

    /// Write `bytes` to `file` from the start, a chunk per call, and
    /// commit.
    ///
    /// # Errors
    /// Where the server refused or wrote short.
    pub fn write_all(&mut self, file: &Handle, bytes: &[u8]) -> Result<()> {
        let mut offset = 0u64;
        for chunk in bytes.chunks(CHUNK) {
            let results =
                self.nfs_call(procedure::WRITE, procedure::write_args(file, offset, chunk))?;
            let written = procedure::take_write(&results)? as usize;
            if written != chunk.len() {
                return Err(protocol_error(format!(
                    "the server wrote {written} of {} bytes",
                    chunk.len()
                )));
            }
            offset += written as u64;
        }
        let results = self.nfs_call(procedure::COMMIT, procedure::commit_args(file))?;
        procedure::take_done(&results, "committing")
    }

    /// The next chunk of `file` from `offset`, at most one call's worth,
    /// and whether the server says it reached the end.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn read_at(&mut self, file: &Handle, offset: u64) -> Result<(Vec<u8>, bool)> {
        let count = u32::try_from(CHUNK).unwrap_or(u32::MAX);
        let results = self.nfs_call(procedure::READ, procedure::read_args(file, offset, count))?;
        procedure::take_read(&results)
    }

    /// The names in `dir`, in the server's order.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn list(&mut self, dir: &Handle) -> Result<Vec<String>> {
        let results = self.nfs_call(procedure::READDIR, procedure::readdir_args(dir, LISTING))?;
        procedure::take_readdir(&results)
    }

    /// Remove `name` from `dir`.
    ///
    /// # Errors
    /// Where there is no such name or the server refused.
    pub fn remove(&mut self, dir: &Handle, name: &str) -> Result<()> {
        let results = self.nfs_call(procedure::REMOVE, procedure::dir_args(dir, name))?;
        procedure::take_done(&results, "removing")
    }

    fn nfs_call(&mut self, procedure: u32, arguments: Vec<u8>) -> Result<Vec<u8>> {
        self.call(rpc::NFS_PROGRAM, rpc::NFS_VERSION, procedure, arguments)
    }

    fn mount_call(&mut self, procedure: u32, arguments: Vec<u8>) -> Result<Vec<u8>> {
        self.call(rpc::MOUNT_PROGRAM, rpc::MOUNT_VERSION, procedure, arguments)
    }

    /// One call and its reply, matched by transaction id.
    fn call(
        &mut self,
        program: u32,
        version: u32,
        procedure: u32,
        arguments: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        let call = Call {
            xid,
            program,
            version,
            procedure,
            credentials: None,
            arguments,
        };
        rpc::write_record(&mut self.writer, &call.to_bytes(&self.credentials))?;
        let record = rpc::read_record(&mut self.reader, MAX_BODY + CHUNK)?
            .ok_or_else(|| protocol_error("the server closed before replying"))?;
        let reply = Reply::from_bytes(&record)?;
        if reply.xid != xid {
            return Err(protocol_error(format!(
                "a reply to call {} where {xid} was awaited",
                reply.xid
            )));
        }
        reply.results()
    }
}

impl Pooled for Client {
    /// While the server has not closed the connection. A root handle gone
    /// stale with a restart fails the next call on it, which goes again on
    /// a new connection and a new mount.
    fn usable(&mut self) -> bool {
        alive(&self.writer)
    }
}
