//! The server's side of one connection: what a test puts at the far end,
//! and what a Receive Location that accepts writes directly runs.
//!
//! Not an NFS server. One session serves one client over one export kept
//! in memory: the mount program and the NFS program on the one port, a
//! root handle and a handle per file, and the seven procedures a Stream
//! takes. A file is handed up as a Stream when the client commits it —
//! the one call that says the writer is done — and served back to reads
//! and listings until it is removed. Credentials are taken as they come.

use std::collections::BTreeMap;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use transport::Arrived;
use transport::error::Result;
use transport::socket;
use transport::wire::MAX_BODY;

use crate::client::CHUNK;
use crate::mount;
use crate::procedure::{self, Handle};
use crate::rpc::{self, Call, Outcome, Reply};
use crate::status;

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client mounted this path.
    Mounted(String),
    /// The client created this name.
    Created(String),
    /// The client wrote this many bytes at this offset of this name.
    Written(String, u64, usize),
    /// The client committed a file; here is the Stream.
    Committed(Arrived),
    /// The client read this name.
    Read(String),
    /// The client listed the export.
    Listed,
    /// The client removed this name.
    Removed(String),
    /// The client unmounted.
    Unmounted,
}

/// The root of the export: one byte no file's name is.
const ROOT: &[u8] = &[0];

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    export: String,
    files: BTreeMap<String, Vec<u8>>,
}

impl Session {
    /// Accept one client on `listener`, serving `export`.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept(listener: &TcpListener, export: &str, timeout: Option<Duration>) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        Ok(Self {
            reader,
            writer,
            peer,
            export: export.to_string(),
            files: BTreeMap::new(),
        })
    }

    /// Serve these files to lookups, reads and listings.
    #[must_use]
    pub fn with_files(mut self, files: BTreeMap<String, Vec<u8>>) -> Self {
        self.files = files;
        self
    }

    /// What the export holds now, commits included.
    #[must_use]
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The next file the client commits, or `None` when it closed.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_store(&mut self) -> Result<Option<Arrived>> {
        loop {
            match self.next_event()? {
                Some(Event::Committed(arrived)) => return Ok(Some(arrived)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    /// The next thing the client did with the export, or `None` when it
    /// closed. Lookups are answered on the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let Some(record) = rpc::read_record(&mut self.reader, MAX_BODY + CHUNK)? else {
                return Ok(None);
            };
            let call = Call::from_bytes(&record)?;
            let (outcome, event) = self.answer(&call);
            let reply = Reply {
                xid: call.xid,
                outcome,
            };
            rpc::write_record(&mut self.writer, &reply.to_bytes())?;
            if let Some(event) = event {
                return Ok(Some(event));
            }
        }
    }

    fn answer(&mut self, call: &Call) -> (Outcome, Option<Event>) {
        let served = match (call.program, call.version) {
            (rpc::MOUNT_PROGRAM, rpc::MOUNT_VERSION) => self.mount(call),
            (rpc::NFS_PROGRAM, rpc::NFS_VERSION) => self.nfs(call),
            (rpc::MOUNT_PROGRAM | rpc::NFS_PROGRAM, _) => {
                return (Outcome::ProgramMismatch { low: 3, high: 3 }, None);
            }
            _ => return (Outcome::ProgramUnavailable, None),
        };
        match served {
            Ok(Some((results, event))) => (Outcome::Success(results), event),
            Ok(None) => (Outcome::ProcedureUnavailable, None),
            Err(_) => (Outcome::GarbageArguments, None),
        }
    }

    /// The mount program: the export's path, or an errno.
    fn mount(&mut self, call: &Call) -> Result<Option<(Vec<u8>, Option<Event>)>> {
        let path = mount::take_args(&call.arguments)?;
        Ok(match call.procedure {
            procedure::NULL => Some((Vec::new(), None)),
            mount::MNT if path == self.export => Some((
                mount::ok(&Handle(ROOT.to_vec())),
                Some(Event::Mounted(path)),
            )),
            mount::MNT => Some((mount::failure(status::ACCES), None)),
            mount::UMNT => Some((Vec::new(), Some(Event::Unmounted))),
            _ => None,
        })
    }

    /// The NFS program: each procedure over the files in memory.
    fn nfs(&mut self, call: &Call) -> Result<Option<(Vec<u8>, Option<Event>)>> {
        let arguments = &call.arguments;
        let served = match call.procedure {
            procedure::NULL => (Vec::new(), None),
            procedure::LOOKUP => {
                let (_, name) = procedure::take_dir_args(arguments)?;
                if self.files.contains_key(&name) {
                    (
                        procedure::handle_ok(&handle(&name), procedure::LOOKUP),
                        None,
                    )
                } else {
                    (
                        procedure::put_failure(status::NOENT, procedure::LOOKUP),
                        None,
                    )
                }
            }
            procedure::CREATE => {
                let (_, name) = procedure::take_dir_args(arguments)?;
                self.files.insert(name.clone(), Vec::new());
                let results = procedure::handle_ok(&handle(&name), procedure::CREATE);
                (results, Some(Event::Created(name)))
            }
            procedure::WRITE => {
                let (file, offset, data) = procedure::take_write_args(arguments)?;
                self.write(&file, offset, &data)
            }
            procedure::COMMIT => {
                let file = procedure::take_commit_args(arguments)?;
                self.commit(&file)
            }
            procedure::READ => {
                let (file, offset, count) = procedure::take_read_args(arguments)?;
                self.read(&file, offset, count)
            }
            procedure::READDIR => {
                procedure::take_readdir_args(arguments)?;
                let names: Vec<String> = self.files.keys().cloned().collect();
                (procedure::readdir_ok(&names), Some(Event::Listed))
            }
            procedure::REMOVE => {
                let (_, name) = procedure::take_dir_args(arguments)?;
                if self.files.remove(&name).is_some() {
                    (procedure::remove_ok(), Some(Event::Removed(name)))
                } else {
                    (
                        procedure::put_failure(status::NOENT, procedure::REMOVE),
                        None,
                    )
                }
            }
            _ => return Ok(None),
        };
        Ok(Some(served))
    }

    fn write(&mut self, file: &Handle, offset: u64, data: &[u8]) -> (Vec<u8>, Option<Event>) {
        let name = name_of(file);
        let Some(bytes) = self.files.get_mut(&name) else {
            return (
                procedure::put_failure(status::STALE, procedure::WRITE),
                None,
            );
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start.saturating_add(data.len()) > MAX_BODY {
            return (procedure::put_failure(27, procedure::WRITE), None);
        }
        if bytes.len() < start + data.len() {
            bytes.resize(start + data.len(), 0);
        }
        bytes[start..start + data.len()].copy_from_slice(data);
        let count = u32::try_from(data.len()).unwrap_or(u32::MAX);
        (
            procedure::write_ok(count, VERIFIER),
            Some(Event::Written(name, offset, data.len())),
        )
    }

    fn commit(&self, file: &Handle) -> (Vec<u8>, Option<Event>) {
        let name = name_of(file);
        match self.files.get(&name) {
            Some(bytes) => {
                let origin = format!("nfs://{}{}/{name}", self.peer, self.export);
                (
                    procedure::commit_ok(VERIFIER),
                    Some(Event::Committed(Arrived::new(origin, bytes.clone()))),
                )
            }
            None => (
                procedure::put_failure(status::STALE, procedure::COMMIT),
                None,
            ),
        }
    }

    fn read(&self, file: &Handle, offset: u64, count: u32) -> (Vec<u8>, Option<Event>) {
        let name = name_of(file);
        let Some(bytes) = self.files.get(&name) else {
            return (procedure::put_failure(status::STALE, procedure::READ), None);
        };
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let end = start.saturating_add(count as usize).min(bytes.len());
        let eof = end == bytes.len();
        (
            procedure::read_ok(&bytes[start..end], eof),
            Some(Event::Read(name)),
        )
    }
}

/// What every write and commit here is verified with: one server, one
/// incarnation.
const VERIFIER: [u8; 8] = *b"xmip-nfs";

/// A file's handle: its name.
fn handle(name: &str) -> Handle {
    Handle(name.as_bytes().to_vec())
}

/// The name a handle is; the root's is empty.
fn name_of(handle: &Handle) -> String {
    if handle.0 == ROOT {
        String::new()
    } else {
        String::from_utf8_lossy(&handle.0).into_owned()
    }
}
