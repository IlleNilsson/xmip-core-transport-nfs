//! The kept NFS connection, shared by the pool and the arrivals of the
//! receive that listed on it.
//!
//! A receive lists the export and hands each file back unread. Its body
//! looks the file up on its first read and reads it a `READ` at a time as
//! the runtime asks, until the server says it is the end; its
//! acknowledgement removes it (`REMOVE`) on `Accepted`, as the receive did
//! when it removed every file itself. NFS is stateless between calls, so
//! the connection is locked for one call and its reply, never across a
//! file: a send on the same connection goes between two reads.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use transport::body::chunked;
use transport::error::Result;
use transport::pool::Pooled;
use transport::{Acknowledgement, Arrived, Verdict};

use crate::client::Client;
use crate::procedure::Handle;

/// A connection to one server, its exports mounted once, kept by the pool
/// and shared with the arrivals of the receive that listed on it.
#[derive(Clone)]
pub struct Connection(Arc<Mutex<Client>>);

impl Connection {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self(Arc::new(Mutex::new(client)))
    }

    fn client(&self) -> MutexGuard<'_, Client> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `act` on the connection: one call and its reply, or a few.
    ///
    /// # Errors
    /// As `act`.
    pub fn with<T>(&self, act: impl FnOnce(&mut Client) -> Result<T>) -> Result<T> {
        act(&mut self.client())
    }

    /// `name` in `root`, listed on this connection, as an arrival from
    /// `origin`: read as the runtime asks, removed on `Accepted` and on
    /// `Refused` where `remove` says — an export has no place for a refused
    /// file — and left on `Failed`.
    #[must_use]
    pub fn arrival(&self, origin: String, root: &Handle, name: String, remove: bool) -> Arrived {
        let connection = self.clone();
        let (directory, removing) = (root.clone(), name.clone());
        let acknowledgement = Acknowledgement::deferred(move |verdict| match verdict {
            Verdict::Accepted | Verdict::Refused(_) if remove => {
                connection.with(|client| client.remove(&directory, &removing))
            }
            Verdict::Accepted | Verdict::Refused(_) | Verdict::Failed => Ok(()),
        });
        let mut file = ExportFile {
            connection: self.clone(),
            root: root.clone(),
            name,
            file: None,
            offset: 0,
            ended: false,
        };
        Arrived::new(origin, chunked(move || file.next_chunk()), acknowledgement)
    }
}

impl Pooled for Connection {
    fn usable(&mut self) -> bool {
        self.client().usable()
    }
}

/// One file's body: looked up on the first read, read a chunk at a time.
struct ExportFile {
    connection: Connection,
    root: Handle,
    name: String,
    file: Option<Handle>,
    /// Where the next `READ` starts.
    offset: u64,
    /// The server said the last `READ` reached the end.
    ended: bool,
}

impl ExportFile {
    /// The next chunk off the export, `None` at the end.
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.ended {
            return Ok(None);
        }
        let mut client = self.connection.client();
        let file = match &self.file {
            Some(file) => file,
            None => self.file.insert(client.lookup(&self.root, &self.name)?),
        };
        let (chunk, eof) = client.read_at(file, self.offset)?;
        self.offset += chunk.len() as u64;
        self.ended = eof || chunk.is_empty();
        Ok(Some(chunk))
    }
}
