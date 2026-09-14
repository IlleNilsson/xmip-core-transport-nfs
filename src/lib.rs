#![forbid(unsafe_code)]

//! Streams that arrive as files on an NFS export. One file is one Stream,
//! its name kept beside it.
//!
//! NFS is the drop directory that is already mounted on every Unix box in
//! the building: an export on a server, a path a producer writes into and
//! an integrator reads out of. What is spoken here is NFS version 3 over
//! ONC RPC on TCP (RFC 1813, RFC 5531) — the mount program for the root
//! handle, then `CREATE`, `WRITE` and `COMMIT` to put a Stream on the
//! export, `READDIR`, `LOOKUP`, `READ` and `REMOVE` to take what is there,
//! with `AUTH_UNIX` credentials and no attributes asked for. A Receive
//! Location mounts, lists and reads each file, removing it once it is
//! safely a Stream; a Send Location mounts, creates, writes and commits.
//! Either may instead accept clients directly through [`Session`], one
//! client's worth of server over one export in memory. The mount program
//! is spoken on the NFS port itself, which is where a server that answers
//! both on one port has it and where this crate's own far end has it; the
//! portmapper that would find a mount daemon elsewhere is not spoken.
//!
//! NFS has artefacts and no locking — the lock manager is another program
//! — so [`Transport::claims`] answers [`NoNativeClaim`], ADR-0024 clause
//! 5: a producer writes to a temporary name and renames, or a Location
//! waits for a listing to stop changing.
//!
//! The origin URI carries what the server knew: `nfs://server/export/name`.
//! A send target is `nfs://host:2049/export/name`, or a name alone on the
//! configured server and export.

pub mod client;
pub mod mount;
pub mod procedure;
pub mod rpc;
pub mod session;
pub mod status;
pub mod xdr;

use std::net::TcpListener;
use std::time::Duration;

pub use client::Client;
pub use procedure::Handle;
pub use rpc::Unix;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, NoNativeClaim, ResourceClaim, Transport};

/// The export the loopback pair agrees on, and the one file put on it.
const LOOPBACK_EXPORT: &str = "/probe";
const LOOPBACK_FILE: &str = "probe.bin";

#[derive(Clone)]
pub struct NfsTransport {
    server: String,
    export: String,
    credentials: Unix,
    delete_after_retrieve: bool,
    timeout: Option<Duration>,
}

impl NfsTransport {
    /// Speak to the server at `server` — `host:2049` — about `export`,
    /// as root on a machine called `xmip` until [`Self::presenting`].
    #[must_use]
    pub fn new(server: impl Into<String>, export: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            export: export.into(),
            credentials: Unix::default(),
            delete_after_retrieve: true,
            timeout: None,
        }
    }

    /// Present these `AUTH_UNIX` credentials.
    #[must_use]
    pub fn presenting(mut self, credentials: Unix) -> Self {
        self.credentials = credentials;
        self
    }

    /// Leave read files in place rather than removing them.
    #[must_use]
    pub const fn leaving_files(mut self) -> Self {
        self.delete_after_retrieve = false;
        self
    }

    /// Give up on a server that stops mid-reply.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Connect to the server.
    ///
    /// # Errors
    /// Where the server could not be reached.
    pub fn connect(&self) -> Result<Client> {
        Client::connect(&self.server, self.credentials.clone(), self.timeout)
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener, serving this
    /// transport's export.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, &self.export, self.timeout)
    }

    /// Where a target names the server, export and file itself —
    /// `nfs://host:2049/export/name` — or is a name alone on this
    /// transport's export.
    fn resolve<'a>(&'a self, target: &'a str) -> Result<(&'a str, String, &'a str)> {
        match socket::target("nfs", target) {
            Some((server, path)) => {
                let (export, name) = path
                    .rsplit_once('/')
                    .filter(|(export, name)| !export.is_empty() && !name.is_empty())
                    .ok_or_else(|| {
                        protocol_error(format!("{target:?} is not nfs://host/export/name"))
                    })?;
                Ok((server, format!("/{export}"), name))
            }
            None if target.contains('/') || target.is_empty() => Err(protocol_error(format!(
                "{target:?} is not a name on {}",
                self.export
            ))),
            None => Ok((&self.server, self.export.clone(), target)),
        }
    }
}

impl Transport for NfsTransport {
    fn name(&self) -> &'static str {
        "nfs"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Every file on the export, each removed once read unless the
    /// transport was told to leave them.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let root = client.mount(&self.export)?;
        let mut arrived = Vec::new();
        for name in client.list(&root)? {
            let file = client.lookup(&root, &name)?;
            let bytes = client.read_all(&file)?;
            if self.delete_after_retrieve {
                client.remove(&root, &name)?;
            }
            let origin = format!("nfs://{}{}/{name}", self.server, self.export);
            arrived.push(Arrived::new(origin, bytes));
        }
        client.unmount(&self.export)?;
        Ok(arrived)
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, export, name) = self.resolve(target)?;
        let mut client = Client::connect(server, self.credentials.clone(), self.timeout)?;
        let root = client.mount(&export)?;
        let file = client.create(&root, name)?;
        client.write_all(&file, bytes)?;
        client.unmount(&export)
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl NfsTransport {
    /// Both ends on this machine: an ephemeral local port, one export,
    /// the loopback timeout on every read.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_EXPORT).timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for NfsTransport {
    fn take_one(&self, listener: &TcpListener) -> Result<Arrived> {
        let mut session = self.accept_one(listener)?;
        let arrived = session
            .next_store()?
            .ok_or_else(|| protocol_error("the client closed without committing"))?;
        // Serve the unmount that follows, so the client's goodbye is
        // answered rather than met by a closed socket.
        while session.next_event()?.is_some() {}
        Ok(arrived)
    }
}

impl Loopback for NfsTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening::new(self.clone(), listener, address)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new(address, &self.export)
            .timing_out_after(LOOPBACK_TIMEOUT)
            .send(LOOPBACK_FILE, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use transport::payload::edge_payloads;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn the_loopback_commits_one_file_and_takes_it() {
        let pair = NfsTransport::loopback();
        let arrived = pair.round(b"UNA:+.? '").expect("round");
        assert_eq!(arrived.bytes, b"UNA:+.? '");
        assert!(arrived.origin_uri.starts_with("nfs://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/probe/probe.bin"));
        let long: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
        assert_eq!(pair.round(&long).expect("chunks").bytes, long);
        assert_eq!(pair.name(), "nfs");
        assert_eq!(pair.directions(), Directions::BOTH);
        assert!(pair.claims().is_some(), "files are artefacts");
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = NfsTransport::loopback();
        assert!(pair.ceiling().is_none());
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }

    #[test]
    fn a_receive_mounts_lists_reads_and_removes_each_file() {
        let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = NfsTransport::new(address.clone(), "/orders").timing_out_after(secs(2));
            let first = near.receive()?;
            let again = NfsTransport::new(address, "/orders")
                .leaving_files()
                .timing_out_after(secs(2))
                .receive()?;
            Ok::<_, transport::TransportError>((first, again))
        });
        let mut files = BTreeMap::new();
        files.insert("1.edi".to_string(), b"UNA:+.? '".to_vec());
        files.insert("2.bin".to_string(), vec![0xff, 0x00]);
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_files(files.clone());
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("event") {
            events.push(event);
        }
        assert_eq!(events[0], Event::Mounted("/orders".to_string()));
        assert_eq!(events[1], Event::Listed);
        assert_eq!(events[2], Event::Read("1.edi".to_string()));
        assert_eq!(events[3], Event::Removed("1.edi".to_string()));
        assert_eq!(events.last(), Some(&Event::Unmounted));
        assert!(session.files().is_empty(), "removed after read");
        let mut session = far_end
            .accept_one(&listener)
            .expect("again")
            .with_files(files);
        while session.next_event().expect("event").is_some() {}
        assert_eq!(session.files().len(), 2, "left in place");
        let (first, again) = receiver.join().expect("thread").expect("receiving");
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].bytes, b"UNA:+.? '");
        assert!(first[0].origin_uri.ends_with("/orders/1.edi"));
        assert_eq!(first[1].bytes, [0xff, 0x00]);
        assert_eq!(again.len(), 2);
    }

    #[test]
    fn the_wrong_export_a_missing_file_and_a_bad_target_are_refused() {
        let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = NfsTransport::new(address.clone(), "/orders").timing_out_after(secs(2));
            let wrong = near.send(&format!("nfs://{address}/elsewhere/x"), b"x");
            let mut client = near.connect()?;
            let root = client.mount("/orders")?;
            let missing = client.lookup(&root, "nothing");
            let gone = client.remove(&root, "nothing");
            let bad = near.send("a/b", b"x");
            client.unmount("/orders")?;
            Ok::<_, transport::TransportError>((wrong, missing, gone, bad))
        });
        for _ in 0..2 {
            let mut session = far_end.accept_one(&listener).expect("accepting");
            while session.next_event().expect("event").is_some() {}
        }
        let (wrong, missing, gone, bad) = sender.join().expect("thread").expect("ran");
        let wrong = wrong.expect_err("not exported");
        assert!(wrong.message.contains("access denied"), "{wrong}");
        assert!(
            missing
                .expect_err("no such file")
                .message
                .contains("no such file")
        );
        assert!(!gone.expect_err("no such file").retryable);
        assert!(!bad.expect_err("not a name").retryable);
        assert_eq!(
            far_end
                .resolve("nfs://h:2049/srv/orders/1.edi")
                .expect("full"),
            ("h:2049", "/srv/orders".to_string(), "1.edi")
        );
        assert_eq!(
            far_end.resolve("1.edi").expect("name"),
            ("127.0.0.1:0", "/orders".to_string(), "1.edi")
        );
        assert!(far_end.resolve("nfs://h:2049/only").is_err());
    }

    #[test]
    fn another_program_or_version_is_answered_as_the_rpc_says() {
        let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let caller = std::thread::spawn(move || {
            let stream = socket::connect_tcp(&address, Some(secs(2))).expect("connect");
            let (mut reader, mut writer) = socket::split(stream).expect("split");
            let mut answers = Vec::new();
            for (program, version, procedure) in [
                (100_000, 2, 0),
                (rpc::NFS_PROGRAM, 4, 0),
                (rpc::NFS_PROGRAM, 3, 99),
                (rpc::NFS_PROGRAM, 3, procedure::NULL),
            ] {
                let call = rpc::Call {
                    xid: procedure + 1,
                    program,
                    version,
                    procedure,
                    credentials: None,
                    arguments: Vec::new(),
                };
                rpc::write_record(&mut writer, &call.to_bytes(&Unix::default())).expect("call");
                let record = rpc::read_record(&mut reader, 1024)
                    .expect("reply")
                    .expect("one");
                answers.push(rpc::Reply::from_bytes(&record).expect("reply").outcome);
            }
            answers
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        while session.next_event().expect("event").is_some() {}
        assert_eq!(
            caller.join().expect("thread"),
            [
                rpc::Outcome::ProgramUnavailable,
                rpc::Outcome::ProgramMismatch { low: 3, high: 3 },
                rpc::Outcome::ProcedureUnavailable,
                rpc::Outcome::Success(Vec::new()),
            ]
        );
    }
}
