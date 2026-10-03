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
//! Location mounts, lists and hands each file back unread, read a `READ` at
//! a time as the runtime asks and removed only when its receive cycle
//! accepted it ([`connection`]); a Send Location mounts, creates, writes
//! and commits.
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
pub mod connection;
pub mod mount;
pub mod procedure;
pub mod rpc;
pub mod session;
pub mod status;
pub mod xdr;

use std::net::TcpListener;
use std::time::Duration;

pub use client::Client;
pub use connection::Connection;
use net::Target;
pub use procedure::Handle;
pub use rpc::Unix;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::taken::Taken;
use transport::{Arrived, Configured, Directions, NoNativeClaim, Pool, ResourceClaim, Transport};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

/// Whether an accepted file is removed, unless told otherwise.
const DELETE_AFTER_RETRIEVE: bool = true;

/// What a user or group id may be: `AUTH_UNIX` carries 32 bits.
const ID: Kind = Kind::Integer {
    minimum: 0,
    maximum: u32::MAX as i64,
};

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
    /// The connections a send writes on and a receive reads on, each export
    /// mounted on each once, kept per server and shared with what a receive
    /// handed back.
    writers: Pool<Connection>,
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
            delete_after_retrieve: DELETE_AFTER_RETRIEVE,
            timeout: None,
            writers: Pool::new(),
        }
    }

    /// Present these `AUTH_UNIX` credentials.
    #[must_use]
    pub fn presenting(mut self, credentials: Unix) -> Self {
        self.credentials = credentials;
        self
    }

    /// Leave accepted files in place rather than removing them.
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
        match Target::under(&["nfs"], target).map(|named| (named.authority(), named.path())) {
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

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a receive lists again what is not yet told")
    }

    /// Every file on the export, listed on the connection kept for the
    /// server — the export mounted on the first receive — and handed back
    /// unread: each body looks the file up on its first read and reads it a
    /// `READ` at a time as the runtime asks; `Accepted` and `Refused`
    /// remove it (`REMOVE`) unless the transport was told to leave files,
    /// `Failed` leaves it for the next receive.
    fn receive(&self) -> Result<Vec<Arrived>> {
        self.writers.exchange(
            self.server.as_str(),
            || self.connect().map(Connection::new),
            |connection| {
                let (root, names) = connection.with(|client| {
                    let root = client.root(&self.export)?;
                    let names = client.list(&root)?;
                    Ok((root, names))
                })?;
                Ok(names
                    .into_iter()
                    .map(|name| {
                        let origin = format!("nfs://{}{}/{name}", self.server, self.export);
                        connection.arrival(origin, &root, name, self.delete_after_retrieve)
                    })
                    .collect())
            },
        )
    }

    /// Create, write and commit the file on the connection kept for the
    /// server, the export mounted on it once. The mount is not given back
    /// per file: `UMNT` only tells the server's list of mounts, and the
    /// connection keeps using it.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, export, name) = self.resolve(target)?;
        self.writers.exchange(
            server,
            || Client::connect(server, self.credentials.clone(), self.timeout).map(Connection::new),
            |connection| {
                connection.with(|client| {
                    let root = client.root(&export)?;
                    let file = client.create(&root, name)?;
                    client.write_all(&file, bytes)
                })
            },
        )
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl Configured for NfsTransport {
    /// The address is the server's host and port, `host:2049`: where a
    /// Location mounts.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "export",
                kind: Kind::Text,
                presence: Presence::Required,
                meaning: "The export a Receive Location reads, and the one a Send Location \
                          writes to when its target is a name alone.",
                applies: Applies::Both,
            },
            Setting {
                name: "delete_after_retrieve",
                kind: Kind::Boolean,
                presence: Presence::Default(Fixed::Boolean(DELETE_AFTER_RETRIEVE)),
                meaning: "Whether a file is removed once its receive cycle accepted it.",
                applies: Applies::Receive,
            },
            Setting {
                name: "machine",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The machine name the AUTH_UNIX credentials present; Xmip's own \
                          when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "uid",
                kind: ID,
                presence: Presence::Optional,
                meaning: "The user id the AUTH_UNIX credentials present; root when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "gid",
                kind: ID,
                presence: Presence::Optional,
                meaning: "The group id the AUTH_UNIX credentials present; root's when left \
                          out.",
                applies: Applies::Both,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a server that stops mid-reply is waited on; unbounded \
                          when left out.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let id = |name: &str, fallback: u32| {
            settings.optional_integer(name).map_or(Ok(fallback), |id| {
                u32::try_from(id).map_err(|_| protocol_error(format!("{name} {id} is not 32 bits")))
            })
        };
        let unix = Unix::default();
        let credentials = Unix {
            machine: settings
                .optional_text("machine")
                .map_or(unix.machine, str::to_string),
            uid: id("uid", unix.uid)?,
            gid: id("gid", unix.gid)?,
        };
        let mut transport = Self::new(address, settings.text("export")).presenting(credentials);
        if settings.optional_boolean("delete_after_retrieve") == Some(false) {
            transport = transport.leaving_files();
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport)
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
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        // The client keeps its connection, and its mount, for the next file.
        self.accept_one(listener)?
            .next_store()?
            .ok_or_else(|| protocol_error("the client closed without committing"))
    }
}

impl Loopback for NfsTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
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
    fn nfs_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(NfsTransport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("export", "/srv/in"),
            ("delete_after_retrieve".to_string(), Given::Boolean(false)),
            ("uid".to_string(), Given::Integer(1000)),
            text("timeout", "2s"),
        ];
        let built = NfsTransport::open("files:2049", Applies::Receive, &given).expect("built");
        assert_eq!(built.export, "/srv/in");
        assert!(!built.delete_after_retrieve);
        assert_eq!(built.credentials.uid, 1000);
        assert_eq!(built.credentials.gid, 0);
        assert_eq!(built.credentials.machine, Unix::default().machine);
        assert_eq!(built.timeout, Some(secs(2)));
        let Err(refused) = NfsTransport::open("files:2049", Applies::Send, &given[2..]) else {
            panic!("export is required");
        };
        assert!(
            refused.message.contains("\"export\""),
            "{}",
            refused.message
        );
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
            // Two transports, so two connections: each keeps its own.
            let first = NfsTransport::new(address.clone(), "/orders")
                .timing_out_after(secs(2))
                .receive()?
                .into_iter()
                .map(Arrived::taken)
                .collect::<Result<Vec<_>>>()?;
            let again = NfsTransport::new(address, "/orders")
                .leaving_files()
                .timing_out_after(secs(2))
                .receive()?
                .into_iter()
                .map(Arrived::taken)
                .collect::<Result<Vec<_>>>()?;
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
        assert!(
            !events.contains(&Event::Unmounted),
            "the export kept mounted"
        );
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
    fn a_failed_file_stays_on_the_export_and_an_accepted_one_is_removed() {
        let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let long: Vec<u8> = (0..300_000u32).map(|n| (n % 251) as u8).collect();
        let expected = long.clone();
        let receiver = std::thread::spawn(move || {
            let near = NfsTransport::new(address, "/orders").timing_out_after(secs(2));
            let first = transport::arrived::one_arrival(near.receive()?, "listed")?;
            assert!(first.defers());
            let (_, mut body, acknowledgement) = first.into_parts();
            let mut read = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut read).expect("reading");
            drop(body);
            acknowledgement.acknowledge(transport::Verdict::Failed)?;
            let again = transport::arrived::one_arrival(near.receive()?, "listed again")?;
            let taken = again.taken()?;
            Ok::<_, transport::TransportError>((read, taken, near.receive()?.len()))
        });
        let files = BTreeMap::from([("1.bin".to_string(), long)]);
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_files(files);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("event") {
            events.push(event);
        }
        let (read, taken, after) = receiver.join().expect("thread").expect("receiving");
        assert_eq!(read, expected, "read in chunks to its end");
        assert_eq!(taken.bytes, expected);
        assert_eq!(after, 0, "accepted, so not listed again");
        let removed = Event::Removed("1.bin".to_string());
        assert_eq!(
            events.iter().filter(|event| **event == removed).count(),
            1,
            "the failed read removed nothing: {events:?}"
        );
        assert!(session.files().is_empty(), "removed once accepted");
    }

    #[test]
    fn a_refused_file_is_removed_and_not_listed_again() {
        let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = NfsTransport::new(address, "/orders").timing_out_after(secs(2));
            let first = transport::arrived::one_arrival(near.receive()?, "listed")?;
            first.refused(transport::Refusal::Unidentified)?;
            Ok::<_, transport::TransportError>(near.receive()?.len())
        });
        let files = BTreeMap::from([("1.bin".to_string(), b"refused".to_vec())]);
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_files(files);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("event") {
            events.push(event);
        }
        assert_eq!(receiver.join().expect("thread").expect("receiving"), 0);
        assert!(
            events.contains(&Event::Removed("1.bin".to_string())),
            "{events:?}"
        );
        assert!(session.files().is_empty(), "removed once refused");
    }

    #[test]
    fn a_thousand_files_mount_once_and_a_connection_the_server_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = NfsTransport::new(address, "/orders").timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for n in 0..SENDS {
                sending.send(&format!("{n}.edi"), n.to_string().as_bytes())?;
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond a file.
            assert!(took < Duration::from_millis(SENDS as u64), "{took:?}");
            sending.send("last.edi", b"after the close")
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let mut mounts = 0;
        let mut stored = 0;
        while stored < SENDS {
            match session.next_event().expect("serving").expect("one") {
                Event::Mounted(_) => mounts += 1,
                Event::Committed(file) => {
                    assert_eq!(file.bytes, stored.to_string().as_bytes());
                    stored += 1;
                }
                _ => {}
            }
        }
        assert_eq!(mounts, 1, "the export is mounted once on a connection");
        drop(session);
        let mut again = far_end.accept_one(&listener).expect("a new connection");
        let last = again.next_store().expect("store").expect("one");
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.writers.opened(), 2);
    }

    #[test]
    fn a_thousand_receives_mount_once_and_a_connection_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = NfsTransport::new(address, "/orders").timing_out_after(secs(5));
        let (go, going) = std::sync::mpsc::channel();
        let receiver = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for _ in 0..RECEIVES {
                assert!(near.receive()?.is_empty());
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond a receive.
            assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
            // A send on the same kept connection says the receives are done.
            near.send("received.edi", b"received")?;
            going.recv().expect("go");
            Ok::<_, transport::TransportError>((near.receive()?, near.writers.opened()))
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let marker = session.next_store().expect("served").expect("the marker");
        assert_eq!(marker.bytes, b"received");
        drop(session);
        go.send(()).expect("went");
        let mut again = far_end.accept_one(&listener).expect("accepting");
        while again.next_event().expect("served").is_some() {}
        let (arrived, opened) = receiver.join().expect("thread").expect("received");
        assert!(arrived.is_empty());
        assert_eq!(opened, 2);
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
