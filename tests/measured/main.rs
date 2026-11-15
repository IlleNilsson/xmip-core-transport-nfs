//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a thousand files on one mounted connection cost no more than twice
//!   the loopback's round trip a call, measured beside each, the fastest of
//!   five (`xcore::latency::spread`);
//! - a thousand receives on one mounted connection take a millisecond each
//!   at most beyond their wakes, round by round beside a plain wake, the
//!   fastest of five (`xcore::latency::Rounds`).

use std::time::{Duration, Instant};

use transport::Configured;
use transport::{Transport, TransportError, socket};
use xcore::latency::{Rounds, spread};
use xmip_core_transport_nfs::{Event, NfsTransport};

/// What a receive wakes where a plain wake wakes one: the far end at the
/// READDIR, and this end at its reply.
const RECEIVE_WAKES: u32 = 2;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// The calls one small file takes on a kept connection with its export
/// mounted: `CREATE`, `WRITE`, `COMMIT`.
const CALLS_A_FILE: usize = 3;

/// `rounds` calls of `call`, each timed with a call-sized exchange on this
/// loopback beside it, Nagle's algorithm off, read and written whole on
/// both ends: the wire every NFS call here crosses, without the protocol,
/// under the same load in the same rounds. Each call's time and each
/// exchange's, in the order measured.
fn beside_the_wire(
    rounds: usize,
    mut call: impl FnMut(usize) -> Result<(), TransportError>,
) -> Result<(Vec<Duration>, Vec<Duration>), TransportError> {
    let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("binding");
    let echo = std::thread::spawn(move || {
        let (stream, _) = socket::accept_tcp(&listener, Some(secs(5))).expect("accepting");
        let (mut reader, mut writer) = socket::split(stream).expect("split");
        let mut message = [0u8; 128];
        while std::io::Read::read_exact(&mut reader, &mut message).is_ok() {
            std::io::Write::write_all(&mut writer, &message).expect("echoing");
        }
    });
    let stream = socket::connect_tcp(&address, Some(secs(5))).expect("connecting");
    let (mut reader, mut writer) = socket::split(stream).expect("split");
    let mut message = [0u8; 128];
    let (mut took, mut wire) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
    for round in 0..rounds {
        let began = Instant::now();
        call(round)?;
        took.push(began.elapsed());
        let began = Instant::now();
        std::io::Write::write_all(&mut writer, &message).expect("calling");
        std::io::Read::read_exact(&mut reader, &mut message).expect("answered");
        wire.push(began.elapsed());
    }
    drop((reader, writer));
    echo.join().expect("echo");
    Ok((took, wire))
}

#[test]
fn a_thousand_files_cost_no_more_than_twice_the_wire_a_call() {
    const SENDS: usize = 1000;
    let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(5));
    let (listener, address) = far_end.bind().expect("binding");
    let near = NfsTransport::new(address, "/orders").timing_out_after(secs(5));
    // The time is judged after the last send, never in the sender: an
    // assertion there would drop the connection the far end still serves.
    let sender = std::thread::spawn(move || {
        beside_the_wire(SENDS, |n| {
            near.send(&format!("{n}.edi"), n.to_string().as_bytes())
        })
    });
    let mut session = far_end.accept_one(&listener).expect("accepting");
    let mut stored = 0;
    while stored < SENDS {
        match session.next_event().expect("serving").expect("one") {
            Event::Mounted(_) | Event::Created(_) | Event::Written(..) => {}
            Event::Committed(file) => {
                assert_eq!(file.bytes, stored.to_string().as_bytes());
                stored += 1;
            }
            other => panic!("a send does no {other:?}"),
        }
    }
    let (took, wire) = sender.join().expect("thread").expect("sending");
    // A file is three calls — CREATE, WRITE, COMMIT — each a round trip
    // on this loopback. What the transport and its far end do around
    // the wire may not cost as much as the wire again: two round trips
    // a call. Each the fastest of five (`xcore::latency::spread`), the
    // wire measured beside each file, so the machine's load is the wire's,
    // not a verdict on the transport. Until 2026-11-15 the thousand were
    // timed together against the wire's mean before and after them.
    let took = spread("a file sent", took).fastest_of_five;
    let wire = spread("a call-sized round trip on the loopback beside it", wire).fastest_of_five;
    let bound = wire * u32::try_from(CALLS_A_FILE * 2).expect("small");
    assert!(
        took < bound,
        "{took:?} a file, over {bound:?}: {wire:?} a round trip, the fastest of five each"
    );
}

#[test]
fn a_thousand_receives_take_a_millisecond_each_at_most() {
    const RECEIVES: usize = 1000;
    let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(5));
    let (listener, address) = far_end.bind().expect("binding");
    let near = NfsTransport::new(address, "/orders").timing_out_after(secs(5));
    let receiver = std::thread::spawn(move || {
        let mut rounds = Rounds::crossing(RECEIVE_WAKES);
        for _ in 0..RECEIVES {
            assert!(rounds.round(|| near.receive())?.is_empty());
        }
        Ok::<_, TransportError>(rounds)
    });
    // Served until the near end lets its connection go.
    let mut session = far_end.accept_one(&listener).expect("accepting");
    while session.next_event().expect("served").is_some() {}
    let rounds = receiver.join().expect("thread").expect("received");
    rounds.hold("a receive, a listing");
}
