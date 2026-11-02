//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a thousand files on one mounted connection cost no more than twice
//!   the loopback's round trip a call;
//! - a thousand receives on one mounted connection take a millisecond each
//!   at most.

use std::time::{Duration, Instant};

use transport::{Transport, socket};
use xmip_core_transport_nfs::{Event, NfsTransport};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// The calls one small file takes on a kept connection with its export
/// mounted: `CREATE`, `WRITE`, `COMMIT`.
const CALLS_A_FILE: usize = 3;

/// The mean round trip of a call-sized exchange on this loopback with
/// Nagle's algorithm off, read and written whole on both ends: the
/// wire every NFS call here crosses, without the protocol.
fn loopback_round_trip() -> Duration {
    const EXCHANGES: u32 = 200;
    let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("binding");
    let echo = std::thread::spawn(move || {
        let (stream, _) = socket::accept_tcp(&listener, Some(secs(5))).expect("accepting");
        let (mut reader, mut writer) = socket::split(stream).expect("split");
        let mut call = [0u8; 128];
        while std::io::Read::read_exact(&mut reader, &mut call).is_ok() {
            std::io::Write::write_all(&mut writer, &call).expect("echoing");
        }
    });
    let stream = socket::connect_tcp(&address, Some(secs(5))).expect("connecting");
    let (mut reader, mut writer) = socket::split(stream).expect("split");
    let mut call = [0u8; 128];
    let began = Instant::now();
    for _ in 0..EXCHANGES {
        std::io::Write::write_all(&mut writer, &call).expect("calling");
        std::io::Read::read_exact(&mut reader, &mut call).expect("answered");
    }
    let took = began.elapsed();
    drop((reader, writer));
    echo.join().expect("echo");
    took / EXCHANGES
}

#[test]
fn a_thousand_files_cost_no_more_than_twice_the_wire_a_call() {
    const SENDS: usize = 1000;
    let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(5));
    let (listener, address) = far_end.bind().expect("binding");
    let near = NfsTransport::new(address, "/orders").timing_out_after(secs(5));
    let wire = loopback_round_trip();
    // The time is judged after the last send, never in the sender: an
    // assertion there would drop the connection the far end still serves.
    let sender = std::thread::spawn(move || {
        let began = Instant::now();
        for n in 0..SENDS {
            near.send(&format!("{n}.edi"), n.to_string().as_bytes())?;
        }
        Ok::<_, transport::TransportError>(began.elapsed())
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
    let took = sender.join().expect("thread").expect("sending");
    // A file is three calls — CREATE, WRITE, COMMIT — each a round trip
    // on this loopback. What the transport and its far end do around
    // the wire may not cost as much as the wire again: two round trips
    // a call. Measured on the same loopback before and after, so the
    // machine's load is the wire's, not a verdict on the transport.
    let wire = wire.max(loopback_round_trip());
    let bound = wire * u32::try_from(SENDS * CALLS_A_FILE * 2).expect("small");
    assert!(
        took < bound,
        "{took:?} for {SENDS} files, over {bound:?}: {wire:?} a round trip"
    );
}

#[test]
fn a_thousand_receives_take_a_millisecond_each_at_most() {
    const RECEIVES: usize = 1000;
    let far_end = NfsTransport::new("127.0.0.1:0", "/orders").timing_out_after(secs(5));
    let (listener, address) = far_end.bind().expect("binding");
    let near = NfsTransport::new(address, "/orders").timing_out_after(secs(5));
    let receiver = std::thread::spawn(move || {
        let began = Instant::now();
        for _ in 0..RECEIVES {
            assert!(near.receive()?.is_empty());
        }
        let took = began.elapsed();
        // Generous for a debug build under load: a millisecond a receive.
        assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
        Ok::<_, transport::TransportError>(())
    });
    // Served until the near end lets its connection go.
    let mut session = far_end.accept_one(&listener).expect("accepting");
    while session.next_event().expect("served").is_some() {}
    receiver.join().expect("thread").expect("received");
}
