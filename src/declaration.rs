//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// Whether an accepted file is removed, unless told otherwise.
pub const DELETE_AFTER_RETRIEVE: bool = true;

/// What a user or group id may be: `AUTH_UNIX` carries 32 bits.
const ID: Kind = Kind::Integer {
    minimum: 0,
    maximum: u32::MAX as i64,
};

/// Every setting a Location takes beyond its address, the server's host
/// and port, `host:2049`: where a Location mounts.
pub const SETTINGS: &Settings = &Settings {
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
            meaning: "Whether a file is removed once its receive cycle accepted it; a \
                      refused one is never removed.",
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
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a server that stops mid-reply is waited on; unbounded \
             when left out.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["nfs"];
