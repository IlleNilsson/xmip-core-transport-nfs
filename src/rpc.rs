//! ONC RPC version 2 (RFC 5531) as it goes over TCP: a record of fragments
//! each marked with its length and whether it is the last, a call naming a
//! program, a version and a procedure with the caller's credentials, and
//! the reply that accepts or denies it. `AUTH_UNIX` is the credential a
//! mount presents — a machine name, a user and a group — and what this
//! crate presents; the verifier is `AUTH_NULL` both ways.

use std::io::{Read, Write};

use transport::error::{Result, TransportError, classify, protocol_error};

use crate::xdr::{self, Reader};

/// The NFS program, and the version this crate speaks.
pub const NFS_PROGRAM: u32 = 100_003;
/// NFS version 3.
pub const NFS_VERSION: u32 = 3;
/// The mount program, and the version that hands out version 3 handles.
pub const MOUNT_PROGRAM: u32 = 100_005;
/// Mount version 3.
pub const MOUNT_VERSION: u32 = 3;

const RPC_VERSION: u32 = 2;
const CALL: u32 = 0;
const REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;
const AUTH_NULL: u32 = 0;
const AUTH_UNIX: u32 = 1;
const LAST_FRAGMENT: u32 = 0x8000_0000;

/// `AUTH_UNIX` credentials: who the caller says it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unix {
    pub machine: String,
    pub uid: u32,
    pub gid: u32,
}

impl Default for Unix {
    /// Root on a machine called `xmip`, which is what a mount presents.
    fn default() -> Self {
        Self {
            machine: "xmip".to_string(),
            uid: 0,
            gid: 0,
        }
    }
}

/// One call: which procedure of which program, and its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub xid: u32,
    pub program: u32,
    pub version: u32,
    pub procedure: u32,
    /// The caller's credentials where they were `AUTH_UNIX`.
    pub credentials: Option<Unix>,
    pub arguments: Vec<u8>,
}

impl Call {
    /// The call message, `credentials` as `AUTH_UNIX` and the verifier
    /// `AUTH_NULL`.
    #[must_use]
    pub fn to_bytes(&self, credentials: &Unix) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.arguments.len());
        xdr::put_u32(&mut out, self.xid);
        xdr::put_u32(&mut out, CALL);
        xdr::put_u32(&mut out, RPC_VERSION);
        xdr::put_u32(&mut out, self.program);
        xdr::put_u32(&mut out, self.version);
        xdr::put_u32(&mut out, self.procedure);
        let mut body = Vec::new();
        xdr::put_u32(&mut body, 0);
        xdr::put_string(&mut body, &credentials.machine);
        xdr::put_u32(&mut body, credentials.uid);
        xdr::put_u32(&mut body, credentials.gid);
        xdr::put_u32(&mut body, 0);
        xdr::put_u32(&mut out, AUTH_UNIX);
        xdr::put_opaque(&mut out, &body);
        xdr::put_u32(&mut out, AUTH_NULL);
        xdr::put_opaque(&mut out, &[]);
        out.extend_from_slice(&self.arguments);
        out
    }

    /// The call a record carries.
    ///
    /// # Errors
    /// Where the record is not a version 2 call.
    pub fn from_bytes(record: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(record);
        let xid = reader.u32()?;
        if reader.u32()? != CALL {
            return Err(protocol_error("a reply where a call was expected"));
        }
        if reader.u32()? != RPC_VERSION {
            return Err(protocol_error("an RPC version other than 2"));
        }
        let program = reader.u32()?;
        let version = reader.u32()?;
        let procedure = reader.u32()?;
        let flavor = reader.u32()?;
        let body = reader.opaque()?;
        let credentials = if flavor == AUTH_UNIX {
            let mut unix = Reader::new(body);
            unix.u32()?;
            Some(Unix {
                machine: unix.string()?,
                uid: unix.u32()?,
                gid: unix.u32()?,
            })
        } else {
            None
        };
        reader.u32()?;
        reader.opaque()?;
        Ok(Self {
            xid,
            program,
            version,
            procedure,
            credentials,
            arguments: reader.rest().to_vec(),
        })
    }
}

/// How a call was answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Accepted and run; here are the results.
    Success(Vec<u8>),
    /// No such program here.
    ProgramUnavailable,
    /// The program is here in these versions.
    ProgramMismatch { low: u32, high: u32 },
    /// No such procedure in the program.
    ProcedureUnavailable,
    /// The arguments could not be read.
    GarbageArguments,
}

/// The reply to one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub xid: u32,
    pub outcome: Outcome,
}

impl Reply {
    /// The reply message, accepted with an `AUTH_NULL` verifier.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        xdr::put_u32(&mut out, self.xid);
        xdr::put_u32(&mut out, REPLY);
        xdr::put_u32(&mut out, MSG_ACCEPTED);
        xdr::put_u32(&mut out, AUTH_NULL);
        xdr::put_opaque(&mut out, &[]);
        match &self.outcome {
            Outcome::Success(results) => {
                xdr::put_u32(&mut out, 0);
                out.extend_from_slice(results);
            }
            Outcome::ProgramUnavailable => xdr::put_u32(&mut out, 1),
            Outcome::ProgramMismatch { low, high } => {
                xdr::put_u32(&mut out, 2);
                xdr::put_u32(&mut out, *low);
                xdr::put_u32(&mut out, *high);
            }
            Outcome::ProcedureUnavailable => xdr::put_u32(&mut out, 3),
            Outcome::GarbageArguments => xdr::put_u32(&mut out, 4),
        }
        out
    }

    /// The reply a record carries.
    ///
    /// # Errors
    /// Where the record is not a reply, or the call was denied.
    pub fn from_bytes(record: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(record);
        let xid = reader.u32()?;
        if reader.u32()? != REPLY {
            return Err(protocol_error("a call where a reply was expected"));
        }
        match reader.u32()? {
            MSG_ACCEPTED => {}
            MSG_DENIED => {
                let reason = match reader.u32()? {
                    0 => "the server speaks another RPC version".to_string(),
                    _ => format!("the credentials were refused, status {}", reader.u32()?),
                };
                return Err(TransportError::permanent(format!(
                    "the call was denied: {reason}"
                )));
            }
            other => return Err(protocol_error(format!("reply status {other}"))),
        }
        reader.u32()?;
        reader.opaque()?;
        let outcome = match reader.u32()? {
            0 => Outcome::Success(reader.rest().to_vec()),
            1 => Outcome::ProgramUnavailable,
            2 => Outcome::ProgramMismatch {
                low: reader.u32()?,
                high: reader.u32()?,
            },
            3 => Outcome::ProcedureUnavailable,
            4 => Outcome::GarbageArguments,
            other => return Err(protocol_error(format!("accept status {other}"))),
        };
        Ok(Self { xid, outcome })
    }

    /// The results, or why there are none.
    ///
    /// # Errors
    /// Where the call was accepted but not run.
    pub fn results(self) -> Result<Vec<u8>> {
        match self.outcome {
            Outcome::Success(results) => Ok(results),
            Outcome::ProgramUnavailable => Err(protocol_error("the server has no such program")),
            Outcome::ProgramMismatch { low, high } => Err(protocol_error(format!(
                "the server speaks versions {low} to {high}"
            ))),
            Outcome::ProcedureUnavailable => {
                Err(protocol_error("the server has no such procedure"))
            }
            Outcome::GarbageArguments => Err(protocol_error("the server could not read the call")),
        }
    }
}

/// Write `message` as one record of one last fragment.
///
/// # Errors
/// Where the connection broke.
pub fn write_record(writer: &mut impl Write, message: &[u8]) -> Result<()> {
    let length = u32::try_from(message.len())
        .ok()
        .filter(|length| *length < LAST_FRAGMENT)
        .ok_or_else(|| protocol_error("a record longer than a fragment can say"))?;
    writer
        .write_all(&(length | LAST_FRAGMENT).to_be_bytes())
        .and_then(|()| writer.write_all(message))
        .and_then(|()| writer.flush())
        .map_err(|e| classify("writing a record", &e))
}

/// Read one record, fragment by fragment until the last; `None` where the
/// connection closed cleanly before one began.
///
/// # Errors
/// Where the connection broke mid-record, or the record grew past `max`.
pub fn read_record(reader: &mut impl Read, max: usize) -> Result<Option<Vec<u8>>> {
    let mut record = Vec::new();
    loop {
        let mut mark = [0u8; 4];
        match reader.read_exact(&mut mark) {
            Ok(()) => {}
            Err(e) if record.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => return Err(classify("reading a record mark", &e)),
        }
        let mark = u32::from_be_bytes(mark);
        let length = (mark & !LAST_FRAGMENT) as usize;
        if record.len() + length > max {
            return Err(protocol_error(format!(
                "a record over the {max} bytes read here"
            )));
        }
        let start = record.len();
        record.resize(start + length, 0);
        reader
            .read_exact(&mut record[start..])
            .map_err(|e| classify("reading a fragment", &e))?;
        if mark & LAST_FRAGMENT != 0 {
            return Ok(Some(record));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_carries_its_unix_credentials_and_reads_back() {
        let call = Call {
            xid: 9,
            program: NFS_PROGRAM,
            version: NFS_VERSION,
            procedure: 6,
            credentials: Some(Unix::default()),
            arguments: vec![1, 2, 3, 4],
        };
        let bytes = call.to_bytes(&Unix::default());
        assert_eq!(Call::from_bytes(&bytes).expect("call"), call);
        assert!(
            Call::from_bytes(
                &Reply {
                    xid: 9,
                    outcome: Outcome::Success(vec![])
                }
                .to_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn a_reply_is_accepted_or_says_why_not() {
        let good = Reply {
            xid: 9,
            outcome: Outcome::Success(vec![0, 0, 0, 0]),
        };
        let read = Reply::from_bytes(&good.to_bytes()).expect("reply");
        assert_eq!(read, good);
        assert_eq!(read.results().expect("results"), [0, 0, 0, 0]);
        for outcome in [
            Outcome::ProgramUnavailable,
            Outcome::ProgramMismatch { low: 3, high: 3 },
            Outcome::ProcedureUnavailable,
            Outcome::GarbageArguments,
        ] {
            let reply = Reply { xid: 1, outcome };
            let read = Reply::from_bytes(&reply.to_bytes()).expect("reply");
            assert_eq!(read, reply);
            assert!(!read.results().expect_err("not run").retryable);
        }
        let mut denied = Vec::new();
        xdr::put_u32(&mut denied, 1);
        xdr::put_u32(&mut denied, REPLY);
        xdr::put_u32(&mut denied, MSG_DENIED);
        xdr::put_u32(&mut denied, 1);
        xdr::put_u32(&mut denied, 2);
        let error = Reply::from_bytes(&denied).expect_err("denied");
        assert!(error.message.contains("status 2"), "{error}");
    }

    #[test]
    fn a_record_crosses_in_fragments_and_a_closed_wire_is_none() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&3u32.to_be_bytes());
        wire.extend_from_slice(b"abc");
        wire.extend_from_slice(&(2u32 | LAST_FRAGMENT).to_be_bytes());
        wire.extend_from_slice(b"de");
        let mut cursor = &wire[..];
        assert_eq!(
            read_record(&mut cursor, 64).expect("record"),
            Some(b"abcde".to_vec())
        );
        assert_eq!(read_record(&mut cursor, 64).expect("closed"), None);
        assert!(read_record(&mut &wire[..], 4).is_err(), "over the maximum");
        let mut out = Vec::new();
        write_record(&mut out, b"xy").expect("written");
        assert_eq!(out, [0x80, 0, 0, 2, b'x', b'y']);
        assert!(read_record(&mut &out[..5], 64).is_err(), "cut mid-fragment");
    }
}
