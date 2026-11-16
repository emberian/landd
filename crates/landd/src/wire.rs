//! The daemon's wire protocol: a big-endian `u32` length, then that many
//! bytes of canonical JSON. Requests and responses are closed enums; there
//! is no prose to parse on either side.

use landd_core::canonical_json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Frames larger than this are refused.
pub const MAX_FRAME: u32 = 1 << 20;
/// A request is a lane name and a few words.
pub const MAX_REQUEST: u32 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Queue `lane`. With `tip`, that commit; without, the lane's branch as
    /// the push destination holds it right now.
    Enqueue {
        lane: String,
        #[serde(default)]
        tip: Option<String>,
    },
    /// What is queued and running, and the lanes settled after `since`
    /// (a cursor from an earlier reply; 0 for the oldest still kept).
    Status {
        #[serde(default)]
        since: u64,
    },
    // Braces, not a unit variant: serde only rejects unknown keys on variants with fields.
    Shutdown {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
    pub lane: String,
    pub tip: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settled {
    /// Position in the daemon's history; pass the reply's `next` as `since`.
    pub seq: u64,
    pub lane: String,
    pub tip: String,
    /// `landed`, `carried`, `on_base`, `no_change`, `declined`, `refused`,
    /// `deferred`, `unknown` or `error`.
    pub outcome: String,
    /// The full outcome (evidence, blockers) as JSON.
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Response {
    Enqueued { tip: String, depth: usize, duplicate: bool, replaced: bool },
    Status { queued: Vec<Waiting>, running: Vec<Waiting>, settled: Vec<Settled>, next: u64, batches: u64 },
    ShuttingDown {},
    Error { message: String },
}

pub fn write_frame<T: Serialize>(stream: &mut impl Write, message: &T) -> io::Result<()> {
    let body = canonical_json(message).map_err(io::Error::other)?;
    let length = u32::try_from(body.len()).ok().filter(|l| *l <= MAX_FRAME);
    let length = length.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

/// Read one frame of at most `limit` bytes. The buffer grows with the bytes
/// that actually arrive, never with the length a peer merely claims.
pub fn read_frame<T: DeserializeOwned>(stream: &mut impl Read, limit: u32) -> io::Result<T> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length);
    if length > limit.min(MAX_FRAME) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = Vec::new();
    stream.take(length as u64).read_to_end(&mut body)?;
    if body.len() != length as usize {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "frame cut short"));
    }
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut buffer = Vec::new();
        let requests =
            [Request::Enqueue { lane: "lane/a".into(), tip: None }, Request::Status { since: 7 }, Request::Shutdown {}];
        for request in &requests {
            write_frame(&mut buffer, request).unwrap();
        }
        assert_eq!(&buffer[..4], &43u32.to_be_bytes());
        assert_eq!(&buffer[4..47], br#"{"lane":"lane/a","op":"enqueue","tip":null}"#);
        let mut reader = buffer.as_slice();
        for request in &requests {
            assert_eq!(&read_frame::<Request>(&mut reader, MAX_REQUEST).unwrap(), request);
        }
        assert!(read_frame::<Request>(&mut reader, MAX_REQUEST).is_err());
        // Older clients that omit the optional fields still parse.
        let terse = br#"{"op":"status"}"#;
        let mut frame = (terse.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(terse);
        assert_eq!(read_frame::<Request>(&mut frame.as_slice(), MAX_REQUEST).unwrap(), Request::Status { since: 0 });
    }

    #[test]
    fn tooth_oversized_truncated_and_unknown_frames_are_refused() {
        let oversized = (MAX_FRAME + 1).to_be_bytes();
        assert!(read_frame::<Request>(&mut oversized.as_slice(), MAX_FRAME).is_err());
        // A request may not be as large as a reply.
        let big_request = (MAX_REQUEST + 1).to_be_bytes();
        assert!(read_frame::<Request>(&mut big_request.as_slice(), MAX_REQUEST).is_err());
        // A length that promises a megabyte and delivers three bytes.
        let mut liar = MAX_FRAME.to_be_bytes().to_vec();
        liar.extend_from_slice(b"{}!");
        assert!(read_frame::<Request>(&mut liar.as_slice(), MAX_FRAME).is_err());

        let mut truncated = Vec::new();
        write_frame(&mut truncated, &Request::Status { since: 0 }).unwrap();
        truncated.pop();
        assert!(read_frame::<Request>(&mut truncated.as_slice(), MAX_REQUEST).is_err());

        for body in [&br#"{"op":"reboot"}"#[..], br#"{"op":"status","extra":1}"#, br#"{"op":"shutdown","now":true}"#, b"status"] {
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(body);
            assert!(read_frame::<Request>(&mut frame.as_slice(), MAX_REQUEST).is_err(), "{}", String::from_utf8_lossy(body));
        }
    }
}
