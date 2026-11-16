//! The daemon's wire protocol: a big-endian `u32` length, then that many
//! bytes of canonical JSON. Requests and responses are closed enums; there
//! is no prose to parse on either side.

use landd_core::canonical_json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Frames larger than this are refused before any allocation.
pub const MAX_FRAME: u32 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Enqueue { lane: String },
    // Braces, not unit variants: serde only rejects unknown keys on variants with fields.
    Status {},
    Shutdown {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
    pub lane: String,
    pub tip: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settled {
    pub lane: String,
    pub tip: String,
    /// `landed`, `already_landed`, `declined`, `refused`, `unknown` or `error`.
    pub outcome: String,
    /// The full outcome (evidence, blockers) as JSON.
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Response {
    Enqueued { tip: String, depth: usize, duplicate: bool },
    Status { queued: Vec<Waiting>, running: Vec<Waiting>, settled: Vec<Settled>, batches: u64 },
    ShuttingDown,
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

pub fn read_frame<T: DeserializeOwned>(stream: &mut impl Read) -> io::Result<T> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length);
    if length > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; length as usize];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut buffer = Vec::new();
        let requests = [Request::Enqueue { lane: "lane/a".into() }, Request::Status {}, Request::Shutdown {}];
        for request in &requests {
            write_frame(&mut buffer, request).unwrap();
        }
        assert_eq!(&buffer[..4], &32u32.to_be_bytes());
        assert_eq!(&buffer[4..36], br#"{"lane":"lane/a","op":"enqueue"}"#);
        let mut reader = buffer.as_slice();
        for request in &requests {
            assert_eq!(&read_frame::<Request>(&mut reader).unwrap(), request);
        }
        assert!(read_frame::<Request>(&mut reader).is_err());
    }

    #[test]
    fn tooth_oversized_truncated_and_unknown_frames_are_refused() {
        let oversized = (MAX_FRAME + 1).to_be_bytes();
        assert!(read_frame::<Request>(&mut oversized.as_slice()).is_err());

        let mut truncated = Vec::new();
        write_frame(&mut truncated, &Request::Status {}).unwrap();
        truncated.pop();
        assert!(read_frame::<Request>(&mut truncated.as_slice()).is_err());

        for body in [&br#"{"op":"reboot"}"#[..], br#"{"op":"status","extra":1}"#, b"status"] {
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(body);
            assert!(read_frame::<Request>(&mut frame.as_slice()).is_err(), "{}", String::from_utf8_lossy(body));
        }
    }
}
