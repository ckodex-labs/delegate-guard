//! Wire format: a `u32` big-endian length, then that many bytes of JSON.
//! One request frame and one response frame per connection.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Version carried in every frame; a mismatch is a failure, never a guess.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest accepted frame body: the 8 MiB hook payload limit plus envelope room.
pub const MAX_FRAME: usize = (8 << 20) + (64 << 10);

/// Client → daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// [`PROTOCOL_VERSION`].
    pub v: u32,
    /// The hook payload exactly as Claude Code wrote it to stdin.
    pub event: serde_json::Value,
}

/// Daemon → client: what the hook process should emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// [`PROTOCOL_VERSION`].
    pub v: u32,
    /// Process exit code (0, 1 or 2).
    pub exit: u8,
    /// Hook stdout.
    #[serde(default)]
    pub stdout: String,
    /// Hook stderr.
    #[serde(default)]
    pub stderr: String,
}

/// Why a frame could not be read.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Transport failure, including timeouts and a peer that closed early.
    #[error("read frame: {0}")]
    Io(#[from] io::Error),
    /// Declared length exceeds [`MAX_FRAME`].
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
}

/// Writes one frame.
///
/// # Errors
///
/// Fails if `body` exceeds [`MAX_FRAME`] or the write fails.
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Reads one frame, refusing oversized ones before allocating.
///
/// # Errors
///
/// [`FrameError`] on transport failure or an oversized declared length.
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, FrameError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len =
        usize::try_from(u32::from_be_bytes(len)).map_err(|_| FrameError::TooLarge(usize::MAX))?;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"v\":1}").unwrap();
        assert_eq!(read_frame(&mut buf.as_slice()).unwrap(), b"{\"v\":1}");
    }

    #[test]
    fn test_read_frame_rejects_oversized_length_before_allocating() {
        let declared = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
        assert!(matches!(
            read_frame(&mut declared.as_slice()),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn test_read_frame_rejects_truncated_body() {
        let mut buf = 10u32.to_be_bytes().to_vec();
        buf.extend_from_slice(b"short");
        assert!(matches!(
            read_frame(&mut buf.as_slice()),
            Err(FrameError::Io(_))
        ));
    }
}
