//! A hash-chained, append-only JSONL decision log, and its verifier.
//!
//! Each record's hash is sha256 of its canonical body (the record serialized
//! with `hash` empty), and that body includes `prev_hash`, so any edit,
//! deletion or reordering of an earlier line breaks verification. Verification
//! also requires every line to be byte-identical to its canonical encoding, so
//! injected fields or reformatting are detected too.
//!
//! This is tamper-evident, not tamper-proof: an attacker who can rewrite the
//! whole file can recompute the chain. Anchoring the head hash elsewhere is
//! required for that; see the README.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub use delegate_guard_kernel::fact::{Decision, Fact};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `prev_hash` of the first record.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Longest accepted line.
const MAX_LINE: u64 = 4 << 20;

/// A kernel [`Fact`] stamped with the time it was decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// When the decision was made.
    pub time: Timestamp,
    /// What was decided.
    #[serde(flatten)]
    pub fact: Fact,
}

impl Entry {
    /// Stamps `fact` with `time`.
    #[must_use]
    pub fn new(time: Timestamp, fact: Fact) -> Self {
        Entry { time, fact }
    }
}

/// One chained decision as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// 1-based position in the log.
    pub seq: usize,
    /// The recorded facts.
    #[serde(flatten)]
    pub entry: Entry,
    /// Hash of the previous record, or [`GENESIS`].
    pub prev_hash: String,
    /// sha256 of this record's canonical body with `hash` empty.
    pub hash: String,
}

/// Errors from reading, writing or verifying a receipt log.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    /// A filesystem operation failed.
    #[error("{op} {}: {source}", .path.display())]
    Io {
        /// What was being done.
        op: &'static str,
        /// Log file.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// A line is not a valid record.
    #[error("line {line}: {source}")]
    Parse {
        /// 1-based line number.
        line: usize,
        /// Decode error.
        #[source]
        source: serde_json::Error,
    },
    /// A line exceeds the length limit.
    #[error("line {line}: longer than {MAX_LINE} bytes")]
    LineTooLong {
        /// 1-based line number.
        line: usize,
    },
    /// A record could not be encoded.
    #[error("encode record: {0}")]
    Encode(#[source] serde_json::Error),
    /// Sequence number out of order.
    #[error("record {line}: seq {got}, want {line}")]
    Seq {
        /// Expected sequence (line number).
        line: usize,
        /// Sequence found.
        got: usize,
    },
    /// Chain link broken.
    #[error("record {seq}: prev_hash does not match previous record")]
    PrevHash {
        /// Record sequence.
        seq: usize,
    },
    /// Content does not match its hash.
    #[error("record {seq}: hash mismatch (record altered)")]
    Hash {
        /// Record sequence.
        seq: usize,
    },
    /// The stored line differs from the canonical encoding of what it decodes to.
    #[error("record {seq}: not in canonical form (record altered)")]
    NonCanonical {
        /// Record sequence.
        seq: usize,
    },
}

/// A verification failure and how many records verified before it.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct VerifyFailure {
    /// Records that verified before the failure.
    pub valid: usize,
    /// What failed.
    #[source]
    pub error: ReceiptError,
}

fn io_err<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> ReceiptError + 'a {
    move |source| ReceiptError::Io {
        op,
        path: path.to_owned(),
        source,
    }
}

fn digest(record: &Record) -> Result<String, ReceiptError> {
    let body = Record {
        hash: String::new(),
        ..record.clone()
    };
    let bytes = serde_json::to_vec(&body).map_err(ReceiptError::Encode)?;
    Ok(hex(&Sha256::digest(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Last sequence number and hash in `path` (`(0, GENESIS)` if absent). The
/// caller must hold the session lock.
///
/// # Errors
///
/// Fails if the log cannot be read or a line does not decode.
pub fn head(path: &Path) -> Result<(usize, String), ReceiptError> {
    Ok(read_all(path)?.pop().map_or_else(
        || (0, GENESIS.to_owned()),
        |(_, record)| (record.seq, record.hash),
    ))
}

/// Chains `entry` after the current head and writes it with `O_APPEND` +
/// fsync. The caller must hold the session lock.
///
/// # Errors
///
/// Fails if the log cannot be read, encoded or written.
pub fn append(path: &Path, entry: Entry) -> Result<Record, ReceiptError> {
    let (seq, prev_hash) = head(path)?;
    let mut record = Record {
        seq: seq + 1,
        entry,
        prev_hash,
        hash: String::new(),
    };
    record.hash = digest(&record)?;
    let mut line = serde_json::to_vec(&record).map_err(ReceiptError::Encode)?;
    line.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err("open", path))?;
    file.write_all(&line).map_err(io_err("write", path))?;
    file.sync_all().map_err(io_err("sync", path))?;
    Ok(record)
}

/// Checks every link of the chain and returns the number of records.
///
/// # Errors
///
/// Returns the first failure and how many records verified before it.
pub fn verify(path: &Path) -> Result<usize, VerifyFailure> {
    let records = read_all(path).map_err(|error| VerifyFailure { valid: 0, error })?;
    let mut prev = GENESIS.to_owned();
    for (i, (raw, record)) in records.iter().enumerate() {
        check(i + 1, raw, record, &prev).map_err(|error| VerifyFailure { valid: i, error })?;
        prev.clone_from(&record.hash);
    }
    Ok(records.len())
}

fn check(line: usize, raw: &[u8], record: &Record, prev: &str) -> Result<(), ReceiptError> {
    if record.seq != line {
        return Err(ReceiptError::Seq {
            line,
            got: record.seq,
        });
    }
    if record.prev_hash != prev {
        return Err(ReceiptError::PrevHash { seq: record.seq });
    }
    if record.hash != digest(record)? {
        return Err(ReceiptError::Hash { seq: record.seq });
    }
    if serde_json::to_vec(record).map_err(ReceiptError::Encode)? != raw {
        return Err(ReceiptError::NonCanonical { seq: record.seq });
    }
    Ok(())
}

/// Reads every line as (raw bytes without the newline, decoded record).
fn read_all(path: &Path) -> Result<Vec<(Vec<u8>, Record)>, ReceiptError> {
    let file = match File::open(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        record => record.map_err(io_err("open", path))?,
    };
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in 1.. {
        let mut buf = Vec::new();
        let n = (&mut reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut buf)
            .map_err(io_err("read", path))?;
        if n == 0 {
            break;
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        } else if u64::try_from(buf.len()).map_or(true, |len| len > MAX_LINE) {
            return Err(ReceiptError::LineTooLong { line });
        }
        let rec =
            serde_json::from_slice(&buf).map_err(|source| ReceiptError::Parse { line, source })?;
        out.push((buf, rec));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
