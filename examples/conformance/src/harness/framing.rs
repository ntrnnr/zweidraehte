//! Length-prefixed postcard framing for the conformance IPC protocol.
//!
//! # Wire format
//!
//! ```text
//! [len: 2B LE][postcard bytes ...]
//! ```
//!
//! The 2-byte little-endian length prefix delimits one postcard-
//! serialized message. Postcard itself is a stream codec — it does not
//! know where one message ends and the next begins on a shared stream,
//! which is why we need the length prefix.
//!
//! `MAX_PAYLOAD` is generous (64 KiB − 2) so log forwarding with long
//! hex-dump messages fits. Real protocol messages are a few hundred
//! bytes at most.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use async_io::Async;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Header size on the wire (length prefix only; postcard has no magic).
const HEADER_SIZE: usize = 2;

/// Upper bound on the postcard payload in a single frame.
///
/// Chosen so `usize <= u16::MAX` is guaranteed to fit. No real
/// conformance message approaches this; log entries with large hex
/// dumps are the only realistic consumers.
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

/// Encode `msg` into a fresh `Vec<u8>` via postcard.
///
/// Returned buffer does not include the wire-format length prefix —
/// that's added by the `write_frame_*` helpers.
pub fn encode<M: Serialize>(msg: &M) -> io::Result<Vec<u8>> {
    postcard::to_allocvec(msg).map_err(|e| io::Error::other(format!("postcard encode: {e}")))
}

/// Decode a postcard payload into `M`.
pub fn decode<M: DeserializeOwned>(bytes: &[u8]) -> io::Result<M> {
    postcard::from_bytes(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard decode: {e}")))
}

// ============================================================================
// Blocking helpers (used by the IpcLogger in the DUT binaries, which can't
// depend on an async runtime since `log::log!` may fire from any context).
// ============================================================================

/// Encode `msg` and write it as a length-prefixed frame on a blocking
/// stream. Panics on oversized payload — logging callers should keep
/// messages under `MAX_PAYLOAD`.
pub fn write_msg_blocking<M: Serialize>(stream: &mut UnixStream, msg: &M) -> io::Result<()> {
    let payload = encode(msg)?;
    write_frame_blocking(stream, &payload)
}

/// Write a pre-encoded payload as a length-prefixed frame.
///
/// The header and payload are concatenated into a single buffer before
/// writing, so one kernel `write()` call covers the whole frame. On a
/// Unix socketpair, writes shorter than `PIPE_BUF` (4 KiB on Linux)
/// are atomic — this matters when the logger and the async link
/// layer share the same socket: interleaved partial writes would
/// corrupt postcard frames.
pub fn write_frame_blocking(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    assert!(payload.len() <= MAX_PAYLOAD, "IPC payload too large: {}", payload.len());
    let len = payload.len() as u16;
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    stream.write_all(&buf)
}

// ============================================================================
// Async helpers (used everywhere in the parent harness and the child's
// IpcLinkLayer main loop).
// ============================================================================

/// Encode `msg` and write it as a length-prefixed frame on an async
/// stream.
pub async fn write_msg_async<M: Serialize>(stream: &Async<UnixStream>, msg: &M) -> io::Result<()> {
    let payload = encode(msg)?;
    write_frame_async(stream, &payload).await
}

/// Write a pre-encoded payload as a length-prefixed frame on an async
/// stream.
///
/// Concatenates header + payload into a single buffer and writes it in
/// one `.await` cycle per kernel `write()`. On a Unix socketpair,
/// writes shorter than `PIPE_BUF` (4 KiB) are atomic at the kernel
/// level, so other fds duped from the same socketpair (e.g. the
/// blocking log forwarder) can't interleave partial bytes with our
/// frames.
///
/// Frames larger than `PIPE_BUF` would theoretically split; in
/// practice conformance payloads are far smaller than 4 KiB so we
/// don't handle that case specially — a warning is logged if
/// payload exceeds `PIPE_BUF`.
pub async fn write_frame_async(stream: &Async<UnixStream>, payload: &[u8]) -> io::Result<()> {
    assert!(payload.len() <= MAX_PAYLOAD, "IPC payload too large: {}", payload.len());
    let len = payload.len() as u16;
    let total = HEADER_SIZE + payload.len();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);

    // Writes above PIPE_BUF are not atomic — log a warning so we
    // notice if conformance frames ever grow that big.
    const PIPE_BUF: usize = 4096;
    if total > PIPE_BUF {
        log::warn!("IPC frame size {} exceeds PIPE_BUF ({}) — atomicity not guaranteed", total, PIPE_BUF);
    }

    let mut written = 0;
    while written < buf.len() {
        stream.writable().await?;
        match stream.get_ref().write(&buf[written..]) {
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read one length-prefixed frame and decode it as `M`.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read.
pub async fn read_msg_async<M: DeserializeOwned>(stream: &Async<UnixStream>) -> io::Result<Option<M>> {
    match read_frame_async(stream).await? {
        Some(payload) => decode(&payload).map(Some),
        None => Ok(None),
    }
}

/// Read one length-prefixed frame into a fresh `Vec<u8>`.
///
/// Returns `Ok(None)` on clean EOF before any bytes are read.
pub async fn read_frame_async(stream: &Async<UnixStream>) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; HEADER_SIZE];
    if !read_exact_async(stream, &mut header).await? {
        return Ok(None);
    }

    let len = u16::from_le_bytes(header) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 && !read_exact_async(stream, &mut payload).await? {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial frame"));
    }
    Ok(Some(payload))
}

/// Read exactly `buf.len()` bytes from an async stream.
///
/// Returns `Ok(false)` on clean EOF before the first byte; partial
/// reads after some bytes have been consumed are surfaced as
/// `UnexpectedEof`.
async fn read_exact_async(stream: &Async<UnixStream>, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        stream.readable().await?;
        match stream.get_ref().read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial frame")),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}
