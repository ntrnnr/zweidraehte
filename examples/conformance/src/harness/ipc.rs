//! IPC primitives for multi-process conformance testing.
//!
//! This module provides:
//! - Length-prefixed framing over Unix stream sockets
//! - Shared memory layout for persistent device state
//! - An IPC-backed link layer that replaces MockLinkLayer in the child process
//!
//! # Architecture
//!
//! The parent (conformance-runner) creates a `socketpair` and shared memory
//! region (`memfd_create`), then spawns the child (conformance-dut) passing
//! both FDs. The child maps the shared memory and creates an `IpcLinkLayer`
//! that communicates over the socket instead of in-process embassy channels.
//!
//! On restart, the child flushes persistent state to shared memory and
//! exits. The parent detects EOF on the socket, respawns a fresh child,
//! and the new child starts with clean volatile state (transport connections,
//! programming mode, COM object status) while persistent state survives
//! in shared memory.

use core::future::Future;
use core::mem::MaybeUninit;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use async_io::Async;
use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;

use zweidraehte_device::{
    encoding::tp1,
    layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase},
    messages::{
        buffers::{Buffer, MessageBuffer},
        builder::{ConfirmationMessage, IndicationMessage, RequestMessage},
        knx::*,
    },
};

// ============================================================================
// Framing Protocol
// ============================================================================
//
// Each frame on the IPC socket is:
//
//   +----------+----------+---------+
//   | tag (1B) | len (2B) | payload |
//   +----------+----------+---------+
//
// - tag: Message type discriminator
// - len: Little-endian u16 payload length
// - payload: Up to ~300 bytes of raw data
//
// The parent and child each read/write frames on their end of the
// socketpair. EOF on read means the other side exited.

/// Frame header size: 1 byte tag + 2 bytes length.
const HEADER_SIZE: usize = 3;

/// Maximum payload size. KNX messages are at most ~300 bytes in TP1 format.
const MAX_PAYLOAD: usize = 512;

// Tag values — parent-to-child
pub const TAG_INJECT: u8 = 0x01;
pub const TAG_SET_PROGRAMMING_MODE: u8 = 0x03;
pub const TAG_TRIGGER_READ: u8 = 0x04;
pub const TAG_TRIGGER_WRITE: u8 = 0x05;
pub const TAG_SHUTDOWN: u8 = 0x07;

// Tag values — child-to-parent
pub const TAG_CAPTURED: u8 = 0x02;
pub const TAG_READY: u8 = 0x06;
pub const TAG_LOG: u8 = 0x08;

/// A decoded IPC frame.
#[derive(Debug)]
pub struct IpcFrame {
    pub tag: u8,
    pub payload: Vec<u8>,
}

/// Write a framed message to a blocking Unix stream.
pub fn write_frame_blocking(stream: &mut UnixStream, tag: u8, payload: &[u8]) -> io::Result<()> {
    assert!(payload.len() <= MAX_PAYLOAD, "IPC payload too large: {}", payload.len());
    let len = payload.len() as u16;
    let header = [tag, len as u8, (len >> 8) as u8];
    stream.write_all(&header)?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }
    Ok(())
}

/// Read a framed message from a blocking Unix stream.
///
/// Returns `None` on EOF (other side closed).
pub fn read_frame_blocking(stream: &mut UnixStream) -> io::Result<Option<IpcFrame>> {
    let mut header = [0u8; HEADER_SIZE];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let tag = header[0];
    let len = u16::from_le_bytes([header[1], header[2]]) as usize;

    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload)?;
    }

    Ok(Some(IpcFrame { tag, payload }))
}

/// Write a framed message to an async Unix stream.
pub async fn write_frame_async(stream: &Async<UnixStream>, tag: u8, payload: &[u8]) -> io::Result<()> {
    assert!(payload.len() <= MAX_PAYLOAD, "IPC payload too large: {}", payload.len());
    let len = payload.len() as u16;
    let header = [tag, len as u8, (len >> 8) as u8];

    // Write header
    let mut written = 0;
    while written < HEADER_SIZE {
        stream.writable().await?;
        match stream.get_ref().write(&header[written..]) {
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }

    // Write payload
    if !payload.is_empty() {
        let mut written = 0;
        while written < payload.len() {
            stream.writable().await?;
            match stream.get_ref().write(&payload[written..]) {
                Ok(n) => written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    Ok(())
}

/// Read a framed message from an async Unix stream.
///
/// Returns `None` on EOF (other side closed/exited).
pub async fn read_frame_async(stream: &Async<UnixStream>) -> io::Result<Option<IpcFrame>> {
    let mut header = [0u8; HEADER_SIZE];
    if !read_exact_async(stream, &mut header).await? {
        return Ok(None);
    }

    let tag = header[0];
    let len = u16::from_le_bytes([header[1], header[2]]) as usize;

    let mut payload = vec![0u8; len];
    if len > 0
        && !read_exact_async(stream, &mut payload).await? {
            return Ok(None);
        }

    Ok(Some(IpcFrame { tag, payload }))
}

/// Read exactly `buf.len()` bytes from an async stream.
///
/// Returns `false` on EOF before any bytes are read.
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

// ============================================================================
// Shared Memory
// ============================================================================
//
// The shared memory region stores device state serialized with postcard,
// using the same `[magic][len][payload]` format as the RP flash storage.
// This lets us reuse the existing `to_persisted()` / `from_persisted()`
// serialization which correctly handles auth keys, table load/run states,
// etc. We wrap the `PersistedState` with test memory regions in a
// `ConformancePersistedState` struct for the full snapshot.

/// Magic bytes at the start of the shared memory region.
const SHM_MAGIC: [u8; 4] = *b"KNXS";
/// Header: 4 bytes magic + 2 bytes payload length.
const SHM_HEADER_SIZE: usize = 6;

/// Size of the shared memory region (64 KiB).
///
/// Generous for postcard-serialized state (typically ~2-4 KiB).
pub const SHM_SIZE: usize = 64 * 1024;

/// RAII wrapper around a `memfd_create`-backed shared memory region.
///
/// The region stores postcard-serialized device state:
///
/// ```text
/// [magic: 4B "KNXS"] [len: 2B LE] [postcard payload ...]
/// ```
///
/// When the magic doesn't match, the region is uninitialized.
pub struct SharedMemory {
    fd: std::os::fd::OwnedFd,
    ptr: *mut u8,
    size: usize,
}

// SAFETY: The shared memory region is only accessed by one process at a
// time (parent writes before spawn, child has exclusive access while
// running, parent reads after child dies).
unsafe impl Send for SharedMemory {}

impl SharedMemory {
    /// Create a new anonymous shared memory region via `memfd_create`.
    pub fn create() -> io::Result<Self> {
        use nix::sys::memfd;
        use nix::sys::mman;

        let size = SHM_SIZE;

        // Create anonymous fd
        let fd = memfd::memfd_create(
            c"conformance_state",
            memfd::MemFdCreateFlag::MFD_CLOEXEC,
        )
        .map_err(io::Error::other)?;

        // Set the size
        nix::unistd::ftruncate(&fd, size as i64)
            .map_err(io::Error::other)?;

        // Map into our address space
        let ptr = unsafe {
            mman::mmap(
                None,
                std::num::NonZeroUsize::new(size).expect("non-zero size"),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_SHARED,
                &fd,
                0,
            )
            .map_err(io::Error::other)?
        };

        Ok(Self { fd, ptr: ptr.as_ptr() as *mut u8, size })
    }

    /// Map an existing shared memory region from a raw fd.
    ///
    /// # Safety
    ///
    /// The caller must ensure `fd` is a valid, open file descriptor
    /// referring to a shared memory region of at least `SHM_SIZE` bytes.
    /// Ownership of the fd is transferred to this struct.
    pub unsafe fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        use nix::sys::mman;
        use std::os::fd::OwnedFd;

        let size = SHM_SIZE;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let ptr = unsafe {
            mman::mmap(
                None,
                std::num::NonZeroUsize::new(size).expect("non-zero size"),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_SHARED,
                &owned_fd,
                0,
            )
            .map_err(io::Error::other)?
        };

        Ok(Self { fd: owned_fd, ptr: ptr.as_ptr() as *mut u8, size })
    }

    /// Get a raw byte slice of the shared memory region.
    fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for `size` bytes; synchronization is
        // handled by process lifecycle (no concurrent access).
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    /// Get a mutable raw byte slice of the shared memory region.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for `size` bytes; we have exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    /// Write a postcard-serialized blob into shared memory.
    ///
    /// Writes the `[magic][len][payload]` header then the serialized bytes.
    pub fn write_state<T: serde::Serialize>(&mut self, state: &T) -> io::Result<()> {
        let buf = self.as_mut_slice();

        // Write magic
        buf[..4].copy_from_slice(&SHM_MAGIC);

        // Serialize directly into the payload region
        let payload = postcard::to_slice(state, &mut buf[SHM_HEADER_SIZE..])
            .map_err(|e| io::Error::other(format!("postcard serialize: {e}")))?;
        let len = payload.len();

        // Write length
        buf[4..6].copy_from_slice(&(len as u16).to_le_bytes());

        Ok(())
    }

    /// Read and deserialize state from shared memory.
    ///
    /// Returns `None` if the magic doesn't match (uninitialized).
    pub fn read_state<T: for<'de> serde::Deserialize<'de>>(&self) -> io::Result<Option<T>> {
        let buf = self.as_slice();

        // Check magic
        if buf[..4] != SHM_MAGIC {
            return Ok(None);
        }

        // Read length
        let len = u16::from_le_bytes([buf[4], buf[5]]) as usize;
        if len == 0 || SHM_HEADER_SIZE + len > self.size {
            return Ok(None);
        }

        let payload = &buf[SHM_HEADER_SIZE..SHM_HEADER_SIZE + len];
        let state = postcard::from_bytes(payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("postcard deserialize: {e}")))?;
        Ok(Some(state))
    }

    /// Get the raw file descriptor (for passing to child process).
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Clear the `FD_CLOEXEC` flag so the fd is inherited by the child.
    pub fn clear_cloexec(&self) -> io::Result<()> {
        use nix::fcntl;
        let raw = self.fd.as_raw_fd();
        let flags = fcntl::fcntl(raw, fcntl::FcntlArg::F_GETFD)
            .map_err(io::Error::other)?;
        let mut fd_flags = nix::fcntl::FdFlag::from_bits_truncate(flags);
        fd_flags.remove(nix::fcntl::FdFlag::FD_CLOEXEC);
        fcntl::fcntl(raw, fcntl::FcntlArg::F_SETFD(fd_flags))
            .map_err(io::Error::other)?;
        Ok(())
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe {
            let _ = nix::sys::mman::munmap(
                std::ptr::NonNull::new(self.ptr as *mut _).expect("non-null ptr"),
                self.size,
            );
        }
        // OwnedFd closes the fd when dropped (happens automatically after this)
    }
}

// ============================================================================
// IPC Commands
// ============================================================================
//
// Non-INJECT frames from the parent (SetProgrammingMode, TriggerRead,
// TriggerWrite) are dispatched by the link layer to a command channel.
// A separate task in the DUT binary reads from this channel and executes
// the commands against the stack.

/// Commands received from the parent that need stack access.
pub enum IpcCommand {
    /// Set programming mode on/off.
    SetProgrammingMode(bool),
    /// Trigger a GroupValue_Read for the given ASAP.
    TriggerRead(u16),
    /// Trigger a GroupValue_Write for the given ASAP.
    TriggerWrite(u16),
}

// ============================================================================
// IPC Link Layer
// ============================================================================

/// Link layer that communicates over a Unix socket for multi-process
/// conformance testing.
///
/// Instead of in-process embassy channels, this link layer:
/// - Reads injected telegrams from the socket (parent → child)
/// - Writes captured telegrams to the socket (child → parent)
/// - Dispatches non-INJECT commands to a command channel for the DUT
///
/// The parent sends `TAG_INJECT` frames containing TP1 bytes. This layer
/// converts them to internal format and sends them up as indications.
///
/// When the stack sends outgoing requests, this layer converts them to TP1
/// format and writes `TAG_CAPTURED` frames to the socket, then sends an
/// immediate L_Data_Con confirmation back to the stack.
pub struct IpcLinkLayer<'a> {
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
    socket: Async<UnixStream>,
    buffer_manager: zweidraehte_device::messages::buffers::DynBufferManager<'static>,
    command_tx: DynamicSender<'a, IpcCommand>,
}

impl<'a> IpcLinkLayer<'a> {
    fn new(
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        socket: Async<UnixStream>,
        buffer_manager: zweidraehte_device::messages::buffers::DynBufferManager<'static>,
        command_tx: DynamicSender<'a, IpcCommand>,
    ) -> Self {
        Self { ind_tx, conf_tx, socket, buffer_manager, command_tx }
    }
}

impl<'a> IpcLinkLayer<'a> {
    async fn process(&mut self, mut req_rx: impl Inbox<RequestMessage<Buffer<'static>>>) -> ! {
        loop {
            match select(read_frame_async(&self.socket), req_rx.next()).await {
                // Frame from parent (injected telegram or command)
                Either::First(Ok(Some(frame))) => {
                    match frame.tag {
                        TAG_INJECT => {
                            // Convert from TP1 format to internal format
                            let mut buffer = self.buffer_manager.alloc().await;
                            buffer.fill_from_slice(&frame.payload);
                            let msg = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
                            let converted_buf = tp1::tp1_to_knx_message_no_checksum(msg.into_inner());
                            let internal_msg = KnxMessageBuffer::new(converted_buf, ServiceType::L_Data_Ind);
                            log::debug!("IPC LL injecting message: {:x?}", internal_msg);
                            self.ind_tx.send(
                                IndicationMessage::indication(internal_msg)
                            ).await;
                        }
                        TAG_SET_PROGRAMMING_MODE => {
                            let enabled = frame.payload.first().copied().unwrap_or(0) != 0;
                            log::debug!("IPC LL: SetProgrammingMode({})", enabled);
                            self.command_tx.send(IpcCommand::SetProgrammingMode(enabled)).await;
                        }
                        TAG_TRIGGER_READ => {
                            if frame.payload.len() >= 2 {
                                let asap = u16::from_le_bytes([frame.payload[0], frame.payload[1]]);
                                log::debug!("IPC LL: TriggerRead(ASAP {})", asap);
                                self.command_tx.send(IpcCommand::TriggerRead(asap)).await;
                            }
                        }
                        TAG_TRIGGER_WRITE => {
                            if frame.payload.len() >= 2 {
                                let asap = u16::from_le_bytes([frame.payload[0], frame.payload[1]]);
                                log::debug!("IPC LL: TriggerWrite(ASAP {})", asap);
                                self.command_tx.send(IpcCommand::TriggerWrite(asap)).await;
                            }
                        }
                        TAG_SHUTDOWN => {
                            log::info!("IPC LL received shutdown, exiting");
                            std::process::exit(0);
                        }
                        other => {
                            log::warn!("IPC LL ignoring unknown tag: 0x{:02x}", other);
                        }
                    }
                }

                // Socket EOF — parent closed its end (we're being killed)
                Either::First(Ok(None)) => {
                    log::info!("IPC LL socket EOF, parent closed connection");
                    std::process::exit(0);
                }

                // Socket error
                Either::First(Err(e)) => {
                    log::error!("IPC LL socket error: {}", e);
                    std::process::exit(1);
                }

                // Request from upper layers (outgoing message)
                Either::Second(msg) => {
                    log::trace!("IPC LL received request: {:?}", msg);

                    // Capture the outgoing message and send to parent
                    let data = knx_to_tp1_vec_no_checksum(&msg.buf()[..msg.len()]);
                    let service_type = msg.service_type();

                    // Build captured frame: service_type byte + TP1 data
                    let mut payload = Vec::with_capacity(1 + data.len());
                    payload.push(service_type.into());
                    payload.extend_from_slice(&data);

                    if let Err(e) = write_frame_async(&self.socket, TAG_CAPTURED, &payload).await {
                        log::error!("IPC LL failed to write captured frame: {}", e);
                    }

                    // Send confirmation back to stack (simulate successful transmission)
                    let mut inner = msg.into_inner();
                    match inner.service_type() {
                        ServiceType::L_Data_Req => {
                            inner.ctrl_field_mut().set_c(Confirm::NoError);
                            inner.set_service_type(ServiceType::L_Data_Con);
                            self.conf_tx.send(ConfirmationMessage::confirmation(inner)).await;
                        }
                        _ => {
                            log::warn!("IPC LL: unhandled request service type: {:?}", inner.service_type());
                            inner.ctrl_field_mut().set_c(Confirm::Err);
                            self.conf_tx.send(ConfirmationMessage::confirmation(inner)).await;
                        }
                    }
                }
            }
        }
    }
}

/// Convert internal KNX message bytes to TP1 format (no checksum) using Vec.
///
/// This is the same conversion as `mock.rs::knx_to_tp1_vec_no_checksum`
/// but exposed here for the IPC link layer.
fn knx_to_tp1_vec_no_checksum(src: &[u8]) -> Vec<u8> {
    let len = src.len();

    // Check for standard frame: length <= 23 and lower 4 bits of NPDU are 0
    if (len < 23) && ((src[5] & 0x0f) == 0) {
        // Standard frame - copy with modified control and length fields
        let mut data = src.to_vec();
        data[5] = (data[5] & 0xf0) | ((len - 7) as u8);
        data[0] = (data[0] & 0x0c) | 0xb0;
        data
    } else {
        // Extended frame - need to insert extended control field
        let orig_npdu = src[5];
        let mut data = Vec::with_capacity(len + 1);

        // Control byte with extended frame marker
        data.push((src[0] & 0x0C) | 0x30);
        // Insert extended control field
        data.push(orig_npdu);
        // Copy bytes 1-5 (source addr, dest addr, NPDU high nibble)
        data.extend_from_slice(&src[1..5]);
        // Insert length field
        data.push((len - 7) as u8);
        // Copy remaining data (APDU)
        data.extend_from_slice(&src[6..]);
        data
    }
}

/// Resources for IpcLinkLayer (minimal — the socket is passed at build time).
pub struct IpcLinkLayerResources {
    _private: MaybeUninit<()>,
}

impl Default for IpcLinkLayerResources {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcLinkLayerResources {
    pub const fn new() -> Self {
        Self { _private: MaybeUninit::uninit() }
    }
}

/// Builder for the IPC link layer.
///
/// Takes the child's end of the socketpair, a buffer manager for
/// allocating injection buffers, and a command channel sender for
/// dispatching non-INJECT commands to the stack.
pub struct IpcLinkLayerBuilder {
    socket: Async<UnixStream>,
    buffer_manager: zweidraehte_device::messages::buffers::DynBufferManager<'static>,
    command_tx: DynamicSender<'static, IpcCommand>,
}

impl IpcLinkLayerBuilder {
    /// Create a new builder from a raw socket fd, buffer manager, and
    /// command channel sender.
    ///
    /// The fd should be the child's end of a `socketpair`. It will be
    /// set to non-blocking and wrapped in `async_io::Async`.
    pub fn new(
        socket_fd: RawFd,
        buffer_manager: zweidraehte_device::messages::buffers::DynBufferManager<'static>,
        command_tx: DynamicSender<'static, IpcCommand>,
    ) -> io::Result<Self> {
        let stream = unsafe { UnixStream::from_raw_fd(socket_fd) };
        stream.set_nonblocking(true)?;
        let socket = Async::new(stream)?;
        Ok(Self { socket, buffer_manager, command_tx })
    }
}

impl LinkLayerBuilderBase for IpcLinkLayerBuilder {
    type Resources = IpcLinkLayerResources;

    fn create_resources(&self) -> Self::Resources {
        IpcLinkLayerResources::new()
    }
}

impl<CTX> LinkLayerBuilder<CTX> for IpcLinkLayerBuilder {
    fn build_and_run<'a>(
        self,
        _resources: &'a mut Self::Resources,
        _context: &'a CTX,
        _ll_endpoints: (),
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl Future<Output = !> + 'a {
        let mut link_layer = IpcLinkLayer::new(
            ind_tx,
            conf_tx,
            self.socket,
            self.buffer_manager,
            self.command_tx,
        );
        async move { link_layer.process(req_rx).await }
    }
}