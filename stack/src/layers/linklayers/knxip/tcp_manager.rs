//! TCP connection manager for KNX/IP.
//!
//! Owns the TCP listener and a fixed-size array of active TCP connections.
//! Each connection wraps a stream with a [`KnxIpFrameReader`] for frame
//! extraction and tracks idle timeout state.
//!
//! The [`TcpManager`] presents a unified event interface via
//! [`next_event()`](TcpManager::next_event) that the main loop `select`s
//! alongside UDP socket futures.

use core::cell::RefCell;
use core::net::SocketAddrV4;
use core::pin::Pin;

use embassy_time::{Duration, Instant};
use heapless::Vec;

use platform::{AsyncTcpListener, IpTransport, TcpListenerOptions};

use crate::messages::buffers::{Buffer, DynBufferManager, MessageBuffer};

use super::tcp_framing::{FrameEvent, KnxIpFrameReader};

// ============================================================================
// Constants
// ============================================================================

/// Idle timeout for TCP connections without an active inner KNX/IP connection.
///
/// Per KNX spec 3/8/2 §8.4.3: if a TCP connection has no active KNX/IP
/// connection (i.e., no ConnectRequest has been processed, or all inner
/// connections have been disconnected), the server closes the TCP
/// connection after this duration.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum bytes to read from a TCP stream in one call.
///
/// Sized to hold several KNX/IP frames. Actual frame extraction is
/// handled by `KnxIpFrameReader` which can assemble frames across
/// multiple reads.
const TCP_READ_BUF_SIZE: usize = 512;

/// Output buffer for frame reassembly. Must be large enough for the
/// largest KNX/IP frame we want to handle. Frames exceeding this size
/// are skipped (not fatal per spec).
const FRAME_OUTPUT_BUF_SIZE: usize = 512;

// ============================================================================
// Per-connection state
// ============================================================================

/// State of a single active TCP connection.
///
/// Wraps the async stream with a frame reader, peer address, and idle
/// tracking. The `channel_ids` field tracks which inner KNX/IP connections
/// are running over this TCP stream — when the stream closes, the
/// connection manager uses this to tear down the right channels.
pub struct TcpConnectionState<S> {
    stream: S,
    framer: KnxIpFrameReader,
    peer_addr: SocketAddrV4,
    connected_at: Instant,
    last_activity: Instant,
    /// Channel IDs of inner KNX/IP connections on this TCP stream.
    /// Updated by the main loop when connections are created/destroyed.
    channel_ids: Vec<u8, 4>,
}

impl<S> TcpConnectionState<S> {
    fn new(stream: S, peer_addr: SocketAddrV4) -> Self {
        let now = Instant::now();
        Self {
            stream,
            framer: KnxIpFrameReader::new(),
            peer_addr,
            connected_at: now,
            last_activity: now,
            channel_ids: Vec::new(),
        }
    }

    /// Whether this TCP connection has an active inner KNX/IP connection.
    fn has_active_channels(&self) -> bool {
        !self.channel_ids.is_empty()
    }

    /// Whether the idle timeout has expired (only applies when no inner
    /// connections are active).
    fn is_idle_expired(&self, now: Instant) -> bool {
        !self.has_active_channels() && now.duration_since(self.last_activity) >= TCP_IDLE_TIMEOUT
    }

    /// Record a channel ID as using this TCP connection.
    pub fn add_channel(&mut self, channel_id: u8) {
        if !self.channel_ids.contains(&channel_id) {
            let _ = self.channel_ids.push(channel_id);
        }
    }

    /// Remove a channel ID from this TCP connection.
    pub fn remove_channel(&mut self, channel_id: u8) {
        if let Some(pos) = self.channel_ids.iter().position(|&id| id == channel_id) {
            self.channel_ids.swap_remove(pos);
        }
    }
}

// ============================================================================
// TCP events
// ============================================================================

/// Event produced by the TCP manager for the main loop.
pub enum TcpEvent {
    /// A complete KNX/IP frame was extracted from a TCP stream.
    Frame {
        tcp_idx: usize,
        peer: SocketAddrV4,
        buffer: Buffer<'static>,
    },
    /// A TCP connection was closed (peer disconnect, I/O error, or idle
    /// timeout). The `channel_ids` are the inner KNX/IP connections that
    /// need to be torn down.
    Closed {
        tcp_idx: usize,
        channel_ids: Vec<u8, 4>,
    },
}

// ============================================================================
// TCP Manager
// ============================================================================

/// Manages TCP listener and active connections for KNX/IP.
///
/// Generic over the platform's `IpTransport` and a const `MAX_TCP`
/// parameter controlling the maximum number of concurrent TCP connections.
///
/// The manager is driven by the main loop calling [`next_event()`] in a
/// select alongside other futures. It handles:
/// - Accepting new connections (rejecting when full)
/// - Reading from all active streams and extracting frames
/// - Detecting idle timeouts
/// - Writing responses back on specific connections
pub struct TcpManager<T: IpTransport, const MAX_TCP: usize> {
    listener: Option<T::TcpListener>,
    connections: [Option<TcpConnectionState<T::TcpStream>>; MAX_TCP],
}

impl<T: IpTransport, const MAX_TCP: usize> TcpManager<T, MAX_TCP> {
    /// Create a new TCP manager with no listener and no connections.
    ///
    /// Call [`bind()`](Self::bind) to start the listener.
    pub fn new() -> Self {
        Self {
            listener: None,
            connections: core::array::from_fn(|_| None),
        }
    }

    /// Bind the TCP listener to the given options.
    ///
    /// Returns an error if binding fails (e.g., port in use). The manager
    /// remains usable without a listener — it just won't accept connections.
    pub fn bind(
        &mut self,
        options: TcpListenerOptions,
    ) -> Result<(), <T::TcpListener as AsyncTcpListener>::Error> {
        match T::TcpListener::bind(options) {
            Ok(listener) => {
                self.listener = Some(listener);
                Ok(())
            }
            Err(e) => {
                error!("Failed to bind TCP listener: {:?}", e);
                Err(e)
            }
        }
    }

    /// Get the local endpoint the listener is bound to, if any.
    pub fn local_endpoint(&self) -> Option<SocketAddrV4> {
        self.listener.as_ref().map(|l| l.local_endpoint())
    }

    /// Find the connection state for a given TCP index.
    pub fn connection_mut(&mut self, tcp_idx: usize) -> Option<&mut TcpConnectionState<T::TcpStream>> {
        self.connections.get_mut(tcp_idx).and_then(|slot| slot.as_mut())
    }

    /// Check idle timeouts and close expired connections.
    ///
    /// Returns a list of closed connection events. Called from the main
    /// loop's timer handler.
    pub fn check_idle_timeouts(&mut self) -> Vec<TcpEvent, MAX_TCP> {
        let now = Instant::now();
        let mut events = Vec::new();

        for (idx, slot) in self.connections.iter_mut().enumerate() {
            let should_close = slot.as_ref().map_or(false, |conn| conn.is_idle_expired(now));

            if should_close {
                let conn = slot.take().expect("just checked Some");
                info!(
                    "TCP connection {} from {} idle for {}s, closing",
                    idx,
                    conn.peer_addr,
                    now.duration_since(conn.last_activity).as_secs()
                );
                let _ = events.push(TcpEvent::Closed { tcp_idx: idx, channel_ids: conn.channel_ids });
                // Stream is dropped here, closing the TCP connection.
            }
        }

        events
    }

    /// Read from a specific TCP connection and extract frames.
    ///
    /// Returns `Some(TcpEvent)` if a frame was extracted or the connection
    /// was closed. Returns `None` if more data is needed (caller should
    /// re-poll).
    ///
    /// This method reads once from the stream and processes all complete
    /// frames in the read buffer. The caller should call this in a loop
    /// until it returns `None` or a `Closed` event.
    pub async fn read_from(
        &mut self,
        tcp_idx: usize,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> Option<TcpEvent> {
        let conn = self.connections[tcp_idx].as_mut()?;

        let mut read_buf = [0u8; TCP_READ_BUF_SIZE];

        // Read from the stream
        let n = match embedded_io_async::Read::read(&mut conn.stream, &mut read_buf).await {
            Ok(0) => {
                // Clean close
                info!("TCP connection {} from {} closed by peer", tcp_idx, conn.peer_addr);
                let conn = self.connections[tcp_idx].take().expect("just checked Some");
                return Some(TcpEvent::Closed { tcp_idx, channel_ids: conn.channel_ids });
            }
            Ok(n) => n,
            Err(_e) => {
                #[cfg(feature = "log")]
                log::error!("TCP connection {} read error: {:?}", tcp_idx, _e);
                #[cfg(feature = "defmt")]
                defmt::error!("TCP connection {} read error", tcp_idx);
                let conn = self.connections[tcp_idx].take().expect("just checked Some");
                return Some(TcpEvent::Closed { tcp_idx, channel_ids: conn.channel_ids });
            }
        };

        conn.last_activity = Instant::now();

        // Process the read data through the frame reader
        let mut pos = 0;
        let mut frame_output = [0u8; FRAME_OUTPUT_BUF_SIZE];

        while pos < n {
            let (consumed, event) = conn.framer.feed(&read_buf[pos..n], &mut frame_output);
            pos += consumed;

            match event {
                FrameEvent::Frame(frame_len) => {
                    // Copy the complete frame into a buffer for dispatch
                    let mut buffer = buffer_manager.borrow().alloc().await;
                    buffer.push_slice(&frame_output[..frame_len]);

                    let peer = conn.peer_addr;
                    return Some(TcpEvent::Frame { tcp_idx, peer, buffer });
                }
                FrameEvent::NeedMoreData => {
                    // Need more bytes from the stream
                    break;
                }
                FrameEvent::FrameSkipped { total_length } => {
                    warn!(
                        "TCP connection {}: skipped oversized frame ({} bytes)",
                        tcp_idx, total_length
                    );
                    // Continue processing remaining bytes in the read buffer
                }
                FrameEvent::ProtocolError => {
                    error!("TCP connection {}: protocol error, closing", tcp_idx);
                    let conn = self.connections[tcp_idx].take().expect("just checked Some");
                    return Some(TcpEvent::Closed { tcp_idx, channel_ids: conn.channel_ids });
                }
            }
        }

        // All bytes consumed, no complete frame yet
        None
    }

    /// Write data to a specific TCP connection.
    ///
    /// Returns `Ok(())` on success, or `Err(())` if the connection is
    /// gone or the write fails. On write failure the connection is closed
    /// and a `TcpEvent::Closed` should be emitted by the caller.
    pub async fn write_to(&mut self, tcp_idx: usize, data: &[u8]) -> Result<(), ()> {
        let conn = match self.connections[tcp_idx].as_mut() {
            Some(c) => c,
            None => {
                error!("TCP write to closed connection {}", tcp_idx);
                return Err(());
            }
        };

        // Write all bytes. embedded_io_async::Write::write may not write
        // everything in one call, so loop until done.
        let mut written = 0;
        while written < data.len() {
            match embedded_io_async::Write::write(&mut conn.stream, &data[written..]).await {
                Ok(0) => {
                    error!("TCP connection {} write returned 0 bytes", tcp_idx);
                    // Close the connection
                    self.connections[tcp_idx] = None;
                    return Err(());
                }
                Ok(n) => {
                    written += n;
                }
                Err(_e) => {
                    #[cfg(feature = "log")]
                    log::error!("TCP connection {} write error: {:?}", tcp_idx, _e);
                    #[cfg(feature = "defmt")]
                    defmt::error!("TCP connection {} write error", tcp_idx);
                    self.connections[tcp_idx] = None;
                    return Err(());
                }
            }
        }

        Ok(())
    }

    /// Close a specific TCP connection and return the channel IDs
    /// that were active on it.
    pub fn close(&mut self, tcp_idx: usize) -> Vec<u8, 4> {
        match self.connections[tcp_idx].take() {
            Some(conn) => {
                info!("Closing TCP connection {} from {}", tcp_idx, conn.peer_addr);
                conn.channel_ids
            }
            None => Vec::new(),
        }
    }

    /// Whether any TCP connections are active (used by main loop to
    /// decide whether to poll TCP futures).
    pub fn has_active_connections(&self) -> bool {
        self.connections.iter().any(|s| s.is_some())
    }

    /// Number of active TCP connections.
    pub fn active_count(&self) -> usize {
        self.connections.iter().filter(|s| s.is_some()).count()
    }

    /// Whether the TCP manager has a bound listener.
    pub fn has_listener(&self) -> bool {
        self.listener.is_some()
    }

    /// Whether the TCP manager has anything to poll (listener or active
    /// connections). When `false`, the main loop can skip the TCP branch.
    pub fn is_active(&self) -> bool {
        self.listener.is_some() || self.has_active_connections()
    }

    /// Wait for the next TCP event: either a new connection is accepted
    /// (handled internally) or a frame / close event is returned.
    ///
    /// Uses `select_slice` to poll ALL active TCP connections concurrently
    /// alongside the listener's accept. Empty connection slots pend
    /// forever via `read_slot`, so `select_slice` naturally ignores them.
    ///
    /// Pends forever if no listener is bound and no connections exist.
    pub async fn next_event(
        &mut self,
        buffer_manager: &RefCell<DynBufferManager<'static>>,
    ) -> TcpEvent {
        use embassy_futures::select::{Either, select, select_slice};

        loop {
            // The select result must outlive the futures vec, so we
            // extract it from a scoped block where futures are built,
            // polled, and dropped before we touch self.connections again.
            enum SelectOutcome<S> {
                Frame { slot_idx: usize, buffer: Buffer<'static> },
                Closed { slot_idx: usize, channel_ids: Vec<u8, 4> },
                NeedMoreData,
                Accepted(S, SocketAddrV4),
                AcceptError,
            }

            let outcome: SelectOutcome<T::TcpStream> = {
                // Split-borrow: listener and connections are disjoint fields.
                let listener = self.listener.as_ref();
                let connections = &mut self.connections;

                // Build a future for each connection slot. Empty slots pend
                // forever, so select_slice naturally ignores them.
                let mut read_futures = Vec::<_, MAX_TCP>::new();
                for slot in connections.iter_mut() {
                    let _ = read_futures.push(read_slot(slot, buffer_manager));
                }

                // Accept future: pends forever if no listener is bound.
                let accept_future = async {
                    match listener {
                        Some(l) => l.accept().await,
                        None => core::future::pending::<_>().await,
                    }
                };

                // Poll all connections and the listener simultaneously.
                match select(
                    // SAFETY: read_futures is a local variable that won't be moved after pinning.
                    select_slice(unsafe { Pin::new_unchecked(read_futures.as_mut_slice()) }),
                    accept_future,
                )
                .await
                {
                    Either::First((read_result, slot_idx)) => match read_result {
                        ConnectionReadResult::Frame(buffer) => {
                            SelectOutcome::Frame { slot_idx, buffer }
                        }
                        ConnectionReadResult::Closed(channel_ids) => {
                            SelectOutcome::Closed { slot_idx, channel_ids }
                        }
                        ConnectionReadResult::NeedMoreData => SelectOutcome::NeedMoreData,
                    },
                    Either::Second(accept_result) => match accept_result {
                        Ok((stream, peer)) => SelectOutcome::Accepted(stream, peer),
                        Err(_e) => {
                            error!("TCP accept error: {:?}", _e);
                            SelectOutcome::AcceptError
                        }
                    },
                }
            };
            // read_futures is dropped here — self.connections is free
            // to borrow again.

            match outcome {
                SelectOutcome::Frame { slot_idx, buffer } => {
                    let peer = self.connections[slot_idx]
                        .as_ref()
                        .expect("read_slot returned Frame from Some slot")
                        .peer_addr;
                    return TcpEvent::Frame { tcp_idx: slot_idx, peer, buffer };
                }
                SelectOutcome::Closed { slot_idx, channel_ids } => {
                    let conn = self.connections[slot_idx]
                        .take()
                        .expect("read_slot returned Closed from Some slot");
                    info!("TCP connection {} from {} closed", slot_idx, conn.peer_addr);
                    return TcpEvent::Closed { tcp_idx: slot_idx, channel_ids };
                }
                SelectOutcome::NeedMoreData => {
                    // Loop to rebuild futures and poll again.
                }
                SelectOutcome::Accepted(stream, peer) => {
                    let free = self.connections.iter().position(|s| s.is_none());
                    match free {
                        Some(slot) => {
                            info!("TCP connection {} accepted from {}", slot, peer);
                            self.connections[slot] =
                                Some(TcpConnectionState::new(stream, peer));
                        }
                        None => {
                            warn!(
                                "TCP connection from {} rejected: all {} slots full",
                                peer, MAX_TCP
                            );
                            drop(stream);
                        }
                    }
                    // Loop to start reading from the new (or existing) connections.
                }
                SelectOutcome::AcceptError => {
                    // Loop — nothing to do.
                }
            }
        }
    }
}

// ============================================================================
// Free functions for split-borrow TCP event handling
// ============================================================================

/// Read from a single TCP connection, extracting one frame.
///
/// This is a free function (not a method) so the caller can borrow
/// individual connection slots independently of each other and of the
/// listener.
async fn read_one_connection<S>(
    conn: &mut TcpConnectionState<S>,
    buffer_manager: &RefCell<DynBufferManager<'static>>,
) -> ConnectionReadResult
where
    S: embedded_io_async::Read<Error: core::fmt::Debug>,
{
    let mut read_buf = [0u8; TCP_READ_BUF_SIZE];

    let n = match embedded_io_async::Read::read(&mut conn.stream, &mut read_buf).await {
        Ok(0) => return ConnectionReadResult::Closed(core::mem::take(&mut conn.channel_ids)),
        Ok(n) => n,
        Err(_e) => {
            #[cfg(feature = "log")]
            log::error!("TCP read error: {:?}", _e);
            #[cfg(feature = "defmt")]
            defmt::error!("TCP read error");
            return ConnectionReadResult::Closed(core::mem::take(&mut conn.channel_ids));
        }
    };

    conn.last_activity = Instant::now();

    // Process the read data through the frame reader
    let mut pos = 0;
    let mut frame_output = [0u8; FRAME_OUTPUT_BUF_SIZE];

    while pos < n {
        let (consumed, event) = conn.framer.feed(&read_buf[pos..n], &mut frame_output);
        pos += consumed;

        match event {
            FrameEvent::Frame(frame_len) => {
                let mut buffer = buffer_manager.borrow().alloc().await;
                buffer.push_slice(&frame_output[..frame_len]);
                return ConnectionReadResult::Frame(buffer);
            }
            FrameEvent::NeedMoreData => break,
            FrameEvent::FrameSkipped { total_length } => {
                warn!("TCP: skipped oversized frame ({} bytes)", total_length);
            }
            FrameEvent::ProtocolError => {
                error!("TCP: protocol error");
                return ConnectionReadResult::Closed(core::mem::take(&mut conn.channel_ids));
            }
        }
    }

    ConnectionReadResult::NeedMoreData
}

/// Outcome of reading from a single TCP connection.
enum ConnectionReadResult {
    /// A complete KNX/IP frame was extracted.
    Frame(Buffer<'static>),
    /// The connection was closed or errored. Contains the channel IDs
    /// that were active on it.
    Closed(Vec<u8, 4>),
    /// More data needed — no complete frame yet.
    NeedMoreData,
}

/// Read from a connection slot, pending forever if empty.
///
/// Wraps `read_one_connection` to produce a uniform future type for
/// every slot in the connections array, regardless of whether the slot
/// is occupied. Empty slots pend forever and are effectively ignored
/// by `select_slice`.
async fn read_slot<S>(
    slot: &mut Option<TcpConnectionState<S>>,
    buffer_manager: &RefCell<DynBufferManager<'static>>,
) -> ConnectionReadResult
where
    S: embedded_io_async::Read<Error: core::fmt::Debug>,
{
    match slot.as_mut() {
        Some(conn) => read_one_connection(conn, buffer_manager).await,
        None => {
            core::future::pending::<()>().await;
            unreachable!()
        }
    }
}
