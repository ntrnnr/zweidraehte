//! Per-connection state types for the KNX/IP connection manager.

use core::net::SocketAddrV4;

use embassy_time::Instant;

use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knxip::substructs::ConnectionType;

use super::super::types::ResponseTarget;

// ============================================================================
// Connection Transport
// ============================================================================

/// The transport over which a KNX/IP connection was established.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConnectionTransport {
    /// Connection runs over UDP — responses go to the data endpoint.
    Udp,
    /// Connection runs over TCP — responses go back on the same stream.
    Tcp { tcp_idx: usize },
}

// ============================================================================
// Pending ACK
// ============================================================================

/// Tracks a server->client frame waiting for an ACK (UDP only).
///
/// When the server sends a `DeviceConfigurationRequest` or `TunnelingRequest`
/// to a client, it stores a copy here for potential retransmission. The ACK
/// timeout and retry limits differ by connection type:
///
/// - Tunneling: 1s timeout, 1 retry (spec 03/08/04 §2.6.1)
/// - Device Management: 10s timeout, 3 retries (spec 03/08/03 §2.3.2)
pub struct PendingAck {
    /// The sequence counter we sent — the ACK must echo this value.
    pub sequence_counter: u8,
    /// Serialized frame for retransmission.
    pub buffer: Buffer<'static>,
    /// Where to send the retransmission.
    pub target: ResponseTarget,
    /// When the frame was (last) sent.
    pub sent_at: Instant,
    /// How many times we've already sent this frame (0 = first send).
    pub attempt: u8,
}

// ============================================================================
// Connection Context
// ============================================================================

/// Per-connection state tracked by the connection manager.
///
/// Exposed to [`ConnectionTypeHandler`](super::ConnectionTypeHandler)
/// implementations so they can read/update sequence counters and access
/// endpoint information.
pub struct ConnectionContext {
    pub channel_id: u8,
    pub connection_type: ConnectionType,
    pub control_endpoint: SocketAddrV4,
    pub data_endpoint: SocketAddrV4,
    pub recv_sequence_counter: u8,
    pub send_sequence_counter: u8,
    pub last_activity: Instant,
    pub socket_idx: usize,
    /// Which transport this connection uses.
    pub transport: ConnectionTransport,
    /// Server->client frame awaiting an ACK. `None` when no frame is
    /// in flight or when the connection uses TCP (which has no ACKs).
    pub pending_ack: Option<PendingAck>,
}

impl ConnectionContext {
    /// Build a [`ResponseTarget`] for sending data frames to the client.
    ///
    /// For UDP, routes to the data endpoint on the originating socket.
    /// For TCP, routes back on the TCP connection.
    pub fn response_target(&self) -> ResponseTarget {
        match self.transport {
            ConnectionTransport::Udp => {
                ResponseTarget::Udp { destination: self.data_endpoint, socket_idx: self.socket_idx }
            }
            ConnectionTransport::Tcp { tcp_idx } => ResponseTarget::Tcp { tcp_idx },
        }
    }
}
