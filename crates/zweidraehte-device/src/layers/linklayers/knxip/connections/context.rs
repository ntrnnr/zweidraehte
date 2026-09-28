//! Per-connection state types for the KNX/IP connection manager.

use core::net::SocketAddrV4;

use embassy_time::Instant;

use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::knxip::substructs::ConnectionType;

use super::super::types::ResponseTarget;

// ============================================================================
// Connect Access
// ============================================================================

/// What a CONNECT_REQUEST's user may open (03/08/09 §2.2.1.4.2, 03/08/04
/// §5.4.3.3.2).
///
/// The restrictions exist only for a connection type whose service family
/// is secured in PID_SECURED_SERVICE_FAMILIES, and never for the
/// management user (01h), who has access to every KNXnet/IP resource.
/// Computed once per CONNECT_REQUEST by the dispatcher from the session's
/// user and the IP Secure configuration; plain data, so the handlers need
/// no view of the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectAccess {
    /// A Device Management connection may be opened.
    pub device_management: bool,
    /// Tunnelling is limited to [`tunnel_slots`](Self::tunnel_slots).
    pub tunnel_restricted: bool,
    /// Bit `k` set: tunnel slot `k`, tunnelling address index `k + 1` in
    /// PID_TUNNELLING_USERS, may be used.
    pub tunnel_slots: u32,
}

impl ConnectAccess {
    /// No restriction: a plain connect to an unsecured family, or the
    /// management user.
    pub const OPEN: Self = Self { device_management: true, tunnel_restricted: false, tunnel_slots: u32::MAX };

    /// The access of `user_id` in a secure session, for a device with
    /// `tunnel_slots` tunnelling addresses.
    ///
    /// - DEVICE_MGMT_CONNECTION: "only the management user (01h) has
    ///   access" once the family is secured.
    /// - TUNNEL_CONNECTION: once the family is secured, a user other than
    ///   01h may use exactly the addresses PID_TUNNELLING_USERS links it to.
    ///
    /// The mask holds 32 slots; slots beyond it stay unlinked, so a larger
    /// tunnel capacity fails closed for everyone but the management user.
    pub fn for_user<V: crate::ip::IpSecureStateView>(config: &V, user_id: u8, tunnel_slots: usize) -> Self {
        use zweidraehte_proto::messages::knxip::substructs::ServiceFamily;

        if user_id == super::super::secure::user_id::MANAGEMENT {
            return Self::OPEN;
        }

        let device_management = config.secured_service_family(ServiceFamily::DeviceManagement) == 0;
        let tunnel_restricted = config.secured_service_family(ServiceFamily::Tunneling) != 0;
        let mut linked = 0u32;
        for slot in 0..tunnel_slots.min(32) {
            // Tunnelling address index `slot + 1` (1-based) names slot
            // `slot`; see PID_TUNNELLING_ADDRESSES.
            if config.tunnelling_user_allowed(user_id, (slot + 1) as u8) {
                linked |= 1 << slot;
            }
        }
        Self { device_management, tunnel_restricted, tunnel_slots: if tunnel_restricted { linked } else { u32::MAX } }
    }

    /// Whether tunnel slot `slot` may be used.
    pub fn tunnel_slot_allowed(&self, slot: usize) -> bool {
        !self.tunnel_restricted || (slot < 32 && self.tunnel_slots & (1 << slot) != 0)
    }
}

/// Who sent a connection-oriented frame: the IP Secure session it arrived
/// in (`None` for plain frames) and what that session's user may open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Requester {
    pub session: Option<u16>,
    pub access: ConnectAccess,
}

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
    /// The IP Secure session this connection was created in, if any.
    ///
    /// Per 03/08/09 §2.2.3.4, connections created within a secure
    /// session only accept frames arriving through that same session;
    /// CONNECTIONSTATE_REQUEST / DISCONNECT_REQUEST referencing the
    /// channel from outside it are answered with `E_CONNECTION_ID`,
    /// and data frames are discarded. Always `None` on non-secure
    /// builds.
    pub secure_session_id: Option<u16>,
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
