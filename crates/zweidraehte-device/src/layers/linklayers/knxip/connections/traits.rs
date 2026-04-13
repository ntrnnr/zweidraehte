//! Trait definitions and shared types for connection-oriented KNX/IP services.

use heapless::Vec;

use zweidraehte_proto::messages::buffers::{Buffer, DynBufferManager};
use zweidraehte_proto::messages::knxip::substructs::{CRI, ConnectionType};
use zweidraehte_proto::messages::knxip::{ConnectionStatus, KNXnetIPServiceType};

use super::super::types::{PendingResponse, ResponseTarget, ServerError};
use super::context::ConnectionContext;

// ============================================================================
// Connection Type Handler Trait
// ============================================================================

/// Result of a successfully accepted connection.
pub struct AcceptedConnection {
    /// CRD to include in the ConnectResponse.
    pub crd: zweidraehte_proto::messages::knxip::substructs::CRD,
}

/// What the connection manager should do after a handler processes a data frame.
pub enum DataFrameAction {
    /// Send response frames to the client (ACK + optional data response).
    /// Used by device management: ACK + M_PropRead.con / M_PropWrite.con.
    Responses(Vec<PendingResponse, 4>),
    /// ACK the client and inject a cEMI frame into the KNX stack.
    /// Used by tunneling: ACK + L_Data forwarded to network layer.
    /// The `Buffer` contains raw cEMI data (allocated by the handler from
    /// the buffer manager). The connection manager converts it via
    /// `KnxMessageBuffer::from_cemi().into_internal()` before sending to
    /// the network layer.
    AckAndInject { ack: PendingResponse, cemi_buffer: Buffer<'static> },
    /// Just ACK (e.g., retransmission that was already processed).
    AckOnly(PendingResponse),
}

/// Trait for connection-type-specific logic.
///
/// Each connection type (Device Management, Tunneling, etc.) implements this
/// trait. The connection manager delegates connection acceptance and data
/// frame processing through this interface.
///
/// Handlers own their service-type-specific protocol framing: they parse
/// their own request messages (e.g., `DeviceConfigurationRequest`), validate
/// sequence counters, build ACK responses, and process the payload. The
/// connection manager only handles connection lifecycle (connect, disconnect,
/// connectionstate) and executes the [`DataFrameAction`] returned by handlers.
///
/// Intentionally has **no generic parameters** — concrete handlers hold their
/// own resources (e.g., a reference to a `dyn PropertyServiceHandler`) internally.
pub trait ConnectionTypeHandler {
    /// Called when a ConnectRequest arrives for this connection type.
    ///
    /// The handler inspects the CRI and decides whether to accept (returning
    /// a CRD) or reject (returning an error status).
    fn accept_connection(&mut self, channel_id: u8, cri: &CRI) -> Result<AcceptedConnection, ConnectionStatus>;

    /// Called when a connection is closed (disconnect or heartbeat timeout).
    fn close_connection(&mut self, channel_id: u8);

    /// Handle an incoming data frame for this connection type.
    ///
    /// Receives the full KNX/IP packet (including header), the mutable
    /// connection context (for reading/updating sequence counters and
    /// endpoints), and the buffer manager for allocating response buffers.
    ///
    /// Returns a [`DataFrameAction`] telling the connection manager what
    /// to do: send responses, inject into the stack, or just ACK.
    async fn on_data_frame(
        &mut self,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError>;

    /// Handle an incoming ACK for a frame we sent to the client.
    fn on_data_ack(&mut self, channel_id: u8, data: &[u8], conn: &mut ConnectionContext) -> Result<(), ServerError>;

    /// Which service types this handler processes (both requests and ACKs).
    fn handled_service_types(&self) -> &[KNXnetIPServiceType];
}

// ============================================================================
// Connection Handlers: Compile-Time Handler Collections
// ============================================================================

/// Trait for the handler collection held by [`ConnectionManager`](super::ConnectionManager).
///
/// Dispatches connection lifecycle and data frame operations to the
/// appropriate handler based on connection type. Implemented by
/// [`CompositeHandlers`](super::CompositeHandlers), which composes
/// independently selectable [`ConnectedHandler`](super::ConnectedHandler) slots.
///
/// The const generic `N` is the maximum number of tunneling slots
/// (additional individual addresses). Used for Vec capacities in
/// tunneling-related return types.
pub trait ConnectionHandlers<const N: usize = 0> {
    fn accept_connection(
        &mut self,
        channel_id: u8,
        connection_type: ConnectionType,
        cri: &CRI,
    ) -> Result<AcceptedConnection, ConnectionStatus>;

    fn close_connection(&mut self, channel_id: u8, connection_type: ConnectionType);

    fn on_data_frame(
        &mut self,
        channel_id: u8,
        connection_type: ConnectionType,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> impl core::future::Future<Output = Result<DataFrameAction, ServerError>>;

    fn on_data_ack(
        &mut self,
        channel_id: u8,
        connection_type: ConnectionType,
        service_type: KNXnetIPServiceType,
        data: &[u8],
        conn: &mut ConnectionContext,
    ) -> Result<(), ServerError>;

    fn handles_service_type(&self, connection_type: ConnectionType, service_type: KNXnetIPServiceType) -> bool;

    /// Snapshot the current tunneling slot status for use in DIBs.
    /// Returns `None` when tunneling is not available.
    fn tunneling_slot_info(
        &self,
    ) -> Option<(u16, heapless::Vec<zweidraehte_proto::messages::knxip::substructs::TunnelingSlotInfo, N>)>;

    /// Determine which active tunnel channels should receive a forwarded
    /// bus indication. Returns empty when tunneling is not available.
    fn channels_for_bus_indication(&self, cemi_data: &[u8]) -> heapless::Vec<u8, N>;

    /// Build a TunnelingRequest frame for forwarding a bus indication to
    /// a tunnel client. Returns `None` when tunneling is not available or
    /// buffer allocation fails.
    fn build_tunneling_request(
        channel_id: u8,
        sequence_counter: u8,
        cemi_data: &[u8],
        target: ResponseTarget,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse>;
}

// ============================================================================
// TCP Channel Tracking
// ============================================================================

/// Side-effect for TCP channel tracking.
///
/// Returned from connection manager methods so the main loop can update
/// `TcpConnectionState.channel_ids` without the connection manager needing
/// a reference to the TCP manager.
#[derive(Debug)]
pub enum TcpChannelEvent {
    /// A KNX/IP channel was created on a TCP connection.
    Added { tcp_idx: usize, channel_id: u8 },
    /// A KNX/IP channel was removed from a TCP connection.
    Removed { tcp_idx: usize, channel_id: u8 },
}

/// Bundles responses to send with optional TCP channel tracking events
/// that the main loop must apply to the TCP manager.
///
/// Maximum number of responses from a single `on_indication` call.
///
/// A data frame can produce up to: 1 ACK + 1 data response (DevMgmt) or
/// 1 ACK + forwarded frames to sibling tunnel clients. 4 is sufficient
/// for any realistic configuration.
pub struct ConnectionManagerResult {
    pub responses: Vec<PendingResponse, MAX_RESPONSES>,
    pub tcp_events: Vec<TcpChannelEvent, 2>,
}

pub(super) const MAX_RESPONSES: usize = 4;

impl ConnectionManagerResult {
    pub(super) fn responses_only(responses: Vec<PendingResponse, MAX_RESPONSES>) -> Self {
        Self { responses, tcp_events: Vec::new() }
    }
}

/// Result of [`ConnectionManager::check_ack_timeouts`](super::ConnectionManager::check_ack_timeouts).
pub struct AckTimeoutResult<const MAX_CONNECTIONS: usize> {
    /// Frames to retransmit (timed-out but under max retries).
    pub retransmissions: Vec<PendingResponse, MAX_RESPONSES>,
    /// Channels to disconnect (exceeded max retries).
    /// Each entry is (channel_id, control_endpoint target for the
    /// DISCONNECT_REQUEST).
    pub disconnects: Vec<(u8, ResponseTarget), MAX_CONNECTIONS>,
    /// TCP channel tracking events from disconnected connections.
    pub tcp_events: Vec<TcpChannelEvent, MAX_CONNECTIONS>,
}
