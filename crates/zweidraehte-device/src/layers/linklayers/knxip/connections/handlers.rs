//! Compile-time handler composition for connection types.
//!
//! Device Management is mandatory; tunneling uses an enabled or disabled
//! [`ConnectedHandler`] slot. Both dispatch to concrete handlers.

use zweidraehte_proto::messages::buffers::DynBufferManager;
use zweidraehte_proto::messages::knxip::substructs::{CRI, ConnectionType};
use zweidraehte_proto::messages::knxip::{ConnectionStatus, KNXnetIPServiceType};

use crate::objects::interface::PropertyServiceHandler;

use super::super::types::{PendingResponse, ResponseTarget, ServerError};
use super::{
    AcceptedConnection, ConnectionContext, ConnectionHandlers, ConnectionTypeHandler, DataFrameAction,
    DeviceMgmtConnectionHandler, TunnelConnectionHandler,
};

// ============================================================================
// ConnectedHandler: Per-Slot Compile-Time Handler Selection
// ============================================================================

/// Compile-time slot for a single connection type handler.
///
/// Optional connection types select a real handler or a zero-sized no-op.
/// The `Handler<'a>` GAT carries borrowed resources such as tunnel occupancy.
pub trait ConnectedHandler: 'static {
    type Handler<'a>;
    const CONNECTION_TYPE: ConnectionType;

    fn accept_connection(
        h: &mut Self::Handler<'_>,
        channel_id: u8,
        cri: &CRI,
    ) -> Result<AcceptedConnection, ConnectionStatus>;

    fn close_connection(h: &mut Self::Handler<'_>, channel_id: u8);

    fn on_data_frame<'a>(
        h: &mut Self::Handler<'a>,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> impl core::future::Future<Output = Result<DataFrameAction, ServerError>>;

    fn on_data_ack(
        h: &mut Self::Handler<'_>,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
    ) -> Result<(), ServerError>;

    fn handled_service_types<'h>(h: &'h Self::Handler<'_>) -> &'h [KNXnetIPServiceType];
}

/// Extension of [`ConnectedHandler`] for the tunneling slot.
///
/// Tunneling has three additional "bridge" methods that other connection
/// types don't need. Both [`WithTunnel`] and [`NoTunnel`] implement this;
/// the disabled variant returns `None`/empty.
///
/// The const generic `N` is the maximum number of tunneling slots
/// (additional individual addresses). Vec capacities in return types
/// use `N` directly, so there is no wasted capacity.
pub trait TunnelingConnectedHandler<const N: usize = 0>: ConnectedHandler {
    fn tunneling_slot_info(
        h: &Self::Handler<'_>,
    ) -> Option<(u16, heapless::Vec<zweidraehte_proto::messages::knxip::substructs::TunnelingSlotInfo, N>)>;

    fn channels_for_bus_indication(h: &Self::Handler<'_>, cemi_data: &[u8]) -> heapless::Vec<u8, N>;

    fn build_tunneling_request(
        channel_id: u8,
        sequence_counter: u8,
        cemi_data: &[u8],
        target: ResponseTarget,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse>;
}

// ---- Tunneling slot --------------------------------------------------------

/// Tunneling is enabled — delegates to [`TunnelConnectionHandler`].
///
/// The const generic `N` is the maximum number of tunneling slots
/// (additional individual addresses).
pub struct WithTunnel<const N: usize>;

impl<const N: usize> ConnectedHandler for WithTunnel<N> {
    type Handler<'a> = TunnelConnectionHandler<'a, N>;
    const CONNECTION_TYPE: ConnectionType = ConnectionType::Tunnel;

    fn accept_connection(
        h: &mut Self::Handler<'_>,
        channel_id: u8,
        cri: &CRI,
    ) -> Result<AcceptedConnection, ConnectionStatus> {
        ConnectionTypeHandler::accept_connection(h, channel_id, cri)
    }

    fn close_connection(h: &mut Self::Handler<'_>, channel_id: u8) {
        ConnectionTypeHandler::close_connection(h, channel_id);
    }

    async fn on_data_frame<'a>(
        h: &mut Self::Handler<'a>,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
        ConnectionTypeHandler::on_data_frame(h, channel_id, data, conn, buffer_manager).await
    }

    fn on_data_ack(
        h: &mut Self::Handler<'_>,
        channel_id: u8,
        data: &[u8],
        conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        ConnectionTypeHandler::on_data_ack(h, channel_id, data, conn)
    }

    fn handled_service_types<'h>(h: &'h Self::Handler<'_>) -> &'h [KNXnetIPServiceType] {
        ConnectionTypeHandler::handled_service_types(h)
    }
}

impl<const N: usize> TunnelingConnectedHandler<N> for WithTunnel<N> {
    fn tunneling_slot_info(
        h: &Self::Handler<'_>,
    ) -> Option<(u16, heapless::Vec<zweidraehte_proto::messages::knxip::substructs::TunnelingSlotInfo, N>)> {
        let (apdu_len, slots) = h.slot_info();
        Some((apdu_len, slots))
    }

    fn channels_for_bus_indication(h: &Self::Handler<'_>, cemi_data: &[u8]) -> heapless::Vec<u8, N> {
        h.channels_for_bus_indication(cemi_data)
    }

    fn build_tunneling_request(
        channel_id: u8,
        sequence_counter: u8,
        cemi_data: &[u8],
        target: ResponseTarget,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        TunnelConnectionHandler::<N>::build_tunneling_request(
            channel_id,
            sequence_counter,
            cemi_data,
            target,
            buffer_manager,
        )
    }
}

/// Tunneling is disabled — zero-size no-op.
pub struct NoTunnel;

impl ConnectedHandler for NoTunnel {
    type Handler<'a> = ();
    const CONNECTION_TYPE: ConnectionType = ConnectionType::Tunnel;

    fn accept_connection(
        _h: &mut Self::Handler<'_>,
        _channel_id: u8,
        _cri: &CRI,
    ) -> Result<AcceptedConnection, ConnectionStatus> {
        Err(ConnectionStatus::ConnectionTypeNotSupported)
    }

    fn close_connection(_h: &mut Self::Handler<'_>, _channel_id: u8) {}

    async fn on_data_frame<'a>(
        _h: &mut Self::Handler<'a>,
        _channel_id: u8,
        _data: &[u8],
        _conn: &mut ConnectionContext,
        _buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
        Err(ServerError::Unsupported)
    }

    fn on_data_ack(
        _h: &mut Self::Handler<'_>,
        _channel_id: u8,
        _data: &[u8],
        _conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        Err(ServerError::Unsupported)
    }

    fn handled_service_types<'h>(_h: &'h Self::Handler<'_>) -> &'h [KNXnetIPServiceType] {
        &[]
    }
}

impl TunnelingConnectedHandler<0> for NoTunnel {
    fn tunneling_slot_info(
        _h: &Self::Handler<'_>,
    ) -> Option<(u16, heapless::Vec<zweidraehte_proto::messages::knxip::substructs::TunnelingSlotInfo, 0>)> {
        None
    }

    fn channels_for_bus_indication(_h: &Self::Handler<'_>, _cemi_data: &[u8]) -> heapless::Vec<u8, 0> {
        heapless::Vec::new()
    }

    fn build_tunneling_request(
        _channel_id: u8,
        _sequence_counter: u8,
        _cemi_data: &[u8],
        _target: ResponseTarget,
        _buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        None
    }
}

// ============================================================================
// CompositeHandlers: Composable Handler Collection
// ============================================================================

/// Mandatory Device Management plus a compile-time tunneling slot.
///
/// The property provider remains concrete all the way to cEMI handling.
pub struct CompositeHandlers<'a, P: PropertyServiceHandler, TUN: ConnectedHandler = NoTunnel> {
    dev_mgmt: DeviceMgmtConnectionHandler<'a, P>,
    tunnel: TUN::Handler<'a>,
}

impl<'a, P: PropertyServiceHandler, TUN: ConnectedHandler> CompositeHandlers<'a, P, TUN> {
    pub fn new(dev_mgmt: DeviceMgmtConnectionHandler<'a, P>, tunnel: TUN::Handler<'a>) -> Self {
        Self { dev_mgmt, tunnel }
    }
}

impl<const N: usize, P: PropertyServiceHandler, TUN: TunnelingConnectedHandler<N>> ConnectionHandlers<N>
    for CompositeHandlers<'_, P, TUN>
{
    fn accept_connection(
        &mut self,
        channel_id: u8,
        connection_type: ConnectionType,
        cri: &CRI,
    ) -> Result<AcceptedConnection, ConnectionStatus> {
        match connection_type {
            ConnectionType::DeviceManagement => {
                ConnectionTypeHandler::accept_connection(&mut self.dev_mgmt, channel_id, cri)
            }
            ct if ct == TUN::CONNECTION_TYPE => TUN::accept_connection(&mut self.tunnel, channel_id, cri),
            _ => Err(ConnectionStatus::ConnectionTypeNotSupported),
        }
    }

    fn close_connection(&mut self, channel_id: u8, connection_type: ConnectionType) {
        match connection_type {
            ConnectionType::DeviceManagement => ConnectionTypeHandler::close_connection(&mut self.dev_mgmt, channel_id),
            ct if ct == TUN::CONNECTION_TYPE => TUN::close_connection(&mut self.tunnel, channel_id),
            _ => {}
        }
    }

    async fn on_data_frame(
        &mut self,
        channel_id: u8,
        connection_type: ConnectionType,
        _service_type: KNXnetIPServiceType,
        data: &[u8],
        conn: &mut ConnectionContext,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Result<DataFrameAction, ServerError> {
        match connection_type {
            ConnectionType::DeviceManagement => {
                ConnectionTypeHandler::on_data_frame(&mut self.dev_mgmt, channel_id, data, conn, buffer_manager).await
            }
            ct if ct == TUN::CONNECTION_TYPE => {
                TUN::on_data_frame(&mut self.tunnel, channel_id, data, conn, buffer_manager).await
            }
            _ => Err(ServerError::Unsupported),
        }
    }

    fn on_data_ack(
        &mut self,
        channel_id: u8,
        connection_type: ConnectionType,
        _service_type: KNXnetIPServiceType,
        data: &[u8],
        conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        match connection_type {
            ConnectionType::DeviceManagement => {
                ConnectionTypeHandler::on_data_ack(&mut self.dev_mgmt, channel_id, data, conn)
            }
            ct if ct == TUN::CONNECTION_TYPE => TUN::on_data_ack(&mut self.tunnel, channel_id, data, conn),
            _ => Err(ServerError::Unsupported),
        }
    }

    fn handles_service_type(&self, connection_type: ConnectionType, service_type: KNXnetIPServiceType) -> bool {
        match connection_type {
            ConnectionType::DeviceManagement => {
                ConnectionTypeHandler::handled_service_types(&self.dev_mgmt).contains(&service_type)
            }
            ct if ct == TUN::CONNECTION_TYPE => TUN::handled_service_types(&self.tunnel).contains(&service_type),
            _ => false,
        }
    }

    fn tunneling_slot_info(
        &self,
    ) -> Option<(u16, heapless::Vec<zweidraehte_proto::messages::knxip::substructs::TunnelingSlotInfo, N>)> {
        TUN::tunneling_slot_info(&self.tunnel)
    }

    fn channels_for_bus_indication(&self, cemi_data: &[u8]) -> heapless::Vec<u8, N> {
        TUN::channels_for_bus_indication(&self.tunnel, cemi_data)
    }

    fn build_tunneling_request(
        channel_id: u8,
        sequence_counter: u8,
        cemi_data: &[u8],
        target: ResponseTarget,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        TUN::build_tunneling_request(channel_id, sequence_counter, cemi_data, target, buffer_manager)
    }
}
