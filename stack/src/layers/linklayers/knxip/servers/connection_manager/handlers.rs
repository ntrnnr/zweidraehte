//! Compile-time handler composition for connection types.
//!
//! [`ConnectedHandler`] is a per-slot compile-time wrapper: each connection
//! type (Device Management, Tunneling) has an enabled variant that delegates
//! to the real handler and a disabled variant (`Handler = ()`) whose methods
//! are no-ops that LLVM eliminates.
//!
//! [`CompositeHandlers`] bundles the slots into a single
//! [`ConnectionHandlers`] implementation that dispatches by
//! `CONNECTION_TYPE` constant.

use crate::messages::buffers::DynBufferManager;
use crate::messages::knxip::substructs::{CRI, ConnectionType};
use crate::messages::knxip::{ConnectionStatus, KNXnetIPServiceType};

use super::super::{PendingResponse, ResponseTarget, ServerError};
use super::{
    AcceptedConnection, ConnectionContext, ConnectionHandlers, ConnectionTypeHandler, DataFrameAction,
    DeviceMgmtConnectionHandler, TunnelConnectionHandler,
};

// ============================================================================
// ConnectedHandler: Per-Slot Compile-Time Handler Selection
// ============================================================================

/// Compile-time slot for a single connection type handler.
///
/// Each connection type (Device Management, Tunneling, etc.) has an enabled
/// variant that delegates to the real handler and a disabled variant whose
/// `Handler` is `()` and whose methods are no-ops that LLVM eliminates.
///
/// The `Handler<'a>` GAT carries the handler's lifetime — for example,
/// `DeviceMgmtConnectionHandler<'a>` borrows the property service context.
pub trait ConnectedHandler: 'static {
    type Handler<'a>;
    const CONNECTION_TYPE: ConnectionType;

    fn accept_connection(h: &mut Self::Handler<'_>, channel_id: u8, cri: &CRI)
        -> Result<AcceptedConnection, ConnectionStatus>;

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
pub trait TunnelingConnectedHandler: ConnectedHandler {
    fn tunneling_slot_info(
        h: &Self::Handler<'_>,
    ) -> Option<(
        u16,
        heapless::Vec<
            crate::messages::knxip::substructs::TunnelingSlotInfo,
            { crate::MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES },
        >,
    )>;

    fn channels_for_bus_indication(
        h: &Self::Handler<'_>,
        cemi_data: &[u8],
    ) -> heapless::Vec<u8, { crate::MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES }>;

    fn build_tunneling_request(
        channel_id: u8,
        sequence_counter: u8,
        cemi_data: &[u8],
        target: ResponseTarget,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse>;
}

// ---- Device Management slot ------------------------------------------------

/// Device Management is enabled — delegates to [`DeviceMgmtConnectionHandler`].
pub struct WithDevMgmt;

impl ConnectedHandler for WithDevMgmt {
    type Handler<'a> = DeviceMgmtConnectionHandler<'a>;
    const CONNECTION_TYPE: ConnectionType = ConnectionType::DeviceManagement;

    fn accept_connection(
        h: &mut Self::Handler<'_>, channel_id: u8, cri: &CRI,
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
        h: &mut Self::Handler<'_>, channel_id: u8, data: &[u8], conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        ConnectionTypeHandler::on_data_ack(h, channel_id, data, conn)
    }

    fn handled_service_types<'h>(h: &'h Self::Handler<'_>) -> &'h [KNXnetIPServiceType] {
        ConnectionTypeHandler::handled_service_types(h)
    }
}

/// Device Management is disabled — zero-size no-op.
pub struct NoDevMgmt;

impl ConnectedHandler for NoDevMgmt {
    type Handler<'a> = ();
    const CONNECTION_TYPE: ConnectionType = ConnectionType::DeviceManagement;

    fn accept_connection(
        _h: &mut Self::Handler<'_>, _channel_id: u8, _cri: &CRI,
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
        _h: &mut Self::Handler<'_>, _channel_id: u8, _data: &[u8], _conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        Err(ServerError::Unsupported)
    }

    fn handled_service_types<'h>(_h: &'h Self::Handler<'_>) -> &'h [KNXnetIPServiceType] {
        &[]
    }
}

// ---- Tunneling slot --------------------------------------------------------

/// Tunneling is enabled — delegates to [`TunnelConnectionHandler`].
pub struct WithTunnel;

impl ConnectedHandler for WithTunnel {
    type Handler<'a> = TunnelConnectionHandler;
    const CONNECTION_TYPE: ConnectionType = ConnectionType::Tunnel;

    fn accept_connection(
        h: &mut Self::Handler<'_>, channel_id: u8, cri: &CRI,
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
        h: &mut Self::Handler<'_>, channel_id: u8, data: &[u8], conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        ConnectionTypeHandler::on_data_ack(h, channel_id, data, conn)
    }

    fn handled_service_types<'h>(h: &'h Self::Handler<'_>) -> &'h [KNXnetIPServiceType] {
        ConnectionTypeHandler::handled_service_types(h)
    }
}

impl TunnelingConnectedHandler for WithTunnel {
    fn tunneling_slot_info(
        h: &Self::Handler<'_>,
    ) -> Option<(
        u16,
        heapless::Vec<
            crate::messages::knxip::substructs::TunnelingSlotInfo,
            { crate::MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES },
        >,
    )> {
        Some(h.slot_info())
    }

    fn channels_for_bus_indication(
        h: &Self::Handler<'_>,
        cemi_data: &[u8],
    ) -> heapless::Vec<u8, { crate::MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES }> {
        h.channels_for_bus_indication(cemi_data)
    }

    fn build_tunneling_request(
        channel_id: u8,
        sequence_counter: u8,
        cemi_data: &[u8],
        target: ResponseTarget,
        buffer_manager: &DynBufferManager<'static>,
    ) -> Option<PendingResponse> {
        TunnelConnectionHandler::build_tunneling_request(
            channel_id, sequence_counter, cemi_data, target, buffer_manager,
        )
    }
}

/// Tunneling is disabled — zero-size no-op.
pub struct NoTunnel;

impl ConnectedHandler for NoTunnel {
    type Handler<'a> = ();
    const CONNECTION_TYPE: ConnectionType = ConnectionType::Tunnel;

    fn accept_connection(
        _h: &mut Self::Handler<'_>, _channel_id: u8, _cri: &CRI,
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
        _h: &mut Self::Handler<'_>, _channel_id: u8, _data: &[u8], _conn: &mut ConnectionContext,
    ) -> Result<(), ServerError> {
        Err(ServerError::Unsupported)
    }

    fn handled_service_types<'h>(_h: &'h Self::Handler<'_>) -> &'h [KNXnetIPServiceType] {
        &[]
    }
}

impl TunnelingConnectedHandler for NoTunnel {
    fn tunneling_slot_info(
        _h: &Self::Handler<'_>,
    ) -> Option<(
        u16,
        heapless::Vec<
            crate::messages::knxip::substructs::TunnelingSlotInfo,
            { crate::MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES },
        >,
    )> {
        None
    }

    fn channels_for_bus_indication(
        _h: &Self::Handler<'_>,
        _cemi_data: &[u8],
    ) -> heapless::Vec<u8, { crate::MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES }> {
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

/// Composable handler collection parameterized on independent handler slots.
///
/// Each slot is either enabled (delegates to a real handler) or disabled
/// (`Handler = ()`, zero-size no-op). Adding a new connection type means
/// adding a new type parameter — no combinatorial explosion.
///
/// Defaults to `WithDevMgmt` + `NoTunnel` (Device Management only).
pub struct CompositeHandlers<
    'a,
    DM: ConnectedHandler = WithDevMgmt,
    TUN: TunnelingConnectedHandler = NoTunnel,
> {
    dev_mgmt: DM::Handler<'a>,
    tunnel: TUN::Handler<'a>,
}

impl<'a, DM: ConnectedHandler, TUN: TunnelingConnectedHandler> CompositeHandlers<'a, DM, TUN> {
    pub fn new(dev_mgmt: DM::Handler<'a>, tunnel: TUN::Handler<'a>) -> Self {
        Self { dev_mgmt, tunnel }
    }
}

impl<DM: ConnectedHandler, TUN: TunnelingConnectedHandler> ConnectionHandlers
    for CompositeHandlers<'_, DM, TUN>
{
    fn accept_connection(
        &mut self,
        channel_id: u8,
        connection_type: ConnectionType,
        cri: &CRI,
    ) -> Result<AcceptedConnection, ConnectionStatus> {
        match connection_type {
            ct if ct == DM::CONNECTION_TYPE => DM::accept_connection(&mut self.dev_mgmt, channel_id, cri),
            ct if ct == TUN::CONNECTION_TYPE => TUN::accept_connection(&mut self.tunnel, channel_id, cri),
            _ => Err(ConnectionStatus::ConnectionTypeNotSupported),
        }
    }

    fn close_connection(&mut self, channel_id: u8, connection_type: ConnectionType) {
        match connection_type {
            ct if ct == DM::CONNECTION_TYPE => DM::close_connection(&mut self.dev_mgmt, channel_id),
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
            ct if ct == DM::CONNECTION_TYPE => {
                DM::on_data_frame(&mut self.dev_mgmt, channel_id, data, conn, buffer_manager).await
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
            ct if ct == DM::CONNECTION_TYPE => DM::on_data_ack(&mut self.dev_mgmt, channel_id, data, conn),
            ct if ct == TUN::CONNECTION_TYPE => TUN::on_data_ack(&mut self.tunnel, channel_id, data, conn),
            _ => Err(ServerError::Unsupported),
        }
    }

    fn handles_service_type(&self, connection_type: ConnectionType, service_type: KNXnetIPServiceType) -> bool {
        match connection_type {
            ct if ct == DM::CONNECTION_TYPE => DM::handled_service_types(&self.dev_mgmt).contains(&service_type),
            ct if ct == TUN::CONNECTION_TYPE => TUN::handled_service_types(&self.tunnel).contains(&service_type),
            _ => false,
        }
    }

    fn tunneling_slot_info(
        &self,
    ) -> Option<(
        u16,
        heapless::Vec<
            crate::messages::knxip::substructs::TunnelingSlotInfo,
            { crate::MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES },
        >,
    )> {
        TUN::tunneling_slot_info(&self.tunnel)
    }

    fn channels_for_bus_indication(
        &self,
        cemi_data: &[u8],
    ) -> heapless::Vec<u8, { crate::MAX_ADDITIONAL_INDIVIDUAL_ADDRESSES }> {
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
