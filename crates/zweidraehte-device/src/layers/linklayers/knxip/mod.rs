use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicReceiver, DynamicSender},
};

use crate::{
    context::{
        ApduLengthContext, BufferManagerContext,
        KnxIndividualAddressContext, PropertyServiceContext,
    },
    layers::linklayers::knxip::context::{
        DeviceInfoContext, IpAdditionalIndividualAddressContext, IpDiagnosticsContext,
    }};
use zweidraehte_proto::messages::{
        buffers::Buffer,
        builder::IndicationMessage,
    };

pub(crate) mod connections;    // Connection-oriented state machines
pub mod context;               // IP-specific context traits
pub mod features;              // Compile-time feature selection
pub(crate) mod services;      // Connectionless service handlers

mod builder;
mod dispatch;           // Frame routing and response sending
pub(crate) mod runtime; // Event loop
mod transport;          // UDP/TCP socket management
pub(crate) mod types;   // Shared protocol types (ServerError, PendingResponse, etc.)

pub use builder::KnxNetIpBuilder;
pub use runtime::KnxNetIp;
pub use types::{PacketOrigin, PendingResponse, ResponseTarget, ServerContext, ServerError};

/// Type-erased context for KnxNetIp.
///
/// Bundles all context traits the KNX/IP link layer needs into a single
/// trait object, so `build()` takes one `&dyn KnxNetIpContext` instead
/// of 6+ individual `&dyn` references.
pub(crate) trait KnxNetIpContext:
    BufferManagerContext
    + ApduLengthContext
    + PropertyServiceContext
    + DeviceInfoContext
    + IpDiagnosticsContext
    + IpAdditionalIndividualAddressContext
    + KnxIndividualAddressContext
{
}

impl<T> KnxNetIpContext for T where
    T: BufferManagerContext
        + ApduLengthContext
        + PropertyServiceContext
        + DeviceInfoContext
        + IpDiagnosticsContext
        + IpAdditionalIndividualAddressContext
        + KnxIndividualAddressContext
{
}

/// UDP endpoint for KNX/IP socket deduplication.
///
/// Used during builder setup to collect and deduplicate the UDP sockets
/// needed by all enabled features. TCP is handled separately by
/// `TcpManager` and does not use this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointType {
    socket_addr: SocketAddrV4,
}

impl EndpointType {
    pub const fn new(address: Ipv4Addr, port: u16) -> Self {
        Self { socket_addr: SocketAddrV4::new(address, port) }
    }

    /// Endpoint listening on all interfaces (0.0.0.0).
    pub const fn new_any(port: u16) -> Self {
        Self::new(Ipv4Addr::new(0, 0, 0, 0), port)
    }

    pub const fn address(&self) -> Ipv4Addr {
        *self.socket_addr.ip()
    }

    pub const fn port(&self) -> u16 {
        self.socket_addr.port()
    }

    /// Whether this is a broadcast address (255.255.255.255).
    pub const fn is_broadcast(&self) -> bool {
        let octets = self.socket_addr.ip().octets();
        octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255
    }

    /// Whether this is a multicast address (224.0.0.0/4).
    pub const fn is_multicast(&self) -> bool {
        let octets = self.socket_addr.ip().octets();
        (octets[0] & 0xF0) == 0xE0
    }
}

impl Default for EndpointType {
    fn default() -> Self {
        Self::new(Ipv4Addr::new(0, 0, 0, 0), 0)
    }
}

/// Static resources for KNX/IP link layer.
///
/// Provides externally-owned storage that must outlive the
/// [`KnxNetIp`] link layer instance. Currently holds the response
/// channel through which services queue outbound messages.
pub struct KnxNetIpResources {
    /// Response channel for queuing outbound messages.
    response_channel: Channel<NoopRawMutex, PendingResponse, 16>,
}

impl Default for KnxNetIpResources {
    fn default() -> Self {
        Self::new()
    }
}

impl KnxNetIpResources {
    /// Create a new resource container.
    pub const fn new() -> Self {
        Self { response_channel: Channel::new() }
    }

    /// Get a reference to the response channel.
    pub(super) fn response_channel(&self) -> &Channel<NoopRawMutex, PendingResponse, 16> {
        &self.response_channel
    }
}

// ============================================================================
// Subnet Link (IP Interface composite mode)
// ============================================================================

/// A cEMI subnetwork indication to forward to tunnel clients.
///
/// The composite bridge loop converts TPUART indications to cEMI and
/// sends them here; the KNX/IP run loop calls
/// `ConnectionManager::forward_bus_indication()` to deliver them to
/// matching tunnel connections.
pub struct SubnetIndication {
    pub cemi_data: Buffer<'static>,
}

/// KNX/IP server's link to the KNX subnetwork for IP Interface composite mode.
///
/// When a KNX/IP server runs as part of a composite IP Interface link
/// layer, it needs bidirectional communication with the subnetwork:
///
/// - **`subnet_ind_rx`**: Receive subnetwork indications (cEMI) from the
///   bridge loop. KNX/IP forwards these to matching tunnel clients.
/// - **`subnet_inject_tx`**: Send tunnel-injected frames back to the bridge
///   loop for subnetwork TX. This replaces `ind_tx` for `AckAndInject` so
///   that tunnel-originated frames go to the physical bus instead of the
///   device's own network layer.
pub struct SubnetLink<'a> {
    pub subnet_ind_rx: DynamicReceiver<'a, SubnetIndication>,
    pub subnet_inject_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
}
