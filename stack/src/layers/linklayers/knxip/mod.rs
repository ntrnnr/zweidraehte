use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicReceiver, DynamicSender},
};

use crate::{
    context::{
        ApplicationLayerContext, BufferManagerContext, DeviceInfoContext, IpAdditionalIndividualAddressContext,
        IpDiagnosticsContext, KnxIndividualAddressContext, PropertyServiceContext,
    },
    messages::{
        buffers::Buffer,
        builder::IndicationMessage,
    },
};

mod builder;
pub mod features;
pub(crate) mod runtime;
pub mod servers;

mod tcp_framing;
mod tcp_manager;
mod udp_manager;

pub use builder::KnxNetIpBuilder;
pub use runtime::KnxNetIp;

// Server types re-exported for backward compatibility — these are defined
// in servers/mod.rs alongside the server trait.
pub use servers::{PacketOrigin, PendingResponse, ResponseTarget, ServerContext, ServerError};

/// Type-erased context for KnxNetIp.
///
/// Bundles all context traits the KNX/IP link layer needs into a single
/// trait object, so `build()` takes one `&dyn KnxNetIpContext` instead
/// of 6+ individual `&dyn` references.
pub(crate) trait KnxNetIpContext:
    BufferManagerContext
    + PropertyServiceContext
    + DeviceInfoContext
    + IpDiagnosticsContext
    + IpAdditionalIndividualAddressContext
    + KnxIndividualAddressContext
    + ApplicationLayerContext
{
}

impl<T> KnxNetIpContext for T where
    T: BufferManagerContext
        + PropertyServiceContext
        + DeviceInfoContext
        + IpDiagnosticsContext
        + IpAdditionalIndividualAddressContext
        + KnxIndividualAddressContext
        + ApplicationLayerContext
{
}

/// Protocol type for KNX/IP endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp, // To be implemented later
}

/// Endpoint that KNX/IP servers can listen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointType {
    protocol: Protocol,
    socket_addr: SocketAddrV4,
}

impl EndpointType {
    /// Create a new UDP endpoint
    pub const fn new_udp(address: Ipv4Addr, port: u16) -> Self {
        Self { protocol: Protocol::Udp, socket_addr: SocketAddrV4::new(address, port) }
    }

    /// Create a new TCP endpoint (to be implemented)
    pub const fn new_tcp(address: Ipv4Addr, port: u16) -> Self {
        Self { protocol: Protocol::Tcp, socket_addr: SocketAddrV4::new(address, port) }
    }

    /// Create a UDP endpoint listening on all interfaces (0.0.0.0)
    pub const fn new_udp_any(port: u16) -> Self {
        Self::new_udp(Ipv4Addr::new(0, 0, 0, 0), port)
    }

    /// Create a UDP broadcast endpoint (255.255.255.255)
    pub const fn new_udp_broadcast(port: u16) -> Self {
        Self::new_udp(Ipv4Addr::new(255, 255, 255, 255), port)
    }

    /// Create a UDP multicast endpoint
    pub const fn new_udp_multicast(multicast_addr: Ipv4Addr, port: u16) -> Self {
        Self::new_udp(multicast_addr, port)
    }

    /// Get the protocol
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Get the socket address
    pub const fn socket_addr(&self) -> SocketAddrV4 {
        self.socket_addr
    }

    /// Get the IP address
    pub const fn address(&self) -> Ipv4Addr {
        *self.socket_addr.ip()
    }

    /// Get the port
    pub const fn port(&self) -> u16 {
        self.socket_addr.port()
    }

    /// Check if this is a broadcast address (255.255.255.255)
    pub const fn is_broadcast(&self) -> bool {
        let octets = self.socket_addr.ip().octets();
        octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255
    }

    /// Check if this is a multicast address (224.0.0.0 to 239.255.255.255)
    /// Multicast addresses have the uppermost 4 bits set to 1110 (0xE0-0xEF)
    pub const fn is_multicast(&self) -> bool {
        let octets = self.socket_addr.ip().octets();
        (octets[0] & 0xF0) == 0xE0
    }

    /// Check if this is listening on all interfaces (0.0.0.0)
    pub const fn is_any(&self) -> bool {
        let octets = self.socket_addr.ip().octets();
        octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0
    }

    /// Check if this is a UDP endpoint
    pub const fn is_udp(&self) -> bool {
        matches!(self.protocol, Protocol::Udp)
    }

    /// Check if this is a TCP endpoint
    pub const fn is_tcp(&self) -> bool {
        matches!(self.protocol, Protocol::Tcp)
    }

    /// Check if two endpoints match for message dispatching
    ///
    /// This implements the C++ matching logic:
    /// - Ports must match
    /// - If `self` (registered endpoint) is 0.0.0.0, it matches any address
    /// - If `other` (received packet destination) is multicast and `self` is multicast, they must match exactly
    /// - Otherwise, addresses must match exactly
    ///
    /// Note: `self` is typically the registered endpoint, `other` is the socket/destination
    pub const fn matches(&self, other: &EndpointType) -> bool {
        // Check protocol matches
        let protocol_matches = match (self.protocol, other.protocol) {
            (Protocol::Udp, Protocol::Udp) => true,
            (Protocol::Tcp, Protocol::Tcp) => true,
            _ => false,
        };

        if !protocol_matches || self.socket_addr.port() != other.socket_addr.port() {
            return false;
        }

        // If registered endpoint is 0.0.0.0 (any), match everything on this port
        if self.is_any() {
            return true;
        }

        // Exact address match
        let self_octets = self.socket_addr.ip().octets();
        let other_octets = other.socket_addr.ip().octets();
        if self_octets[0] == other_octets[0]
            && self_octets[1] == other_octets[1]
            && self_octets[2] == other_octets[2]
            && self_octets[3] == other_octets[3]
        {
            return true;
        }

        // No match
        false
    }
}

impl Default for EndpointType {
    fn default() -> Self {
        Self::new_udp(Ipv4Addr::new(0, 0, 0, 0), 0)
    }
}

/// Static resources for KNX/IP link layer.
///
/// Provides externally-owned storage that must outlive the
/// [`KnxNetIp`] link layer instance. Currently holds the response
/// channel through which servers queue outbound messages.
pub struct KnxNetIpResources {
    /// Response channel for queuing outbound messages.
    response_channel: Channel<NoopRawMutex, PendingResponse, 16>,
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
/// [`ConnectionManager::forward_bus_indication()`] to deliver them to
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
