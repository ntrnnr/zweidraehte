use core::net::{Ipv4Addr, SocketAddrV4};

use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicReceiver, DynamicSender},
};

use crate::{
    context::{
        AddressTableContext, ApduLengthContext, BufferManagerContext, IndividualAddressContext, PropertyServiceContext,
    },
    layers::linklayers::knxip::context::{
        DeviceInfoContext, IpAdditionalIndividualAddressContext, IpConfigWriteContext, IpDiagnosticsContext,
        IpSecureConfigContext, RemoteRestartContext, RoutingMulticastRebindContext,
    },
};
use zweidraehte_proto::messages::{buffers::Buffer, builder::IndicationMessage};

pub(crate) mod connections; // Connection-oriented state machines
pub mod context; // IP-specific context traits
pub mod definition; // KnxNetIpDefinition trait — link-layer bill of materials
pub mod features; // Compile-time feature selection
#[cfg(feature = "ip-secure")]
pub(crate) mod multicast_handler; // Secure routing timer sync state machine (§2.2.2.3.2)
pub mod secure; // IP Secure feature slot, session pool, per-session state
pub(crate) mod services;
#[cfg(feature = "ip-secure")]
pub(crate) mod session_handler; // IP Secure session state machine (§2.2.3.5.2) // Connectionless service handlers

#[cfg(test)]
mod test_support;

mod builder;
mod dispatch; // Frame routing and response sending
pub(crate) mod runtime; // Event loop
mod transport; // UDP/TCP socket management
pub(crate) mod types; // Shared protocol types (ServerError, PendingResponse, etc.)

pub use builder::KnxNetIpBuilder;
pub use definition::KnxNetIpDefinition;
pub use runtime::KnxNetIp;
pub use types::{PacketOrigin, PendingResponse, ResponseTarget, ServerContext, ServerError};

/// Context bounds for the concrete provider retained by [`KnxNetIp`].
///
/// Associated property and security providers preserve the device's types.
/// Runtime values such as addresses and keys are still queried live.
pub trait KnxNetIpContext:
    BufferManagerContext
    + ApduLengthContext
    + PropertyServiceContext
    + DeviceInfoContext
    + IpDiagnosticsContext
    + IpConfigWriteContext
    + RemoteRestartContext
    + IpAdditionalIndividualAddressContext
    + IndividualAddressContext
    + AddressTableContext
    + RoutingMulticastRebindContext
    + IpSecureConfigContext
{
}

impl<T> KnxNetIpContext for T where
    T: BufferManagerContext
        + ApduLengthContext
        + PropertyServiceContext
        + DeviceInfoContext
        + IpDiagnosticsContext
        + IpConfigWriteContext
        + RemoteRestartContext
        + IpAdditionalIndividualAddressContext
        + IndividualAddressContext
        + AddressTableContext
        + RoutingMulticastRebindContext
        + IpSecureConfigContext
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

/// Static resources for the KNX/IP link layer.
///
/// Externally-owned storage that must outlive the [`KnxNetIp`] runtime.
/// Holds the response channel through which services queue outbound
/// messages, plus per-feature storage like the tunnel-occupancy counter
/// (size zero for `NoTunneling`).
pub struct KnxNetIpResources<F: features::FeatureSet = features::DefaultFeatures> {
    /// Response channel for queuing outbound messages.
    response_channel: Channel<NoopRawMutex, PendingResponse, 16>,
    /// Per-feature storage for the tunneling slot. `()` when tunneling is
    /// disabled; [`connections::TunnelOccupancy`] when enabled.
    tunneling: <F::Tunneling as features::TunnelingFeature>::Resources,
}

impl<F: features::FeatureSet> Default for KnxNetIpResources<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: features::FeatureSet> KnxNetIpResources<F> {
    /// Create a new resource container.
    pub fn new() -> Self {
        Self { response_channel: Channel::new(), tunneling: Default::default() }
    }

    /// Get a reference to the response channel.
    pub(super) fn response_channel(&self) -> &Channel<NoopRawMutex, PendingResponse, 16> {
        &self.response_channel
    }

    /// Get a reference to the tunneling feature's per-resource storage.
    pub(super) fn tunneling_resources(&self) -> &<F::Tunneling as features::TunnelingFeature>::Resources {
        &self.tunneling
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

/// Compile-time choice of where tunnel frames enter the KNX stack.
///
/// Channel endpoints still erase their capacity and mutex type deliberately.
/// The presence of a physical subnet is fixed by the link-layer builder.
pub trait SubnetConnection<'a> {
    /// Wait for a frame from the subnet; a standalone IP device never produces one.
    async fn receive_indication(&mut self) -> SubnetIndication;

    /// Select the bridge endpoint, or the local stack for a standalone device.
    fn injection_sender(
        &self,
        local: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    ) -> DynamicSender<'a, IndicationMessage<Buffer<'static>>>;
}

/// Standalone KNX/IP device with no physical subnet bridge.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSubnetLink;

impl<'a> SubnetConnection<'a> for NoSubnetLink {
    async fn receive_indication(&mut self) -> SubnetIndication {
        core::future::pending().await
    }

    fn injection_sender(
        &self,
        local: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    ) -> DynamicSender<'a, IndicationMessage<Buffer<'static>>> {
        local
    }
}

impl<'a> SubnetConnection<'a> for SubnetLink<'a> {
    async fn receive_indication(&mut self) -> SubnetIndication {
        self.subnet_ind_rx.receive().await
    }

    fn injection_sender(
        &self,
        _local: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    ) -> DynamicSender<'a, IndicationMessage<Buffer<'static>>> {
        self.subnet_inject_tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_futures::{block_on, poll_once};
    use zweidraehte_proto::messages::{buffers::BufferManager, knx::KnxMessageBuffer};

    #[test]
    fn subnet_selection_routes_injections_and_receives_only_bridge_indications() {
        let pool = Box::leak(Box::new([[0u8; 64]; 2]));
        let buffers = Box::leak(Box::new(unsafe { BufferManager::new(pool) }));
        let buffers = buffers.dyn_buffer_manager();
        let local: Channel<NoopRawMutex, IndicationMessage<Buffer<'static>>, 1> = Channel::new();
        let inject: Channel<NoopRawMutex, IndicationMessage<Buffer<'static>>, 1> = Channel::new();
        let indications: Channel<NoopRawMutex, SubnetIndication, 1> = Channel::new();
        let mut standalone = NoSubnetLink;
        let mut bridge =
            SubnetLink { subnet_ind_rx: indications.dyn_receiver(), subnet_inject_tx: inject.dyn_sender() };

        // A standalone IP device injects locally; the interface must instead
        // reach the physical subnet without also delivering locally.
        let message = IndicationMessage::indication(KnxMessageBuffer::from_buffer(block_on(buffers.alloc())));
        standalone.injection_sender(local.dyn_sender()).try_send(message).expect("empty local channel");
        assert!(inject.try_receive().is_err());
        let message = local.try_receive().expect("standalone injects locally");
        bridge.injection_sender(local.dyn_sender()).try_send(message).expect("empty bridge channel");
        assert!(local.try_receive().is_err());
        drop(inject.try_receive().expect("interface injects into bridge"));

        assert!(poll_once(standalone.receive_indication()).is_pending());
        assert!(poll_once(bridge.receive_indication()).is_pending());
        assert!(indications.try_send(SubnetIndication { cemi_data: block_on(buffers.alloc()) }).is_ok());
        assert!(poll_once(standalone.receive_indication()).is_pending());
        assert!(poll_once(bridge.receive_indication()).is_ready());
    }
}
