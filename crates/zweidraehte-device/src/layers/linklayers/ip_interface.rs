//! Composite link layer for KNX IP Interface devices.
//!
//! An IP Interface bridges KNX/IP tunneling connections to a TP1 bus.
//! Clients (ETS, visualization tools) connect via KNX/IP Tunneling;
//! the interface forwards cEMI frames bidirectionally to/from the bus.
//!
//! # Architecture
//!
//! ```text
//!                     Network Layer
//!                          │
//!                ind_tx / conf_tx / req_rx
//!                          │
//!           ┌──────────────┴──────────────┐
//!           │    IpInterfaceLinkLayer      │
//!           │       (bridge loop)          │
//!           │                              │
//!           │  tpuart_ind ←── TPUART  ──→ conf_tx (direct)
//!           │  knxip_ind  ←── KNX/IP      │
//!           │                              │
//!           │  tpuart_req ──→ TPUART TX   │
//!           └──────────────────────────────┘
//! ```
//!
//! Three concurrent tasks via `embassy_futures::join::join3`:
//!
//! 1. **TPUART** — drives UART RX/TX, sends indications via internal channel
//! 2. **KNX/IP** — handles UDP/TCP, tunneling, discovery; receives bus
//!    indications and injects tunnel-originated frames via [`SubnetLink`]
//! 3. **Bridge loop** — routes frames between TPUART, KNX/IP, and the
//!    real network layer channels
//!
//! Per KNX spec 03/08/04 §2.2.2, all tunnel-originated frames go
//! unconditionally to the physical bus. The bus handles delivery, ACKing,
//! and any hairpin routing (e.g., frames addressed to the device's own
//! primary IA or another tunnel client's additional IA).

use core::future::pending;

use embassy_futures::join::join3;
use embassy_futures::select::{Either3, select3};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender},
};

use crate::{
    context::CemiTransportLayerEndpoints,
    context::{AddressTableContext, IpAdditionalIndividualAddressContext},
    layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase, LinkLayerCapabilities},
    objects::tables::{AddressTable, HasLoadStateMachine},
};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::{
    buffers::*,
    builder::{ConfirmationMessage, IndicationMessage, RequestMessage},
};

use super::{
    knxip::{KnxNetIpBuilder, KnxNetIpContext, KnxNetIpResources, SubnetIndication, SubnetLink, features},
    tpuart::{AddressChecker, DeviceAddressChecker, TpUartLinkLayer},
};

// ============================================================================
// IpInterfaceAddressChecker
// ============================================================================

/// Address checker for IP Interface devices.
///
/// Extends [`DeviceAddressChecker`] in two ways:
///
/// - ACKs frames addressed to additional individual addresses assigned
///   to tunneling connections — so the TPUART transceiver acknowledges
///   bus frames destined for any tunneling endpoint, not just the
///   device's primary IA. The list is read live from
///   [`IpAdditionalIndividualAddressContext`], so writes to
///   `PID_ADDITIONAL_INDIVIDUAL_ADDRESSES` take effect on the next
///   bus frame without a restart.
/// - While at least one tunneling connection is open, ACKs *every*
///   group frame regardless of the device's own group-address table.
///   A pure IP interface usually has no GA table of its own; without
///   this over-ACK the TP1 sender retransmits 3× and gives up on every
///   group frame the tunnel client wants to receive.
pub struct IpInterfaceAddressChecker<'a, ADT: AddressTable + HasLoadStateMachine> {
    inner: DeviceAddressChecker<'a, ADT>,
    additional_ias: &'a dyn IpAdditionalIndividualAddressContext,
    tunnel_occupancy: &'a super::knxip::connections::TunnelOccupancy,
}

impl<'a, ADT: AddressTable + HasLoadStateMachine> IpInterfaceAddressChecker<'a, ADT> {
    pub fn new(
        inner: DeviceAddressChecker<'a, ADT>,
        additional_ias: &'a dyn IpAdditionalIndividualAddressContext,
        tunnel_occupancy: &'a super::knxip::connections::TunnelOccupancy,
    ) -> Self {
        Self { inner, additional_ias, tunnel_occupancy }
    }
}

impl<ADT: AddressTable + HasLoadStateMachine> AddressChecker for IpInterfaceAddressChecker<'_, ADT> {
    fn should_ack(&self, header: &[u8; 6]) -> bool {
        // Delegate to inner checker first (primary IA, group via local
        // table, broadcast).
        if self.inner.should_ack(header) {
            return true;
        }

        let at_npci = header[5];
        let is_group_address = (at_npci & 0x80) != 0;

        if is_group_address {
            // Over-ACK group frames whenever any tunnel is open — the
            // tunnel client is the "interested party" the bus sender
            // wouldn't otherwise hear from.
            self.tunnel_occupancy.any_open()
        } else {
            // Individually-addressed frames the inner checker didn't
            // match: ACK if the destination is one of our additional
            // tunneling IAs.
            let dst = IndividualAddress::from_bytes(&[header[3], header[4]]);
            self.additional_ias.contains_additional_individual_address(dst)
        }
    }
}

// ============================================================================
// NeverInbox
// ============================================================================

/// An [`Inbox`] that never yields a message.
///
/// Used for the KNX/IP server in composite mode — the device's own
/// outbound frames go through TPUART via the bridge loop, not through
/// the KNX/IP server. This is a zero-cost abstraction that pends forever.
pub struct NeverInbox;

impl<M> Inbox<M> for NeverInbox {
    async fn next(&mut self) -> M {
        pending::<M>().await
    }

    fn try_next(&mut self) -> Option<M> {
        None
    }
}

// ============================================================================
// IpInterfaceLinkLayerBuilder
// ============================================================================

/// Builder for the composite IP Interface link layer.
///
/// Wraps a TPUART builder (for bus access) and a KNX/IP builder (for
/// tunneling, discovery, device management) behind a single
/// [`LinkLayerBuilder`] implementation.
///
/// Parameterised by `D: KnxNetIpDefinition` — the same definition the
/// inner `KnxNetIpBuilder<D>` uses. Numeric sizing flows through plain
/// const generics with defaults projected from `D::*`, exactly like
/// `KnxNetIpBuilder`.
pub struct IpInterfaceLinkLayerBuilder<
    W,
    R,
    D: super::knxip::KnxNetIpDefinition,
    const MAX_SOCKETS: usize = { <D as super::knxip::KnxNetIpDefinition>::MAX_UDP_SOCKETS },
    const MAX_TCP_STREAMS: usize = { <D as super::knxip::KnxNetIpDefinition>::MAX_TCP_STREAMS },
    const MAX_CHANNELS: usize = { <D as super::knxip::KnxNetIpDefinition>::MAX_TCP_CHANNELS },
    const TUNNEL_CAPACITY: usize = { <D as super::knxip::KnxNetIpDefinition>::TUNNEL_CAPACITY },
    const MAX_CONNECTIONS: usize = { <D as super::knxip::KnxNetIpDefinition>::MAX_CONNECTIONS },
    const TCP_BUF_SZ: usize = { <D as super::knxip::KnxNetIpDefinition>::TCP_SCRATCH_BUF_SIZE },
> {
    tpuart_tx: W,
    tpuart_rx: R,
    knxip_builder:
        KnxNetIpBuilder<D, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS, TUNNEL_CAPACITY, MAX_CONNECTIONS, TCP_BUF_SZ>,
}

impl<
    W,
    R,
    D: super::knxip::KnxNetIpDefinition,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
    const TC: usize,
    const MX: usize,
    const TBS: usize,
> IpInterfaceLinkLayerBuilder<W, R, D, MS, MTS, MC, TC, MX, TBS>
{
    pub fn new(tpuart_tx: W, tpuart_rx: R, knxip_builder: KnxNetIpBuilder<D, MS, MTS, MC, TC, MX, TBS>) -> Self {
        Self { tpuart_tx, tpuart_rx, knxip_builder }
    }
}

/// Resources for the composite IP Interface link layer.
///
/// Parameterised by the same definition used for the inner
/// `KnxNetIpBuilder<D>` so that
/// [`KnxNetIpResources`] can carry feature-specific storage (e.g. the
/// tunnel-occupancy counter).
pub struct IpInterfaceResources<D: super::knxip::KnxNetIpDefinition> {
    pub knxip: KnxNetIpResources<D::Features>,
    // TPUART resources are a ZST (TpUartResources), no storage needed.
}

impl<D: super::knxip::KnxNetIpDefinition> IpInterfaceResources<D> {
    pub fn new() -> Self {
        Self { knxip: KnxNetIpResources::new() }
    }
}

impl<D: super::knxip::KnxNetIpDefinition> Default for IpInterfaceResources<D> {
    fn default() -> Self {
        Self::new()
    }
}

// -- LinkLayerBuilderBase -----------------------------------------------------

impl<
    W: Send + 'static,
    R: Send + 'static,
    D: super::knxip::KnxNetIpDefinition + 'static,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
    const TC: usize,
    const MX: usize,
    const TBS: usize,
> LinkLayerBuilderBase for IpInterfaceLinkLayerBuilder<W, R, D, MS, MTS, MC, TC, MX, TBS>
{
    type Resources = IpInterfaceResources<D>;
    type LLEndpoints<'a> = CemiTransportLayerEndpoints<'a>;

    fn create_resources(&self) -> Self::Resources {
        IpInterfaceResources::new()
    }
}

impl<
    W: Send + 'static,
    R: Send + 'static,
    D: super::knxip::KnxNetIpDefinition + 'static,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
    const TC: usize,
    const MX: usize,
    const TBS: usize,
> LinkLayerCapabilities for IpInterfaceLinkLayerBuilder<W, R, D, MS, MTS, MC, TC, MX, TBS>
{
    const KNXNETIP_DEVICE_CAPABILITIES: u16 = <D::Features as features::FeatureSet>::KNXNETIP_DEVICE_CAPABILITIES;
}

// -- LinkLayerBuilder ---------------------------------------------------------
//
// Context must provide everything that both TPUART and KNX/IP need:
// - `KnxNetIpContext` for the KNX/IP server
// - `AddressTableContext` for the address checker (group ACK decisions)

impl<
    CTX,
    W,
    R,
    D,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
    const TC: usize,
    const MX: usize,
    const TBS: usize,
> LinkLayerBuilder<CTX> for IpInterfaceLinkLayerBuilder<W, R, D, MS, MTS, MC, TC, MX, TBS>
where
    CTX: KnxNetIpContext + AddressTableContext,
    W: embedded_io_async::Write + Send + 'static,
    R: embedded_io_async::Read + Send + 'static,
    D: super::knxip::KnxNetIpDefinition + 'static,
    <<D::Features as features::FeatureSet>::Tunneling as features::TunnelingFeature>::Tunnel:
        super::knxip::connections::TunnelingConnectedHandler<TC>,
    // The composite mode only makes sense when tunneling is enabled, so
    // the resource type must be the real occupancy counter (not `()`).
    <D::Features as features::FeatureSet>::Tunneling:
        features::TunnelingFeature<Resources = super::knxip::connections::TunnelOccupancy>,
{
    fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        ll_endpoints: CemiTransportLayerEndpoints<'a>,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        async move {
            // ==============================================================
            // Build address checker — reads additional IAs live from
            // the context, no snapshot.
            // ==============================================================
            let inner_checker = DeviceAddressChecker::new(context, context.address_table());
            let address_checker =
                IpInterfaceAddressChecker::new(inner_checker, context, resources.knxip.tunneling_resources());

            // ==============================================================
            // Internal channels
            // ==============================================================

            // TPUART → bridge: bus frame indications
            let tpuart_ind_channel: Channel<NoopRawMutex, IndicationMessage<Buffer<'static>>, 4> = Channel::new();

            // Bridge → TPUART: transmission requests (from stack or tunnel inject)
            let tpuart_req_channel: Channel<NoopRawMutex, RequestMessage<Buffer<'static>>, 4> = Channel::new();

            // Bridge → KNX/IP: bus indications for tunnel forwarding (cEMI)
            let subnet_ind_channel: Channel<NoopRawMutex, SubnetIndication, 4> = Channel::new();

            // KNX/IP → bridge: tunnel-injected frames for bus TX
            let subnet_inject_channel: Channel<NoopRawMutex, IndicationMessage<Buffer<'static>>, 4> = Channel::new();

            // KNX/IP indication channel (device management indications that
            // must reach the device's own stack — currently unused since device
            // management `Responses` go directly to the UDP/TCP response channel,
            // not through `ind_tx`). Capacity 1 is sufficient.
            let knxip_ind_channel: Channel<NoopRawMutex, IndicationMessage<Buffer<'static>>, 1> = Channel::new();

            // Discard channel for KNX/IP confirmations — the KNX/IP server in
            // composite mode never receives stack requests, so it never sends
            // confirmations. Capacity 1 to avoid panic on accidental send.
            let knxip_conf_channel: Channel<NoopRawMutex, ConfirmationMessage<Buffer<'static>>, 1> = Channel::new();

            // ==============================================================
            // Build TPUART link layer
            // ==============================================================
            let mut tpuart = TpUartLinkLayer::with_address_checker(
                self.tpuart_tx,
                self.tpuart_rx,
                context,
                tpuart_ind_channel.sender().into(),
                conf_tx, // confirmations go directly to the real network layer
                address_checker,
            );

            // ==============================================================
            // Build KNX/IP server with bus bridge
            // ==============================================================
            let bus_bridge = SubnetLink {
                subnet_ind_rx: subnet_ind_channel.receiver().into(),
                subnet_inject_tx: subnet_inject_channel.sender().into(),
            };

            // Construct address filter for routing frames. The IP interface
            // uses the same filter as standalone — RoutingIndications only
            // go to the local NL, not to tunnel clients.
            let routing_filter =
                super::knxip::types::RoutingAddressFilter::new(context.individual_address(), context.address_table());

            let mut knxip = self.knxip_builder.build(
                &resources.knxip,
                context,
                ll_endpoints,
                knxip_ind_channel.sender().into(),
                knxip_conf_channel.sender().into(),
                Some(bus_bridge),
                Some(&routing_filter),
            );

            // ==============================================================
            // Run all three tasks concurrently
            // ==============================================================
            join3(
                // Task 1: TPUART — drives UART RX/TX
                tpuart.run(tpuart_req_channel.receiver()),
                // Task 2: KNX/IP — handles UDP/TCP, tunneling, discovery
                knxip.run(NeverInbox),
                // Task 3: Bridge loop — routes frames between the three
                bridge_loop(
                    ind_tx,
                    req_rx,
                    tpuart_ind_channel.receiver(),
                    tpuart_req_channel.sender().into(),
                    subnet_ind_channel.sender().into(),
                    subnet_inject_channel.receiver(),
                    knxip_ind_channel.receiver(),
                    context.buffer_manager(),
                ),
            )
            .await;

            // join3 on three `-> !` futures never returns, but the type
            // system needs a diverging expression.
            #[allow(unreachable_code)]
            loop {}
        }
    }
}

// ============================================================================
// Bridge Loop
// ============================================================================

/// Central routing loop for the IP Interface composite link layer.
///
/// Multiplexes three event sources:
///
/// | Source | Action |
/// |--------|--------|
/// | `req_rx` (stack TX request) | Forward to TPUART for bus transmission |
/// | `tpuart_ind_rx` (bus frame) | Forward to network layer + convert to cEMI for tunnel forwarding |
/// | `subnet_inject_rx` (tunnel→bus) | Forward to TPUART for bus transmission |
///
/// KNX/IP indications (`knxip_ind_rx`) are also monitored — these carry
/// device management indications that need to reach the device's own stack.
/// In practice this channel is rarely used since device management returns
/// responses directly via the UDP/TCP response channel, but the path exists
/// for `AckAndInject` from device management if needed in the future.
async fn bridge_loop<'a>(
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    mut req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    tpuart_ind_rx: embassy_sync::channel::Receiver<'a, NoopRawMutex, IndicationMessage<Buffer<'static>>, 4>,
    tpuart_req_tx: DynamicSender<'a, RequestMessage<Buffer<'static>>>,
    subnet_ind_tx: DynamicSender<'a, SubnetIndication>,
    subnet_inject_rx: embassy_sync::channel::Receiver<'a, NoopRawMutex, IndicationMessage<Buffer<'static>>, 4>,
    knxip_ind_rx: embassy_sync::channel::Receiver<'a, NoopRawMutex, IndicationMessage<Buffer<'static>>, 1>,
    buffer_manager: &'a DynBufferManager<'static>,
) -> ! {
    loop {
        // Wait for any of the three event sources. The knxip_ind_rx arm
        // is nested with subnet_inject_rx since both originate from KNX/IP.
        let knxip_events = select(subnet_inject_rx.receive(), knxip_ind_rx.receive());

        match select3(req_rx.next(), tpuart_ind_rx.receive(), knxip_events).await {
            // ============================================================
            // Stack TX request → forward to TPUART
            // ============================================================
            Either3::First(request) => {
                tpuart_req_tx.send(request).await;
            }

            // ============================================================
            // Bus frame received from TPUART
            // ============================================================
            //
            // Two destinations:
            // 1. Forward to the device's own network layer (always)
            // 2. Convert to cEMI and offer to KNX/IP for tunnel forwarding
            Either3::Second(indication) => {
                // Convert the internal message to cEMI for tunnel forwarding.
                // This must happen before we move `indication` to `ind_tx`.
                if let Some(cemi_data) = internal_to_cemi(&indication, buffer_manager) {
                    // Non-blocking: if KNX/IP is busy, drop this indication
                    // rather than stalling bus reception.
                    let _ = subnet_ind_tx.try_send(SubnetIndication { cemi_data });
                }

                // Forward the original indication to the device's network layer.
                ind_tx.send(indication).await;
            }

            // ============================================================
            // Tunnel-injected frame → forward to TPUART for bus TX
            // ============================================================
            //
            // Per spec §2.2.2, all tunnel-originated frames go unconditionally
            // to the physical bus. No destination inspection needed.
            Either3::Third(embassy_futures::select::Either::First(tunnel_indication)) => {
                // The tunnel handler produced an IndicationMessage containing
                // an internal-format frame. Convert it to a RequestMessage for
                // TPUART transmission.
                let request = indication_to_request(tunnel_indication);
                tpuart_req_tx.send(request).await;
            }

            // ============================================================
            // KNX/IP device management indication → forward to stack
            // ============================================================
            Either3::Third(embassy_futures::select::Either::Second(knxip_indication)) => {
                ind_tx.send(knxip_indication).await;
            }
        }
    }
}

// ============================================================================
// Message Conversion Helpers
// ============================================================================

/// Convert an internal-format indication to cEMI for tunnel forwarding.
///
/// A separate buffer copy is necessary here because the original indication
/// buffer is consumed by `ind_tx.send()` (network layer) while the cEMI
/// copy goes to the KNX/IP runtime (different async task) via
/// `subnet_ind_tx`. Non-blocking allocation (`try_alloc`) ensures buffer
/// pressure causes graceful indication drops rather than bus stalls.
///
/// Returns `None` if no free buffers are available.
fn internal_to_cemi(
    indication: &IndicationMessage<Buffer<'static>>,
    buffer_manager: &DynBufferManager<'static>,
) -> Option<Buffer<'static>> {
    use zweidraehte_proto::messages::knx::{KnxMessageBuffer, ServiceType};

    // Deref through IndicationMessage → KnxMessageBuffer<Buffer, InternalFormat>
    let internal_msg: &KnxMessageBuffer<Buffer<'static>> = indication;

    // Allocate with default headroom (16 bytes — more than the 3 needed
    // by into_cemi()) and copy the internal-format payload.
    let mut buffer = buffer_manager.try_alloc()?;
    buffer.push_slice(internal_msg.buf());

    // Wrap as an internal-format message and convert to cEMI.
    let msg = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
    let cemi_msg = msg.into_cemi();

    Some(cemi_msg.into_inner())
}

/// Convert a tunnel-injected indication (internal format) into a request
/// for TPUART transmission.
fn indication_to_request(indication: IndicationMessage<Buffer<'static>>) -> RequestMessage<Buffer<'static>> {
    use zweidraehte_proto::messages::knx::ServiceType;

    // Re-wrap the inner message buffer as a request. The message content
    // (internal format) is the same — only the envelope changes from
    // "indication" to "request" for the TPUART transmit path.
    let mut msg = indication.into_inner();
    msg.set_service_type(ServiceType::L_Data_Req);
    RequestMessage::request(msg)
}

// Import `select` for the nested 2-arm select inside bridge_loop.
use embassy_futures::select::select;
