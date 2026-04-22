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

use zweidraehte_platform::IpTransport;

use crate::{
    context::AddressTableContext,
    layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase},
    objects::tables::{AddressTable, HasLoadStateMachine}};
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

// FIXME: I think we have to ACK all group address and other broadcast traffic, at least if at least one tunnel connection is established
/// Address checker for IP Interface devices.
///
/// Extends [`DeviceAddressChecker`] to also ACK frames addressed to
/// additional individual addresses assigned to tunneling connections.
/// This ensures the TPUART transceiver acknowledges bus frames destined
/// for any tunneling endpoint, not just the device's primary IA.
///
/// The additional addresses are snapshotted at build time — they only
/// change during ETS programming (which requires a device restart).
pub struct IpInterfaceAddressChecker<'a, ADT: AddressTable + HasLoadStateMachine, const N: usize> {
    inner: DeviceAddressChecker<'a, ADT>,
    additional_addresses: heapless::Vec<IndividualAddress, N>,
}

impl<'a, ADT: AddressTable + HasLoadStateMachine, const N: usize> IpInterfaceAddressChecker<'a, ADT, N> {
    pub fn new(
        inner: DeviceAddressChecker<'a, ADT>,
        additional_addresses: heapless::Vec<IndividualAddress, N>,
    ) -> Self {
        Self { inner, additional_addresses }
    }
}

impl<ADT: AddressTable + HasLoadStateMachine, const N: usize> AddressChecker for IpInterfaceAddressChecker<'_, ADT, N> {
    fn should_ack(&self, header: &[u8; 6]) -> bool {
        // Delegate to inner checker first (primary IA, group, broadcast).
        if self.inner.should_ack(header) {
            return true;
        }

        // For individually-addressed frames that the inner checker didn't
        // match, check against the additional tunneling addresses.
        let at_npci = header[5];
        let is_group_address = (at_npci & 0x80) != 0;

        if !is_group_address {
            let dst = IndividualAddress::from_bytes(&[header[3], header[4]]);
            self.additional_addresses.contains(&dst)
        } else {
            false
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
pub struct IpInterfaceLinkLayerBuilder<
    W,
    R,
    T: IpTransport,
    F: features::FeatureSet = features::DefaultFeatures,
    const MAX_SOCKETS: usize = 4,
    const MAX_TCP_STREAMS: usize = 1,
    const MAX_CHANNELS: usize = 1,
> {
    tpuart_tx: W,
    tpuart_rx: R,
    knxip_builder: KnxNetIpBuilder<T, F, MAX_SOCKETS, MAX_TCP_STREAMS, MAX_CHANNELS>,
}

impl<W, R, T: IpTransport, F: features::FeatureSet, const MS: usize, const MTS: usize, const MC: usize>
    IpInterfaceLinkLayerBuilder<W, R, T, F, MS, MTS, MC>
{
    pub fn new(tpuart_tx: W, tpuart_rx: R, knxip_builder: KnxNetIpBuilder<T, F, MS, MTS, MC>) -> Self {
        Self { tpuart_tx, tpuart_rx, knxip_builder }
    }
}

/// Resources for the composite IP Interface link layer.
pub struct IpInterfaceResources {
    pub knxip: KnxNetIpResources,
    // TPUART resources are a ZST (TpUartResources), no storage needed.
}

impl IpInterfaceResources {
    pub const fn new() -> Self {
        Self { knxip: KnxNetIpResources::new() }
    }
}

// -- LinkLayerBuilderBase -----------------------------------------------------

impl<
    W: Send + 'static,
    R: Send + 'static,
    T: IpTransport + 'static,
    F: features::FeatureSet + 'static,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> LinkLayerBuilderBase for IpInterfaceLinkLayerBuilder<W, R, T, F, MS, MTS, MC>
{
    type Resources = IpInterfaceResources;
    type LLEndpoints<'a> = crate::context::CemiTransportLayerEndpoints<'a>;

    fn create_resources(&self) -> Self::Resources {
        IpInterfaceResources::new()
    }
}

impl<
    W: Send + 'static,
    R: Send + 'static,
    T: IpTransport + 'static,
    F: features::FeatureSet + 'static,
    const MS: usize,
    const MTS: usize,
    const MC: usize,
> crate::layers::LinkLayerCapabilities for IpInterfaceLinkLayerBuilder<W, R, T, F, MS, MTS, MC>
{
    const KNXNETIP_DEVICE_CAPABILITIES: u16 = F::KNXNETIP_DEVICE_CAPABILITIES;
}

// -- LinkLayerBuilder ---------------------------------------------------------
//
// Context must provide everything that both TPUART and KNX/IP need:
// - `KnxNetIpContext` for the KNX/IP server
// - `AddressTableContext` for the address checker (group ACK decisions)

impl<CTX, W, R, T, F, const MS: usize, const MTS: usize, const MC: usize> LinkLayerBuilder<CTX>
    for IpInterfaceLinkLayerBuilder<W, R, T, F, MS, MTS, MC>
where
    CTX: KnxNetIpContext + AddressTableContext,
    W: embedded_io_async::Write + Send + 'static,
    R: embedded_io_async::Read + Send + 'static,
    T: IpTransport + 'static,
    F: features::FeatureSet + 'static,
    <F::Tunneling as features::TunnelingFeature>::Tunnel: super::knxip::connections::TunnelingConnectedHandler<{ <F::Tunneling as features::TunnelingFeature>::CAPACITY }>,
{
    fn build_and_run<'a>(
        self,
        resources: &'a mut Self::Resources,
        context: &'a CTX,
        ll_endpoints: crate::context::CemiTransportLayerEndpoints<'a>,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        async move {
            // ==============================================================
            // Snapshot additional IAs and build address checker
            // ==============================================================
            let mut addr_buf = [IndividualAddress::default(); <F::Tunneling as features::TunnelingFeature>::CAPACITY];
            let addr_count =
                crate::context::IpAdditionalIndividualAddressContext::write_additional_individual_addresses(
                    context,
                    &mut addr_buf,
                );
            let mut additional_ias =
                heapless::Vec::<IndividualAddress, { <F::Tunneling as features::TunnelingFeature>::CAPACITY }>::new();
            for &addr in &addr_buf[..addr_count] {
                let _ = additional_ias.push(addr);
            }
            let inner_checker = DeviceAddressChecker::new(context, context.address_table());
            let address_checker = IpInterfaceAddressChecker::new(inner_checker, additional_ias);

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
                &mut resources.knxip,
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
