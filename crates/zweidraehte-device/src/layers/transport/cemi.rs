//! cEMI Transport Layer bridge.
//!
//! When a KNX/IP Device Management connection is established, ETS can send
//! cEMI Transport Layer frames (`T_Data_Connected.req`, `T_Data_Individual.req`)
//! alongside the Local Management frames (`M_PropRead`, `M_PropWrite`). Per
//! KNX spec 03/03/04 §6.2 and 03/08/03 §2.6, these frames bypass the normal
//! bus transport layer and are routed directly to the Application Layer.
//!
//! `CemiTransportLayer` wraps the normal [`TransportLayer`] and acts as a
//! switch: when activated (by a DevMgmt connection), it intercepts
//! connection-oriented AL requests (`T_Data_Req`, `T_Connect_Req`,
//! `T_Disconnect_Req`) and forwards them to the cEMI response channel
//! instead of the bus. Everything else — group data, broadcast, system
//! broadcast, NL indications, and NL confirmations — always delegates to
//! the inner transport layer.
//!
//! # Data Flow
//!
//! ```text
//! Inbound (ETS → AL):
//!   cEMI Client → DevMgmt handler → patches .req→.ind
//!   → CemiEvent::Frame → CemiTransportLayer (service input)
//!   → stamps T_Data_Ind + AccessSource::Explicit(MAX_ACCESS) → outbox → AL
//!
//! Outbound (AL → ETS):
//!   AL → T_Data_Req → dispatch table → CemiTransportLayer.process()
//!   → if active: send on response channel → KNX/IP runtime → ETS
//!   → if inactive: delegate to inner TransportLayer (normal bus path)
//! ```

use embassy_sync::channel::DynamicSender;

use crate::StackDefinition;
use crate::context::layer::LayerContext;
use crate::service::Layer;
use zweidraehte_proto::AccessSource;
use zweidraehte_proto::messages::{
    buffers::Buffer,
    knx::{KnxMessageBuffer, ServiceType},
};

use super::TransportLayer;

// ============================================================================
// CemiEvent
// ============================================================================

/// Events sent from the DevMgmt connection handler to the CemiTransportLayer.
///
/// Carried over a `Channel<NoopRawMutex, CemiEvent, 2>` — the DevMgmt
/// handler is the sole producer, the layer stack's `recv_service_input` is
/// the sole consumer. Capacity 2 ensures a pending Frame + Deactivate
/// can coexist when the layer stack is busy.
pub enum CemiEvent {
    /// A Device Management connection was established.
    ///
    /// Force-close any active bus connections, lock incoming, and
    /// synthesize `T_Connect.ind` to AL.
    Activate,

    /// The Device Management connection was closed.
    ///
    /// Synthesize `T_Disconnect.ind` to AL and unlock incoming
    /// connections.
    Deactivate,

    /// An inbound cEMI TL frame from ETS, already patched to `.ind`
    /// message code by the DevMgmt handler.
    ///
    /// The buffer contains the full cEMI TL wire frame (msg_code +
    /// add_info_len + reserved(6) + tpdu_len + tpdu). This layer
    /// converts it to internal format before pushing to the outbox.
    Frame(Buffer<'static>),
}

// ============================================================================
// CemiTransportLayer
// ============================================================================

/// cEMI Transport Layer bridge that wraps the normal [`TransportLayer`].
///
/// Registered for exactly the same [`ServiceType`]s as `TransportLayer`.
/// When inactive, all messages delegate to the inner TL. When activated by
/// a [`CemiEvent::Activate`], connection-oriented requests from AL are
/// intercepted and sent to the cEMI response channel instead.
pub struct CemiTransportLayer<'a, D: StackDefinition, const MAX_INCOMING: usize = 1, const MAX_OUTGOING: usize = 0> {
    /// The wrapped normal transport layer.
    inner: TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>,

    /// Shared runtime infrastructure — held directly rather than reached
    /// through the inner TL, so the TL needs no context accessors.
    lctx: &'a LayerContext<D>,

    /// Whether cEMI TL mode is active (DevMgmt connection established).
    active: bool,

    /// Sender for AL response messages that should be routed back to the
    /// cEMI client (ETS) via the KNX/IP runtime. Only used when active.
    response_sender: DynamicSender<'a, Buffer<'static>>,
}

impl<'a, D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize>
    CemiTransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>
{
    /// Create a new CemiTransportLayer wrapping the given TransportLayer.
    pub fn new(
        inner: TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING>,
        lctx: &'a LayerContext<D>,
        response_sender: DynamicSender<'a, Buffer<'static>>,
    ) -> Self {
        Self { inner, lctx, active: false, response_sender }
    }

    /// Mutable access to the inner transport layer.
    ///
    /// Useful for callers that need to access TL state directly (e.g.,
    /// timeout deadlines).
    pub fn inner_mut(&mut self) -> &mut TransportLayer<'a, D, MAX_INCOMING, MAX_OUTGOING> {
        &mut self.inner
    }
}

// ============================================================================
// Activate / Deactivate
// ============================================================================

impl<D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize>
    CemiTransportLayer<'_, D, MAX_INCOMING, MAX_OUTGOING>
{
    /// Activate cEMI Transport Layer mode.
    ///
    /// 1. Force-disconnect any active incoming bus connections (sends
    ///    `T_Disconnect` to remote devices and `T_Disconnect.ind` to AL).
    /// 2. Lock incoming connections so the bus TL rejects new `T_Connect`.
    /// 3. Synthesize `T_Connect.ind` to AL for the cEMI path.
    fn activate(&mut self) {
        if self.active {
            return;
        }

        info!("cEMI TL: activating");
        self.inner.force_close_incoming();
        self.inner.lock_incoming();
        self.active = true;

        // Synthesize T_Connect.ind to AL. Use address 0.0.0 as the
        // "source" of the cEMI connection — there is no real bus address
        // for the cEMI client, and AL doesn't use the source address for
        // anything beyond building response destination (which we
        // intercept anyway).
        self.inner.send_connect_indication(CEMI_PSEUDO_ADDR);
    }

    /// Deactivate cEMI Transport Layer mode.
    ///
    /// 1. Synthesize `T_Disconnect.ind` to AL for the cEMI path.
    /// 2. Unlock incoming connections so bus TL accepts `T_Connect` again.
    fn deactivate(&mut self) {
        if !self.active {
            return;
        }

        info!("cEMI TL: deactivating");
        self.active = false;
        self.inner.send_disconnect_indication(CEMI_PSEUDO_ADDR);
        self.inner.unlock_incoming();
    }

    /// Handle a cEMI event from the DevMgmt handler.
    ///
    /// Called by the `LayerRegistry` implementation's `handle_service_input`.
    pub fn handle_cemi_event(&mut self, event: CemiEvent) {
        match event {
            CemiEvent::Activate => self.activate(),
            CemiEvent::Deactivate => self.deactivate(),
            CemiEvent::Frame(buf) => self.inject_cemi_frame(buf),
        }
    }

    /// Convert a cEMI TL frame to internal format and push to the outbox
    /// as `T_Data_Ind` with full access.
    ///
    /// cEMI TL wire format (after DevMgmt handler has patched msg_code):
    /// ```text
    /// Byte 0:     Message Code (.ind, already patched)
    /// Byte 1:     Additional Info Length (usually 0)
    /// Bytes 2+N:  Additional Info
    /// Bytes 2+N..8+N: Reserved (6 zero bytes)
    /// Byte 8+N:   TPDU Length
    /// Bytes 9+N:  TPDU (TPCI/APCI + data)
    /// ```
    ///
    /// Internal format:
    /// ```text
    /// Byte 0:     CTRL (priority, address type flags)
    /// Bytes 1-2:  Source Address
    /// Bytes 3-4:  Destination Address (our own address)
    /// Byte 5:     NPDU (hop count, address type)
    /// Byte 6+:    TPCI/APCI + data
    /// ```
    fn inject_cemi_frame(&mut self, buf: Buffer<'static>) {
        if !self.active {
            warn!("cEMI TL: frame received while inactive, dropping");
            return;
        }

        debug!("cEMI TL: inject_cemi_frame ({} bytes): {:?}", buf.len(), zweidraehte_util::fmt::Bytes(buf.as_ref()));

        // Parse the cEMI TL wire frame: skip msg_code(1) + add_info_len(1) +
        // add_info(N) to find the reserved bytes and TPDU.
        let data = buf.as_ref();
        if data.len() < 2 {
            warn!("cEMI TL: frame too short ({} bytes)", data.len());
            return;
        }

        let add_info_len = data[1] as usize;
        let body_start = 2 + add_info_len;

        // Need at least 6 reserved bytes + 1 tpdu_len byte = 7 bytes after add_info
        if data.len() < body_start + 7 {
            warn!("cEMI TL: frame too short for header ({} bytes)", data.len());
            return;
        }

        // The L field follows the same convention as the NPDU length field
        // in standard KNX cEMI L_Data frames: it counts the number of TPDU
        // octets *after* the first one. Total TPDU size = L + 1.
        let l_field = data[body_start + 6] as usize;
        let tpdu_len = l_field + 1;
        let tpdu_start = body_start + 7;

        if data.len() < tpdu_start + tpdu_len {
            warn!(
                "cEMI TL: frame truncated (L={}, need {} TPDU bytes, have {})",
                l_field,
                tpdu_len,
                data.len() - tpdu_start
            );
            return;
        }

        let tpdu = &data[tpdu_start..tpdu_start + tpdu_len];
        debug!("cEMI TL: L={}, TPDU ({} bytes): {:?}", l_field, tpdu.len(), zweidraehte_util::fmt::Bytes(tpdu));

        // Build internal format message: ctrl(1) + src(2) + dst(2) + npdu(1) + tpdu
        let internal_len = 6 + tpdu.len();
        let Some(mut msg_buf) = self.lctx.buffer_manager.try_alloc_with_size(internal_len) else {
            warn!("cEMI TL: no buffer for injected frame");
            return;
        };

        // CTRL: individual addressing, system priority, no repeat
        msg_buf.as_mut()[0] = 0x00;
        // Source: pseudo address for cEMI client
        msg_buf.as_mut()[1..3].copy_from_slice(CEMI_PSEUDO_ADDR.as_bytes());
        // Destination: our own device address (not critical — AL doesn't check it)
        msg_buf.as_mut()[3..5].copy_from_slice(&[0x00, 0x00]);
        // NPDU: individual address type (bit 7 = 0), hop count = 7
        msg_buf.as_mut()[5] = 0x70;
        // TPDU
        msg_buf.as_mut()[6..6 + tpdu.len()].copy_from_slice(tpdu);

        let mut msg = KnxMessageBuffer::new(msg_buf, ServiceType::T_Data_Ind);
        msg.set_access_source(AccessSource::Explicit(zweidraehte_proto::AccessContext::MAX_ACCESS));

        self.lctx.push_outbox(msg);
    }
}

// The pseudo source address for cEMI TL frames lives in the parent module so
// the Secure AL can reference it without the `knxip` feature — see
// `super::CEMI_PSEUDO_ADDR` for the rationale.
use super::CEMI_PSEUDO_ADDR;

// ============================================================================
// Layer impl — delegates to inner TransportLayer with interception
// ============================================================================

impl<D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize> Layer<D>
    for CemiTransportLayer<'_, D, MAX_INCOMING, MAX_OUTGOING>
{
    // Register for exactly the same ServiceTypes as the inner TransportLayer.
    const HANDLES: &'static [ServiceType] = <TransportLayer<'_, D, MAX_INCOMING, MAX_OUTGOING> as Layer<D>>::HANDLES;

    fn init(&mut self) {
        Layer::<D>::init(&mut self.inner);
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        Layer::<D>::next_deadline(&self.inner)
    }

    fn poll(&mut self) {
        Layer::<D>::poll(&mut self.inner);
    }

    fn process(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        // When cEMI TL is active, intercept connection-oriented requests
        // from AL and route them to the cEMI response channel instead of
        // the bus. Everything else always delegates to the inner TL.
        if self.active {
            match msg.service_type() {
                ServiceType::T_Data_Req | ServiceType::T_Connect_Req | ServiceType::T_Disconnect_Req => {
                    self.intercept_al_request(msg);
                    return;
                }
                _ => {}
            }
        }

        Layer::<D>::process(&mut self.inner, msg);
    }
}

// ============================================================================
// Response interception
// ============================================================================

impl<D: StackDefinition, const MAX_INCOMING: usize, const MAX_OUTGOING: usize>
    CemiTransportLayer<'_, D, MAX_INCOMING, MAX_OUTGOING>
{
    /// Intercept an AL connection-oriented request and send it to the cEMI
    /// response channel.
    ///
    /// `T_Connect_Req` and `T_Disconnect_Req` are silently dropped — the
    /// cEMI TL connection lifecycle is managed by the DevMgmt handler, not
    /// by AL. Only `T_Data_Req` payloads are forwarded.
    fn intercept_al_request(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        match msg.service_type() {
            ServiceType::T_Data_Req => {
                // Send the internal-format buffer to the KNX/IP runtime,
                // which converts it to cEMI TL wire format and wraps it in
                // a DeviceConfigurationRequest.
                //
                // `try_send` is non-blocking — if the channel is full, the
                // frame is dropped. This matches the fire-and-forget
                // semantics: the cEMI protocol has its own retransmission.
                if self.response_sender.try_send(msg.into_inner()).is_err() {
                    warn!("cEMI TL: response channel full, dropping T_Data_Req");
                }
            }
            ServiceType::T_Connect_Req | ServiceType::T_Disconnect_Req => {
                // Silently absorb — cEMI TL lifecycle is not driven by AL.
                trace!("cEMI TL: absorbing {:?} from AL (lifecycle managed by DevMgmt)", msg.service_type());
            }
            _ => unreachable!(),
        }
    }
}

// ============================================================================
// cEMI channel types (Moved from context.rs)
// ============================================================================

/// Owned channel pair for cEMI Transport Layer communication.
///
/// Allocated by [`Runner::run()`](crate::Runner::run) as a stack-local
/// when the [`LayerStackBuilder`](crate::LayerStackBuilder) requires it.
/// Both the router task (layer side) and the LL task (link-layer side)
/// borrow from this structure.
pub struct CemiTransportLayerChannelPair {
    /// DevMgmt handler → CemiTransportLayer (capacity 2: one Frame + one
    /// Activate/Deactivate can be pending simultaneously).
    pub event: embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, CemiEvent, 2>,
    /// CemiTransportLayer → KNX/IP runtime (capacity 1: at most one
    /// response pending).
    pub response: embassy_sync::channel::Channel<
        embassy_sync::blocking_mutex::raw::NoopRawMutex,
        zweidraehte_proto::messages::buffers::Buffer<'static>,
        1,
    >,
}

impl Default for CemiTransportLayerChannelPair {
    fn default() -> Self {
        Self::new()
    }
}

impl CemiTransportLayerChannelPair {
    /// Create a new channel pair.
    pub fn new() -> Self {
        Self { event: embassy_sync::channel::Channel::new(), response: embassy_sync::channel::Channel::new() }
    }

    /// Extract layer-side endpoints (for the router/layer stack).
    pub fn layer_endpoints(&self) -> CemiTransportLayerClientEndpoints<'_> {
        CemiTransportLayerClientEndpoints {
            event_receiver: self.event.receiver().into(),
            response_sender: self.response.sender().into(),
        }
    }

    /// Extract link-layer-side endpoints (for the KNX/IP runtime).
    pub fn ll_endpoints(&self) -> CemiTransportLayerEndpoints<'_> {
        CemiTransportLayerEndpoints {
            event_sender: self.event.sender().into(),
            response_receiver: self.response.receiver().into(),
        }
    }
}

/// Layer-side endpoints borrowed from [`CemiTransportLayerChannelPair`].
///
/// Used by [`IpDeviceLayers`](crate::IpDeviceLayers) to
/// receive cEMI events and send responses.
pub struct CemiTransportLayerClientEndpoints<'a> {
    pub event_receiver: embassy_sync::channel::DynamicReceiver<'a, CemiEvent>,
    pub response_sender:
        embassy_sync::channel::DynamicSender<'a, zweidraehte_proto::messages::buffers::Buffer<'static>>,
}

/// Link-layer-side endpoints borrowed from [`CemiTransportLayerChannelPair`].
///
/// Used by the KNX/IP runtime to send cEMI events and receive responses.
pub struct CemiTransportLayerEndpoints<'a> {
    pub event_sender: embassy_sync::channel::DynamicSender<'a, CemiEvent>,
    pub response_receiver:
        embassy_sync::channel::DynamicReceiver<'a, zweidraehte_proto::messages::buffers::Buffer<'static>>,
}
