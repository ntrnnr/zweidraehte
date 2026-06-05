//! KNX-RF Ready link layer.
//!
//! Bridges a KNX-RF radio transceiver to the device stack's network layer over
//! the standard req/ind/conf channels. It performs the Data-Link-Layer duties
//! the spec assigns to the receiver — **RF Domain Address acceptance** and
//! **LFN duplicate suppression** (KNX 03/02/05 §6.1.4–§6.1.5) — and converts
//! between the internal `KnxMessageBuffer` format and CRC-stripped RF telegrams
//! via [`zweidraehte_proto::encoding::rf`].
//!
//! Scope: **KNX RF Ready asynchronous Standard frames**, bidirectional (RX + TX
//! with confirmations). RF Multi, BiBat, and LTE-extended frames are out of
//! scope.
//!
//! # Layering
//!
//! The radio specifics (Manchester coding, block CRCs, listen-before-talk, the
//! SX1211 itself) live behind the [`RfTransceiver`] trait, implemented by the
//! embedded binary (and by a mock in tests). The transceiver exchanges
//! *CRC-stripped telegrams* whose first octet is the length field; everything
//! above that — field parsing, addressing, filtering — happens here.
//!
//! ```text
//!   Network layer ──req/ind/conf── KnxRfLinkLayer ──telegrams── RfTransceiver ── SX1211
//! ```

mod history;

use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;

use crate::context::{LinkLayerBufferContext, RfDomainAddressContext};
use crate::layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase, LinkLayerCapabilities};
use history::LfnHistory;
use zweidraehte_proto::encoding::rf;
use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage};
use zweidraehte_proto::messages::knx::{KnxMessageBuffer, ServiceType};

/// Largest CRC-stripped telegram / internal frame we handle, in octets. Sized
/// to the RF physical layer's maximum on-air payload.
const RF_FRAME_BUF: usize = 96;

/// Repetition counter advertised on transmitted frames. KNX 03/02/05 §6.2.1.2
/// fixes RF-Ready end devices at 6.
const TX_REPEAT_COUNTER: u8 = 6;

// ============================================================================
// RfTransceiver — the radio abstraction
// ============================================================================

/// One received telegram's framing-independent result.
#[derive(Debug, Clone, Copy)]
pub struct RfRx {
    /// Number of valid octets written to the receive buffer (`buf[0]` = length).
    pub len: usize,
    /// Raw RSSI sample at reception (medium-specific scale).
    pub rssi: u8,
}

/// A KNX-RF radio that delivers and accepts **CRC-stripped telegrams**.
///
/// Implementations own all physical-layer concerns: Manchester coding, the FT3
/// block CRCs, preamble/sync framing, channel selection, and listen-before-talk.
/// The link layer only ever sees the contiguous telegram bytes.
///
/// ## Cancel-safety
///
/// [`receive`](Self::receive) is raced against transmit requests in the link
/// layer's event loop, so its future **must be cancel-safe**: if it is dropped
/// before completing (because a frame to transmit arrived), the next
/// `receive` call must re-arm the radio cleanly without losing the ability to
/// receive. Implementations typically re-arm RX at the top of `receive`.
pub trait RfTransceiver {
    /// Transceiver error type (driver / SPI failures, timeouts, …).
    type Error: core::fmt::Debug;

    /// Await one CRC-verified telegram, writing it into `buf` and returning its
    /// length and RSSI. Cancel-safe (see the trait docs).
    async fn receive(&mut self, buf: &mut [u8]) -> Result<RfRx, Self::Error>;

    /// Transmit one field-encoded telegram (the implementation inserts block
    /// CRCs, Manchester-encodes, and performs listen-before-talk).
    async fn transmit(&mut self, telegram: &[u8]) -> Result<(), Self::Error>;
}

// ============================================================================
// Builder
// ============================================================================

/// Resources for the KNX-RF link layer (none — the radio is owned by the
/// builder and moved into the run loop).
pub struct KnxRfResources;

/// Builds and runs the KNX-RF link layer over a concrete [`RfTransceiver`].
///
/// The radio is owned by the builder and handed to the run loop; create the
/// builder with the platform-specific transceiver (e.g. an SX1211 adapter) and
/// wire it into the device as `type LLB = KnxRfLinkLayerBuilder<MyRadio>`.
pub struct KnxRfLinkLayerBuilder<R: RfTransceiver> {
    radio: R,
    /// Whether this device is unidirectional (sets the RF-info Unidir flag on TX).
    unidir: bool,
}

impl<R: RfTransceiver> KnxRfLinkLayerBuilder<R> {
    /// Create a bidirectional KNX-RF link-layer builder over `radio`.
    pub fn new(radio: R) -> Self {
        Self { radio, unidir: false }
    }

    /// Mark this device as unidirectional (transmit-only sensors, etc.).
    pub fn unidirectional(mut self) -> Self {
        self.unidir = true;
        self
    }
}

impl<R: RfTransceiver> LinkLayerBuilderBase for KnxRfLinkLayerBuilder<R> {
    type Resources = KnxRfResources;

    fn create_resources(&self) -> Self::Resources {
        KnxRfResources
    }
}

impl<R: RfTransceiver> LinkLayerCapabilities for KnxRfLinkLayerBuilder<R> {}

// `R: 'static` because the radio is owned by — and moved into — the run-loop
// future. Concrete transceivers own 'static peripherals (e.g. embassy SPI), so
// this is satisfied in practice.
impl<R, CTX> LinkLayerBuilder<CTX> for KnxRfLinkLayerBuilder<R>
where
    R: RfTransceiver + 'static,
    CTX: LinkLayerBufferContext + RfDomainAddressContext,
{
    fn build_and_run<'a>(
        self,
        _resources: &'a mut Self::Resources,
        context: &'a CTX,
        _ll_endpoints: (),
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        req_rx: impl Inbox<RequestMessage<Buffer<'static>>> + 'a,
    ) -> impl core::future::Future<Output = !> + 'a {
        let mut ll = KnxRfLinkLayer {
            radio: self.radio,
            unidir: self.unidir,
            context,
            ind_tx,
            conf_tx,
            history: LfnHistory::new(),
            tx_lfn: 0,
        };
        async move { ll.run(req_rx).await }
    }
}

// ============================================================================
// Runtime
// ============================================================================

struct KnxRfLinkLayer<'a, R: RfTransceiver, CTX> {
    radio: R,
    unidir: bool,
    context: &'a CTX,
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
    history: LfnHistory,
    tx_lfn: u8,
}

impl<R, CTX> KnxRfLinkLayer<'_, R, CTX>
where
    R: RfTransceiver,
    CTX: LinkLayerBufferContext + RfDomainAddressContext,
{
    /// Event loop: race radio reception against transmit requests. Reception is
    /// cancel-safe per [`RfTransceiver`], so dropping it to service a request is
    /// fine — the next loop iteration re-arms RX.
    async fn run(&mut self, mut req_rx: impl Inbox<RequestMessage<Buffer<'static>>>) -> ! {
        let mut rx_buf = [0u8; RF_FRAME_BUF];
        loop {
            match select(self.radio.receive(&mut rx_buf), req_rx.next()).await {
                Either::First(Ok(rx)) => {
                    let len = rx.len.min(rx_buf.len());
                    // Copy out of `rx_buf` so the receive buffer is free for the
                    // next arming while we process this frame.
                    let mut telegram = [0u8; RF_FRAME_BUF];
                    telegram[..len].copy_from_slice(&rx_buf[..len]);
                    self.handle_received(&telegram[..len]).await;
                }
                Either::First(Err(_e)) => {
                    // `R::Error` is only `Debug`-bound; defmt's `{:?}` needs
                    // `Format`, so log without the payload.
                    warn!("KNX-RF: receive error");
                }
                Either::Second(request) => {
                    self.handle_request(request).await;
                }
            }
        }
    }

    /// Decode, filter (frame type, Domain Address, LFN), and forward a received
    /// telegram up to the network layer as an `L_Data.ind`.
    async fn handle_received(&mut self, telegram: &[u8]) {
        let mut internal = [0u8; RF_FRAME_BUF];
        let meta = match rf::rf_to_knx_message(telegram, &mut internal) {
            Ok(meta) => meta,
            Err(e) => {
                trace!("KNX-RF: undecodable frame dropped: {:?}", e);
                return;
            }
        };

        // Only KNX RF-Ready asynchronous data frames (frame-type nibble 0x0,
        // 0x8, 0x9). BiBat / RF-Multi control frames are not handled.
        if !matches!(meta.frame_type, 0x0 | 0x8 | 0x9) {
            trace!("KNX-RF: non-RF-Ready frame type {=u8:#x} dropped", meta.frame_type);
            return;
        }

        // Domain-Address acceptance (KNX 03/02/05 §6.1.5.3). A domain-addressed
        // frame (AET=1) must carry our Domain Address; otherwise it belongs to a
        // different installation and is discarded here at the DLL. Serial-
        // addressed frames (AET=0) are system broadcasts or group frames bearing
        // the sender's KNX Serial Number — no domain check applies; group
        // membership is filtered by the application layer.
        if meta.aet {
            let mut doa = [0u8; 6];
            self.context.rf_domain_address(&mut doa);
            if meta.sn_or_doa != doa {
                trace!("KNX-RF: frame for foreign domain dropped");
                return;
            }
        }

        // LFN duplicate suppression (KNX 03/02/05 §6.1.4.3), aged by wall-clock.
        let src = u16::from_be_bytes([internal[1], internal[2]]);
        let now_ms = embassy_time::Instant::now().as_millis();
        if self.history.is_duplicate(&meta.sn_or_doa, src, meta.lfn, now_ms) {
            trace!("KNX-RF: duplicate LFN {=u8} from {=u16:#06x} dropped", meta.lfn, src);
            return;
        }

        // Forward. Destination filtering (individual address / group membership)
        // is left to the transport and application layers, which already drop
        // frames not meant for this device.
        // TODO: optionally pre-filter by individual address / address table to
        // avoid allocating buffers for frames addressed elsewhere.
        let buffer = self.context.buffer_manager().alloc_from_slice(&internal[..meta.internal_len]).await;
        let msg = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
        self.ind_tx.send(IndicationMessage::indication(msg)).await;
    }

    /// Encode and transmit an `L_Data.req` from the network layer, then confirm.
    async fn handle_request(&mut self, request: RequestMessage<Buffer<'static>>) {
        let msg = request.into_inner();

        if msg.service_type() != ServiceType::L_Data_Req {
            warn!("KNX-RF: unhandled request service type {:?}", msg.service_type());
            self.conf_tx.send(msg.error().build()).await;
            return;
        }

        // Choose the block-1 address and AET from the destination kind
        // (KNX 03/02/05 §6.1.5.1): individual and installation-broadcast frames
        // carry the Domain Address (AET=1); group frames and system broadcasts
        // carry the device's KNX Serial Number (AET=0).
        let internal = &msg.buf()[..msg.len()];
        let (aet, block1) = self.tx_block1(internal);

        let lfn = self.next_lfn();
        let mut telegram = [0u8; RF_FRAME_BUF];
        let result =
            match rf::knx_message_to_rf(internal, &block1, aet, lfn, TX_REPEAT_COUNTER, self.unidir, &mut telegram) {
                Ok(n) => self.radio.transmit(&telegram[..n]).await,
                Err(e) => {
                    warn!("KNX-RF: frame encode failed: {:?}", e);
                    self.conf_tx.send(msg.error().build()).await;
                    return;
                }
            };

        match result {
            Ok(()) => self.conf_tx.send(msg.confirm().build()).await,
            Err(_e) => {
                // `R::Error` is only `Debug`-bound (defmt's `{:?}` needs `Format`).
                warn!("KNX-RF: transmit failed");
                self.conf_tx.send(msg.error().build()).await;
            }
        }
    }

    /// Pick the block-1 address (Domain Address vs. KNX Serial Number) and AET
    /// for an outgoing internal frame.
    fn tx_block1(&self, internal: &[u8]) -> (bool, [u8; 6]) {
        let dst_zero = internal[3] == 0 && internal[4] == 0;
        if tx_uses_domain_address(internal[0], internal[5], dst_zero, self.unidir) {
            let mut doa = [0u8; 6];
            self.context.rf_domain_address(&mut doa);
            (true, doa)
        } else {
            (false, self.context.knx_serial_number())
        }
    }

    /// Advance and return the per-device link-layer Frame Number (mod 8).
    fn next_lfn(&mut self) -> u8 {
        self.tx_lfn = (self.tx_lfn + 1) & 0x07;
        self.tx_lfn
    }
}

/// Decide whether an outgoing frame's block-1 `SN/DoA` field carries the RF
/// Domain Address (`true`, AET=1) or the device's KNX Serial Number (`false`,
/// AET=0).
///
/// A **bidirectional** device (one with a configured Domain Address) addresses
/// everything by its Domain Address — point-to-point, multicast *and*
/// installation broadcast — and only falls back to its KNX Serial Number for
/// *system* broadcasts. This matches real RF-Ready devices: the captured MDT
/// group telegram carries AET=1 + DoA for a normal Group Address, and an RF↔TP
/// coupler forwards domain-addressed frames. (KNX 03/02/05 Table 17 leaves the
/// multicast choice to the profile; §6.1.5.1's serial-number rule is the
/// *unidirectional* / transmit-only case, selected here by `unidir`.)
///
/// - `ctrl`: internal CTRL octet (SB bit `0x10` cleared ⇒ system broadcast).
/// - `npdu`: internal NPDU octet (bit 7 set ⇒ group Address Type).
/// - `dst_zero`: destination address is `0x0000`.
/// - `unidir`: this device is unidirectional (transmit-only).
fn tx_uses_domain_address(ctrl: u8, npdu: u8, dst_zero: bool, unidir: bool) -> bool {
    let group = npdu & 0x80 != 0;
    let system_broadcast = (ctrl & 0x10) == 0;

    if group && dst_zero {
        // DA=0000h: installation broadcast → DoA; system broadcast → Serial Number.
        !system_broadcast
    } else if group {
        // Multicast group: bidirectional devices address by DoA, unidirectional
        // (transmit-only) devices by their KNX Serial Number.
        !unidir
    } else {
        // Point-to-point individual → Domain Address.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::tx_uses_domain_address;

    // Internal CTRL bit 0x10 set = normal/installation; cleared = system broadcast.
    const CTRL_NORMAL: u8 = 0xBC;
    const CTRL_SYS_BCAST: u8 = 0xAC;
    // NPDU bit 7 = group Address Type.
    const NPDU_INDIVIDUAL: u8 = 0x60;
    const NPDU_GROUP: u8 = 0xE0;

    #[test]
    fn individual_destination_uses_domain_address() {
        assert!(tx_uses_domain_address(CTRL_NORMAL, NPDU_INDIVIDUAL, false, false));
    }

    #[test]
    fn bidirectional_group_uses_domain_address() {
        // Normal Group Address on a bidirectional device ⇒ Domain Address (AET=1),
        // matching the captured MDT group telegram.
        assert!(tx_uses_domain_address(CTRL_NORMAL, NPDU_GROUP, false, false));
    }

    #[test]
    fn unidirectional_group_uses_serial_number() {
        // Transmit-only device ⇒ multicast by KNX Serial Number (AET=0).
        assert!(!tx_uses_domain_address(CTRL_NORMAL, NPDU_GROUP, false, true));
    }

    #[test]
    fn installation_broadcast_uses_domain_address() {
        // Group + DA=0000h + not system broadcast ⇒ Domain Address.
        assert!(tx_uses_domain_address(CTRL_NORMAL, NPDU_GROUP, true, false));
    }

    #[test]
    fn system_broadcast_uses_serial_number() {
        // Group + DA=0000h + system broadcast (SB bit cleared) ⇒ Serial Number,
        // regardless of direction.
        assert!(!tx_uses_domain_address(CTRL_SYS_BCAST, NPDU_GROUP, true, false));
        assert!(!tx_uses_domain_address(CTRL_SYS_BCAST, NPDU_GROUP, true, true));
    }
}
