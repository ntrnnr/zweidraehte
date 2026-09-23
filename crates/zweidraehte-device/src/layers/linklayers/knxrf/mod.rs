//! KNX-RF Ready link layer.
//!
//! Bridges a KNX-RF radio transceiver to the device stack's network layer over
//! the standard req/ind/conf channels. It performs the Data-Link-Layer duties
//! the spec assigns to the receiver — **RF Domain Address acceptance** and
//! **LFN duplicate suppression** (KNX 03/02/05 §6.1.4–§6.1.5) — and converts
//! between the internal `KnxMessageBuffer` format and CRC-stripped RF telegrams
//! via [`zweidraehte_proto::encoding::rf`].
//!
//! # Optional retransmitter (repeater)
//!
//! The link layer is generic over a [`RetransmitPolicy`]. The default
//! [`NoRetransmit`] compiles the repeating path away. [`RetransmitEnabled`]
//! (selected with [`KnxRfLinkLayerBuilder::with_retransmitter`]) turns the
//! device into a KNX-RF **DoA retransmitter** (03/02/05 §6.1.7): on each
//! accepted frame it re-broadcasts the CRC-stripped telegram with the RF
//! Repetition Counter decremented, gated by the shared LFN history (never
//! repeat a duplicate), the RC limit (PID 74) and the runtime enable flag
//! (PID 57). Those parameters reach the link layer through
//! [`RfRetransmitterContext`], which a stack context only provides when the
//! device composes the
//! [`RfRetransmitterExtension`](crate::bcus::system_b::RfRetransmitterExtension)
//! — so the policy and the extension are wired together at compile time.
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

use core::marker::PhantomData;

use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;

use crate::context::{
    AddressTableContext, IndividualAddressContext, LinkLayerBufferContext, RfDomainAddressContext,
    RfRetransmitterContext,
};
use crate::layers::linklayers::address_check::{AddressChecker, DeviceAddressChecker};
use crate::layers::linklayers::is_secure_data_without_sbc;
use crate::layers::{Inbox, LinkLayerBuilder, LinkLayerBuilderBase, LinkLayerCapabilities};
use history::LfnHistory;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::config::{MAX_APDU_LENGTH_RF, max_outgoing_msg_len};
use zweidraehte_proto::encoding::rf;
use zweidraehte_proto::messages::buffers::Buffer;
use zweidraehte_proto::messages::builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage, RequestMessage};
use zweidraehte_proto::messages::knx::{AddressType, KnxMessageBuffer, ServiceType};

/// Largest CRC-stripped telegram / internal frame we handle, in octets.
///
/// This is a chosen budget, not a wire constant: it must cover
/// [`rf::TELEGRAM_HEADER_OVERHEAD`] plus the largest APDU the device may
/// configure. 96 gives [`MAX_SUPPORTED_APDU`] comfortable headroom above
/// the RF profile default
/// [`MAX_APDU_LENGTH_RF`](zweidraehte_proto::config::MAX_APDU_LENGTH_RF)
/// (55) that every current RF device uses.
const RF_FRAME_BUF: usize = 96;

/// Largest APDU (PID 56 / `MAX_APDU_LENGTH` value) whose Standard telegram still
/// fits `RF_FRAME_BUF`. The link layer advertises whatever the device puts in
/// [`StackDefinition::MAX_APDU_LENGTH`](crate::StackDefinition::MAX_APDU_LENGTH)
/// (the same value the pool buffers are sized from); a device whose ceiling
/// exceeds this cannot frame its own telegrams on RF, so it should compile-time
/// `assert!(MAX_APDU_LENGTH <= MAX_SUPPORTED_APDU)`. (Frames larger than this
/// that arrive on-air are dropped, not truncated — see the up-delivery guard.)
pub const MAX_SUPPORTED_APDU: u16 = (RF_FRAME_BUF - rf::TELEGRAM_HEADER_OVERHEAD) as u16;

// The recommended RF APDU value must itself be framable in the scratch buffer;
// if `MAX_APDU_LENGTH_RF` is ever raised past what `RF_FRAME_BUF` can hold, fail
// the build. `core::assert!` avoids defmt's non-const `assert!` override (which
// fails const evaluation on targets that pull in defmt).
const _: () = core::assert!(MAX_APDU_LENGTH_RF <= MAX_SUPPORTED_APDU);

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
///
/// `P` selects the [`RetransmitPolicy`]: the default [`NoRetransmit`] compiles
/// the repeating code path away entirely, while [`RetransmitEnabled`] (via
/// [`with_retransmitter`](Self::with_retransmitter)) makes the device a KNX-RF
/// DoA retransmitter — which the type system then requires the device to back
/// with the retransmitter extension (see [`RetransmitEnabled`]).
pub struct KnxRfLinkLayerBuilder<R: RfTransceiver, P = NoRetransmit> {
    radio: R,
    _policy: PhantomData<P>,
}

impl<R: RfTransceiver> KnxRfLinkLayerBuilder<R, NoRetransmit> {
    /// Create a bidirectional KNX-RF link-layer builder over `radio`.
    pub fn new(radio: R) -> Self {
        Self { radio, _policy: PhantomData }
    }
}

impl<R: RfTransceiver, P> KnxRfLinkLayerBuilder<R, P> {
    /// Turn this into a KNX-RF DoA **retransmitter** link layer (03/02/05
    /// §6.1.7). The resulting builder only satisfies `LinkLayerBuilder` for a
    /// stack context that exposes [`RfRetransmitterContext`] — i.e. a device
    /// that composes the retransmitter extension — so the dependency is checked
    /// at compile time.
    pub fn with_retransmitter(self) -> KnxRfLinkLayerBuilder<R, RetransmitEnabled> {
        KnxRfLinkLayerBuilder { radio: self.radio, _policy: PhantomData }
    }
}

impl<R: RfTransceiver, P> LinkLayerBuilderBase for KnxRfLinkLayerBuilder<R, P> {
    type Resources = KnxRfResources;

    fn create_resources(&self) -> Self::Resources {
        KnxRfResources
    }
}

impl<R: RfTransceiver, P> LinkLayerCapabilities for KnxRfLinkLayerBuilder<R, P> {}

// `R: 'static` because the radio is owned by — and moved into — the run-loop
// future. Concrete transceivers own 'static peripherals (e.g. embassy SPI), so
// this is satisfied in practice.
//
// A single impl covers both policies: `P: RetransmitPolicy<CTX>` holds
// unconditionally for `NoRetransmit`, but for `RetransmitEnabled` it requires
// `CTX: RfRetransmitterContext` (see the policy impls below) — which a
// `StackContext` only provides when the device composes the retransmitter
// extension. Selecting the retransmitter link layer without the extension is
// therefore a compile error at the device's `LinkLayerBuilder` use site.
impl<R, CTX, P> LinkLayerBuilder<CTX> for KnxRfLinkLayerBuilder<R, P>
where
    R: RfTransceiver + 'static,
    CTX: LinkLayerBufferContext + RfDomainAddressContext + IndividualAddressContext + AddressTableContext,
    // `P` is a zero-sized marker (`NoRetransmit` / `RetransmitEnabled`), so the
    // `'static` bound is trivially met and lets the run-loop future hold a
    // `PhantomData<P>` for the lifetime `'a`.
    P: RetransmitPolicy<CTX> + 'static,
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
        let mut ll = KnxRfLinkLayer::<R, CTX, P> {
            radio: self.radio,
            context,
            ind_tx,
            conf_tx,
            history: LfnHistory::new(),
            tx_lfn: 0,
            _policy: PhantomData,
        };
        async move { ll.run(req_rx).await }
    }
}

// ============================================================================
// Retransmit policy — compile-time gate for the §6.1.7 repeating behaviour
// ============================================================================

/// Compile-time selector for the KNX-RF retransmit (repeater) behaviour.
///
/// Implemented for a given stack context only by the variant that is legal in
/// it: [`NoRetransmit`] for *every* context (no-op), [`RetransmitEnabled`]
/// only for a context that exposes [`RfRetransmitterContext`]. The link layer
/// is generic over `P: RetransmitPolicy<CTX>`, so the wrong combination simply
/// fails to type-check rather than misbehaving at runtime.
pub trait RetransmitPolicy<CTX> {
    /// Apply the §6.1.7 retransmit decision to a just-received frame.
    ///
    /// `dup` is the result of the shared LFN-history check (a duplicate is
    /// never repeated). For [`NoRetransmit`] this is a no-op the optimiser
    /// removes entirely.
    fn maybe_retransmit<R: RfTransceiver>(
        radio: &mut R,
        dup: bool,
        telegram: &[u8],
        meta: &rf::RfRxMeta,
        context: &CTX,
    ) -> impl core::future::Future<Output = ()>;
}

/// No retransmit behaviour — the default. The repeating code path is
/// monomorphised away, so a normal RF device carries none of it.
pub struct NoRetransmit;

impl<CTX> RetransmitPolicy<CTX> for NoRetransmit {
    async fn maybe_retransmit<R: RfTransceiver>(_: &mut R, _: bool, _: &[u8], _: &rf::RfRxMeta, _: &CTX) {}
}

/// KNX-RF DoA retransmitter behaviour. Only valid for a stack context that
/// exposes the retransmitter parameters ([`RfRetransmitterContext`]), which in
/// turn requires the device to compose the retransmitter extension.
///
/// The bound is enforced at compile time: a context that does not implement
/// [`RfRetransmitterContext`] is not a valid `RetransmitPolicy`, so selecting
/// the retransmitter link layer without the backing extension fails to build.
///
/// ```compile_fail
/// use zweidraehte_device::layers::linklayers::knxrf::{RetransmitEnabled, RetransmitPolicy};
/// // A context with no retransmitter parameters.
/// struct PlainCtx;
/// fn requires_policy<P: RetransmitPolicy<PlainCtx>>() {}
/// // `PlainCtx: !RfRetransmitterContext`, so this line does not compile.
/// requires_policy::<RetransmitEnabled>();
/// ```
///
/// The same usage with [`NoRetransmit`] compiles, since it is a policy for
/// every context:
///
/// ```
/// use zweidraehte_device::layers::linklayers::knxrf::{NoRetransmit, RetransmitPolicy};
/// struct PlainCtx;
/// fn requires_policy<P: RetransmitPolicy<PlainCtx>>() {}
/// requires_policy::<NoRetransmit>();
/// ```
pub struct RetransmitEnabled;

impl<CTX: RfRetransmitterContext> RetransmitPolicy<CTX> for RetransmitEnabled {
    async fn maybe_retransmit<R: RfTransceiver>(
        radio: &mut R,
        dup: bool,
        telegram: &[u8],
        meta: &rf::RfRxMeta,
        context: &CTX,
    ) {
        // §6.1.7.3 History List: never repeat a frame we already saw (the
        // shared LFN history was updated by the caller's duplicate check).
        // §6.1.7 runtime toggle (PID 57): honour the enable flag.
        if dup || !context.rf_retransmit_enabled() {
            return;
        }

        // §6.1.7.4 RF Repetition Counter: repeat only while RC > 0 and
        // RC > limit, decrementing on this hop. Otherwise discard.
        let rc = meta.rc;
        let limit = context.rf_repeat_counter_limit();
        if rc == 0 || rc <= limit {
            return;
        }
        let rc_decremented = rc - 1;

        // Re-emit the CRC-stripped frame unchanged except for the decremented
        // RC nibble; the LFN and every other field are preserved (the
        // retransmitter must not alter the LFN) and the transceiver recomputes
        // block CRCs. RSSI annotation (RF-info bits 3:2) is left void — a
        // conformant value when we don't measure signal strength.
        if telegram.len() <= rf::LPCI1_IDX {
            return;
        }
        let mut out = [0u8; RF_FRAME_BUF];
        let n = telegram.len().min(out.len());
        out[..n].copy_from_slice(&telegram[..n]);
        out[rf::LPCI1_IDX] =
            (out[rf::LPCI1_IDX] & !rf::LPCI1_RC_MASK) | ((rc_decremented << rf::LPCI1_RC_SHIFT) & rf::LPCI1_RC_MASK);

        if radio.transmit(&out[..n]).await.is_err() {
            warn!("KNX-RF: retransmit failed");
        }
    }
}

// ============================================================================
// Runtime
// ============================================================================

struct KnxRfLinkLayer<'a, R: RfTransceiver, CTX, P> {
    radio: R,
    context: &'a CTX,
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
    history: LfnHistory,
    tx_lfn: u8,
    _policy: PhantomData<P>,
}

impl<R, CTX, P> KnxRfLinkLayer<'_, R, CTX, P>
where
    R: RfTransceiver,
    CTX: LinkLayerBufferContext + RfDomainAddressContext + IndividualAddressContext + AddressTableContext,
    P: RetransmitPolicy<CTX>,
{
    /// Event loop: race radio reception against transmit requests. Reception is
    /// cancel-safe per [`RfTransceiver`], so dropping it to service a request is
    /// fine — the next loop iteration re-arms RX.
    async fn run(&mut self, mut req_rx: impl Inbox<RequestMessage<Buffer<'static>>>) -> ! {
        // Note: unlike TP-UART / USB we do *not* call `set_max_apdu_length`. RF
        // has no link-time capability negotiation — the radio carries whatever
        // the device's compile-time `MAX_APDU_LENGTH` was sized for — so the
        // runtime value (already initialised to that ceiling by the device
        // state) is correct as-is. PID 56 therefore reports the configured RF
        // APDU directly. Frames that exceed it are dropped by the up-delivery
        // guard below; the build-time `MAX_APDU_LENGTH_RF <= MAX_SUPPORTED_APDU`
        // assertion keeps the recommended ceiling framable in `RF_FRAME_BUF`.
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
            trace!("KNX-RF: non-RF-Ready frame type {:#x} dropped", meta.frame_type);
            return;
        }

        // RF-Ready here supports ordinary addressing, not LTE. Reject unknown
        // formats before repeating or delivering them (03/03/02 §2.2.4).
        if KnxMessageBuffer::from_buffer(internal.as_slice()).ctrl2_field().extended_frame_format() != 0 {
            return;
        }

        // Domain-Address acceptance (KNX 03/02/05 §6.1.5.3). A domain-addressed
        // frame (AET=1) must carry our Domain Address; otherwise it belongs to a
        // different installation and is discarded here at the DLL. Serial-
        // addressed frames (AET=0) are system broadcasts or group frames bearing
        // the sender's KNX Serial Number — no domain check applies; group
        // membership is filtered by the application layer.
        let foreign_domain = meta.aet && meta.sn_or_doa != self.context.rf_domain_address();

        if foreign_domain {
            trace!("KNX-RF: frame for foreign domain dropped");
            return;
        }

        // Drop frames we originated ourselves. On KNX-RF a device hears its own
        // telegrams come back — repeated by a retransmitter on the domain (the
        // source IA is preserved across retransmission), or directly when
        // another device still shares our individual address (e.g. the default
        // 15.15.255 before programming). TP1 never receives its own sent frames,
        // so the network layer's duplication check assumes a self-sourced frame
        // means a cloned IA; on RF that is normal traffic. Dropping it here also
        // stops the application from reprocessing its own telegrams and stops a
        // combined end-device/retransmitter from re-repeating its own frames.
        let src = u16::from_be_bytes([internal[1], internal[2]]);
        if IndividualAddress::from_bytes(&[internal[1], internal[2]]) == self.context.individual_address() {
            trace!("KNX-RF: own-source frame (echo) dropped");
            return;
        }

        // LFN duplicate suppression (KNX 03/02/05 §6.1.4.3), aged by wall-clock.
        // A single shared history serves both the receiver dedup (§6.1.4.3.3)
        // and the retransmitter History List (§6.1.7.3): both key on
        // (sender, LFN) and cap at 7 entries, so one `is_duplicate` call —
        // which also records the frame — gates both paths below.
        let now_ms = embassy_time::Instant::now().as_millis();
        let dup = self.history.is_duplicate(&meta.sn_or_doa, src, meta.lfn, now_ms);

        // Retransmit (§6.1.7) before up-delivery, for timely repeating. For the
        // default `NoRetransmit` policy this is a monomorphised no-op.
        P::maybe_retransmit(&mut self.radio, dup, telegram, &meta, self.context).await;

        if dup {
            trace!("KNX-RF: duplicate LFN {} from {:#06x} dropped", meta.lfn, src);
            return;
        }

        // Reject frames longer than the APDU ceiling we advertise, before
        // copying them into a pool buffer. The codec bounds the decoded frame
        // only by the scratch-buffer size; our pool buffers are sized to the
        // advertised MAX_APDU_LENGTH, so a longer internal frame would overflow
        // the buffer the indication is built in. Like the destination filter,
        // this runs *after* the retransmit branch — a repeater still forwards
        // frames it cannot itself receive — and only gates local up-delivery.
        let max_internal = max_outgoing_msg_len(self.context.max_apdu_length(), false);
        if meta.internal_len > max_internal {
            trace!("KNX-RF: over-length frame ({} > {}) dropped from up-delivery", meta.internal_len, max_internal);
            return;
        }

        // Destination filtering (KNX 03/02/05 §6.1.5.3 reception): only deliver
        // frames actually addressed to this device. Unlike TP1 — where the
        // TP-UART ACKs and accepts by address — RF has no Layer-2 ACK, so the
        // link layer must drop foreign-destination frames itself; otherwise
        // every individual-addressed telegram on the domain reaches the
        // transport / secure application layer and (for secure devices) fails
        // MAC verification. This runs *after* the retransmit branch above: a
        // retransmitter still repeats frames not meant for it.
        if !self.is_destination_local(&internal) {
            trace!("KNX-RF: frame not addressed to us dropped from up-delivery");
            return;
        }

        // Enforce the RF communication-mode rule before local delivery. Keep
        // retransmission transparent above: a repeater does not apply the
        // local application's acceptance policy to transit traffic.
        let packet = KnxMessageBuffer::from_buffer(&internal[..meta.internal_len]);
        if packet.get_address_type() == AddressType::SystemBroadcast && is_secure_data_without_sbc(packet.buf()) {
            return;
        }

        let buffer = self.context.buffer_manager().alloc_from_slice(&internal[..meta.internal_len]).await;
        let msg = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
        self.ind_tx.send(IndicationMessage::indication(msg)).await;
    }

    /// Whether a received frame's destination targets this device, using the
    /// shared [`DeviceAddressChecker`]: accept broadcasts (destination
    /// `0x0000`), group frames whose Group Address is in the loaded address
    /// table (an empty loaded table accepts all, matching the ETS programming
    /// window), and individual frames addressed to our own IA.
    ///
    /// The internal frame's first six octets (`[ctrl, src_hi, src_lo, dst_hi,
    /// dst_lo, npci]`) share the standard L_Data header layout the checker
    /// parses, so the same logic the TP1 link layer uses for its ACK decision
    /// drives RF up-delivery filtering.
    fn is_destination_local(&self, internal: &[u8]) -> bool {
        let Ok(header) = <&[u8; 6]>::try_from(&internal[..6]) else {
            return false;
        };
        DeviceAddressChecker::new(self.context).should_ack(header)
    }

    /// Encode and transmit an `L_Data.req` from the network layer, then confirm.
    async fn handle_request(&mut self, request: RequestMessage<Buffer<'static>>) {
        let msg = request.into_inner();

        if msg.service_type() != ServiceType::L_Data_Req {
            warn!("KNX-RF: unhandled request service type {:?}", msg.service_type());
            self.conf_tx.send(msg.error().build()).await;
            return;
        }

        let internal = &msg.buf()[..msg.len()];
        let (aet, block1) = self.tx_block1(internal);

        let lfn = self.next_lfn();
        let mut telegram = [0u8; RF_FRAME_BUF];
        // We currently listen continuously. Semi-directional operation would
        // report its live Bidirectional Mode here (03/02/05 §6.7), never a fixed
        // device-direction type. TODO: implement that mode and its RX scheduling.
        let result = match rf::knx_message_to_rf(internal, &block1, aet, lfn, TX_REPEAT_COUNTER, false, &mut telegram) {
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
        // Multicast addressing follows the profile, not the receiver's power
        // state (03/02/05 Table 17; 06/01/35 §3.2.3). Our System B RF profile
        // uses DoA for individual, multicast and installation broadcasts;
        // only system broadcasts carry the serial number.
        let system_broadcast =
            internal[5] & 0x80 != 0 && internal[3] == 0 && internal[4] == 0 && internal[0] & 0x10 == 0;
        if system_broadcast {
            (false, self.context.knx_serial_number())
        } else {
            (true, self.context.rf_domain_address())
        }
    }

    /// Advance and return the per-device link-layer Frame Number (mod 8).
    fn next_lfn(&mut self) -> u8 {
        self.tx_lfn = (self.tx_lfn + 1) & 0x07;
        self.tx_lfn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ApduLengthContext, BufferManagerContext};
    use crate::objects::tables::{AddrTab7Impl, Table};
    use const_default::ConstDefault;
    use core::cell::{Cell, RefCell};
    use embassy_futures::block_on;
    use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
    use zweidraehte_proto::messages::buffers::{BufferManager, DynBufferManager};
    use zweidraehte_proto::messages::knx::Confirm;

    // Internal CTRL bit 0x10 set = normal/installation; cleared = system broadcast.
    const CTRL_NORMAL: u8 = 0xBC;
    const CTRL_SYS_BCAST: u8 = 0xAC;
    // NPDU bit 7 = group Address Type.
    const NPDU_INDIVIDUAL: u8 = 0x60;
    const NPDU_GROUP: u8 = 0xE0;

    struct TxContext {
        buffers: DynBufferManager<'static>,
        domain: Cell<[u8; 6]>,
        table: RefCell<Table<AddrTab7Impl<8>>>,
    }

    impl BufferManagerContext for TxContext {
        fn buffer_manager(&self) -> &DynBufferManager<'static> {
            &self.buffers
        }
    }

    impl ApduLengthContext for TxContext {
        fn max_apdu_length(&self) -> u16 {
            MAX_APDU_LENGTH_RF
        }

        fn set_max_apdu_length(&self, _: u16) {
            panic!("RF has no APDU negotiation");
        }
    }

    impl IndividualAddressContext for TxContext {
        fn individual_address(&self) -> IndividualAddress {
            IndividualAddress::new(1, 2, 1)
        }
    }

    impl AddressTableContext for TxContext {
        type ADT = Table<AddrTab7Impl<8>>;

        fn address_table(&self) -> &RefCell<Self::ADT> {
            &self.table
        }
    }

    impl RfDomainAddressContext for TxContext {
        fn rf_domain_address(&self) -> [u8; 6] {
            self.domain.get()
        }

        fn knx_serial_number(&self) -> [u8; 6] {
            [0x00, 0x83, 1, 2, 3, 4]
        }
    }

    #[test]
    fn link_layer_transmits_and_receives_with_live_domain() {
        // Buffers sent through the stack channels require static backing memory.
        let pool = Box::leak(Box::new([[0u8; 96]; 1]));
        // SAFETY: the leaked pool outlives every buffer and the manager.
        let manager = Box::leak(Box::new(unsafe { BufferManager::new(pool) }));
        let ctx = TxContext {
            buffers: manager.dyn_buffer_manager(),
            domain: Cell::new([0x00, 0xfa, 0xb6, 0xab, 0xb2, 0x86]),
            table: RefCell::new(Table::DEFAULT),
        };
        let indications = Channel::<NoopRawMutex, _, 1>::new();
        let confirmations = Channel::<NoopRawMutex, _, 1>::new();
        let mut layer = KnxRfLinkLayer::<_, _, NoRetransmit> {
            radio: MockRadio::new(),
            context: &ctx,
            ind_tx: indications.dyn_sender(),
            conf_tx: confirmations.dyn_sender(),
            history: LfnHistory::new(),
            tx_lfn: 0,
            _policy: PhantomData,
        };

        // Verify actual transmitted bytes, including a domain change after the
        // layer was constructed (as when ETS writes the RF Medium Object).
        for domain in [ctx.domain.get(), [9, 8, 7, 6, 5, 4]] {
            ctx.domain.set(domain);
            for (ctrl, npdu, dst, aet) in [
                (CTRL_NORMAL, NPDU_INDIVIDUAL, 0x1003u16, true),
                (CTRL_NORMAL, NPDU_GROUP, 0x0100, true),
                (CTRL_NORMAL, NPDU_GROUP, 0, true),
                (CTRL_SYS_BCAST, NPDU_GROUP, 0, false),
            ] {
                let [dst_hi, dst_lo] = dst.to_be_bytes();
                let internal = [ctrl, 0x12, 0x01, dst_hi, dst_lo, npdu, 0x00, 0x80, 0x0c, 0xc4];
                let buffer = ctx.buffers.try_alloc_from_slice(&internal).expect("previous confirmation released");
                let request = RequestMessage::request(KnxMessageBuffer::new(buffer, ServiceType::L_Data_Req));
                block_on(layer.handle_request(request));
                let confirmation = confirmations.try_receive().expect("request confirmed");
                assert_eq!(confirmation.service_type(), ServiceType::L_Data_Con);
                assert_eq!(confirmation.ctrl_field().c(), Confirm::NoError);

                let address = if aet { domain } else { ctx.knx_serial_number() };
                let lfn = (layer.radio.tx_count as u8) & 7;
                let lpci = (npdu & 0x80) | 0x60 | (lfn << 1) | u8::from(aet);
                let mut expected = [
                    0x13, 0x44, 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0x00, 0x12, 0x01, dst_hi, dst_lo, lpci, 0x00, 0x80, 0x0c,
                    0xc4,
                ];
                expected[4..10].copy_from_slice(&address);
                assert_eq!(&layer.radio.last[..layer.radio.last_len], &expected);
            }
        }
        assert_eq!(layer.radio.tx_count, 8);

        // The same link layer receives addressed telegrams from a peer in either
        // receive mode. Its Unidir bit describes the peer, not our capabilities.
        let peer_message = [CTRL_NORMAL, 0x12, 0x03, 0x12, 0x01, NPDU_INDIVIDUAL, 0x00, 0x80, 0x0c, 0xc4];
        for eff in 1..16 {
            let mut unsupported = peer_message;
            unsupported[5] |= eff;
            let mut telegram = [0u8; 32];
            let len = rf::knx_message_to_rf(&unsupported, &ctx.domain.get(), true, 1, 6, false, &mut telegram)
                .expect("codec retains unsupported EFF");
            block_on(layer.handle_received(&telegram[..len]));
            assert!(indications.try_receive().is_err());
        }
        for (lfn, unidir) in [(1, true), (2, false)] {
            let mut telegram = [0u8; 32];
            let len = rf::knx_message_to_rf(&peer_message, &ctx.domain.get(), true, lfn, 6, unidir, &mut telegram)
                .expect("valid peer telegram");
            block_on(layer.handle_received(&telegram[..len]));

            let indication = indications.try_receive().expect("addressed peer telegram delivered");
            assert_eq!(indication.service_type(), ServiceType::L_Data_Ind);
            assert_eq!(&indication.buf()[..indication.len()], &peer_message);
        }
    }

    #[test]
    fn system_broadcast_requires_sbc_only_for_secure_data() {
        use crate::layers::linklayers::test_support::secure_frame;
        use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
        use zweidraehte_proto::messages::knx::{ApciCode, DestinationAddress};

        let pool = Box::leak(Box::new([[0u8; 96]; 1]));
        // SAFETY: the leaked pool outlives all received buffers.
        let manager = Box::leak(Box::new(unsafe { BufferManager::new(pool) }));
        let ctx = TxContext {
            buffers: manager.dyn_buffer_manager(),
            domain: Cell::new([1, 2, 3, 4, 5, 6]),
            table: RefCell::new(Table::DEFAULT),
        };
        let indications = Channel::<NoopRawMutex, _, 1>::new();
        let confirmations = Channel::<NoopRawMutex, _, 1>::new();
        let mut layer = KnxRfLinkLayer::<_, _, NoRetransmit> {
            radio: MockRadio::new(),
            context: &ctx,
            ind_tx: indications.dyn_sender(),
            conf_tx: confirmations.dyn_sender(),
            history: LfnHistory::new(),
            tx_lfn: 0,
            _policy: PhantomData,
        };

        let mut lfn = 0;
        for destination in [DestinationAddress::Broadcast, DestinationAddress::SystemBroadcast] {
            for service in [SecureServiceType::Data, SecureServiceType::SyncRequest, SecureServiceType::SyncResponse] {
                for confidentiality in [false, true] {
                    if service != SecureServiceType::Data && !confidentiality {
                        continue;
                    }
                    for sbc in [false, true] {
                        let scf =
                            SecurityControlField { service, system_broadcast: sbc, confidentiality, tool_access: true };
                        let internal = secure_frame(destination, scf);
                        let aet = destination == DestinationAddress::Broadcast;
                        let block1 = if aet { ctx.domain.get() } else { ctx.knx_serial_number() };
                        let mut telegram = [0; RF_FRAME_BUF];
                        let len = rf::knx_message_to_rf(&internal, &block1, aet, lfn, 6, false, &mut telegram)
                            .expect("valid RF telegram");
                        lfn = (lfn + 1) % 8;
                        block_on(layer.handle_received(&telegram[..len]));
                        let accepted = indications.try_receive().is_ok();
                        assert_eq!(
                            accepted,
                            aet || service != SecureServiceType::Data || sbc,
                            "destination={destination:?}, service={service:?}, SBC={sbc}, confidentiality={confidentiality}"
                        );
                    }
                }
            }
        }

        // A plaintext system broadcast must not be interpreted as an SCF.
        let mut plain = secure_frame(DestinationAddress::SystemBroadcast, SecurityControlField {
            service: SecureServiceType::Data,
            system_broadcast: false,
            confidentiality: true,
            tool_access: true,
        });
        KnxMessageBuffer::from_buffer(plain.as_mut_slice()).set_apci_code(ApciCode::IndividualAddressRead);
        let mut telegram = [0; RF_FRAME_BUF];
        let len = rf::knx_message_to_rf(&plain, &ctx.knx_serial_number(), false, lfn, 6, false, &mut telegram)
            .expect("plain RF broadcast");
        block_on(layer.handle_received(&telegram[..len]));
        assert!(indications.try_receive().is_ok());
    }

    // ========================================================================
    // Retransmit policy (§6.1.7) tests
    // ========================================================================

    /// Records the last transmitted telegram; `receive` never resolves.
    struct MockRadio {
        last: [u8; super::RF_FRAME_BUF],
        last_len: usize,
        tx_count: usize,
    }

    impl MockRadio {
        fn new() -> Self {
            Self { last: [0; super::RF_FRAME_BUF], last_len: 0, tx_count: 0 }
        }
    }

    impl RfTransceiver for MockRadio {
        type Error = ();

        async fn receive(&mut self, _buf: &mut [u8]) -> Result<RfRx, ()> {
            core::future::pending().await
        }

        async fn transmit(&mut self, telegram: &[u8]) -> Result<(), ()> {
            let n = telegram.len().min(self.last.len());
            self.last[..n].copy_from_slice(&telegram[..n]);
            self.last_len = n;
            self.tx_count += 1;
            Ok(())
        }
    }

    /// Minimal retransmitter-parameter context for policy tests.
    struct MockCtx {
        enabled: bool,
        limit: u8,
    }

    impl RfRetransmitterContext for MockCtx {
        fn rf_retransmit_enabled(&self) -> bool {
            self.enabled
        }

        fn rf_repeat_counter_limit(&self) -> u8 {
            self.limit
        }
    }

    // LPCI-1 octet (telegram index 15): RC in bits 6:4, LFN in bits 3:1.
    // 0x66 = RC 6, LFN 3, AET 0.
    const LPCI1_RC6_LFN3: u8 = 0x66;

    fn meta_with_rc(rc: u8) -> rf::RfRxMeta {
        rf::RfRxMeta {
            internal_len: 0,
            sn_or_doa: [0; 6],
            aet: true,
            lfn: 3,
            rc,
            unidir: false,
            battery_ok: true,
            frame_type: 0,
        }
    }

    /// A 20-octet CRC-stripped telegram with a recognisable LPCI-1 octet and
    /// distinct surrounding bytes, so we can assert byte-exact preservation.
    fn sample_telegram() -> [u8; 20] {
        let mut t = [0u8; 20];
        for (i, b) in t.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        t[rf::LPCI1_IDX] = LPCI1_RC6_LFN3;
        t
    }

    #[test]
    fn retransmit_decrements_rc_and_preserves_lfn() {
        let mut radio = MockRadio::new();
        let telegram = sample_telegram();
        let ctx = MockCtx { enabled: true, limit: 0 };
        block_on(RetransmitEnabled::maybe_retransmit(&mut radio, false, &telegram, &meta_with_rc(6), &ctx));

        assert_eq!(radio.tx_count, 1, "frame with RC>limit must be repeated once");
        assert_eq!(radio.last_len, telegram.len());
        // RC nibble decremented 6→5, LFN bits (0x06) preserved ⇒ 0x56.
        assert_eq!(radio.last[rf::LPCI1_IDX], 0x56);
        // Every other octet is byte-identical (LFN unchanged, no re-encode).
        for (i, (actual, expected)) in radio.last.iter().zip(telegram.iter()).enumerate() {
            if i != rf::LPCI1_IDX {
                assert_eq!(actual, expected, "octet {i} must be preserved");
            }
        }
    }

    #[test]
    fn retransmit_honours_rc_limit() {
        // RC 6 > limit 5 ⇒ repeated (to RC 5).
        let mut radio = MockRadio::new();
        let telegram = sample_telegram();
        let ctx = MockCtx { enabled: true, limit: 5 };
        block_on(RetransmitEnabled::maybe_retransmit(&mut radio, false, &telegram, &meta_with_rc(6), &ctx));
        assert_eq!(radio.tx_count, 1);
        assert_eq!(radio.last[rf::LPCI1_IDX] >> 4, 5);

        // RC 5 == limit 5 ⇒ not repeated.
        let mut radio = MockRadio::new();
        let mut t = sample_telegram();
        t[rf::LPCI1_IDX] = (5 << 4) | 0x06;
        block_on(RetransmitEnabled::maybe_retransmit(&mut radio, false, &t, &meta_with_rc(5), &ctx));
        assert_eq!(radio.tx_count, 0, "RC == limit must not be repeated");
    }

    #[test]
    fn retransmit_drops_rc_zero() {
        let mut radio = MockRadio::new();
        let telegram = sample_telegram();
        let ctx = MockCtx { enabled: true, limit: 0 };
        block_on(RetransmitEnabled::maybe_retransmit(&mut radio, false, &telegram, &meta_with_rc(0), &ctx));
        assert_eq!(radio.tx_count, 0, "RC 0 must never be repeated");
    }

    #[test]
    fn retransmit_skips_duplicates() {
        let mut radio = MockRadio::new();
        let telegram = sample_telegram();
        let ctx = MockCtx { enabled: true, limit: 0 };
        block_on(RetransmitEnabled::maybe_retransmit(&mut radio, true, &telegram, &meta_with_rc(6), &ctx));
        assert_eq!(radio.tx_count, 0, "a history duplicate must not be repeated");
    }

    #[test]
    fn retransmit_respects_disabled_flag() {
        let mut radio = MockRadio::new();
        let telegram = sample_telegram();
        let ctx = MockCtx { enabled: false, limit: 0 };
        block_on(RetransmitEnabled::maybe_retransmit(&mut radio, false, &telegram, &meta_with_rc(6), &ctx));
        assert_eq!(radio.tx_count, 0, "PID 57 disabled suppresses retransmission");
    }

    #[test]
    fn no_retransmit_policy_never_transmits() {
        let mut radio = MockRadio::new();
        let telegram = sample_telegram();
        let ctx = MockCtx { enabled: true, limit: 0 };
        block_on(NoRetransmit::maybe_retransmit(&mut radio, false, &telegram, &meta_with_rc(6), &ctx));
        assert_eq!(radio.tx_count, 0, "NoRetransmit is a no-op");
    }
}
