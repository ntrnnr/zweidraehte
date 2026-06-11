//! TPUART Link Layer Implementation
//!
//! This module implements the KNX TP1 link layer using TPUART-compatible chips.
//!
//! ## Supported Chips
//!
//! - Siemens TPUART1 (legacy, 64 byte buffer, APDU max 56 bytes)
//! - Siemens TPUART2 (64 byte buffer, APDU max 56 bytes)
//! - ON Semiconductor NCN5120/5121/5130 (256 byte buffer, APDU max 248 bytes)
//! - Elmos E981.03 (256 byte buffer, APDU max 248 bytes)
//!
//! ## Features
//!
//! - Automatic chip detection during initialization
//! - Configurable NAK/BUSY retry counts
//! - Bus failure detection (after repeated reset failures)
//! - Repeated telegram detection and filtering
//! - Invalidation state for error recovery (3ms timeout)
//! - Individual address ACK via hardware (set during init)
//! - Frame size validation per chip capabilities
//!
//! ## Max APDU Length Detection
//!
//! After initialization, the detected chip type determines the maximum APDU length
//! based on the chip's TX buffer size. All chips support Extended Frame Format (EFF):
//! - TPUART1/2: 56 bytes (64 byte buffer - 8 bytes overhead)
//! - NCN5120/E981: 248 bytes (256 byte buffer - 8 bytes overhead)
//!
//! During initialization, the link layer automatically calls
//! [`ApduLengthContext::set_max_apdu_length()`](crate::context::ApduLengthContext::set_max_apdu_length)
//! on its context so that PID 56 (MAX_APDU_LENGTH) reports the correct
//! hardware capability. Incoming frames exceeding the chip's limit are dropped.
//!
//! ## Architecture
//!
//! The implementation uses a pure state machine pattern for testability,
//! with async I/O handled separately in the action executor.
//!
//! ## Future Work
//!
//! - Statistics collection
//!
//! ## Bus Monitor Mode
//!
//! The [`busmon::BusMonitor`] struct provides an ergonomic async interface for bus monitor
//! mode. In this mode, the TPUART chip passively captures all bus traffic including
//! ACK/NACK/BUSY bytes and collision events.
//!
//! See the [`busmon`] module for usage details.
//!
//! **Note**: Bus monitor mode is mutually exclusive with normal operation. Once enabled,
//! a chip reset is required to return to normal mode.

use embassy_futures::select::{Either4, select4};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Instant, Timer};

use crate::context::{AddressTableContext, KnxIndividualAddressContext, LinkLayerBufferContext, MaxRetryCountContext};
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::{
    buffers::{Buffer, MessageBuffer},
    builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage},
    knx::*,
};

use crate::layers::Inbox;
use zweidraehte_proto::messages::builder::RequestMessage;

pub mod busmon;
mod chip;
mod state_machine;

/// Type-erased context for the TPUART link layer's
/// `AutoAddressChecker` builder path.
///
/// Bundles the four context traits the builder needs to construct
/// a `DeviceAddressChecker` from the device state and to apply
/// PID 52 (`MAX_RETRY_COUNT`) to the chip.
pub(crate) trait TpuartContext:
    LinkLayerBufferContext + KnxIndividualAddressContext + AddressTableContext + MaxRetryCountContext
{
}

impl<T> TpuartContext for T where
    T: LinkLayerBufferContext + KnxIndividualAddressContext + AddressTableContext + MaxRetryCountContext
{
}

use chip::{ChipType, RetryConfig};
use state_machine::*;
use zweidraehte_proto::encoding::tp1::{knx_to_tp1_message, tp1_to_knx_message_no_checksum, validate_tp1_checksum};

// Re-export for external use
pub use chip::ChipType as TpUartChipType;

// The address-checking abstraction is medium-neutral and lives in
// `super::address_check` so the KNX-RF link layer can share it. Re-exported
// here for backward compatibility (TPUART builders and downstream code still
// refer to `tpuart::AddressChecker`, `DeviceAddressChecker`, etc.).
pub use super::address_check::{AckAllChecker, AddressChecker, DeviceAddressChecker, NoAddressChecker};
// The TPUART receive path also parses raw headers directly for its ACK
// decision; reuse the shared helper under the historic name.
use super::address_check::extract_header_fields as extract_tp1_header_fields;

/// Marker type: construct a [`DeviceAddressChecker`] automatically at
/// link layer build time from the stack context.
///
/// This is the default for [`TpUartLinkLayerBuilder::new`]. The builder's
/// [`build_and_run`](super::super::LinkLayerBuilder::build_and_run) impl
/// requires the context to provide [`KnxIndividualAddressContext`] and
/// [`AddressTableContext`](crate::context::AddressTableContext), and creates a [`DeviceAddressChecker`] that
/// ACKs the device's own individual address, group addresses from the
/// loaded address table, and broadcasts.
///
/// Use [`TpUartLinkLayerBuilder::with_address_checker`] to supply a
/// different checker (e.g., [`AckAllChecker`] for tunneling gateways or
/// [`NoAddressChecker`] for bus monitors).
pub struct AutoAddressChecker;

// ============================================================================
// Link Layer Builder
// ============================================================================

/// Builder for creating a [`TpUartLinkLayer`] that plugs into the stack's
/// [`LinkLayerBuilder`](super::super::LinkLayerBuilder) framework.
///
/// The builder owns split UART TX/RX halves and an [`AddressChecker`]
/// (or the [`AutoAddressChecker`] marker). The caller is responsible for
/// splitting the UART before constructing the builder (e.g.,
/// `BufferedUart::split()` on Embassy).
///
/// # Default: automatic address checking
///
/// [`new`](Self::new) uses [`AutoAddressChecker`], which constructs a
/// [`DeviceAddressChecker`] from the stack context at build time. This
/// ACKs the device's own individual address, loaded group addresses, and
/// broadcasts — the right default for normal KNX TP1 devices.
///
/// # Custom checkers
///
/// Use [`with_address_checker`](Self::with_address_checker) to supply a
/// different policy:
///
/// ```ignore
/// // Tunneling gateway — ACK everything
/// let builder = TpUartLinkLayerBuilder::with_address_checker(tx, rx, AckAllChecker);
///
/// // Bus monitor — ACK nothing
/// let builder = TpUartLinkLayerBuilder::with_address_checker(tx, rx, NoAddressChecker);
/// ```
pub struct TpUartLinkLayerBuilder<W, R, A = AutoAddressChecker> {
    uart_tx: W,
    uart_rx: R,
    address_checker: A,
}

impl<W, R> TpUartLinkLayerBuilder<W, R, AutoAddressChecker> {
    /// Create a builder with automatic address checking.
    ///
    /// The link layer will ACK frames addressed to the device's own
    /// individual address, group addresses in the loaded address table,
    /// and broadcasts. The checker is constructed from the stack context
    /// at build time.
    pub fn new(uart_tx: W, uart_rx: R) -> Self {
        Self { uart_tx, uart_rx, address_checker: AutoAddressChecker }
    }
}

impl<W, R, A: AddressChecker> TpUartLinkLayerBuilder<W, R, A> {
    /// Create a builder with a custom [`AddressChecker`].
    pub fn with_address_checker(uart_tx: W, uart_rx: R, address_checker: A) -> Self {
        Self { uart_tx, uart_rx, address_checker }
    }
}

/// Resources for the TPUART link layer.
///
/// Empty — TPUART needs no pre-allocated resources beyond the UART itself.
pub struct TpUartResources;

// -- LinkLayerBuilderBase for explicit AddressChecker --------------------------

impl<W: Send + 'static, R: Send + 'static, A: AddressChecker + Send + 'static> super::super::LinkLayerBuilderBase
    for TpUartLinkLayerBuilder<W, R, A>
{
    type Resources = TpUartResources;

    fn create_resources(&self) -> Self::Resources {
        TpUartResources
    }
}

impl<W: Send + 'static, R: Send + 'static, A: AddressChecker + Send + 'static> super::super::LinkLayerCapabilities
    for TpUartLinkLayerBuilder<W, R, A>
{
}

impl<CTX, W, R, A> super::super::LinkLayerBuilder<CTX> for TpUartLinkLayerBuilder<W, R, A>
where
    CTX: LinkLayerBufferContext + MaxRetryCountContext,
    W: embedded_io_async::Write + Send + 'static,
    R: embedded_io_async::Read + Send + 'static,
    A: AddressChecker + Send + 'static,
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
        let mut ll = TpUartLinkLayer::with_address_checker(
            self.uart_tx,
            self.uart_rx,
            context,
            ind_tx,
            conf_tx,
            self.address_checker,
        );
        // Apply PID_MAX_RETRY_COUNT from device state to the chip's retry config.
        // PID 52 format: busy_retry bits 6-4, nak_retry bits 2-0.
        let mrc = context.max_retry_count();
        ll.set_retry_config(RetryConfig::new(mrc & 0x07, (mrc >> 4) & 0x07));
        async move { ll.run(req_rx).await }
    }
}

// -- LinkLayerBuilderBase/Builder for AutoAddressChecker ----------------------
//
// AutoAddressChecker is NOT an AddressChecker — it's a marker that tells the
// builder to construct a DeviceAddressChecker from the context at build time.
// This requires the context to provide KnxIndividualAddressContext (individual address)
// and AddressTableContext (group address table).

impl<W: Send + 'static, R: Send + 'static> super::super::LinkLayerBuilderBase
    for TpUartLinkLayerBuilder<W, R, AutoAddressChecker>
{
    type Resources = TpUartResources;

    fn create_resources(&self) -> Self::Resources {
        TpUartResources
    }
}

impl<W: Send + 'static, R: Send + 'static> super::super::LinkLayerCapabilities
    for TpUartLinkLayerBuilder<W, R, AutoAddressChecker>
{
}

impl<CTX, W, R> super::super::LinkLayerBuilder<CTX> for TpUartLinkLayerBuilder<W, R, AutoAddressChecker>
where
    CTX: TpuartContext,
    W: embedded_io_async::Write + Send + 'static,
    R: embedded_io_async::Read + Send + 'static,
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
        let checker = DeviceAddressChecker::new(context, context.address_table());
        let mut ll =
            TpUartLinkLayer::with_address_checker(self.uart_tx, self.uart_rx, context, ind_tx, conf_tx, checker);
        // Apply PID_MAX_RETRY_COUNT from device state to the chip's retry config.
        // PID 52 format: busy_retry bits 6-4, nak_retry bits 2-0.
        let mrc = context.max_retry_count();
        ll.set_retry_config(RetryConfig::new(mrc & 0x07, (mrc >> 4) & 0x07));
        async move { ll.run(req_rx).await }
    }
}

// ============================================================================
// Link Layer
// ============================================================================

/// TPUART Link Layer
///
/// Handles communication with TPUART-compatible transceiver chips for KNX TP1.
pub struct TpUartLinkLayer<'a, W, R, A = NoAddressChecker>
where
    W: embedded_io_async::Write,
    R: embedded_io_async::Read,
    A: AddressChecker,
{
    // Hardware interface (split for concurrent TX/RX in the event loop)
    uart_tx: W,
    uart_rx: R,

    // Stack context — provides buffer allocation and max APDU length management.
    context: &'a dyn LinkLayerBufferContext,

    // Upper layer channels — indications and confirmations flow UP to NL
    ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
    conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,

    // State machines
    main_ctx: StateMachineContext,
    send_ctx: SendContext,

    retry_config: RetryConfig,

    // ACK decision — the checker owns all address-matching logic (individual,
    // group, broadcast). Different checkers implement different policies.
    address_checker: A,

    // Receive buffer
    receive_buffer: Option<Buffer<'static>>,

    // Transmission state
    pending_tx: Option<PendingTransmission>,
    current_tx: Option<CurrentTransmission>,

    // Timeout tracking — main and send state machines use independent deadlines
    // so that a receive inter-byte timeout doesn't kill the send echo wait.
    timeout_deadline: Option<Instant>,
    send_timeout_deadline: Option<Instant>,

    // Previous control byte for repeat detection
    prev_control_byte: u8,
}

/// Pending transmission waiting for link layer to become idle
struct PendingTransmission {
    buffer: Buffer<'static>,
}

/// Current active transmission
struct CurrentTransmission {
    /// Original KNX format buffer
    knx_buffer: Buffer<'static>,
    /// TP1 format buffer (with checksum)
    tp1_buffer: Buffer<'static>,
}

impl<'a, W, R> TpUartLinkLayer<'a, W, R, NoAddressChecker>
where
    W: embedded_io_async::Write,
    R: embedded_io_async::Read,
{
    /// Create a TPUART link layer with [`NoAddressChecker`] (ACKs nothing).
    ///
    /// Useful for bus monitor mode or testing. For normal device operation,
    /// use [`with_address_checker`](Self::with_address_checker) with a
    /// [`DeviceAddressChecker`].
    pub fn new(
        uart_tx: W,
        uart_rx: R,
        context: &'a dyn LinkLayerBufferContext,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
    ) -> Self {
        Self::with_address_checker(uart_tx, uart_rx, context, ind_tx, conf_tx, NoAddressChecker)
    }
}

impl<'a, W, R, A> TpUartLinkLayer<'a, W, R, A>
where
    W: embedded_io_async::Write,
    R: embedded_io_async::Read,
    A: AddressChecker,
{
    /// Create a TPUART link layer with a custom [`AddressChecker`].
    ///
    /// The checker is called for every incoming frame header to decide
    /// whether to send `U_ACK_INF`. See [`AddressChecker`] for the
    /// available implementations.
    pub fn with_address_checker(
        uart_tx: W,
        uart_rx: R,
        context: &'a dyn LinkLayerBufferContext,
        ind_tx: DynamicSender<'a, IndicationMessage<Buffer<'static>>>,
        conf_tx: DynamicSender<'a, ConfirmationMessage<Buffer<'static>>>,
        address_checker: A,
    ) -> Self {
        Self {
            uart_tx,
            uart_rx,
            context,
            ind_tx,
            conf_tx,
            main_ctx: StateMachineContext::new(),
            send_ctx: SendContext::new(),
            retry_config: RetryConfig::default(),
            address_checker,
            receive_buffer: None,
            pending_tx: None,
            current_tx: None,
            timeout_deadline: None,
            send_timeout_deadline: None,
            prev_control_byte: 0xFF,
        }
    }

    /// Set the retry configuration
    pub fn set_retry_config(&mut self, config: RetryConfig) {
        self.retry_config = config;
    }

    /// Write bytes to the UART, logging them at trace level.
    async fn uart_write(&mut self, bytes: &[u8]) {
        trace!("TPUART TX: {:?}", zweidraehte_util::fmt::Bytes(bytes));
        let _ = self.uart_tx.write_all(bytes).await;
    }

    /// Check if the bus is operational
    pub fn is_bus_ok(&self) -> bool {
        self.main_ctx.is_bus_ok()
    }

    /// Check if the bus has failed
    pub fn is_bus_failed(&self) -> bool {
        self.main_ctx.is_bus_failed()
    }

    /// Get the detected chip type
    pub fn chip_type(&self) -> ChipType {
        self.main_ctx.chip_type
    }

    /// Get the maximum APDU length supported by the detected chip
    ///
    /// This value should be used to update the stack state after initialization
    /// so that PID 56 (MAX_APDU_LENGTH) reports the correct hardware capability.
    ///
    /// Returns:
    /// - 56 for TPUART1/2 (64 byte buffer - 8 bytes overhead)
    /// - 248 for NCN5120/E981 (256 byte buffer - 8 bytes overhead)
    pub fn max_apdu_length(&self) -> u16 {
        self.main_ctx.chip_type.max_apdu_length()
    }

    /// Check if the chip supports register read operations (E981 only)
    pub fn supports_register_read(&self) -> bool {
        self.main_ctx.chip_type.supports_register_access()
    }

    /// Check if the chip supports register write operations (E981 and NCN5120)
    pub fn supports_register_write(&self) -> bool {
        matches!(self.main_ctx.chip_type, ChipType::E981 | ChipType::Ncn5120)
    }

    /// Read a register from the E981 chip
    ///
    /// This method can only be called when the layer is in the Idle state.
    /// Returns `None` if the chip doesn't support register read, is not idle,
    /// or if the read times out.
    ///
    /// # Arguments
    /// * `address` - The 16-bit register address to read
    ///
    /// # Returns
    /// * `Some(value)` - The register value on success
    /// * `None` - On failure (unsupported chip, busy, or timeout)
    pub async fn read_register(&mut self, address: u16) -> Option<u8> {
        // Only E981 supports register read
        if self.main_ctx.chip_type != ChipType::E981 {
            return None;
        }

        // Must be in Idle state
        if self.main_ctx.main_state != MainState::Idle {
            return None;
        }

        // Trigger the register read
        let actions = process_main_event(&mut self.main_ctx, MainEvent::ReadRegister { address });
        self.execute_main_actions(actions).await;

        // Wait for response
        while self.main_ctx.main_state == MainState::WaitRegRes {
            let mut buf = [0u8];

            let timeout_future = async {
                if let Some(deadline) = self.timeout_deadline {
                    Timer::at(deadline).await;
                    true
                } else {
                    core::future::pending::<bool>().await
                }
            };

            match embassy_futures::select::select(timeout_future, self.uart_rx.read(&mut buf)).await {
                embassy_futures::select::Either::First(_) => {
                    // Timeout
                    let actions = process_main_event(&mut self.main_ctx, MainEvent::Timer);
                    self.execute_main_actions(actions).await;
                }
                embassy_futures::select::Either::Second(result) => {
                    if result.is_ok() {
                        let actions = process_main_event(&mut self.main_ctx, MainEvent::ReceivedByte(buf[0]));
                        self.execute_main_actions(actions).await;
                    } else {
                        let actions = process_main_event(&mut self.main_ctx, MainEvent::ReceiveError);
                        self.execute_main_actions(actions).await;
                    }
                }
            }
        }

        // Check if read was successful
        if self.main_ctx.reg_read_state.received_bytes >= self.main_ctx.reg_read_state.expected_bytes {
            Some(self.main_ctx.reg_read_state.value)
        } else {
            None
        }
    }

    /// Write a register value to the E981 or NCN5120 chip
    ///
    /// This is a fire-and-forget operation. The chip does not send a response.
    ///
    /// # Arguments
    /// * `address` - The register address (8-bit for NCN5120, 16-bit for E981)
    /// * `value` - The value to write
    ///
    /// # Returns
    /// * `true` - If the write command was sent
    /// * `false` - If the chip doesn't support register write
    pub async fn write_register(&mut self, address: u16, value: u8) -> bool {
        // Must be in Idle state and support register write
        if self.main_ctx.main_state != MainState::Idle {
            return false;
        }

        let actions = process_main_event(&mut self.main_ctx, MainEvent::WriteRegister { address, value });

        // Check if the action includes a write command (not RegisterOperationFailed)
        let has_write_action = actions
            .iter()
            .any(|a| matches!(a, MainAction::SendE981RegWrite { .. } | MainAction::SendNcn5120RegWrite { .. }));

        self.execute_main_actions(actions).await;
        has_write_action
    }

    /// Write a register value to the E981 chip with a 16-bit address
    ///
    /// This is a fire-and-forget operation. The chip does not send a response.
    /// Use this method when you need the full 16-bit address space of the E981.
    ///
    /// # Arguments
    /// * `address` - The 16-bit register address
    /// * `value` - The value to write
    ///
    /// # Returns
    /// * `true` - If the write command was sent
    /// * `false` - If the chip is not E981 or not idle
    pub async fn write_register_e981(&mut self, address: u16, value: u8) -> bool {
        // Must be E981 and in Idle state
        if self.main_ctx.chip_type != ChipType::E981 || self.main_ctx.main_state != MainState::Idle {
            return false;
        }

        // Send E981 register write directly
        let buf = [E981_REG_WRITE_REQ, (address >> 8) as u8, (address & 0xFF) as u8, value];
        self.uart_write(&buf).await;

        // Reset keepalive timer
        self.timeout_deadline = Some(Instant::now() + TIMEOUT_KEEPALIVE);
        true
    }

    // ========================================================================
    // Action Execution
    // ========================================================================

    /// Execute actions returned by the main state machine
    async fn execute_main_actions(&mut self, actions: ActionBuffer) {
        for action in actions.iter().copied() {
            match action {
                MainAction::StartTimer(duration) => {
                    self.timeout_deadline = Some(Instant::now() + duration);
                }
                MainAction::StopTimer => {
                    self.timeout_deadline = None;
                }
                MainAction::SendByte(byte) => {
                    self.uart_write(&[byte]).await;
                }
                MainAction::AllocReceiveBuffer => {
                    let buffer = self.context.buffer_manager().alloc().await;
                    self.receive_buffer = Some(buffer);
                }
                MainAction::StoreReceivedByte(byte) => {
                    if let Some(buf) = self.receive_buffer.as_mut() {
                        buf.push(byte);
                    }
                }
                MainAction::ReleaseReceiveBuffer => {
                    self.receive_buffer = None;
                }
                MainAction::ClearReceiveState => {
                    self.main_ctx.receive_state.reset();
                }
                MainAction::ParseHeaderAndCheckAck => {
                    // Parse header and decide on ACK after 6 bytes received
                    // Extract header bytes first to avoid borrow issues
                    let header: Option<[u8; 6]> = self.receive_buffer.as_ref().and_then(|buf| {
                        if buf.len() >= 6 {
                            let mut h = [0u8; 6];
                            h.copy_from_slice(&buf[..6]);
                            Some(h)
                        } else {
                            None
                        }
                    });
                    if let Some(h) = header {
                        self.parse_header_and_check_ack(&h).await;
                    }
                }
                MainAction::SendAck => {
                    self.uart_write(&[U_ACK_INF]).await;
                }
                MainAction::SendNack => {
                    self.uart_write(&[U_NACK_INF]).await;
                }
                MainAction::SendBusy => {
                    self.uart_write(&[U_BUSY_INF]).await;
                }
                MainAction::IndicationToNetwork => {
                    if let Some(mut buffer) = self.receive_buffer.take() {
                        // Validate checksum
                        if validate_tp1_checksum(&buffer[..]) {
                            // Strip the check octet and convert TP1 to KNX format.
                            // Checksum already validated above, so use the no-checksum
                            // variant to avoid redundant validation.
                            let new_len = buffer.len() - 1;
                            buffer.set_len(new_len);
                            let knx_buffer = tp1_to_knx_message_no_checksum(buffer);

                            // Internal format: ctrl(1) + src(2) + dst(2) + npdu(1) + tpci/apdu...
                            // The NPDU length (TPCI + APDU bytes) is everything past the 6-byte header.
                            let npdu_length = knx_buffer.len().saturating_sub(6);
                            if npdu_length as u16 > self.main_ctx.chip_type.max_apdu_length() {
                                warn!(
                                    "TPUART: NPDU length {} exceeds chip maximum {} - dropping frame",
                                    npdu_length,
                                    self.main_ctx.chip_type.max_apdu_length()
                                );
                            } else {
                                let msg = KnxMessageBuffer::new(knx_buffer, ServiceType::L_Data_Ind);
                                let indication = IndicationMessage::indication(msg);
                                self.ind_tx.send(indication).await;
                            }
                        } else {
                            warn!("TPUART: Invalid checksum on received frame");
                        }
                    }
                }
                MainAction::ConfirmationToNetwork { success } => {
                    self.complete_transmission(success).await;
                }
                MainAction::SetChipType(chip_type) => {
                    debug!("TPUART: Detected chip type: {:?}", chip_type);
                }
                MainAction::SetChipVersion(version) => {
                    debug!("TPUART: Chip version: {}", version);
                }
                MainAction::IncrementResetCounter => {
                    self.main_ctx.reset_counter = self.main_ctx.reset_counter.saturating_add(1);
                }
                MainAction::ResetBusFailureCounter => {
                    self.main_ctx.reset_counter = 0;
                }
                MainAction::StoreControlByte(byte) => {
                    self.prev_control_byte = byte;
                }
                MainAction::MarkAsRepeatedFrame => {
                    self.main_ctx.receive_state.is_repeated = true;
                }
                MainAction::ClearRepeatedFlag => {
                    self.main_ctx.receive_state.is_repeated = false;
                }
                MainAction::MarkFrameInvalid => {
                    // Mark frame as invalid (control = 0xFF) so it won't be processed
                    self.main_ctx.receive_state.control_byte = 0xFF;
                }
                MainAction::SendSmFrameStart => {
                    // Check if this is an echo of our transmission
                    if let Some(ref tx) = self.current_tx
                        && let Some(ref buf) = self.receive_buffer
                        && buf.len() >= 4
                        && self.is_echo(&tx.tp1_buffer, buf)
                    {
                        self.main_ctx.receive_state.is_echo = true;
                        let actions =
                            process_send_event(&mut self.send_ctx, SendEvent::FrameStartReceived { is_echo: true });
                        self.execute_send_actions(actions).await;
                    }
                }
                MainAction::SendSmFrameComplete => {
                    let actions = process_send_event(&mut self.send_ctx, SendEvent::EchoReceived);
                    self.execute_send_actions(actions).await;
                }
                MainAction::SendSmConfirmation { ack } => {
                    let actions = process_send_event(&mut self.send_ctx, SendEvent::Confirmation { ack });
                    self.execute_send_actions(actions).await;
                }
                MainAction::ResetSendStateMachine => {
                    // Reset send state machine due to error (e.g., U_State.ind with error flags).
                    // complete_transmission sends L_Data.con(err) and resets send_ctx, so the
                    // transport layer isn't left waiting forever for a confirmation that will
                    // never arrive.
                    debug!("TPUART: Send state machine reset due to error");
                    self.complete_transmission(false).await;
                }
                MainAction::ConfigureRetryCounts => {
                    let buf = [U_MAX_RST_CNT, self.retry_config.encode()];
                    self.uart_write(&buf).await;
                }
                MainAction::SendStateRequest => {
                    self.uart_write(&[U_STATE_REQ]).await;
                }
                MainAction::SendVersionRequest => {
                    self.uart_write(&[U_VERSION_REQ]).await;
                }
                MainAction::SendNcn5120SysStateRequest => {
                    // Wire order must be: U_VERSION_REQ first, then NCN5120_SYS_STATE_REQ.
                    // The LIFO send buffer sends [1] before [0]).
                    // The NCN5120 ignores 0x20 (undefined command, triggers protocol error)
                    // but responds to 0x0D with U_SystemStat.ind (0x4B + status).
                    // A TPUART2 would instead respond to 0x20 with a version indication.
                    self.uart_write(&[U_VERSION_REQ, NCN5120_SYS_STATE_REQ]).await;
                }
                MainAction::InitComplete => {
                    info!("TPUART: Initialization complete, chip: {}", self.main_ctx.chip_type.name());
                }
                MainAction::SendE981RegRead { address } => {
                    // E981 register read: 3 bytes (cmd, addr_hi, addr_lo)
                    let buf = [E981_REG_READ_REQ, (address >> 8) as u8, (address & 0xFF) as u8];
                    self.uart_write(&buf).await;
                }
                MainAction::SendE981RegWrite { address, value } => {
                    // E981 register write: 4 bytes (cmd, addr_hi, addr_lo, value)
                    let buf = [E981_REG_WRITE_REQ, (address >> 8) as u8, (address & 0xFF) as u8, value];
                    self.uart_write(&buf).await;
                }
                MainAction::SendNcn5120RegWrite { address, value } => {
                    // NCN5120 register write: 2 bytes (cmd | addr, value)
                    // Address is in lower 3 bits of command
                    let buf = [NCN5120_REG_WRITE_REQ | (address & 0x07), value];
                    self.uart_write(&buf).await;
                }
                MainAction::RegisterReadComplete { value } => {
                    // Register read completed - this is handled by the async read_register method
                    trace!("TPUART: Register read complete, value: 0x{:02X}", value);
                }
                MainAction::RegisterOperationFailed => {
                    // Register operation failed - this is handled by the async read_register method
                    trace!("TPUART: Register operation failed");
                }
            }
        }
    }

    /// Execute actions returned by the send state machine
    async fn execute_send_actions(&mut self, actions: SendActionBuffer) {
        for action in actions.iter().copied() {
            match action {
                SendAction::SendByte { index, is_last } => {
                    if let Some(ref tx) = self.current_tx
                        && index < tx.tp1_buffer.len()
                    {
                        let byte = tx.tp1_buffer[index];
                        let is_long_frame = tx.tp1_buffer.len() > 64;

                        match self.main_ctx.chip_type {
                            // E981: Uses special long frame commands for frames >64 bytes
                            ChipType::E981 if is_long_frame => {
                                if index == 0 {
                                    // First byte: normal start command
                                    self.uart_write(&[U_L_DATA_START, byte]).await;
                                } else if is_last {
                                    // Last byte: E981_LONG_DATA_END + full index
                                    self.uart_write(&[E981_LONG_DATA_END, index as u8, byte]).await;
                                } else {
                                    // Middle bytes: E981_LONG_DATA_CONTINUE + full index
                                    self.uart_write(&[E981_LONG_DATA_CONTINUE, index as u8, byte]).await;
                                }
                            }

                            // NCN5120: Uses offset command at 64-byte boundaries
                            ChipType::Ncn5120 if is_long_frame => {
                                // Send offset command at each 64-byte boundary (except 0)
                                if (index & 0x3F) == 0 && index > 0 {
                                    let offset_cmd = U_L_DATA_OFFSET_REQ | (index >> 6) as u8;
                                    self.uart_write(&[offset_cmd]).await;
                                }
                                // Normal start/end with 6-bit index
                                let cmd = if is_last {
                                    U_L_DATA_END | (index & 0x3F) as u8
                                } else {
                                    U_L_DATA_START | (index & 0x3F) as u8
                                };
                                self.uart_write(&[cmd, byte]).await;
                            }

                            // Standard frame (<=64 bytes) or TPUART1/2
                            _ => {
                                let cmd = if is_last {
                                    U_L_DATA_END | (index & 0x3F) as u8
                                } else {
                                    U_L_DATA_START | (index & 0x3F) as u8
                                };
                                self.uart_write(&[cmd, byte]).await;
                            }
                        }
                    }
                }
                SendAction::StartSendTimer => {
                    self.send_timeout_deadline = Some(Instant::now() + TIMEOUT_SEND);
                }
                SendAction::StopSendTimer => {
                    self.send_timeout_deadline = None;
                }
                SendAction::TransmissionComplete { success } => {
                    self.complete_transmission(success).await;
                }
                SendAction::FrameSendingComplete => {
                    // All bytes sent to TPUART, waiting for echo
                }
            }
        }
    }

    /// Complete the current transmission
    async fn complete_transmission(&mut self, success: bool) {
        if let Some(tx) = self.current_tx.take() {
            let mut msg = KnxMessageBuffer::new(tx.knx_buffer, ServiceType::L_Data_Con);
            if success {
                msg.ctrl_field_mut().set_c(Confirm::NoError);
            } else {
                msg.ctrl_field_mut().set_c(Confirm::Err);
            }
            let confirmation = ConfirmationMessage::confirmation(msg);
            self.conf_tx.send(confirmation).await;
        }
        self.send_ctx.reset();
    }

    /// Check if received bytes match our transmitted frame (echo detection)
    fn is_echo(&self, tx_buf: &Buffer<'static>, rx_buf: &Buffer<'static>) -> bool {
        if rx_buf.len() < 4 || tx_buf.len() < 4 {
            return false;
        }
        // Compare control byte (ignoring repeat bit) and source/dest addresses
        ((rx_buf[0] ^ tx_buf[0]) & !0x20) == 0 && rx_buf[1..4] == tx_buf[1..4]
    }

    /// Calculate expected frame length from received header
    fn parse_frame_header(&mut self) {
        let (is_extended, byte5, byte6) = if let Some(ref buf) = self.receive_buffer {
            let is_extended = self.main_ctx.receive_state.is_extended;
            let min_header = if is_extended { 8 } else { 7 };
            if buf.len() < min_header {
                return;
            }
            (is_extended, buf[5], buf[6])
        } else {
            return;
        };

        let expected_len = if is_extended {
            // Extended frame: length at byte 7, plus header and checksum
            byte6 as usize + 9
        } else {
            // Standard frame: length in lower 4 bits of byte 6
            (byte5 & 0x0F) as usize + 8
        };

        self.main_ctx.receive_state.expected_len = Some(expected_len);

        // Check for echo
        let is_echo = if let (Some(tx), Some(buf)) = (&self.current_tx, &self.receive_buffer) {
            self.is_echo(&tx.tp1_buffer, buf)
        } else {
            false
        };

        if is_echo {
            self.main_ctx.receive_state.is_echo = true;
        }
    }

    /// Parse the frame header (after 6 bytes received) and decide on ACK
    ///
    /// This function:
    /// 1. Parses the control byte to determine frame format (standard vs extended)
    /// 2. Extracts destination address (bytes 3-4)
    /// 3. Checks if it's a group address (byte 5 bit 7)
    /// 4. For group addresses: checks address table and sends ACK if found
    /// 5. Updates expected frame length in receive_state
    /// 6. Checks if this is an echo of our transmission
    async fn parse_header_and_check_ack(&mut self, header: &[u8; 6]) {
        let ctrl = header[0];

        // Determine frame format from control byte
        // Standard frame: bit 7 = 1, extended frame: bit 7 = 0
        let is_extended = (ctrl & 0x80) == 0;
        self.main_ctx.receive_state.is_extended = is_extended;
        self.main_ctx.receive_state.control_byte = ctrl;

        // Check if this is an echo of our transmission using all 6 header bytes
        // (ctrl + src(2) + dst(2) + routing).  The earlier 4-byte check in
        // `SendSmFrameStart` runs when only ctrl+addr have arrived; this
        // 6-byte version runs here, after the full header is buffered, to
        // confirm the match before we decide on ACK.
        if let Some(ref tx) = self.current_tx
            && tx.tp1_buffer.len() >= 6
        {
            let tx_buf = &tx.tp1_buffer;
            let ctrl_match = ((header[0] ^ tx_buf[0]) & !0x20) == 0;
            let addr_match = header[1..6] == tx_buf[1..6];
            if ctrl_match && addr_match {
                debug!("TPUART: echo detected, skipping ACK");
                self.main_ctx.receive_state.is_echo = true;
                // Don't ACK our own echoes
                return;
            }
        }

        // Delegate the full ACK decision to the address checker. Different
        // checkers implement different policies (normal device, tunneling
        // gateway, bus monitor). The link layer doesn't have its own opinion.
        let (dst_hi, dst_lo, is_group) = extract_tp1_header_fields(header);
        let dst = IndividualAddress::from_bytes(&[dst_hi, dst_lo]);
        if self.address_checker.should_ack(header) {
            debug!("TPUART: ACK frame dst={} group={}", dst, is_group);
            self.uart_write(&[U_ACK_INF]).await;
            self.main_ctx.receive_state.acked = true;
        } else {
            debug!("TPUART: no ACK for dst={} group={}", dst, is_group);
        }
    }

    /// Start a new transmission
    async fn start_transmission(&mut self, msg: Buffer<'static>) {
        // Check frame size
        let tp1_size = self.calculate_tp1_frame_size(&msg);
        if tp1_size > self.main_ctx.chip_type.max_frame_size() {
            // Frame too large
            warn!("TPUART: Frame too large ({} > {})", tp1_size, self.main_ctx.chip_type.max_frame_size());
            let mut error_msg = KnxMessageBuffer::new(msg, ServiceType::L_Data_Con);
            error_msg.ctrl_field_mut().set_c(Confirm::Err);
            self.conf_tx.send(ConfirmationMessage::confirmation(error_msg)).await;
            return;
        }

        // Allocate buffer for TP1 format and copy data
        let mut tp1_buf = self.context.buffer_manager().alloc().await;
        for &byte in &msg[..] {
            tp1_buf.push(byte);
        }

        // Convert KNX format to TP1 wire format (including check octet).
        let tp1_buffer = knx_to_tp1_message(tp1_buf);

        self.send_ctx.total_bytes = tp1_buffer.len();
        self.current_tx = Some(CurrentTransmission { knx_buffer: msg, tp1_buffer });

        // Start transmission
        let actions = process_send_event(&mut self.send_ctx, SendEvent::StartTransmission);
        self.execute_send_actions(actions).await;
    }

    /// Calculate TP1 frame size without converting
    fn calculate_tp1_frame_size(&self, knx_msg: &Buffer<'static>) -> usize {
        let len = knx_msg.len();
        // Check for standard frame: length <= 23 and lower 4 bits of NPDU are 0
        if len < 23 && (knx_msg[5] & 0x0F) == 0 {
            len + 1 // Standard: same size + checksum
        } else {
            len + 2 // Extended: +1 for extended control + checksum
        }
    }

    /// Queue a frame for transmission
    async fn queue_transmission(&mut self, msg: Buffer<'static>) {
        // If idle and nothing pending, start immediately
        if self.main_ctx.main_state == MainState::Idle && self.pending_tx.is_none() && self.current_tx.is_none() {
            self.start_transmission(msg).await;
            return;
        }

        // Replace any pending transmission — send error confirmation for the displaced one
        if let Some(old) = self.pending_tx.take() {
            let mut error_msg = KnxMessageBuffer::new(old.buffer, ServiceType::L_Data_Con);
            error_msg.ctrl_field_mut().set_c(Confirm::Err);
            self.conf_tx.send(ConfirmationMessage::confirmation(error_msg)).await;
        }

        self.pending_tx = Some(PendingTransmission { buffer: msg });
    }

    /// Check and start pending transmission if idle
    async fn check_pending_transmission(&mut self) {
        if self.main_ctx.main_state == MainState::Idle
            && self.current_tx.is_none()
            && let Some(pending) = self.pending_tx.take()
        {
            self.start_transmission(pending.buffer).await;
        }
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initialize the TPUART transceiver (chip detection, reset sequence).
    ///
    /// After chip detection, the hardware's max APDU length is propagated
    /// to the stack state via [`ApduLengthContext::set_max_apdu_length()`](crate::context::ApduLengthContext::set_max_apdu_length).
    async fn initialize(&mut self) {
        // Start initial timer to trigger reset sequence
        self.timeout_deadline = Some(Instant::now() + TIMEOUT_RESET);

        // Process initial timer event
        let actions = process_main_event(&mut self.main_ctx, MainEvent::Timer);
        self.execute_main_actions(actions).await;

        // Wait for initialization to complete
        while !matches!(self.main_ctx.main_state, MainState::Idle | MainState::Error) {
            let mut buf = [0u8];

            let timeout_future = async {
                if let Some(deadline) = self.timeout_deadline {
                    Timer::at(deadline).await;
                    true
                } else {
                    // No timeout, wait forever (will never complete)
                    core::future::pending::<bool>().await
                }
            };

            match embassy_futures::select::select(timeout_future, self.uart_rx.read(&mut buf)).await {
                embassy_futures::select::Either::First(_) => {
                    // Timeout
                    let actions = process_main_event(&mut self.main_ctx, MainEvent::Timer);
                    self.execute_main_actions(actions).await;
                }
                embassy_futures::select::Either::Second(result) => {
                    if result.is_ok() {
                        trace!("TPUART RX: 0x{:02X}", buf[0]);
                        let actions = process_main_event(&mut self.main_ctx, MainEvent::ReceivedByte(buf[0]));
                        self.execute_main_actions(actions).await;
                    } else {
                        let actions = process_main_event(&mut self.main_ctx, MainEvent::ReceiveError);
                        self.execute_main_actions(actions).await;
                    }
                }
            }
        }

        if self.main_ctx.main_state == MainState::Error {
            error!("TPUART: Initialization failed");
        }

        // Propagate the detected chip's max APDU length to the stack state
        // so that PID 56 (MAX_APDU_LENGTH) reports the actual hardware capability.
        let hw_max = self.main_ctx.chip_type.max_apdu_length();
        info!("TPUART: Chip {:?}, max APDU length: {} bytes", self.main_ctx.chip_type, hw_max);
        self.context.set_max_apdu_length(hw_max);
    }
}

// ============================================================================
// Event Loop
// ============================================================================

impl<'a, W, R, A> TpUartLinkLayer<'a, W, R, A>
where
    W: embedded_io_async::Write,
    R: embedded_io_async::Read,
    A: AddressChecker,
{
    /// Run the TPUART link layer event loop.
    ///
    /// Initializes the transceiver (chip detection, reset), propagates the
    /// detected max APDU length to the stack state, then enters the main
    /// event loop. Receives request messages from the network layer via
    /// `req_rx`, sends indications and confirmations up via `self.ind_tx`
    /// / `self.conf_tx`.
    pub async fn run(&mut self, mut req_rx: impl Inbox<RequestMessage<Buffer<'static>>>) -> ! {
        self.initialize().await;
        loop {
            let mut buf = [0u8];

            // Compute the earliest deadline across both state machines.
            // We track which ones fired so we dispatch to the correct SM.
            let earliest_deadline = match (self.timeout_deadline, self.send_timeout_deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };

            let timeout_future = async {
                if let Some(deadline) = earliest_deadline {
                    Timer::at(deadline).await;
                } else {
                    core::future::pending::<()>().await
                }
            };

            // Send pump: resolves immediately when there are frame bytes to
            // transmit, stays pending otherwise. This replaces the hardware
            // TX-complete interrupt — we yield
            // back into the select so RX bytes are still processed between TX
            // byte pairs, preventing the send loop from starving reception.
            let send_ready_future = async {
                if self.send_ctx.state == SendState::Sending {
                    embassy_futures::yield_now().await;
                } else {
                    core::future::pending::<()>().await
                }
            };

            match select4(timeout_future, self.uart_rx.read(&mut buf), req_rx.next(), send_ready_future).await {
                Either4::First(_) => {
                    // Timer fired — dispatch to the state machine(s) whose
                    // deadline has been reached. The main and send SMs use
                    // independent deadlines so that e.g. a receive inter-byte
                    // timeout doesn't kill the send echo wait.
                    let now = Instant::now();

                    if self.timeout_deadline.is_some_and(|d| now >= d) {
                        trace!("TPUART: Timeout");
                        let actions = process_main_event(&mut self.main_ctx, MainEvent::Timer);
                        self.execute_main_actions(actions).await;
                    }

                    if self.send_timeout_deadline.is_some_and(|d| now >= d) {
                        trace!("TPUART: Send timeout");
                        self.send_timeout_deadline = None;
                        let send_actions = process_send_event(&mut self.send_ctx, SendEvent::Timeout);
                        self.execute_send_actions(send_actions).await;
                    }
                }
                Either4::Second(result) => {
                    match result {
                        Ok(_) => {
                            trace!("TPUART RX: 0x{:02X}", buf[0]);
                            let actions = process_main_event(&mut self.main_ctx, MainEvent::ReceivedByte(buf[0]));
                            self.execute_main_actions(actions).await;

                            // Parse header after receiving enough bytes
                            if self.main_ctx.main_state == MainState::ReceiveFrame {
                                self.parse_frame_header();
                            }
                        }
                        Err(_) => {
                            let actions = process_main_event(&mut self.main_ctx, MainEvent::ReceiveError);
                            self.execute_main_actions(actions).await;
                        }
                    }
                }
                Either4::Third(msg) => {
                    match msg.service_type() {
                        ServiceType::L_Data_Req => {
                            self.queue_transmission(msg.into_inner().into_inner()).await;
                        }
                        _ => {
                            // Unsupported service type — send error confirmation
                            self.conf_tx.send(msg.into_inner().error().build()).await;
                        }
                    }
                }
                Either4::Fourth(_) => {
                    // Send pump: transmit the next frame byte
                    let actions = process_send_event(&mut self.send_ctx, SendEvent::SendNextByte);
                    self.execute_send_actions(actions).await;
                }
            }

            // Check for pending transmission
            self.check_pending_transmission().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // extract_tp1_header_fields
    // =========================================================================

    #[test]
    fn standard_individual_frame() {
        // Standard frame to individual address 1.0.200 (0x10, 0xC8)
        // AT bit = 0 (individual), hop count = 6
        let header: [u8; 6] = [0xB0, 0x10, 0x02, 0x10, 0xC8, 0x60];
        let (dst_hi, dst_lo, is_group) = extract_tp1_header_fields(&header);
        assert_eq!(dst_hi, 0x10);
        assert_eq!(dst_lo, 0xC8);
        assert!(!is_group);
    }

    #[test]
    fn standard_group_frame() {
        // Standard frame to group address 1/2/3 (0x0A, 0x03)
        // AT bit = 1 (group), hop count = 6, length = 1
        let header: [u8; 6] = [0xB0, 0x10, 0x02, 0x0A, 0x03, 0xE1];
        let (dst_hi, dst_lo, is_group) = extract_tp1_header_fields(&header);
        assert_eq!(dst_hi, 0x0A);
        assert_eq!(dst_lo, 0x03);
        assert!(is_group);
    }

    #[test]
    fn extended_individual_frame() {
        // Extended frame to individual address 1.0.200 (0x10, 0xC8)
        // Ctrl byte bit 7 = 0 → extended frame
        // ExtCtrl: AT=0 (individual), hop count = 6, EFF = 0
        let header: [u8; 6] = [0x30, 0x60, 0x10, 0x02, 0x10, 0xC8];
        let (dst_hi, dst_lo, is_group) = extract_tp1_header_fields(&header);
        assert_eq!(dst_hi, 0x10);
        assert_eq!(dst_lo, 0xC8);
        assert!(!is_group);
    }

    #[test]
    fn extended_group_frame() {
        // Extended frame to group address 1/2/3 (0x0A, 0x03)
        // Ctrl byte bit 7 = 0 → extended frame
        // ExtCtrl: AT=1 (group), hop count = 6, EFF = 0
        let header: [u8; 6] = [0x30, 0xE0, 0x10, 0x02, 0x0A, 0x03];
        let (dst_hi, dst_lo, is_group) = extract_tp1_header_fields(&header);
        assert_eq!(dst_hi, 0x0A);
        assert_eq!(dst_lo, 0x03);
        assert!(is_group);
    }

    #[test]
    fn extended_frame_reproduces_bug_scenario() {
        // Reproduce the exact scenario from the bug trace:
        // ETS at 1.0.2 sends an extended frame to our device at 1.0.200
        // Without the fix, this was parsed as dst=0x02.0x10 (wrong)
        let header: [u8; 6] = [0x30, 0x60, 0x10, 0x02, 0x10, 0xC8];
        let (dst_hi, dst_lo, is_group) = extract_tp1_header_fields(&header);
        let dst = IndividualAddress::from_bytes(&[dst_hi, dst_lo]);
        assert_eq!(dst, IndividualAddress::from_bytes(&[0x10, 0xC8]));
        assert!(!is_group);
    }
}
