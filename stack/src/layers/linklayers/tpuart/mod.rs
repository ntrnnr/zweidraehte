//! TPUART Link Layer Implementation
//!
//! This module implements the KNX TP1 link layer using TPUART-compatible chips.
//!
//! ## Supported Chips
//!
//! - Siemens TPUART1 (legacy, 64 byte max frame)
//! - Siemens TPUART2 (64 byte max frame)
//! - ON Semiconductor NCN5120/5121/5130 (256 byte extended frames)
//! - Elmos E981.03 (256 byte extended frames)
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

use core::cell::RefCell;

use embassy_futures::select::{Either3, select3};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Instant, Timer};

use crate::{
    address::IndividualAddress,
    messages::{
        buffers::{Buffer, DynBufferManager, MessageBuffer},
        builder::{ConfirmationExt, ConfirmationMessage, IndicationMessage},
        knx::*,
    },
};

use super::super::{Inbox, Layer, LayerOp};

pub mod busmon;
mod chip;
mod state_machine;

use chip::{ChipType, RetryConfig};
use crate::encoding::tp1::{knx_to_tp1_message, tp1_to_knx_message};
use state_machine::*;

use crate::address::GroupAddress;

// Re-export for external use
pub use chip::ChipType as TpUartChipType;

/// Trait for checking if a group address should be acknowledged
///
/// This is used by the TPUART link layer to determine whether to send an ACK
/// for incoming frames addressed to group addresses. The link layer will call
/// this after receiving the destination address (byte 6) to decide whether to
/// acknowledge the frame.
///
/// # Implementation Notes
///
/// - Return `true` if the address is in the address table and the table is loaded
/// - Return `false` if the table is not loaded or the address is not found
/// - This is called synchronously during frame reception, so implementations
///   should be fast (e.g., using RefCell, not async)
///
/// # Example
///
/// ```ignore
/// use std::cell::RefCell;
///
/// struct MyAddressChecker<'a> {
///     addr_table: &'a RefCell<AddrTab7>,
/// }
///
/// impl AddressChecker for MyAddressChecker<'_> {
///     fn should_ack_group_address(&self, address: GroupAddress) -> bool {
///         let table = self.addr_table.borrow();
///         table.is_loaded() && table.contains(address)
///     }
/// }
/// ```
pub trait AddressChecker {
    /// Check if a group address should be acknowledged
    ///
    /// Returns `true` if the link layer should send an ACK for this group address.
    fn should_ack_group_address(&self, address: GroupAddress) -> bool;
}

/// A no-op address checker that never ACKs group addresses
///
/// This is used when no address table is configured, which means the device
/// will not ACK any group-addressed frames (only individually-addressed frames
/// matching our address will be ACKed via the TPUART hardware).
pub struct NoAddressChecker;

impl AddressChecker for NoAddressChecker {
    fn should_ack_group_address(&self, _address: GroupAddress) -> bool {
        false
    }
}

/// TPUART Link Layer
///
/// Handles communication with TPUART-compatible transceiver chips for KNX TP1.
pub struct TpUartLinkLayer<'a, U, A = NoAddressChecker>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
    A: AddressChecker,
{
    // Hardware interface
    uart: U,

    // Buffer management
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,

    // Upper layer connection
    network_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,

    // State machines
    main_ctx: StateMachineContext,
    send_ctx: SendContext,

    // Configuration
    individual_addr: Option<IndividualAddress>,
    retry_config: RetryConfig,

    // Group address ACK checker
    address_checker: A,

    // Receive buffer
    receive_buffer: Option<Buffer<'static>>,

    // Transmission state
    pending_tx: Option<PendingTransmission>,
    current_tx: Option<CurrentTransmission>,

    // Timeout tracking (using Instant for simplicity)
    timeout_deadline: Option<Instant>,

    // Previous control byte for repeat detection
    prev_control_byte: u8,
}

/// Pending transmission waiting for link layer to become idle
struct PendingTransmission {
    buffer: Buffer<'static>,
    response_tx: DynamicSender<'static, ConfirmationMessage<Buffer<'static>>>,
}

/// Current active transmission
struct CurrentTransmission {
    /// Original KNX format buffer
    knx_buffer: Buffer<'static>,
    /// TP1 format buffer (with checksum)
    tp1_buffer: Buffer<'static>,
    /// Channel to send confirmation
    response_tx: DynamicSender<'static, ConfirmationMessage<Buffer<'static>>>,
}

impl<'a, U> TpUartLinkLayer<'a, U, NoAddressChecker>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
{
    /// Create a new TPUART link layer without group address ACK support
    ///
    /// This creates a link layer that will not ACK group-addressed frames.
    /// Only individually-addressed frames matching the configured address
    /// will be ACKed (via TPUART hardware).
    ///
    /// Use [`with_address_checker`](Self::with_address_checker) if you need
    /// group address ACK support.
    pub fn new(
        uart: U,
        individual_addr: Option<IndividualAddress>,
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        network_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
    ) -> Self {
        Self::with_address_checker(uart, individual_addr, buffer_manager, network_layer, NoAddressChecker)
    }
}

impl<'a, U, A> TpUartLinkLayer<'a, U, A>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
    A: AddressChecker,
{
    /// Create a new TPUART link layer with group address ACK support
    ///
    /// The `address_checker` is called after receiving the destination address
    /// (byte 6) of incoming frames to determine whether to ACK group-addressed
    /// frames.
    pub fn with_address_checker(
        uart: U,
        individual_addr: Option<IndividualAddress>,
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        network_layer: DynamicSender<'a, LayerOp<Buffer<'static>>>,
        address_checker: A,
    ) -> Self {
        Self {
            uart,
            buffer_manager,
            network_layer,
            main_ctx: StateMachineContext::new(),
            send_ctx: SendContext::new(),
            individual_addr,
            retry_config: RetryConfig::default(),
            address_checker,
            receive_buffer: None,
            pending_tx: None,
            current_tx: None,
            timeout_deadline: None,
            prev_control_byte: 0xFF,
        }
    }

    /// Set the retry configuration
    pub fn set_retry_config(&mut self, config: RetryConfig) {
        self.retry_config = config;
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

            match embassy_futures::select::select(timeout_future, self.uart.read(&mut buf)).await {
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

        let actions = process_main_event(
            &mut self.main_ctx,
            MainEvent::WriteRegister { address, value },
        );

        // Check if the action includes a write command (not RegisterOperationFailed)
        let has_write_action = actions.iter().any(|a| {
            matches!(
                a,
                MainAction::SendE981RegWrite { .. } | MainAction::SendNcn5120RegWrite { .. }
            )
        });

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
        let buf = [
            E981_REG_WRITE_REQ,
            (address >> 8) as u8,
            (address & 0xFF) as u8,
            value,
        ];
        let _ = self.uart.write_all(&buf).await;

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
                    let _ = self.uart.write_all(&[byte]).await;
                }
                MainAction::AllocReceiveBuffer => {
                    let buffer = self.buffer_manager.borrow().alloc().await;
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
                    let _ = self.uart.write_all(&[U_ACK_INF]).await;
                }
                MainAction::SendNack => {
                    let _ = self.uart.write_all(&[U_NACK_INF]).await;
                }
                MainAction::SendBusy => {
                    let _ = self.uart.write_all(&[U_BUSY_INF]).await;
                }
                MainAction::IndicationToNetwork => {
                    if let Some(buffer) = self.receive_buffer.take() {
                        // Validate checksum
                        if validate_checksum(&buffer[..]) {
                            // Convert TP1 to KNX format and send indication
                            let knx_buffer = tp1_to_knx_message(buffer);
                            let msg = KnxMessageBuffer::new(knx_buffer, ServiceType::L_Data_Ind);
                            let indication = IndicationMessage::indication(msg);
                            self.network_layer.send(LayerOp::Indication(indication)).await;
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
                    if self.main_ctx.reset_counter < 255 {
                        self.main_ctx.reset_counter += 1;
                    }
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
                    // On error, the RX frame control field is set to 0xFF
                    self.main_ctx.receive_state.control_byte = 0xFF;
                }
                MainAction::SendSmFrameStart => {
                    // Check if this is an echo of our transmission
                    if let Some(ref tx) = self.current_tx {
                        if let Some(ref buf) = self.receive_buffer {
                            if buf.len() >= 4 && self.is_echo(&tx.tp1_buffer, buf) {
                                self.main_ctx.receive_state.is_echo = true;
                                let actions = process_send_event(&mut self.send_ctx, SendEvent::FrameStartReceived { is_echo: true });
                                self.execute_send_actions(actions).await;
                            }
                        }
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
                    // Reset send state machine due to error (e.g., U_State.ind with error flags)
                    // The send sequence state is reset to 0
                    self.send_ctx.reset();
                    // Also clear any pending transmission
                    if self.current_tx.is_some() {
                        self.current_tx = None;
                        // Notify caller of failure
                        debug!("TPUART: Send state machine reset due to error");
                    }
                }
                MainAction::ConfigureAddress => {
                    if let Some(addr) = self.individual_addr {
                        let mut buf = [U_SET_ADDRESS, 0x00, 0x00];
                        buf[1..].copy_from_slice(addr.as_bytes());
                        let _ = self.uart.write_all(&buf).await;
                    }
                }
                MainAction::ConfigureRetryCounts => {
                    let buf = [U_MAX_RST_CNT, self.retry_config.encode()];
                    let _ = self.uart.write_all(&buf).await;
                }
                MainAction::SendStateRequest => {
                    let _ = self.uart.write_all(&[U_STATE_REQ]).await;
                }
                MainAction::SendVersionRequest => {
                    let _ = self.uart.write_all(&[U_VERSION_REQ]).await;
                }
                MainAction::SendNcn5120SysStateRequest => {
                    let _ = self.uart.write_all(&[NCN5120_SYS_STATE_REQ, U_VERSION_REQ]).await;
                }
                MainAction::InitComplete => {
                    info!("TPUART: Initialization complete, chip: {}", self.main_ctx.chip_type.name());
                }
                MainAction::SendE981RegRead { address } => {
                    // E981 register read: 3 bytes (cmd, addr_hi, addr_lo)
                    let buf = [
                        E981_REG_READ_REQ,
                        (address >> 8) as u8,
                        (address & 0xFF) as u8,
                    ];
                    let _ = self.uart.write_all(&buf).await;
                }
                MainAction::SendE981RegWrite { address, value } => {
                    // E981 register write: 4 bytes (cmd, addr_hi, addr_lo, value)
                    let buf = [
                        E981_REG_WRITE_REQ,
                        (address >> 8) as u8,
                        (address & 0xFF) as u8,
                        value,
                    ];
                    let _ = self.uart.write_all(&buf).await;
                }
                MainAction::SendNcn5120RegWrite { address, value } => {
                    // NCN5120 register write: 2 bytes (cmd | addr, value)
                    // Address is in lower 3 bits of command
                    let buf = [NCN5120_REG_WRITE_REQ | (address & 0x07), value];
                    let _ = self.uart.write_all(&buf).await;
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
                    if let Some(ref tx) = self.current_tx {
                        if index < tx.tp1_buffer.len() {
                            let byte = tx.tp1_buffer[index];
                            let is_long_frame = tx.tp1_buffer.len() > 64;

                            match self.main_ctx.chip_type {
                                // E981: Uses special long frame commands for frames >64 bytes
                                ChipType::E981 if is_long_frame => {
                                    if index == 0 {
                                        // First byte: normal start command
                                        let _ = self.uart.write_all(&[U_L_DATA_START, byte]).await;
                                    } else if is_last {
                                        // Last byte: E981_LONG_DATA_END + full index
                                        let _ = self.uart.write_all(&[E981_LONG_DATA_END, index as u8, byte]).await;
                                    } else {
                                        // Middle bytes: E981_LONG_DATA_CONTINUE + full index
                                        let _ = self.uart.write_all(&[E981_LONG_DATA_CONTINUE, index as u8, byte]).await;
                                    }
                                }

                                // NCN5120: Uses offset command at 64-byte boundaries
                                ChipType::Ncn5120 if is_long_frame => {
                                    // Send offset command at each 64-byte boundary (except 0)
                                    if (index & 0x3F) == 0 && index > 0 {
                                        let offset_cmd = U_L_DATA_OFFSET_REQ | (index >> 6) as u8;
                                        let _ = self.uart.write_all(&[offset_cmd]).await;
                                    }
                                    // Normal start/end with 6-bit index
                                    let cmd = if is_last {
                                        U_L_DATA_END | (index & 0x3F) as u8
                                    } else {
                                        U_L_DATA_START | (index & 0x3F) as u8
                                    };
                                    let _ = self.uart.write_all(&[cmd, byte]).await;
                                }

                                // Standard frame (<=64 bytes) or TPUART1/2
                                _ => {
                                    let cmd = if is_last {
                                        U_L_DATA_END | (index & 0x3F) as u8
                                    } else {
                                        U_L_DATA_START | (index & 0x3F) as u8
                                    };
                                    let _ = self.uart.write_all(&[cmd, byte]).await;
                                }
                            }
                        }
                    }
                }
                SendAction::StartSendTimer => {
                    self.timeout_deadline = Some(Instant::now() + TIMEOUT_SEND);
                }
                SendAction::StopSendTimer => {
                    // Timer is shared with main state machine
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
            tx.response_tx.send(confirmation).await;
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
            self.is_echo_check(&tx.tp1_buffer, buf)
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
        let dst_hi = header[3];
        let dst_lo = header[4];
        let at_npci = header[5];

        // Determine frame format from control byte
        // Standard frame: bit 7 = 1, extended frame: bit 7 = 0
        let is_extended = (ctrl & 0x80) == 0;
        self.main_ctx.receive_state.is_extended = is_extended;
        self.main_ctx.receive_state.control_byte = ctrl;

        // Check if this is an echo of our transmission
        // Compare control byte (ignoring repeat bit) and addresses
        if let Some(ref tx) = self.current_tx {
            if tx.tp1_buffer.len() >= 6 {
                let tx_buf = &tx.tp1_buffer;
                let ctrl_match = ((header[0] ^ tx_buf[0]) & !0x20) == 0;
                let addr_match = header[1..6] == tx_buf[1..6];
                if ctrl_match && addr_match {
                    self.main_ctx.receive_state.is_echo = true;
                    // Don't ACK our own echoes
                    return;
                }
            }
        }

        // Check if group address (bit 7 of AT/NPCI byte)
        let is_group_address = (at_npci & 0x80) != 0;

        if is_group_address {
            // Extract group address from bytes 3-4
            let ga = GroupAddress::from_bytes(&[dst_hi, dst_lo]);

            // Check if we should ACK this group address
            if self.address_checker.should_ack_group_address(ga) {
                // Send ACK
                let _ = self.uart.write_all(&[U_ACK_INF]).await;
                self.main_ctx.receive_state.acked = true;
                trace!("TPUART: ACK sent for group address {}", ga);
            }
        }
        // Individual addresses are ACKed by the TPUART hardware when our address is set
    }

    /// Check if received bytes match our transmitted frame (echo detection) - non-borrowing version
    fn is_echo_check(&self, tx_buf: &Buffer<'static>, rx_buf: &Buffer<'static>) -> bool {
        if rx_buf.len() < 4 || tx_buf.len() < 4 {
            return false;
        }
        // Compare control byte (ignoring repeat bit) and source/dest addresses
        ((rx_buf[0] ^ tx_buf[0]) & !0x20) == 0 && rx_buf[1..4] == tx_buf[1..4]
    }

    /// Start a new transmission
    async fn start_transmission(&mut self, msg: Buffer<'static>, response_tx: DynamicSender<'static, ConfirmationMessage<Buffer<'static>>>) {
        // Check frame size
        let tp1_size = self.calculate_tp1_frame_size(&msg);
        if tp1_size > self.main_ctx.chip_type.max_frame_size() {
            // Frame too large
            warn!("TPUART: Frame too large ({} > {})", tp1_size, self.main_ctx.chip_type.max_frame_size());
            let mut error_msg = KnxMessageBuffer::new(msg, ServiceType::L_Data_Con);
            error_msg.ctrl_field_mut().set_c(Confirm::Err);
            response_tx.send(ConfirmationMessage::confirmation(error_msg)).await;
            return;
        }

        // Allocate buffer for TP1 format and copy data
        let mut tp1_buf = self.buffer_manager.borrow().alloc().await;
        for &byte in &msg[..] {
            tp1_buf.push(byte);
        }

        // Convert KNX format to TP1 format (modifies in place, may add extended control byte)
        let mut tp1_buffer = knx_to_tp1_message(tp1_buf);

        // Add checksum to the buffer
        let checksum = calculate_checksum(&tp1_buffer[..]);
        tp1_buffer.push(checksum);

        self.send_ctx.total_bytes = tp1_buffer.len();
        self.current_tx = Some(CurrentTransmission { knx_buffer: msg, tp1_buffer, response_tx });

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
    async fn queue_transmission(&mut self, msg: Buffer<'static>, response_tx: DynamicSender<'static, ConfirmationMessage<Buffer<'static>>>) {
        // If idle and nothing pending, start immediately
        if self.main_ctx.main_state == MainState::Idle && self.pending_tx.is_none() && self.current_tx.is_none() {
            self.start_transmission(msg, response_tx).await;
            return;
        }

        // Replace any pending transmission
        if let Some(old) = self.pending_tx.take() {
            let mut error_msg = KnxMessageBuffer::new(old.buffer, ServiceType::L_Data_Con);
            error_msg.ctrl_field_mut().set_c(Confirm::Err);
            old.response_tx.send(ConfirmationMessage::confirmation(error_msg)).await;
        }

        self.pending_tx = Some(PendingTransmission { buffer: msg, response_tx });
    }

    /// Check and start pending transmission if idle
    async fn check_pending_transmission(&mut self) {
        if self.main_ctx.main_state == MainState::Idle && self.current_tx.is_none() {
            if let Some(pending) = self.pending_tx.take() {
                self.start_transmission(pending.buffer, pending.response_tx).await;
            }
        }
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initialize the TPUART
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

            match embassy_futures::select::select(timeout_future, self.uart.read(&mut buf)).await {
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

        if self.main_ctx.main_state == MainState::Error {
            error!("TPUART: Initialization failed");
        }
    }
}

// ============================================================================
// Layer Implementation
// ============================================================================

impl<'a, U, A> Layer<'a> for TpUartLinkLayer<'a, U, A>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
    A: AddressChecker,
{
    type Buffer = Buffer<'static>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Buffer>>,
    {
        self.initialize().await;

        loop {
            let mut buf = [0u8];

            // Create timeout future
            let timeout_future = async {
                if let Some(deadline) = self.timeout_deadline {
                    Timer::at(deadline).await;
                    true
                } else {
                    core::future::pending::<bool>().await
                }
            };

            match select3(timeout_future, self.uart.read(&mut buf), inbox.next()).await {
                Either3::First(_) => {
                    // Timeout
                    trace!("TPUART: Timeout");
                    let actions = process_main_event(&mut self.main_ctx, MainEvent::Timer);
                    self.execute_main_actions(actions).await;

                    // Also check send timeout if in sending state
                    if self.send_ctx.state != SendState::Idle {
                        let send_actions = process_send_event(&mut self.send_ctx, SendEvent::Timeout);
                        self.execute_send_actions(send_actions).await;
                    }
                }
                Either3::Second(result) => {
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
                Either3::Third(layer_op) => {
                    match layer_op {
                        LayerOp::Indication(_) => {
                            error!("TPUART: Unexpected indication from upper layer");
                        }
                        LayerOp::Request { message, response_tx } => {
                            match message.service_type() {
                                ServiceType::L_Data_Req => {
                                    self.queue_transmission(message.into_inner().into_inner(), response_tx).await;
                                }
                                _ => {
                                    // Unsupported service type
                                    response_tx.send(message.into_inner().error().build()).await;
                                }
                            }
                        }
                    }
                }
            }

            // Check for pending transmission
            self.check_pending_transmission().await;

            // Continue sending bytes if in Sending state
            if self.send_ctx.state == SendState::Sending {
                let actions = process_send_event(&mut self.send_ctx, SendEvent::SendNextByte);
                self.execute_send_actions(actions).await;
            }
        }
    }
}
