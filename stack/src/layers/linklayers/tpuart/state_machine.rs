//! State machine logic for TPUART link layer
//!
//! This module contains the pure state machine logic for handling TPUART
//! communication. The state machine is separated from async I/O to make it
//! testable and to keep the logic clean.

use embassy_time::Duration;

use super::chip::ChipType;

// ============================================================================
// Timeout Constants
// ============================================================================

/// Timeout waiting for reset response
pub const TIMEOUT_RESET: Duration = Duration::from_millis(50);

/// Timeout between bytes during frame reception (to detect frame end)
pub const TIMEOUT_INTER_BYTE: Duration = Duration::from_millis(4);

/// Timeout for invalidation state (discard invalid frame)
pub const TIMEOUT_INVALIDATE: Duration = Duration::from_millis(3);

/// Idle keepalive timeout (check bus health)
pub const TIMEOUT_KEEPALIVE: Duration = Duration::from_millis(1150);

/// Timeout waiting for L_Data.con after transmission
pub const TIMEOUT_SEND: Duration = Duration::from_millis(1000);

/// Timeout waiting for version response during chip detection
pub const TIMEOUT_VERSION: Duration = Duration::from_millis(5);

/// Timeout waiting for NCN5120 system state response during chip detection.
/// A hardware-ISR-driven implementation can use 3ms, but that assumes the timer runs concurrently
/// with byte transmission (ISR-driven TX). Our `uart_write` returns before
/// bytes are physically on the wire, so we need extra margin to account for
/// the ~1.2ms it takes to transmit the 2-byte probe at 19200 8E1.
pub const TIMEOUT_NCN5120_PROBE: Duration = Duration::from_millis(5);

/// Timeout waiting for register read response
pub const TIMEOUT_REGISTER: Duration = Duration::from_millis(10);

// ============================================================================
// TPUART Protocol Constants
// ============================================================================

/// Reset request command
pub const U_RESET_REQ: u8 = 0x01;
/// State request command
pub const U_STATE_REQ: u8 = 0x02;
/// Reset indication (response to reset request)
pub const U_RESET_IND: u8 = 0x03;
/// State indication mask (lower 3 bits)
pub const U_STATE_IND_MASK: u8 = 0x07;
/// State indication value
pub const U_STATE_IND: u8 = 0x07;
/// ACK information base command (bits 0-2: addr_match, busy, nack)
pub const U_ACK_INF_BASE: u8 = 0x10;
/// ACK information command (address match, no busy, no nack)
pub const U_ACK_INF: u8 = 0x11;
/// NACK information command (address match, no busy, nack)
pub const U_NACK_INF: u8 = 0x15;
/// BUSY information command (address match, busy, no nack)
pub const U_BUSY_INF: u8 = 0x13;
/// L_Data start command prefix (standard frames, index 0-63)
pub const U_L_DATA_START: u8 = 0x80;
/// L_Data end command prefix (standard frames, index 0-63)
pub const U_L_DATA_END: u8 = 0x40;
/// L_Data offset request (NCN5120: set offset for long frames >64 bytes)
/// Format: U_L_DATA_OFFSET_REQ | (offset >> 6), then continue with normal commands
pub const U_L_DATA_OFFSET_REQ: u8 = 0x08;
/// E981 long data continue command (for bytes 1+ in long frames >64 bytes)
/// Format: E981_LONG_DATA_CONTINUE followed by full byte index
pub const E981_LONG_DATA_CONTINUE: u8 = 0xC0;
/// E981 long data end command (for last byte in long frames >64 bytes)
/// Format: E981_LONG_DATA_END followed by full byte index
pub const E981_LONG_DATA_END: u8 = 0xD0;
/// Set address command (4 bytes: 0xF1, addr_hi, addr_lo, dummy).
/// The NCN5120 datasheet (Table 12) specifies 4 total bytes; the dummy byte
/// must be sent or the chip will consume the next UART byte as the dummy.
/// Also activates the auto-acknowledge function (Figure 37).
pub const U_SET_ADDRESS: u8 = 0xF1;
/// Set max retry count command
pub const U_MAX_RST_CNT: u8 = 0x24;
/// Version request command (TPUART2 only).
/// This command is NOT recognized by the NCN5120 — it falls in an undefined
/// range (between U_Configure.req 0x18-0x1F and U_IntRegWr.req 0x28-0x2B per
/// NCN5120 datasheet Table 12). The NCN5120 responds with U_State.ind (pe=1).
pub const U_VERSION_REQ: u8 = 0x20;
/// Version indication mask (TPUART2)
pub const U_VERSION_IND_MASK: u8 = 0xE0;
/// Version indication value (TPUART2): bits [7:5] = 010, bits [4:0] = version number
pub const U_VERSION_IND: u8 = 0x40;

/// L_Data confirmation mask
pub const L_DATA_CON_MASK: u8 = 0x7F;
/// L_Data confirmation value
pub const L_DATA_CON: u8 = 0x0B;
/// L_Data indication start (bit pattern)
pub const L_DATA_IND: u8 = 0x10;

/// NCN5120 system state request
pub const NCN5120_SYS_STATE_REQ: u8 = 0x0D;
/// NCN5120 system state indication
pub const NCN5120_SYS_STATE_IND: u8 = 0x4B;

/// E981 product ID indication
pub const E981_PRODUCT_ID_IND: u8 = 0xFE;

/// E981 register read request command
pub const E981_REG_READ_REQ: u8 = 0x2E;
/// E981 register write request command
pub const E981_REG_WRITE_REQ: u8 = 0x2F;
/// E981 register read response indicator
pub const E981_REG_READ_RESP: u8 = 0xF1;

/// NCN5120 register write command
pub const NCN5120_REG_WRITE_REQ: u8 = 0x28;

// ============================================================================
// Bus Monitor Mode Constants
// ============================================================================

/// Bus monitor mode enable command
pub const U_BUSMON_REQ: u8 = 0x05;

/// Bus monitor ACK byte (seen on bus after successful transmission)
pub const BUSMON_ACK: u8 = 0xCC;
/// Bus monitor NACK byte (seen on bus after failed transmission)
pub const BUSMON_NACK: u8 = 0x0C;
/// Bus monitor BUSY byte (seen on bus when receiver is busy)
pub const BUSMON_BUSY: u8 = 0xC0;

// ============================================================================
// Main State Machine
// ============================================================================

/// Main states of the TPUART link layer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainState {
    /// Initial state, waiting for first timer to start reset sequence
    Init,
    /// Sent reset command, waiting for U_Reset.ind
    SendReset,
    /// Received reset indication, now detecting chip type
    Config,
    /// Ready for TX/RX operations
    Idle,
    /// Receiving a telegram frame byte by byte
    ReceiveFrame,
    /// Waiting for register read response (E981 only)
    WaitRegRes,
    /// Error state, will attempt recovery via reset
    Error,
    /// Invalidating received data after error, waiting for timeout
    Invalidate,
}

/// Events that trigger main state machine transitions
#[derive(Debug, Clone, Copy)]
pub enum MainEvent {
    /// Timer expired
    Timer,
    /// Received a byte from UART
    ReceivedByte(u8),
    /// UART receive error occurred
    ReceiveError,
    /// Request to read a register (E981 only, 16-bit address)
    ReadRegister { address: u16 },
    /// Request to write a register (E981: 16-bit address, NCN5120: 2-bit address)
    WriteRegister { address: u16, value: u8 },
}

/// Actions to be performed by the TPUART layer
#[derive(Debug, Clone, Copy)]
pub enum MainAction {
    // Timer control
    /// Start a timer with the specified duration
    StartTimer(Duration),
    /// Stop the current timer
    StopTimer,

    // UART transmission
    /// Send a single byte to UART
    SendByte(u8),

    // Frame reception
    /// Allocate a receive buffer for incoming frame
    AllocReceiveBuffer,
    /// Store received byte in the buffer
    StoreReceivedByte(u8),
    /// Release the receive buffer (frame invalid or duplicate)
    ReleaseReceiveBuffer,
    /// Clear the receive buffer and state
    ClearReceiveState,

    // Header parsing and ACK handling
    /// Parse the frame header (6 bytes received) and decide on ACK
    /// The action executor should:
    /// 1. Parse control byte to determine frame format
    /// 2. Extract destination address (bytes 3-4)
    /// 3. Check if group address bit is set (byte 5 bit 7)
    /// 4. If group address: check address table, ACK if found
    /// 5. Update expected frame length in receive_state
    ParseHeaderAndCheckAck,
    /// Send ACK for received frame
    SendAck,
    /// Send NACK for received frame
    SendNack,
    /// Send BUSY for received frame (device busy)
    SendBusy,

    // Notifications
    /// Frame received successfully, send indication to network layer
    IndicationToNetwork,
    /// Transmission completed, notify sender with result
    ConfirmationToNetwork { success: bool },

    // Chip detection
    /// Set the detected chip type
    SetChipType(ChipType),
    /// Set the chip version
    SetChipVersion(u8),

    // Bus health
    /// Increment the bus failure counter
    IncrementResetCounter,
    /// Reset the bus failure counter (bus is working)
    ResetBusFailureCounter,

    // Repeated telegram tracking
    /// Store control byte for repeat detection
    StoreControlByte(u8),
    /// Mark current frame as repeated (should be dropped)
    MarkAsRepeatedFrame,
    /// Clear the repeated frame flag
    ClearRepeatedFlag,
    /// Mark current frame as invalid (control byte = 0xFF, won't be processed)
    MarkFrameInvalid,

    // Send state machine integration
    /// Notify send state machine: frame start received (4 bytes)
    SendSmFrameStart,
    /// Notify send state machine: frame complete received
    SendSmFrameComplete,
    /// Notify send state machine: L_Data.con received
    SendSmConfirmation { ack: bool },
    /// Reset send state machine due to error (e.g., U_State.ind with error flags)
    ResetSendStateMachine,

    // Configuration
    /// Set retry counts in TPUART
    ConfigureRetryCounts,
    /// Request state from TPUART
    SendStateRequest,
    /// Send version request
    SendVersionRequest,
    /// Send NCN5120 system state request
    SendNcn5120SysStateRequest,

    // Initialization complete
    /// Initialization completed successfully
    InitComplete,

    // Register operations
    /// Send E981 register read command (3 bytes: cmd, addr_hi, addr_lo)
    SendE981RegRead { address: u16 },
    /// Send E981 register write command (4 bytes: cmd, addr_hi, addr_lo, value)
    SendE981RegWrite { address: u16, value: u8 },
    /// Send NCN5120 register write command (2 bytes: cmd | addr, value)
    SendNcn5120RegWrite { address: u8, value: u8 },
    /// Register read completed with result
    RegisterReadComplete { value: u8 },
    /// Register operation failed (timeout or unsupported)
    RegisterOperationFailed,
}

// ============================================================================
// Config Sub-State (for Chip Detection)
// ============================================================================

/// Sub-states during chip detection/configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigState {
    /// Initial: sent U_Version.req, waiting for response
    #[default]
    ReadVersion,
    /// E981: waiting for second byte of version
    RcvSecondByte,
    /// No version response, trying NCN5120 detection
    CheckNCN5120,
    /// NCN5120: waiting for second byte
    RcvNCN5120,
    /// Chip detected, waiting for config completion
    WaitTimeout,
}

// ============================================================================
// Receive State (track frame reception progress)
// ============================================================================

/// State tracking for frame reception
#[derive(Debug, Clone, Copy, Default)]
pub struct ReceiveState {
    /// Number of bytes received so far
    pub bytes_received: usize,
    /// Expected total frame length (once header is parsed)
    pub expected_len: Option<usize>,
    /// Whether this frame is an echo of our transmission
    pub is_echo: bool,
    /// Whether we've sent an ACK for this frame
    pub acked: bool,
    /// Whether the frame is extended format
    pub is_extended: bool,
    /// Control byte of the frame (for repeat detection)
    pub control_byte: u8,
    /// Flag indicating this is a repeated telegram
    pub is_repeated: bool,
}

impl ReceiveState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ============================================================================
// Main State Machine Context
// ============================================================================

/// State for tracking register read operations
#[derive(Debug, Clone, Copy, Default)]
pub struct RegisterReadState {
    /// Number of response bytes expected
    pub expected_bytes: u8,
    /// Number of response bytes received
    pub received_bytes: u8,
    /// The register value (built up from response bytes)
    pub value: u8,
}

impl RegisterReadState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Context holding all state machine state
#[derive(Debug)]
pub struct StateMachineContext {
    /// Current main state
    pub main_state: MainState,
    /// Configuration sub-state (during Init/Config)
    pub config_state: ConfigState,
    /// Receive state (during ReceiveFrame)
    pub receive_state: ReceiveState,
    /// Register read state (during WaitRegRes)
    pub reg_read_state: RegisterReadState,
    /// Detected chip type
    pub chip_type: ChipType,
    /// Chip version (if available)
    pub chip_version: u8,
    /// Bus failure/reset attempt counter
    pub reset_counter: u8,
    /// Previous frame control byte (for repeat detection)
    pub prev_control_byte: u8,
}

impl Default for StateMachineContext {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachineContext {
    pub fn new() -> Self {
        Self {
            main_state: MainState::Init,
            config_state: ConfigState::default(),
            receive_state: ReceiveState::new(),
            reg_read_state: RegisterReadState::new(),
            chip_type: ChipType::Unknown,
            chip_version: 0,
            reset_counter: 10, // Start at 10 = bus not OK yet
            prev_control_byte: 0xFF,
        }
    }

    /// Check if bus is OK (reset_counter < 10)
    pub fn is_bus_ok(&self) -> bool {
        self.reset_counter < 10
    }

    /// Check if bus has failed (reset_counter > 11)
    pub fn is_bus_failed(&self) -> bool {
        self.reset_counter > 11
    }
}

// ============================================================================
// Action Buffer
// ============================================================================

/// A small fixed-size buffer for actions returned by the state machine
///
/// Buffer for main state machine actions.
/// Most state transitions produce 1-4 actions, so capacity of 8 is sufficient.
pub type ActionBuffer = heapless::Vec<MainAction, 8>;

// ============================================================================
// Main State Machine Logic
// ============================================================================

/// Process a main event and return actions to perform
pub fn process_main_event(ctx: &mut StateMachineContext, event: MainEvent) -> ActionBuffer {
    let mut actions = ActionBuffer::new();

    match (ctx.main_state, event) {
        // =====================================================================
        // Init state - waiting for initial timer
        // =====================================================================
        (MainState::Init, MainEvent::Timer) => {
            // Start reset sequence
            ctx.main_state = MainState::SendReset;
            actions.push(MainAction::SendByte(U_RESET_REQ)).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_RESET)).unwrap();
            actions.push(MainAction::IncrementResetCounter).unwrap();
        }
        (MainState::Init, MainEvent::ReceivedByte(_)) | (MainState::Init, MainEvent::ReceiveError) => {
            // Ignore bytes before initialization
        }

        // =====================================================================
        // SendReset state - waiting for U_Reset.ind
        // =====================================================================
        (MainState::SendReset, MainEvent::Timer) => {
            // Timeout, retry reset
            actions.push(MainAction::SendByte(U_RESET_REQ)).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_RESET)).unwrap();
            actions.push(MainAction::IncrementResetCounter).unwrap();
        }
        (MainState::SendReset, MainEvent::ReceivedByte(U_RESET_IND)) => {
            // Got reset indication, start chip detection
            ctx.main_state = MainState::Config;
            ctx.config_state = ConfigState::ReadVersion;
            actions.push(MainAction::SendVersionRequest).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_VERSION)).unwrap();
        }
        (MainState::SendReset, MainEvent::ReceivedByte(_)) | (MainState::SendReset, MainEvent::ReceiveError) => {
            // Ignore other bytes, keep waiting
        }

        // =====================================================================
        // Config state - chip detection and configuration
        // =====================================================================
        (MainState::Config, MainEvent::Timer) => {
            process_config_timeout(ctx, &mut actions);
        }
        (MainState::Config, MainEvent::ReceivedByte(byte)) => {
            process_config_byte(ctx, byte, &mut actions);
        }
        (MainState::Config, MainEvent::ReceiveError) => {
            // Ignore errors during config
        }

        // =====================================================================
        // Idle state - waiting for activity
        // =====================================================================
        (MainState::Idle, MainEvent::Timer) => {
            // Keepalive timeout, request state to check bus health
            ctx.main_state = MainState::Error;
            actions.push(MainAction::SendStateRequest).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_RESET)).unwrap();
        }
        (MainState::Idle, MainEvent::ReceivedByte(byte)) => {
            process_idle_byte(ctx, byte, &mut actions);
        }
        (MainState::Idle, MainEvent::ReceiveError) => {
            // Ignore errors in idle state
        }
        (MainState::Idle, MainEvent::ReadRegister { address }) => {
            // E981 register read: expects 2 response bytes (0xF1 response indicator + value)
            if ctx.chip_type == ChipType::E981 {
                ctx.main_state = MainState::WaitRegRes;
                ctx.reg_read_state.reset();
                ctx.reg_read_state.expected_bytes = 2;
                actions.push(MainAction::SendE981RegRead { address }).unwrap();
                actions.push(MainAction::StartTimer(TIMEOUT_REGISTER)).unwrap();
            } else {
                // Chip doesn't support register read
                actions.push(MainAction::RegisterOperationFailed).unwrap();
            }
        }
        (MainState::Idle, MainEvent::WriteRegister { address, value }) => {
            match ctx.chip_type {
                ChipType::E981 => {
                    // E981: 16-bit address space (upper 2 bits + lower 8 bits)
                    actions.push(MainAction::SendE981RegWrite { address, value }).unwrap();
                    // Write is fire-and-forget, no state change needed
                    actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
                }
                ChipType::Ncn5120 => {
                    // NCN5120: only 2-bit address (masked from lower bits)
                    actions.push(MainAction::SendNcn5120RegWrite { address: (address & 0x03) as u8, value }).unwrap();
                    // Write is fire-and-forget, no state change needed
                    actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
                }
                _ => {
                    // Chip doesn't support register write
                    actions.push(MainAction::RegisterOperationFailed).unwrap();
                }
            }
        }

        // =====================================================================
        // ReceiveFrame state - receiving telegram bytes
        // =====================================================================
        (MainState::ReceiveFrame, MainEvent::Timer) => {
            // Inter-byte timeout - frame incomplete, invalidate
            ctx.main_state = MainState::Invalidate;
            actions.push(MainAction::ReleaseReceiveBuffer).unwrap();
            actions.push(MainAction::ClearReceiveState).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_INVALIDATE)).unwrap();
        }
        (MainState::ReceiveFrame, MainEvent::ReceivedByte(byte)) => {
            process_receive_byte(ctx, byte, &mut actions);
        }
        (MainState::ReceiveFrame, MainEvent::ReceiveError) => {
            // RX error during frame reception - send BUSY to signal we can't process,
            // then enter invalidation state to wait for bus silence
            ctx.main_state = MainState::Invalidate;
            actions.push(MainAction::SendBusy).unwrap();
            actions.push(MainAction::MarkFrameInvalid).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_INVALIDATE)).unwrap();
        }

        // =====================================================================
        // WaitRegRes state - waiting for register read response (E981)
        // =====================================================================
        (MainState::WaitRegRes, MainEvent::Timer) => {
            // Timeout waiting for register response
            ctx.reg_read_state.reset();
            ctx.main_state = MainState::Idle;
            actions.push(MainAction::RegisterOperationFailed).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
        }
        (MainState::WaitRegRes, MainEvent::ReceivedByte(byte)) => {
            ctx.reg_read_state.received_bytes += 1;

            // For E981: first byte is response indicator (0xF1), second byte is value
            if ctx.reg_read_state.received_bytes == 1 {
                // First byte - should be E981_REG_READ_RESP (0xF1), ignore it
                actions.push(MainAction::StartTimer(TIMEOUT_REGISTER)).unwrap();
            } else if ctx.reg_read_state.received_bytes >= ctx.reg_read_state.expected_bytes {
                // All bytes received, the last byte is the actual register value
                ctx.reg_read_state.value = byte;
                ctx.main_state = MainState::Idle;
                actions.push(MainAction::RegisterReadComplete { value: byte }).unwrap();
                actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
            } else {
                // More bytes expected
                ctx.reg_read_state.value = byte;
                actions.push(MainAction::StartTimer(TIMEOUT_REGISTER)).unwrap();
            }
        }
        (MainState::WaitRegRes, MainEvent::ReceiveError) => {
            ctx.reg_read_state.reset();
            ctx.main_state = MainState::Idle;
            actions.push(MainAction::RegisterOperationFailed).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
        }
        (MainState::WaitRegRes, MainEvent::ReadRegister { .. })
        | (MainState::WaitRegRes, MainEvent::WriteRegister { .. }) => {
            // Busy, ignore
        }

        // =====================================================================
        // Error state - attempting recovery
        // =====================================================================
        (MainState::Error, MainEvent::Timer) => {
            // Timeout in error state, try reset
            ctx.main_state = MainState::SendReset;
            actions.push(MainAction::SendByte(U_RESET_REQ)).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_RESET)).unwrap();
            actions.push(MainAction::IncrementResetCounter).unwrap();
        }
        (MainState::Error, MainEvent::ReceivedByte(byte)) => {
            // Any byte received in Error state recovers to Idle unconditionally,
            // then processes the byte as a normal idle RX. This follows the
            // state table: Error + RxByte → {Idle, AIdleRx}.
            ctx.main_state = MainState::Idle;
            process_idle_byte(ctx, byte, &mut actions);
        }
        (MainState::Error, MainEvent::ReceiveError) => {
            // Ignore
        }

        // =====================================================================
        // Invalidate state - discarding invalid data
        // =====================================================================
        (MainState::Invalidate, MainEvent::Timer) => {
            // Invalidation period over (3ms silence), return to idle
            // Release buffer if allocated, clear state, start keepalive
            ctx.main_state = MainState::Idle;
            actions.push(MainAction::ReleaseReceiveBuffer).unwrap();
            actions.push(MainAction::ClearReceiveState).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
        }
        (MainState::Invalidate, MainEvent::ReceivedByte(_)) => {
            // Discard bytes, mark frame invalid, and reset the invalidation timer
            actions.push(MainAction::MarkFrameInvalid).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_INVALIDATE)).unwrap();
        }
        (MainState::Invalidate, MainEvent::ReceiveError) => {
            // Ignore error, mark frame invalid, stay in invalidate
            actions.push(MainAction::MarkFrameInvalid).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_INVALIDATE)).unwrap();
        }

        // =====================================================================
        // Register operations in invalid states - reject them
        // =====================================================================
        (_, MainEvent::ReadRegister { .. }) | (_, MainEvent::WriteRegister { .. }) => {
            // Register operations only allowed in Idle state
            actions.push(MainAction::RegisterOperationFailed).unwrap();
        }
    }

    actions
}

// ============================================================================
// Config State Processing
// ============================================================================

fn process_config_timeout(ctx: &mut StateMachineContext, actions: &mut ActionBuffer) {
    match ctx.config_state {
        ConfigState::ReadVersion => {
            // No response to version request, try NCN5120 detection.
            // SendNcn5120SysStateRequest sends [0x20, 0x0D] on the wire:
            // U_VERSION_REQ first (ignored by NCN5120, answered by TPUART2),
            // then NCN5120_SYS_STATE_REQ (answered by NCN5120 with 0x4B).
            ctx.config_state = ConfigState::CheckNCN5120;
            actions.push(MainAction::SendNcn5120SysStateRequest).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_NCN5120_PROBE)).unwrap();
        }
        ConfigState::CheckNCN5120 => {
            // No NCN5120 response either, assume TPUART1
            ctx.chip_type = ChipType::TpUart1;
            actions.push(MainAction::SetChipType(ChipType::TpUart1)).unwrap();
            finish_config(ctx, actions);
        }
        ConfigState::WaitTimeout | ConfigState::RcvSecondByte | ConfigState::RcvNCN5120 => {
            // Config complete
            finish_config(ctx, actions);
        }
    }
}

fn process_config_byte(ctx: &mut StateMachineContext, byte: u8, actions: &mut ActionBuffer) {
    match ctx.config_state {
        ConfigState::ReadVersion => {
            // E981 product ID
            if byte == E981_PRODUCT_ID_IND {
                ctx.config_state = ConfigState::RcvSecondByte;
                ctx.chip_type = ChipType::E981;
                actions.push(MainAction::SetChipType(ChipType::E981)).unwrap();
                actions.push(MainAction::StartTimer(TIMEOUT_VERSION)).unwrap();
            }
            // TPUART1: responds with State.ind instead of Version.ind
            else if (byte & U_STATE_IND_MASK) == U_STATE_IND {
                ctx.chip_type = ChipType::TpUart1;
                ctx.chip_version = 0;
                ctx.config_state = ConfigState::WaitTimeout;
                actions.push(MainAction::SetChipType(ChipType::TpUart1)).unwrap();
                actions.push(MainAction::StartTimer(TIMEOUT_VERSION)).unwrap();
            }
            // TPUART2: Version indication
            else if (byte & U_VERSION_IND_MASK) == U_VERSION_IND {
                ctx.chip_type = ChipType::TpUart2;
                ctx.chip_version = byte & 0x1F;
                ctx.config_state = ConfigState::WaitTimeout;
                actions.push(MainAction::SetChipType(ChipType::TpUart2)).unwrap();
                actions.push(MainAction::SetChipVersion(ctx.chip_version)).unwrap();
                actions.push(MainAction::StartTimer(TIMEOUT_VERSION)).unwrap();
            }
            // Unknown response, will timeout and try NCN5120
        }
        ConfigState::RcvSecondByte => {
            // E981 second byte is the version
            ctx.chip_version = byte;
            ctx.config_state = ConfigState::WaitTimeout;
            actions.push(MainAction::SetChipVersion(byte)).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_VERSION)).unwrap();
        }
        ConfigState::CheckNCN5120 => {
            // We sent [0x20, 0x0D] on the wire. Possible responses:
            // - 0x4B: NCN5120 responded to U_SystemState.req (0x0D)
            // - 0x40-0x5F: TPUART2 responded to U_VERSION_REQ (0x20)
            // - 0x17 (U_State.ind with pe=1): NCN5120 protocol error from 0x20
            // - anything else: restart detection (full link-layer restart)
            if byte == NCN5120_SYS_STATE_IND {
                ctx.chip_type = ChipType::Ncn5120;
                ctx.config_state = ConfigState::RcvNCN5120;
                actions.push(MainAction::SetChipType(ChipType::Ncn5120)).unwrap();
                actions.push(MainAction::StartTimer(TIMEOUT_NCN5120_PROBE)).unwrap();
            } else if (byte & U_VERSION_IND_MASK) == U_VERSION_IND {
                // TPUART2 responded to the 0x20 version request
                ctx.chip_type = ChipType::TpUart2;
                ctx.chip_version = byte & 0x1F;
                ctx.config_state = ConfigState::WaitTimeout;
                actions.push(MainAction::SetChipType(ChipType::TpUart2)).unwrap();
                actions.push(MainAction::SetChipVersion(ctx.chip_version)).unwrap();
                actions.push(MainAction::StartTimer(TIMEOUT_VERSION)).unwrap();
            } else if (byte & U_STATE_IND_MASK) == U_STATE_IND {
                // U_State.ind (likely protocol error from NCN5120 reacting to 0x20).
                // Ignore it and keep waiting for the 0x4B response to 0x0D.
                actions.push(MainAction::StartTimer(TIMEOUT_NCN5120_PROBE)).unwrap();
            } else {
                // Unexpected byte — restart detection from scratch
                // (full link-layer restart on non-0x4B)
                ctx.main_state = MainState::SendReset;
                actions.push(MainAction::SendByte(U_RESET_REQ)).unwrap();
                actions.push(MainAction::StartTimer(TIMEOUT_RESET)).unwrap();
                actions.push(MainAction::IncrementResetCounter).unwrap();
            }
        }
        ConfigState::RcvNCN5120 => {
            // NCN5120 second byte received
            ctx.config_state = ConfigState::WaitTimeout;
            actions.push(MainAction::StartTimer(TIMEOUT_VERSION)).unwrap();
        }
        ConfigState::WaitTimeout => {
            // Unexpected byte during wait, restart config
            ctx.main_state = MainState::SendReset;
            actions.push(MainAction::SendByte(U_RESET_REQ)).unwrap();
            actions.push(MainAction::StartTimer(TIMEOUT_RESET)).unwrap();
        }
    }
}

fn finish_config(ctx: &mut StateMachineContext, actions: &mut ActionBuffer) {
    ctx.main_state = MainState::Idle;
    ctx.reset_counter = 0; // Bus is now OK
    actions.push(MainAction::ResetBusFailureCounter).unwrap();
    actions.push(MainAction::ConfigureRetryCounts).unwrap();
    actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
    actions.push(MainAction::InitComplete).unwrap();
}

// ============================================================================
// Idle State Processing
// ============================================================================

fn process_idle_byte(ctx: &mut StateMachineContext, byte: u8, actions: &mut ActionBuffer) {
    // State indication
    if (byte & U_STATE_IND_MASK) == U_STATE_IND {
        // Reset keepalive timer
        actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();

        // Check for errors in state indication
        // SC=0x80 (slave collision), RE=0x40 (receive error), TE=0x20 (transmit error),
        // PE=0x10 (protocol error), TW=0x08 (temperature warning)
        if (byte & 0xF8) != 0 {
            // Any error/warning flags set - reset the send state machine
            actions.push(MainAction::ResetSendStateMachine).unwrap();
        }
    }
    // L_Data confirmation
    else if (byte & L_DATA_CON_MASK) == L_DATA_CON {
        let ack = (byte & 0x80) != 0;
        actions.push(MainAction::SendSmConfirmation { ack }).unwrap();
        actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
    }
    // L_Data indication (start of frame)
    else if (byte & 0x53) == L_DATA_IND {
        // Check for repeated telegram (compare control byte ignoring repeat bit 5)
        let is_repeated = ((byte ^ ctx.prev_control_byte) & !0x20) == 0;

        ctx.main_state = MainState::ReceiveFrame;
        ctx.receive_state.reset();
        ctx.receive_state.bytes_received = 1;
        ctx.receive_state.control_byte = byte;
        ctx.receive_state.is_repeated = is_repeated;
        ctx.receive_state.is_extended = (byte & 0x80) != 0x80;

        actions.push(MainAction::AllocReceiveBuffer).unwrap();
        actions.push(MainAction::StoreReceivedByte(byte)).unwrap();
        actions.push(MainAction::StoreControlByte(byte)).unwrap();
        if is_repeated {
            actions.push(MainAction::MarkAsRepeatedFrame).unwrap();
        }
        actions.push(MainAction::StartTimer(TIMEOUT_INTER_BYTE)).unwrap();
    }
    // L_Poll_Data indication
    else if byte == 0xF0 {
        // Poll data not supported, go to invalidate
        ctx.main_state = MainState::Invalidate;
        actions.push(MainAction::StartTimer(TIMEOUT_INVALIDATE)).unwrap();
    }
    // E981 register read response
    else if byte == E981_PRODUCT_ID_IND && ctx.chip_type == ChipType::E981 {
        ctx.main_state = MainState::WaitRegRes;
        // Will receive the actual register value next
    }
    // Unknown byte - ignore
}

// ============================================================================
// Receive Frame Processing
// ============================================================================

fn process_receive_byte(ctx: &mut StateMachineContext, byte: u8, actions: &mut ActionBuffer) {
    let recv = &mut ctx.receive_state;

    // Check for oversized frame
    let max_frame_size = ctx.chip_type.max_frame_size();
    if recv.bytes_received >= max_frame_size {
        // Frame too large, invalidate
        ctx.main_state = MainState::Invalidate;
        actions.push(MainAction::ReleaseReceiveBuffer).unwrap();
        actions.push(MainAction::ClearReceiveState).unwrap();
        actions.push(MainAction::StartTimer(TIMEOUT_INVALIDATE)).unwrap();
        return;
    }

    // Track repeat detection: if any byte differs from previous frame, not repeated
    // (checked during receive to catch partial matches)
    // Note: Full comparison happens when we have 6+ bytes

    recv.bytes_received += 1;
    actions.push(MainAction::StoreReceivedByte(byte)).unwrap();
    actions.push(MainAction::StartTimer(TIMEOUT_INTER_BYTE)).unwrap();

    // After 4 bytes, notify send state machine (for echo detection)
    if recv.bytes_received == 4 {
        actions.push(MainAction::SendSmFrameStart).unwrap();
    }

    // After 6 bytes (header complete), parse header and decide on ACK
    if recv.bytes_received == 6 {
        // Emit action for the executor to parse header and check ACK
        // The action executor will:
        // 1. Parse header to determine frame format and expected length
        // 2. Extract destination address and check if it's a group address
        // 3. If group address: check address table, send ACK if found
        // 4. Check if this is an echo of our transmission
        actions.push(MainAction::ParseHeaderAndCheckAck).unwrap();
    }

    // Check if we have received the expected length
    if let Some(expected) = recv.expected_len
        && recv.bytes_received >= expected
    {
        // Frame complete
        complete_frame_reception(ctx, actions);
    }
}

fn complete_frame_reception(ctx: &mut StateMachineContext, actions: &mut ActionBuffer) {
    let recv = &ctx.receive_state;

    if recv.is_echo {
        // This was an echo of our transmission — notify the send SM,
        // then release the receive buffer (echo data is not forwarded).
        actions.push(MainAction::SendSmFrameComplete).unwrap();
        actions.push(MainAction::ReleaseReceiveBuffer).unwrap();
    } else if recv.is_repeated {
        // Repeated telegram, drop it
        actions.push(MainAction::ReleaseReceiveBuffer).unwrap();
    } else {
        // Valid new frame, forward to network layer
        // Checksum validation done by action executor
        actions.push(MainAction::IndicationToNetwork).unwrap();
    }

    ctx.main_state = MainState::Idle;
    actions.push(MainAction::ClearReceiveState).unwrap();
    actions.push(MainAction::StartTimer(TIMEOUT_KEEPALIVE)).unwrap();
}

// ============================================================================
// Send State Machine
// ============================================================================

/// States for the transmission state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SendState {
    /// No transmission in progress
    #[default]
    Idle,
    /// Sending frame bytes to TPUART
    Sending,
    /// All bytes sent, waiting for echo on bus
    WaitingForEcho,
    /// Echo received, waiting for L_Data.con (ACK/NACK)
    WaitingForConfirm,
}

/// Events for the send state machine
#[derive(Debug, Clone, Copy)]
pub enum SendEvent {
    /// Start a new transmission
    StartTransmission,
    /// Next byte needs to be sent (previous byte transmitted)
    SendNextByte,
    /// Frame start received (4 bytes) - echo detection
    FrameStartReceived { is_echo: bool },
    /// Complete frame echo received
    EchoReceived,
    /// L_Data confirmation received
    Confirmation { ack: bool },
    /// Transmission timeout
    Timeout,
    /// Cancel current transmission
    Cancel,
}

/// Actions for the send state machine
#[derive(Debug, Clone, Copy)]
pub enum SendAction {
    /// Send the next byte with index prefix
    SendByte { index: usize, is_last: bool },
    /// Start the send timeout timer
    StartSendTimer,
    /// Stop the send timeout timer
    StopSendTimer,
    /// Report transmission result to caller
    TransmissionComplete { success: bool },
    /// Frame sending is complete, waiting for echo
    FrameSendingComplete,
}

/// Send state machine context
#[derive(Debug, Default)]
pub struct SendContext {
    /// Current send state
    pub state: SendState,
    /// Current byte index being sent
    pub byte_index: usize,
    /// Total bytes to send (including checksum)
    pub total_bytes: usize,
}

impl SendContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Buffer for send state machine actions.
pub type SendActionBuffer = heapless::Vec<SendAction, 4>;

/// Process a send event and return actions
pub fn process_send_event(ctx: &mut SendContext, event: SendEvent) -> SendActionBuffer {
    let mut actions = SendActionBuffer::new();

    match (ctx.state, event) {
        // =====================================================================
        // Idle state
        // =====================================================================
        (SendState::Idle, SendEvent::StartTransmission) => {
            ctx.state = SendState::Sending;
            ctx.byte_index = 0;
            actions.push(SendAction::StartSendTimer).unwrap();
            let is_last = ctx.byte_index + 1 >= ctx.total_bytes;
            actions.push(SendAction::SendByte { index: ctx.byte_index, is_last }).unwrap();
        }
        (SendState::Idle, _) => {
            // Ignore other events in idle
        }

        // =====================================================================
        // Sending state
        // =====================================================================
        (SendState::Sending, SendEvent::SendNextByte) => {
            ctx.byte_index += 1;
            if ctx.byte_index < ctx.total_bytes {
                let is_last = ctx.byte_index + 1 >= ctx.total_bytes;
                actions.push(SendAction::SendByte { index: ctx.byte_index, is_last }).unwrap();
            } else {
                // All bytes sent, wait for echo
                ctx.state = SendState::WaitingForEcho;
                actions.push(SendAction::FrameSendingComplete).unwrap();
            }
        }
        (SendState::Sending, SendEvent::Timeout) => {
            ctx.reset();
            actions.push(SendAction::StopSendTimer).unwrap();
            actions.push(SendAction::TransmissionComplete { success: false }).unwrap();
        }
        (SendState::Sending, SendEvent::Cancel) => {
            ctx.reset();
            actions.push(SendAction::StopSendTimer).unwrap();
            actions.push(SendAction::TransmissionComplete { success: false }).unwrap();
        }
        (SendState::Sending, _) => {}

        // =====================================================================
        // WaitingForEcho state
        // =====================================================================
        (SendState::WaitingForEcho, SendEvent::FrameStartReceived { is_echo: true }) => {
            // Echo detected, continue waiting for complete echo
        }
        (SendState::WaitingForEcho, SendEvent::EchoReceived) => {
            // Full echo received, now wait for confirmation
            ctx.state = SendState::WaitingForConfirm;
        }
        (SendState::WaitingForEcho, SendEvent::Timeout) => {
            ctx.reset();
            actions.push(SendAction::StopSendTimer).unwrap();
            actions.push(SendAction::TransmissionComplete { success: false }).unwrap();
        }
        (SendState::WaitingForEcho, SendEvent::Cancel) => {
            ctx.reset();
            actions.push(SendAction::StopSendTimer).unwrap();
            actions.push(SendAction::TransmissionComplete { success: false }).unwrap();
        }
        (SendState::WaitingForEcho, _) => {}

        // =====================================================================
        // WaitingForConfirm state
        // =====================================================================
        (SendState::WaitingForConfirm, SendEvent::Confirmation { ack }) => {
            ctx.reset();
            actions.push(SendAction::StopSendTimer).unwrap();
            actions.push(SendAction::TransmissionComplete { success: ack }).unwrap();
        }
        (SendState::WaitingForConfirm, SendEvent::Timeout) => {
            ctx.reset();
            actions.push(SendAction::StopSendTimer).unwrap();
            actions.push(SendAction::TransmissionComplete { success: false }).unwrap();
        }
        (SendState::WaitingForConfirm, SendEvent::Cancel) => {
            ctx.reset();
            actions.push(SendAction::StopSendTimer).unwrap();
            actions.push(SendAction::TransmissionComplete { success: false }).unwrap();
        }
        (SendState::WaitingForConfirm, _) => {}
    }

    actions
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if a telegram is a repeat of the previous one
/// Compares control bytes ignoring the repeat flag (bit 5)
pub fn is_repeated_telegram(prev_ctrl: u8, new_ctrl: u8) -> bool {
    ((prev_ctrl ^ new_ctrl) & !0x20) == 0
}

/// Calculate TP1 frame checksum (XOR of all bytes, then XOR with 0xFF)
pub fn calculate_checksum(data: &[u8]) -> u8 {
    let mut checksum = 0xFFu8;
    for &b in data {
        checksum ^= b;
    }
    checksum
}

/// Validate TP1 frame checksum
pub fn validate_checksum(data: &[u8]) -> bool {
    let mut checksum = 0u8;
    for &b in data {
        checksum ^= b;
    }
    checksum == 0xFF
}

// ============================================================================
// Bus Monitor State Machine
// ============================================================================

/// Bus monitor mode states
///
/// In bus monitor mode, the TPUART transparently forwards all bus bytes to the host.
/// This includes frame data bytes and acknowledgment bytes (ACK=0xCC, NACK=0x0C, BUSY=0xC0).
/// The only way to exit bus monitor mode is via U_Reset.req.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BusMonitorState {
    /// Not in bus monitor mode (normal operation)
    #[default]
    Disabled,
    /// Bus monitor mode active, receiving raw bus bytes
    Active,
}

/// Events for the bus monitor state machine
#[derive(Debug, Clone, Copy)]
pub enum BusMonitorEvent {
    /// Enable bus monitor mode
    Enable,
    /// Disable bus monitor mode (requires chip reset)
    Disable,
    /// Timer expired (for frame boundary detection)
    Timer,
    /// Received a byte from UART (raw bus byte)
    ReceivedByte(u8),
    /// UART receive error
    ReceiveError,
}

/// Type of bus monitor byte received
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusMonitorByteType {
    /// Regular frame data byte
    Data,
    /// ACK byte (0xCC) - successful transmission acknowledged
    Ack,
    /// NACK byte (0x0C) - transmission not acknowledged
    Nack,
    /// BUSY byte (0xC0) - receiver is busy
    Busy,
}

impl BusMonitorByteType {
    /// Classify a received byte
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            BUSMON_ACK => BusMonitorByteType::Ack,
            BUSMON_NACK => BusMonitorByteType::Nack,
            BUSMON_BUSY => BusMonitorByteType::Busy,
            _ => BusMonitorByteType::Data,
        }
    }

    /// Check if this is an acknowledgment byte (ACK, NACK, or BUSY)
    pub fn is_ack_byte(&self) -> bool {
        !matches!(self, BusMonitorByteType::Data)
    }
}

/// Actions for the bus monitor state machine
#[derive(Debug, Clone, Copy)]
pub enum BusMonitorAction {
    /// Send bus monitor enable command (U_BUSMON_REQ)
    SendBusMonitorEnable,
    /// Send reset request (U_Reset.req) to exit bus monitor mode
    SendReset,
    /// Start inter-byte timer for frame boundary detection
    StartTimer(Duration),
    /// Stop the timer
    StopTimer,
    /// Bus monitor mode is now active
    BusMonitorActive,
    /// Received a raw bus byte
    ReceivedByte {
        /// The raw bus byte
        byte: u8,
        /// Classification of the byte
        byte_type: BusMonitorByteType,
    },
    /// Frame complete (inter-byte timeout detected frame boundary)
    FrameComplete,
    /// Allocate a receive buffer for the frame
    AllocReceiveBuffer,
    /// Store byte in receive buffer
    StoreReceivedByte(u8),
    /// Release receive buffer (on disable or error)
    ReleaseReceiveBuffer,
    /// Forward completed frame to callback
    ForwardFrame,
}

/// Bus monitor state machine context
#[derive(Debug, Default)]
pub struct BusMonitorContext {
    /// Current state
    pub state: BusMonitorState,
    /// Number of bytes received in current frame
    pub bytes_received: usize,
}

impl BusMonitorContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Check if bus monitor mode is active
    pub fn is_active(&self) -> bool {
        self.state == BusMonitorState::Active
    }
}

/// Buffer for bus monitor state machine actions.
pub type BusMonitorActionBuffer = heapless::Vec<BusMonitorAction, 8>;

/// Process a bus monitor event and return actions
pub fn process_busmon_event(ctx: &mut BusMonitorContext, event: BusMonitorEvent) -> BusMonitorActionBuffer {
    let mut actions = BusMonitorActionBuffer::new();

    match (ctx.state, event) {
        // =====================================================================
        // Disabled state - normal operation
        // =====================================================================
        (BusMonitorState::Disabled, BusMonitorEvent::Enable) => {
            ctx.state = BusMonitorState::Active;
            ctx.bytes_received = 0;
            actions.push(BusMonitorAction::SendBusMonitorEnable).unwrap();
            actions.push(BusMonitorAction::BusMonitorActive).unwrap();
            actions.push(BusMonitorAction::AllocReceiveBuffer).unwrap();
        }
        (BusMonitorState::Disabled, _) => {
            // Ignore other events when disabled
        }

        // =====================================================================
        // Active state - transparently receiving bus bytes
        // =====================================================================
        (BusMonitorState::Active, BusMonitorEvent::ReceivedByte(byte)) => {
            let byte_type = BusMonitorByteType::from_byte(byte);

            // ACK/NACK/BUSY bytes mark frame boundaries
            if byte_type.is_ack_byte() {
                // Store the ack byte as part of the frame
                actions.push(BusMonitorAction::StoreReceivedByte(byte)).unwrap();
                ctx.bytes_received += 1;

                // Report the byte
                actions.push(BusMonitorAction::ReceivedByte { byte, byte_type }).unwrap();

                // Frame is complete after ACK/NACK/BUSY
                if ctx.bytes_received > 0 {
                    actions.push(BusMonitorAction::FrameComplete).unwrap();
                    actions.push(BusMonitorAction::ForwardFrame).unwrap();
                    actions.push(BusMonitorAction::AllocReceiveBuffer).unwrap();
                    ctx.bytes_received = 0;
                }
            } else {
                // Regular data byte
                actions.push(BusMonitorAction::StoreReceivedByte(byte)).unwrap();
                ctx.bytes_received += 1;
                actions.push(BusMonitorAction::ReceivedByte { byte, byte_type }).unwrap();
                actions.push(BusMonitorAction::StartTimer(TIMEOUT_INTER_BYTE)).unwrap();
            }
        }
        (BusMonitorState::Active, BusMonitorEvent::Timer) => {
            // Inter-byte timeout - frame boundary detected (no ACK received)
            if ctx.bytes_received > 0 {
                actions.push(BusMonitorAction::FrameComplete).unwrap();
                actions.push(BusMonitorAction::ForwardFrame).unwrap();
                actions.push(BusMonitorAction::AllocReceiveBuffer).unwrap();
                ctx.bytes_received = 0;
            }
        }
        (BusMonitorState::Active, BusMonitorEvent::Disable) => {
            ctx.state = BusMonitorState::Disabled;
            actions.push(BusMonitorAction::StopTimer).unwrap();
            if ctx.bytes_received > 0 {
                actions.push(BusMonitorAction::ReleaseReceiveBuffer).unwrap();
            }
            actions.push(BusMonitorAction::SendReset).unwrap();
            ctx.bytes_received = 0;
        }
        (BusMonitorState::Active, BusMonitorEvent::ReceiveError) => {
            // Receive error - continue but restart timeout
            actions.push(BusMonitorAction::StartTimer(TIMEOUT_INTER_BYTE)).unwrap();
        }
        (BusMonitorState::Active, BusMonitorEvent::Enable) => {
            // Already active
        }
    }

    actions
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_to_reset() {
        let mut ctx = StateMachineContext::new();
        assert_eq!(ctx.main_state, MainState::Init);

        let actions = process_main_event(&mut ctx, MainEvent::Timer);

        assert_eq!(ctx.main_state, MainState::SendReset);
        assert!(!actions.is_empty());

        // Should have: SendByte(RESET), StartTimer, IncrementResetCounter
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::SendByte(U_RESET_REQ))));
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::StartTimer(_))));
    }

    #[test]
    fn test_reset_to_config() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::SendReset;

        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(U_RESET_IND));

        assert_eq!(ctx.main_state, MainState::Config);
        assert_eq!(ctx.config_state, ConfigState::ReadVersion);

        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::SendVersionRequest)));
    }

    #[test]
    fn test_config_tpuart2_detected() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Config;
        ctx.config_state = ConfigState::ReadVersion;

        // TPUART2 version indication: 0x4x where lower 5 bits are version
        let version_byte = 0x45; // Version 5

        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(version_byte));

        assert_eq!(ctx.chip_type, ChipType::TpUart2);
        assert_eq!(ctx.chip_version, 5);
        assert_eq!(ctx.config_state, ConfigState::WaitTimeout);
    }

    #[test]
    fn test_repeated_telegram_detection() {
        assert!(is_repeated_telegram(0xBC, 0xBC));
        assert!(is_repeated_telegram(0xBC, 0x9C)); // Same but with repeat bit toggled
        assert!(!is_repeated_telegram(0xBC, 0xBD)); // Different
    }

    #[test]
    fn test_checksum() {
        let data = [0xBC, 0x11, 0x01, 0x00, 0x01, 0xE1, 0x00, 0x80];
        let checksum = calculate_checksum(&data);

        let mut full_frame = data.to_vec();
        full_frame.push(checksum);
        assert!(validate_checksum(&full_frame));
    }

    #[test]
    fn test_invalidate_state() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Invalidate;

        // Bytes during invalidation should be discarded and reset timer
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0xFF));
        assert_eq!(ctx.main_state, MainState::Invalidate);
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_INVALIDATE))));
        assert!(actions.iter().any(|a| matches!(a, MainAction::MarkFrameInvalid)));

        // Timer expiry should return to idle
        let actions = process_main_event(&mut ctx, MainEvent::Timer);
        assert_eq!(ctx.main_state, MainState::Idle);
        assert!(actions.iter().any(|a| matches!(a, MainAction::ReleaseReceiveBuffer)));
        assert!(actions.iter().any(|a| matches!(a, MainAction::ClearReceiveState)));
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_KEEPALIVE))));
    }

    #[test]
    fn test_invalidate_from_rx_error() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::ReceiveFrame;
        ctx.receive_state.bytes_received = 5;

        // RX error during frame reception should:
        // - Transition to Invalidate
        // - Send BUSY
        // - Mark frame invalid
        // - Start invalidation timer
        let actions = process_main_event(&mut ctx, MainEvent::ReceiveError);
        assert_eq!(ctx.main_state, MainState::Invalidate);
        assert!(actions.iter().any(|a| matches!(a, MainAction::SendBusy)));
        assert!(actions.iter().any(|a| matches!(a, MainAction::MarkFrameInvalid)));
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_INVALIDATE))));
    }

    #[test]
    fn test_invalidate_rx_error_restarts_timer() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Invalidate;

        // RX error in Invalidate should mark invalid and restart timer
        let actions = process_main_event(&mut ctx, MainEvent::ReceiveError);
        assert_eq!(ctx.main_state, MainState::Invalidate);
        assert!(actions.iter().any(|a| matches!(a, MainAction::MarkFrameInvalid)));
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_INVALIDATE))));
    }

    #[test]
    fn test_state_indication_error_resets_send_sm() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;

        // U_State.ind with no errors (0x07) - should NOT reset send SM
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(U_STATE_IND));
        assert!(!actions.iter().any(|a| matches!(a, MainAction::ResetSendStateMachine)));

        // U_State.ind with transmit error (TE=0x20) - should reset send SM
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(U_STATE_IND | 0x20));
        assert!(actions.iter().any(|a| matches!(a, MainAction::ResetSendStateMachine)));

        // U_State.ind with slave collision (SC=0x80) - should reset send SM
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(U_STATE_IND | 0x80));
        assert!(actions.iter().any(|a| matches!(a, MainAction::ResetSendStateMachine)));

        // U_State.ind with temperature warning (TW=0x08) - should reset send SM
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(U_STATE_IND | 0x08));
        assert!(actions.iter().any(|a| matches!(a, MainAction::ResetSendStateMachine)));
    }

    #[test]
    fn test_error_state_recovers_on_state_response() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;

        // Keepalive timeout transitions to Error and sends U_State.req
        let actions = process_main_event(&mut ctx, MainEvent::Timer);
        assert_eq!(ctx.main_state, MainState::Error);
        assert!(actions.iter().any(|a| matches!(a, MainAction::SendStateRequest)));

        // Receiving U_State.ind (0x07, no errors) should recover to Idle.
        // Reference: Error + RxByte → {Idle, AIdleRx}
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(U_STATE_IND));
        assert_eq!(ctx.main_state, MainState::Idle);
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_KEEPALIVE))));
        assert!(!actions.iter().any(|a| matches!(a, MainAction::ResetSendStateMachine)));
    }

    #[test]
    fn test_error_state_recovers_with_error_flags() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Error;

        // U_State.ind with protocol error (PE=0x10) should still recover to Idle
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(U_STATE_IND | 0x10));
        assert_eq!(ctx.main_state, MainState::Idle);
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_KEEPALIVE))));
        assert!(actions.iter().any(|a| matches!(a, MainAction::ResetSendStateMachine)));
    }

    #[test]
    fn test_error_state_recovers_on_frame_start() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Error;

        // An incoming frame start (0xBC) during Error should also recover.
        // Reference transitions to Idle first, then AIdleRx processes it as
        // an L_Data indication, which transitions to ReceiveFrame.
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0xBC));
        assert_eq!(ctx.main_state, MainState::ReceiveFrame);
        assert!(actions.iter().any(|a| matches!(a, MainAction::AllocReceiveBuffer)));
    }

    #[test]
    fn test_error_state_resets_on_timeout() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Error;

        // Timeout in Error state (no response to U_State.req) triggers full reset
        let actions = process_main_event(&mut ctx, MainEvent::Timer);
        assert_eq!(ctx.main_state, MainState::SendReset);
        assert!(actions.iter().any(|a| matches!(a, MainAction::SendByte(U_RESET_REQ))));
        assert!(actions.iter().any(|a| matches!(a, MainAction::IncrementResetCounter)));
    }

    #[test]
    fn test_invalidate_waits_for_silence() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Invalidate;

        // Simulate bytes arriving - each should restart the timer
        for _ in 0..5 {
            let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0xAB));
            assert_eq!(ctx.main_state, MainState::Invalidate);
            assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_INVALIDATE))));
        }

        // Only after 3ms of silence (timer fires) do we return to Idle
        let actions = process_main_event(&mut ctx, MainEvent::Timer);
        assert_eq!(ctx.main_state, MainState::Idle);
        assert!(actions.iter().any(|a| matches!(a, MainAction::ReleaseReceiveBuffer)));
    }

    // =========================================================================
    // Group Address ACK Tests
    // =========================================================================

    #[test]
    fn test_parse_header_action_emitted_at_byte_6() {
        // Test that ParseHeaderAndCheckAck is emitted exactly when the 6th byte is received
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;
        ctx.chip_type = ChipType::TpUart2;

        // Simulate receiving a standard frame header
        // Frame: CTRL, SA_hi, SA_lo, DA_hi, DA_lo, AT/NPCI, ...

        // Byte 0 (CTRL): triggers transition to ReceiveFrame
        // 0xBC is a standard frame control byte (bit 7 = 1)
        let _actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0xBC));
        assert_eq!(ctx.main_state, MainState::ReceiveFrame);
        assert_eq!(ctx.receive_state.bytes_received, 1);

        // Bytes 1-4: no ParseHeaderAndCheckAck
        for i in 0..4 {
            let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0x11 + i));
            assert!(
                !actions.iter().any(|a| matches!(a, MainAction::ParseHeaderAndCheckAck)),
                "ParseHeaderAndCheckAck should not be emitted at byte {}",
                i + 2
            );
        }
        assert_eq!(ctx.receive_state.bytes_received, 5);

        // Byte 5 (6th byte, AT/NPCI): ParseHeaderAndCheckAck should be emitted
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0x80)); // Group address bit set
        assert_eq!(ctx.receive_state.bytes_received, 6);
        assert!(
            actions.iter().any(|a| matches!(a, MainAction::ParseHeaderAndCheckAck)),
            "ParseHeaderAndCheckAck should be emitted after byte 6"
        );
    }

    #[test]
    fn test_frame_start_emitted_after_byte_4() {
        // Test that SendSmFrameStart is emitted after the 4th byte (for echo detection)
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;
        ctx.chip_type = ChipType::TpUart2;

        // Byte 0: transition to ReceiveFrame
        // 0xBC is a standard frame control byte (bit 7 = 1)
        let _actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0xBC));
        assert_eq!(ctx.receive_state.bytes_received, 1);

        // Bytes 1-2: no SendSmFrameStart yet
        for i in 0..2 {
            let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0x11 + i));
            assert!(
                !actions.iter().any(|a| matches!(a, MainAction::SendSmFrameStart)),
                "SendSmFrameStart should not be emitted at byte {}",
                i + 2
            );
        }
        assert_eq!(ctx.receive_state.bytes_received, 3);

        // Byte 3 (4th byte): SendSmFrameStart should be emitted
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0x33));
        assert_eq!(ctx.receive_state.bytes_received, 4);
        assert!(
            actions.iter().any(|a| matches!(a, MainAction::SendSmFrameStart)),
            "SendSmFrameStart should be emitted after byte 4"
        );
    }

    #[test]
    fn test_send_state_machine() {
        let mut ctx = SendContext::new();
        ctx.total_bytes = 10;

        // Start transmission - sends byte 0
        let actions = process_send_event(&mut ctx, SendEvent::StartTransmission);
        assert_eq!(ctx.state, SendState::Sending);
        assert_eq!(ctx.byte_index, 0);
        assert!(actions.iter().any(|a| matches!(a, SendAction::SendByte { index: 0, .. })));

        // Send remaining 9 bytes (indices 1-9)
        for i in 1..10 {
            let actions = process_send_event(&mut ctx, SendEvent::SendNextByte);
            assert_eq!(ctx.byte_index, i);
            assert_eq!(ctx.state, SendState::Sending);
            // Check that byte i is being sent
            assert!(actions.iter().any(|a| matches!(a, SendAction::SendByte { index, .. } if *index == i)));
        }

        // One more SendNextByte to trigger transition (byte_index becomes 10, >= total_bytes)
        let actions = process_send_event(&mut ctx, SendEvent::SendNextByte);
        assert_eq!(ctx.state, SendState::WaitingForEcho);

        // Echo received
        process_send_event(&mut ctx, SendEvent::EchoReceived);
        assert_eq!(ctx.state, SendState::WaitingForConfirm);

        // Confirmation received
        let actions = process_send_event(&mut ctx, SendEvent::Confirmation { ack: true });
        assert_eq!(ctx.state, SendState::Idle);
        assert!(actions.iter().any(|a| matches!(a, SendAction::TransmissionComplete { success: true })));
    }

    #[test]
    fn test_register_read_e981() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;
        ctx.chip_type = ChipType::E981;

        // Trigger register read
        let actions = process_main_event(&mut ctx, MainEvent::ReadRegister { address: 0x1234 });

        assert_eq!(ctx.main_state, MainState::WaitRegRes);
        assert_eq!(ctx.reg_read_state.expected_bytes, 2);
        assert_eq!(ctx.reg_read_state.received_bytes, 0);

        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::SendE981RegRead { address: 0x1234 })));
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_REGISTER))));

        // Receive first byte (response indicator 0xF1)
        let _actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(E981_REG_READ_RESP));
        assert_eq!(ctx.main_state, MainState::WaitRegRes);
        assert_eq!(ctx.reg_read_state.received_bytes, 1);

        // Receive second byte (actual value)
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0x42));
        assert_eq!(ctx.main_state, MainState::Idle);
        assert_eq!(ctx.reg_read_state.value, 0x42);

        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::RegisterReadComplete { value: 0x42 })));
    }

    #[test]
    fn test_register_read_unsupported_chip() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;
        ctx.chip_type = ChipType::TpUart2; // TPUART2 doesn't support register read

        let actions = process_main_event(&mut ctx, MainEvent::ReadRegister { address: 0x0000 });

        // Should stay in Idle and return failure
        assert_eq!(ctx.main_state, MainState::Idle);
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::RegisterOperationFailed)));
    }

    #[test]
    fn test_register_read_timeout() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;
        ctx.chip_type = ChipType::E981;

        // Trigger register read
        let _actions = process_main_event(&mut ctx, MainEvent::ReadRegister { address: 0x0000 });
        assert_eq!(ctx.main_state, MainState::WaitRegRes);

        // Timeout occurs
        let actions = process_main_event(&mut ctx, MainEvent::Timer);

        assert_eq!(ctx.main_state, MainState::Idle);
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::RegisterOperationFailed)));
    }

    #[test]
    fn test_register_write_e981() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;
        ctx.chip_type = ChipType::E981;

        let actions = process_main_event(&mut ctx, MainEvent::WriteRegister { address: 0x12, value: 0xAB });

        // Write is fire-and-forget, stays in Idle
        assert_eq!(ctx.main_state, MainState::Idle);

        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::SendE981RegWrite { address: 0x12, value: 0xAB })));
    }

    #[test]
    fn test_register_write_ncn5120() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;
        ctx.chip_type = ChipType::Ncn5120;

        // NCN5120 only uses 2-bit address, so 0x05 becomes 0x01 (0x05 & 0x03)
        let actions = process_main_event(&mut ctx, MainEvent::WriteRegister { address: 0x02, value: 0xFF });

        assert_eq!(ctx.main_state, MainState::Idle);

        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::SendNcn5120RegWrite { address: 0x02, value: 0xFF })));
    }

    #[test]
    fn test_register_write_unsupported_chip() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Idle;
        ctx.chip_type = ChipType::TpUart1; // TPUART1 doesn't support register write

        let actions = process_main_event(&mut ctx, MainEvent::WriteRegister { address: 0x00, value: 0x00 });

        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::RegisterOperationFailed)));
    }

    #[test]
    fn test_register_operation_not_in_idle() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::ReceiveFrame;
        ctx.chip_type = ChipType::E981;

        // Register read should fail when not in Idle
        let actions = process_main_event(&mut ctx, MainEvent::ReadRegister { address: 0x0000 });
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::RegisterOperationFailed)));

        // Register write should also fail when not in Idle
        let actions = process_main_event(&mut ctx, MainEvent::WriteRegister { address: 0x00, value: 0x00 });
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, MainAction::RegisterOperationFailed)));
    }

    // =========================================================================
    // Chip Detection Tests
    // =========================================================================

    #[test]
    fn test_config_ncn5120_detected() {
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Config;
        ctx.config_state = ConfigState::CheckNCN5120;

        // NCN5120 responds with U_SystemStat.ind (0x4B)
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(NCN5120_SYS_STATE_IND));

        assert_eq!(ctx.chip_type, ChipType::Ncn5120);
        assert_eq!(ctx.config_state, ConfigState::RcvNCN5120);
        assert!(actions.iter().any(|a| matches!(a, MainAction::SetChipType(ChipType::Ncn5120))));
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_NCN5120_PROBE))));

        // Second byte (status) completes the NCN5120 config
        let _actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0x37));
        assert_eq!(ctx.config_state, ConfigState::WaitTimeout);
    }

    #[test]
    fn test_config_tpuart2_via_check_ncn5120() {
        // When we send [0x20, 0x0D], a TPUART2 responds to 0x20 with a version indication.
        // We should detect it as TPUART2 even during CheckNCN5120 state.
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Config;
        ctx.config_state = ConfigState::CheckNCN5120;

        let version_byte = 0x43; // TPUART2 version 3
        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(version_byte));

        assert_eq!(ctx.chip_type, ChipType::TpUart2);
        assert_eq!(ctx.chip_version, 3);
        assert_eq!(ctx.config_state, ConfigState::WaitTimeout);
        assert!(actions.iter().any(|a| matches!(a, MainAction::SetChipType(ChipType::TpUart2))));
    }

    #[test]
    fn test_config_check_ncn5120_ignores_state_ind() {
        // NCN5120 may send U_State.ind (pe=1, i.e. 0x17) in response to
        // the invalid 0x20 command. We should ignore it and keep waiting.
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Config;
        ctx.config_state = ConfigState::CheckNCN5120;

        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0x17));

        // Should still be in CheckNCN5120, just restarted the timer
        assert_eq!(ctx.main_state, MainState::Config);
        assert_eq!(ctx.config_state, ConfigState::CheckNCN5120);
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_NCN5120_PROBE))));
    }

    #[test]
    fn test_config_check_ncn5120_restarts_on_unknown_byte() {
        // Any non-0x4B, non-version, non-state byte
        // should trigger a full link-layer restart, not assume TPUART1.
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Config;
        ctx.config_state = ConfigState::CheckNCN5120;

        let actions = process_main_event(&mut ctx, MainEvent::ReceivedByte(0xAB));

        assert_eq!(ctx.main_state, MainState::SendReset);
        assert!(actions.iter().any(|a| matches!(a, MainAction::SendByte(U_RESET_REQ))));
        assert!(actions.iter().any(|a| matches!(a, MainAction::IncrementResetCounter)));
    }

    #[test]
    fn test_config_check_ncn5120_timeout_assumes_tpuart1() {
        // If neither NCN5120 nor TPUART2 responds within the 3ms timeout,
        // fall through to TPUART1 (timeout handler).
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Config;
        ctx.config_state = ConfigState::CheckNCN5120;

        let actions = process_main_event(&mut ctx, MainEvent::Timer);

        assert_eq!(ctx.chip_type, ChipType::TpUart1);
        assert_eq!(ctx.main_state, MainState::Idle);
        assert!(actions.iter().any(|a| matches!(a, MainAction::SetChipType(ChipType::TpUart1))));
        assert!(actions.iter().any(|a| matches!(a, MainAction::InitComplete)));
    }

    #[test]
    fn test_config_read_version_timeout_starts_ncn5120_probe() {
        // When the initial version request times out, we should transition
        // to CheckNCN5120 with the 3ms timeout.
        let mut ctx = StateMachineContext::new();
        ctx.main_state = MainState::Config;
        ctx.config_state = ConfigState::ReadVersion;

        let actions = process_main_event(&mut ctx, MainEvent::Timer);

        assert_eq!(ctx.config_state, ConfigState::CheckNCN5120);
        assert!(actions.iter().any(|a| matches!(a, MainAction::SendNcn5120SysStateRequest)));
        assert!(actions.iter().any(|a| matches!(a, MainAction::StartTimer(TIMEOUT_NCN5120_PROBE))));
    }

    // =========================================================================
    // Bus Monitor Mode Tests
    // =========================================================================

    #[test]
    fn test_busmon_byte_type_classification() {
        // ACK byte
        assert_eq!(BusMonitorByteType::from_byte(BUSMON_ACK), BusMonitorByteType::Ack);
        assert!(BusMonitorByteType::from_byte(BUSMON_ACK).is_ack_byte());

        // NACK byte
        assert_eq!(BusMonitorByteType::from_byte(BUSMON_NACK), BusMonitorByteType::Nack);
        assert!(BusMonitorByteType::from_byte(BUSMON_NACK).is_ack_byte());

        // BUSY byte
        assert_eq!(BusMonitorByteType::from_byte(BUSMON_BUSY), BusMonitorByteType::Busy);
        assert!(BusMonitorByteType::from_byte(BUSMON_BUSY).is_ack_byte());

        // Regular data bytes
        assert_eq!(BusMonitorByteType::from_byte(0xBC), BusMonitorByteType::Data);
        assert!(!BusMonitorByteType::from_byte(0xBC).is_ack_byte());
        assert_eq!(BusMonitorByteType::from_byte(0x00), BusMonitorByteType::Data);
        assert_eq!(BusMonitorByteType::from_byte(0xFF), BusMonitorByteType::Data);
    }

    #[test]
    fn test_busmon_enable() {
        let mut ctx = BusMonitorContext::new();
        assert_eq!(ctx.state, BusMonitorState::Disabled);
        assert!(!ctx.is_active());

        // Enable bus monitor mode
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::Enable);

        assert_eq!(ctx.state, BusMonitorState::Active);
        assert!(ctx.is_active());
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::SendBusMonitorEnable)));
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::BusMonitorActive)));
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::AllocReceiveBuffer)));
    }

    #[test]
    fn test_busmon_receive_data_bytes() {
        let mut ctx = BusMonitorContext::new();
        ctx.state = BusMonitorState::Active;

        // Receive several data bytes
        for i in 0u8..5 {
            let actions = process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0x10 + i));
            assert_eq!(ctx.state, BusMonitorState::Active);
            assert_eq!(ctx.bytes_received, (i + 1) as usize);

            let action_vec: Vec<_> = actions.iter().collect();
            assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::StoreReceivedByte(_))));
            assert!(
                action_vec
                    .iter()
                    .any(|a| matches!(a, BusMonitorAction::ReceivedByte { byte_type: BusMonitorByteType::Data, .. }))
            );
            assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::StartTimer(_))));
        }
    }

    #[test]
    fn test_busmon_frame_complete_on_ack() {
        let mut ctx = BusMonitorContext::new();
        ctx.state = BusMonitorState::Active;

        // Receive some data bytes
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0xBC));
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0x11));
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0x01));
        assert_eq!(ctx.bytes_received, 3);

        // Receive ACK - should complete the frame
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(BUSMON_ACK));

        assert_eq!(ctx.bytes_received, 0); // Reset after frame complete
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(
            action_vec
                .iter()
                .any(|a| matches!(a, BusMonitorAction::ReceivedByte { byte_type: BusMonitorByteType::Ack, .. }))
        );
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::FrameComplete)));
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::ForwardFrame)));
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::AllocReceiveBuffer)));
    }

    #[test]
    fn test_busmon_frame_complete_on_nack() {
        let mut ctx = BusMonitorContext::new();
        ctx.state = BusMonitorState::Active;

        // Receive some data bytes
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0xBC));
        assert_eq!(ctx.bytes_received, 1);

        // Receive NACK - should complete the frame
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(BUSMON_NACK));

        assert_eq!(ctx.bytes_received, 0);
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(
            action_vec
                .iter()
                .any(|a| matches!(a, BusMonitorAction::ReceivedByte { byte_type: BusMonitorByteType::Nack, .. }))
        );
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::FrameComplete)));
    }

    #[test]
    fn test_busmon_frame_complete_on_busy() {
        let mut ctx = BusMonitorContext::new();
        ctx.state = BusMonitorState::Active;

        // Receive some data bytes
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0xBC));
        assert_eq!(ctx.bytes_received, 1);

        // Receive BUSY - should complete the frame
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(BUSMON_BUSY));

        assert_eq!(ctx.bytes_received, 0);
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(
            action_vec
                .iter()
                .any(|a| matches!(a, BusMonitorAction::ReceivedByte { byte_type: BusMonitorByteType::Busy, .. }))
        );
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::FrameComplete)));
    }

    #[test]
    fn test_busmon_frame_complete_on_timeout() {
        let mut ctx = BusMonitorContext::new();
        ctx.state = BusMonitorState::Active;
        ctx.bytes_received = 5; // Simulate 5 bytes received

        // Timeout completes the frame (no ACK received - maybe collision)
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::Timer);

        assert_eq!(ctx.bytes_received, 0);
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::FrameComplete)));
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::ForwardFrame)));
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::AllocReceiveBuffer)));
    }

    #[test]
    fn test_busmon_disable() {
        let mut ctx = BusMonitorContext::new();
        ctx.state = BusMonitorState::Active;
        ctx.bytes_received = 3;

        // Disable bus monitor mode
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::Disable);

        assert_eq!(ctx.state, BusMonitorState::Disabled);
        assert_eq!(ctx.bytes_received, 0);
        assert!(!ctx.is_active());
        let action_vec: Vec<_> = actions.iter().collect();
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::SendReset)));
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::ReleaseReceiveBuffer)));
    }

    #[test]
    fn test_busmon_multiple_frames() {
        let mut ctx = BusMonitorContext::new();
        ctx.state = BusMonitorState::Active;

        // First frame: data bytes + ACK
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0xBC));
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0x11));
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0x01));
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(BUSMON_ACK));
        assert!(actions.iter().any(|a| matches!(a, BusMonitorAction::FrameComplete)));
        assert_eq!(ctx.bytes_received, 0);

        // Second frame: data bytes + NACK
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0xBC));
        process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(0x22));
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(BUSMON_NACK));
        assert!(actions.iter().any(|a| matches!(a, BusMonitorAction::FrameComplete)));
        assert_eq!(ctx.bytes_received, 0);
    }

    #[test]
    fn test_busmon_ack_byte_included_in_frame() {
        let mut ctx = BusMonitorContext::new();
        ctx.state = BusMonitorState::Active;

        // ACK byte should be stored as part of the frame
        let actions = process_busmon_event(&mut ctx, BusMonitorEvent::ReceivedByte(BUSMON_ACK));

        let action_vec: Vec<_> = actions.iter().collect();
        // The ACK byte should be stored before frame complete
        assert!(action_vec.iter().any(|a| matches!(a, BusMonitorAction::StoreReceivedByte(BUSMON_ACK))));
    }
}
