//! TPUART chip type definitions and capabilities
//!
//! This module defines the supported TPUART-compatible chips and their capabilities.
//! Different chips have different maximum frame sizes and feature sets.

/// Supported TPUART-compatible chip types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChipType {
    /// Unknown chip type (before detection)
    #[default]
    Unknown,
    /// Siemens TPUART1 - original chip, no version command support
    TpUart1,
    /// Siemens TPUART2 - supports version command
    TpUart2,
    /// ON Semiconductor NCN5120/5121/5130
    Ncn5120,
    /// Elmos E981.03
    E981,
}

impl ChipType {
    /// Maximum frame size supported by this chip (including control byte and checksum)
    ///
    /// TPUART1/2: 64 bytes (standard frames only)
    /// NCN5120: 256 bytes (extended frames supported)
    /// E981: 264 bytes — the size of its transmit frame buffer
    /// (E981.03 datasheet, RAM table: 0x000...0x107)
    pub const fn max_frame_size(&self) -> usize {
        match self {
            ChipType::Unknown => 23, // Conservative default - minimum APDU of 15 bytes + TP1 overhead
            ChipType::TpUart1 => 64,
            ChipType::TpUart2 => 64,
            ChipType::Ncn5120 => 256,
            ChipType::E981 => 264,
        }
    }

    /// Maximum APDU length supported by this chip
    ///
    /// This is the value that should be reported via PID 56 (MAX_APDU_LENGTH)
    /// in the Device Object.
    ///
    /// For known chips that support Extended Frame Format (EFF), the max APDU
    /// is calculated from the buffer size minus the TP1 frame overhead.
    ///
    /// TP1 Extended Frame Format (on wire):
    /// - CTRL (1) + CTRL2 (1) + SRC (2) + DST (2) + LEN (1) + APDU (n) + CHK (1)
    /// - Total overhead: 8 bytes (7 header + 1 checksum)
    ///
    /// Results:
    /// - Unknown: 15 bytes (23 - 8, conservative fallback for standard TP1)
    /// - TPUART1/2: 56 bytes (64 - 8)
    /// - NCN5120: 248 bytes (256 - 8)
    /// - E981: 254 bytes (264 - 8 = 256, capped by the EFF length octet)
    pub const fn max_apdu_length(&self) -> u16 {
        // TP1 EFF overhead: CTRL(1) + CTRL2(1) + SRC(2) + DST(2) + LEN(1) + CHK(1) = 8 bytes
        let max = self.max_frame_size() - 8;
        // Cap at 254: the EFF length octet counts the characters *after* the
        // TPCI octet, values 0..=254 — 255 is reserved as an escape code
        // (03/02/02 §2.2.5.6).
        if max > 254 { 254 } else { max as u16 }
    }

    /// Whether this chip supports the U_Version.req command
    pub const fn supports_version_command(&self) -> bool {
        match self {
            ChipType::Unknown => false,
            ChipType::TpUart1 => false,
            ChipType::TpUart2 => true,
            ChipType::Ncn5120 => true,
            ChipType::E981 => true,
        }
    }

    /// Whether this chip supports register read/write (E981 only)
    pub const fn supports_register_access(&self) -> bool {
        matches!(self, ChipType::E981)
    }

    /// Whether this chip supports Extended Frame Format (EFF)
    ///
    /// EFF uses a different frame structure with an explicit length byte,
    /// allowing APDUs larger than the 14-byte limit of standard frames.
    /// All known TPUART-compatible chips support EFF.
    ///
    /// For unknown chips, we conservatively assume no EFF support.
    ///
    /// Note: This is different from [`Self::supports_long_frames`], which indicates
    /// support for frames longer than 64 bytes.
    pub const fn supports_extended_frame_format(&self) -> bool {
        // Unknown chip: conservatively assume no EFF support
        !matches!(self, ChipType::Unknown)
    }

    /// Whether this chip supports long frames (>64 bytes)
    ///
    /// Only NCN5120 and E981 have buffers large enough for frames >64 bytes.
    /// They use different protocols for long frame transmission:
    ///
    /// **NCN5120**: Uses offset command when crossing 64-byte boundaries
    /// - At each 64-byte boundary: Send `U_L_DataOffset.req | (index >> 6)`
    /// - Continue with normal `U_L_DATA_START`/`U_L_DATA_END` with 6-bit index
    ///
    /// **E981**: Uses special long frame commands for entire frame
    /// - First byte: Normal `U_L_DATA_START` (0x80)
    /// - Bytes 1 to N-1: `E981_LONG_DATA_CONTINUE` (0xC0) + full byte index
    /// - Last byte: `E981_LONG_DATA_END` (0xD0) + full byte index
    pub const fn supports_long_frames(&self) -> bool {
        matches!(self, ChipType::Ncn5120 | ChipType::E981)
    }

    /// Whether this chip supports extended frames (>64 bytes)
    ///
    /// Alias for [`Self::supports_long_frames`] for backwards compatibility.
    pub const fn supports_extended_frames(&self) -> bool {
        self.supports_long_frames()
    }

    /// The chip's autonomous busy-mode service bytes, as
    /// `(activate, deactivate)`.
    ///
    /// In busy mode the transceiver answers addressed frames with a
    /// BUSY acknowledge *by itself*, without MCU involvement — the only
    /// way to keep BUSY responses flowing while the MCU is stalled in a
    /// blocking flash erase/write (see
    /// [`ChipBusyRequest`](super::busy::ChipBusyRequest)).
    ///
    /// - TPUART 1/2 and the TPUART-compatible E981.03:
    ///   `U_ActivateBusymode` (0x21) / `U_ResetBusymode` (0x22). The
    ///   chip auto-leaves busy mode after ~700 ms; our flash stalls are
    ///   well inside, and the explicit reset is sent regardless.
    /// - NCN5120/5121/5130: `U_SetBusy` (0x03) / `U_QuitBusy` (0x04),
    ///   per the ON Semi datasheet.
    ///   TODO: verify that busy responses do not additionally require
    ///   the auto-acknowledge address (`U_SetAddress`) to be
    ///   programmed — we acknowledge manually and never set it.
    ///
    /// `None` for unknown chips — the storage glue then has only the
    /// software busy gate, which cannot answer during a full stall.
    pub const fn busy_mode_commands(&self) -> Option<(u8, u8)> {
        match self {
            ChipType::Unknown => None,
            ChipType::TpUart1 | ChipType::TpUart2 | ChipType::E981 => Some((0x21, 0x22)),
            ChipType::Ncn5120 => Some((0x03, 0x04)),
        }
    }

    /// Human-readable name for the chip
    pub const fn name(&self) -> &'static str {
        match self {
            ChipType::Unknown => "Unknown",
            ChipType::TpUart1 => "TPUART1",
            ChipType::TpUart2 => "TPUART2",
            ChipType::Ncn5120 => "NCN5120",
            ChipType::E981 => "E981",
        }
    }
}

/// Transient parameter object encoding the TPUART `U_SetMaxRstCnt` command.
///
/// Despite the `*Config` suffix this is **not** persisted — it is a
/// bundle of NAK / BUSY retry counts used at the moment the chip command
/// is issued. The persisted source of these values is
/// [`Tp1ExtensionConfig`](crate::bcus::system_b::extensions::tp1::Tp1ExtensionConfig),
/// whose runtime counterpart
/// [`Tp1ExtensionState`](crate::bcus::system_b::extensions::tp1::Tp1ExtensionState)
/// materialises a `RetryConfig` when it programs the chip.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Number of retries after receiving NACK (0-7)
    pub nak_retry_count: u8,
    /// Number of retries after receiving BUSY (0-7)
    pub busy_retry_count: u8,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self { nak_retry_count: 3, busy_retry_count: 3 }
    }
}

impl RetryConfig {
    /// Create a new retry configuration
    pub const fn new(nak_retry: u8, busy_retry: u8) -> Self {
        Self { nak_retry_count: nak_retry & 0x07, busy_retry_count: busy_retry & 0x07 }
    }

    /// Encode retry counts for U_SetMaxRstCnt command
    pub const fn encode(&self) -> u8 {
        ((self.busy_retry_count & 0x07) << 5) | (self.nak_retry_count & 0x07)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chip_max_frame_size() {
        assert_eq!(ChipType::TpUart1.max_frame_size(), 64);
        assert_eq!(ChipType::TpUart2.max_frame_size(), 64);
        assert_eq!(ChipType::Ncn5120.max_frame_size(), 256);
        assert_eq!(ChipType::E981.max_frame_size(), 264);
    }

    #[test]
    fn test_chip_max_apdu_length() {
        // Unknown: 23 - 8 = 15 bytes (conservative fallback)
        assert_eq!(ChipType::Unknown.max_apdu_length(), 15);
        // TP1 EFF overhead: CTRL(1) + CTRL2(1) + SRC(2) + DST(2) + LEN(1) + CHK(1) = 8 bytes
        // TPUART1/2: 64 - 8 = 56
        assert_eq!(ChipType::TpUart1.max_apdu_length(), 56);
        assert_eq!(ChipType::TpUart2.max_apdu_length(), 56);
        // NCN5120: 256 - 8 = 248
        assert_eq!(ChipType::Ncn5120.max_apdu_length(), 248);
        // E981: 264 - 8 = 256, capped at 254 by the EFF length octet
        assert_eq!(ChipType::E981.max_apdu_length(), 254);
    }

    #[test]
    fn test_chip_supports_eff() {
        // Unknown chip: no EFF support (conservative)
        assert!(!ChipType::Unknown.supports_extended_frame_format());
        // All known chips support EFF
        assert!(ChipType::TpUart1.supports_extended_frame_format());
        assert!(ChipType::TpUart2.supports_extended_frame_format());
        assert!(ChipType::Ncn5120.supports_extended_frame_format());
        assert!(ChipType::E981.supports_extended_frame_format());
    }

    #[test]
    fn test_busy_mode_commands() {
        // TPUART family + the TPUART-compatible E981: U_ActivateBusymode /
        // U_ResetBusymode.
        assert_eq!(ChipType::TpUart1.busy_mode_commands(), Some((0x21, 0x22)));
        assert_eq!(ChipType::TpUart2.busy_mode_commands(), Some((0x21, 0x22)));
        assert_eq!(ChipType::E981.busy_mode_commands(), Some((0x21, 0x22)));
        // NCN5120 has its own service codes: U_SetBusy / U_QuitBusy.
        assert_eq!(ChipType::Ncn5120.busy_mode_commands(), Some((0x03, 0x04)));
        // Unknown chip: no autonomous busy mode.
        assert_eq!(ChipType::Unknown.busy_mode_commands(), None);
    }

    #[test]
    fn test_retry_config_encode() {
        let config = RetryConfig::new(3, 3);
        assert_eq!(config.encode(), 0x63); // (3 << 5) | 3 = 0x60 | 0x03

        let config = RetryConfig::new(7, 7);
        assert_eq!(config.encode(), 0xE7); // (7 << 5) | 7 = 0xE0 | 0x07
    }
}
