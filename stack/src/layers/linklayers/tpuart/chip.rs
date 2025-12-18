//! TPUART chip type definitions and capabilities
//!
//! This module defines the supported TPUART-compatible chips and their capabilities.
//! Different chips have different maximum frame sizes and feature sets.

/// Supported TPUART-compatible chip types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// NCN5120/E981: 256+ bytes (extended frames supported)
    pub const fn max_frame_size(&self) -> usize {
        match self {
            ChipType::Unknown => 64, // Conservative default
            ChipType::TpUart1 => 64,
            ChipType::TpUart2 => 64,
            ChipType::Ncn5120 => 256,
            ChipType::E981 => 256,
        }
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

    /// Whether this chip supports extended frames (>64 bytes)
    ///
    /// NCN5120 and E981 support extended frames but use different protocols:
    ///
    /// **NCN5120**: Uses offset command when crossing 64-byte boundaries
    /// - At each 64-byte boundary: Send `U_L_DataOffset.req | (index >> 6)`
    /// - Continue with normal `U_L_DATA_START`/`U_L_DATA_END` with 6-bit index
    ///
    /// **E981**: Uses special long frame commands for entire frame
    /// - First byte: Normal `U_L_DATA_START` (0x80)
    /// - Bytes 1 to N-1: `E981_LONG_DATA_CONTINUE` (0xC0) + full byte index
    /// - Last byte: `E981_LONG_DATA_END` (0xD0) + full byte index
    pub const fn supports_extended_frames(&self) -> bool {
        matches!(self, ChipType::Ncn5120 | ChipType::E981)
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

/// Configuration for TPUART retry behavior
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
        assert_eq!(ChipType::E981.max_frame_size(), 256);
    }

    #[test]
    fn test_retry_config_encode() {
        let config = RetryConfig::new(3, 3);
        assert_eq!(config.encode(), 0x63); // (3 << 5) | 3 = 0x60 | 0x03

        let config = RetryConfig::new(7, 7);
        assert_eq!(config.encode(), 0xE7); // (7 << 5) | 7 = 0xE0 | 0x07
    }
}
