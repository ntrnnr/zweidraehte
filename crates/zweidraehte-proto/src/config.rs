//! KNX protocol buffer sizing constants.
//!
//! These constants define APDU sizes and buffer calculations used by both
//! device stacks and client implementations.

// ============================================================================
// APDU Size Constants
// ============================================================================

/// Maximum APDU length for standard TP1 without Extended Frame Format.
///
/// This is the baseline APDU size supported by all TP1 devices.
/// Standard frames can carry TPCI (1 byte) + up to 14 bytes of payload = 15 bytes.
pub const MAX_APDU_LENGTH_TP1_STANDARD: u16 = 15;

/// Maximum APDU length for TP1 with Extended Frame Format (EFF).
///
/// The NPDU length byte (1 byte) encodes TPCI + APDU. Maximum NPDU length
/// is 255 (= 1 byte TPCI + 254 bytes APDU), so the maximum APDU is 254.
/// This is also the maximum for KNX/IP devices.
pub const MAX_APDU_LENGTH_EXTENDED: u16 = 254;

/// Frame overhead in bytes.
///
/// This is the maximum overhead for any KNX frame format that may be stored
/// in a buffer. We use the cEMI header size since that's the largest:
///
/// **Internal format (6 bytes):**
/// - Control byte: 1
/// - Source address: 2
/// - Destination address: 2
/// - NPDU (hop count): 1
///
/// **cEMI format (9 bytes, without additional info):**
/// - Message code: 1
/// - Additional info length: 1 (value 0)
/// - Control field 1: 1
/// - Control field 2: 1
/// - Source address: 2
/// - Destination address: 2
/// - NPDU length: 1
///
/// **Extended TP1 format (7 bytes):**
/// - Control byte: 1
/// - Extended control: 1
/// - Source address: 2
/// - Destination address: 2
/// - Length: 1
///
/// Since received cEMI frames are copied into the buffer before conversion
/// to internal format (which happens in-place), the buffer capacity must
/// be able to hold the full cEMI frame.
pub const FRAME_OVERHEAD: usize = 9;

/// Default headroom for protocol headers.
///
/// This headroom is used for zero-copy prepending of headers:
/// - cEMI expansion: 3 bytes (msg_code + add_info_len + ctrl2)
/// - KNXnet/IP header: 6 bytes
/// - Extra margin: 7 bytes
pub const DEFAULT_HEADROOM: usize = 16;

/// Calculate the required buffer size for a given maximum APDU length.
///
/// The buffer must be large enough to hold:
/// - Frame overhead (9 bytes for cEMI compatibility)
/// - Maximum APDU
/// - Headroom for protocol headers (16 bytes)
pub const fn buffer_size_for_apdu(max_apdu_length: u16) -> usize {
    max_apdu_length as usize + FRAME_OVERHEAD + DEFAULT_HEADROOM
}

/// Common maximum APDU length configurations.
///
/// Use this enum to select a standard APDU size configuration for your device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MaxApduLength {
    /// Standard TP1 without EFF: 15 bytes (TPCI + 14 bytes payload)
    Tp1Standard = MAX_APDU_LENGTH_TP1_STANDARD,
    /// TP1 with EFF or KNX/IP: 254 bytes
    Extended = MAX_APDU_LENGTH_EXTENDED,
}

impl MaxApduLength {
    /// Get the maximum APDU length as a u16.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Calculate the required buffer size for this APDU length.
    pub const fn buffer_size(self) -> usize {
        buffer_size_for_apdu(self as u16)
    }
}

impl From<MaxApduLength> for u16 {
    fn from(len: MaxApduLength) -> Self {
        len as u16
    }
}
