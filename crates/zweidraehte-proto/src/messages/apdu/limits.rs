//! Shared APDU length limits for KNX wire formats.
//!
//! These limits are independent of buffer allocation and headroom policies.

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
