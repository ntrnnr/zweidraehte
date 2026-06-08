//! KNX protocol buffer sizing constants.
//!
//! These constants define APDU sizes and buffer calculations used by both
//! device stacks and client implementations.
//!
//! # Plaintext vs secure APDU budgets
//!
//! `PID_MAX_APDU_LENGTH` (spec 03/05/01 §4.3.7) is a **wire-level** value:
//! the maximum size of the complete APDU a device can send or receive,
//! measured from the TPCI byte. The KNX Data Secure envelope
//! (TPCI/APCI(2) + SCF(1) + SeqNr(6) + plaintext-APDU + MAC(4)) *is*
//! the APDU when the frame is secure — not a wrapper around it
//! (spec 03/03/07 Annex C.1.1 shows the secure APDU starting with
//! `0x03 0xF1` for `T_Data_Individual` + `A_Secure`). A device that
//! advertises `PID_MAX_APDU_LENGTH = 254` is committing to buffers
//! that hold a full 254-byte APDU regardless of whether it is plain
//! or secure.
//!
//! [`buffer_size_for_apdu`] sizes for the wire APDU and therefore
//! naturally accommodates secure frames at the same budget — no
//! secure-specific sizing is required. Callers that need to know the
//! plaintext-content budget after secure wrapping can compute it as
//! `max_apdu - `[`apdu::secure::OVERHEAD`](crate::messages::apdu::secure::OVERHEAD).

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

/// Recommended `StackDefinition::MAX_APDU_LENGTH` for a KNX-RF System B device
/// (mask 27B0h).
///
/// Like [`MAX_APDU_LENGTH_TP1_STANDARD`] / [`MAX_APDU_LENGTH_EXTENDED`], this is
/// a value a device assigns to its compile-time `MAX_APDU_LENGTH` — which sizes
/// the buffers and is what PID 56 reports. It is *not* enforced by the link
/// layer; a device is free to choose another value (the RF link layer caps the
/// physically framable ceiling at `knxrf::MAX_SUPPORTED_APDU`).
///
/// Unlike TP1, a KNX-RF Standard frame carries an 8-bit length field and splits
/// the LSDU across multiple 16-octet data blocks (KNX 03/02/05 §6.1.2.4), so it
/// is **not** limited to the 15-octet TP1 standard-frame APDU. The mask 27B0h
/// profile (KNX 06/01/35 §3.2) mandates `APDU-length ≥ 15`; that 15 is a floor,
/// not the value a real device reports.
///
/// We pick **55**, the established KNX long-frame APDU length, because the
/// 15-octet floor is unusable with KNX Data Secure: the secure envelope costs
/// [`apdu::secure::OVERHEAD`](crate::messages::apdu::secure::OVERHEAD) = 13
/// octets, so a 15-octet ceiling leaves only 2 octets of plaintext — too little
/// for even a 1-octet secured `A_GroupValue_Write`. 55 leaves 42 octets of
/// secure plaintext budget while still fitting the RF link layer's frame
/// buffers (see `encoding::rf::max_telegram_len`).
pub const MAX_APDU_LENGTH_RF: u16 = 55;

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
///
/// **KNX-RF wire frames are intentionally excluded.** The RF block-1 header
/// (length / C / Esc / RF-info + 6-octet SN/DoA = 10 octets) is larger than
/// this, but RF wire telegrams never reach a pool buffer: the radio driver
/// strips preamble, Manchester coding, and the FT3 block CRCs below the
/// `RfTransceiver` boundary, and the RF link layer converts to the 6-octet
/// internal header in its own scratch buffers before allocating from the pool.
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
/// - Maximum APDU — this covers both plain and secure frames, since
///   the Data Secure envelope is part of the APDU (see module docs).
/// - Headroom for protocol headers (16 bytes)
pub const fn buffer_size_for_apdu(max_apdu_length: u16) -> usize {
    max_apdu_length as usize + FRAME_OVERHEAD + DEFAULT_HEADROOM
}

/// Maximum internal-format `msg_len` allowed for an outgoing response
/// at the given wire APDU ceiling.
///
/// `max_apdu_length` is the NPDU length-field value (spec 03/05/01
/// §4.3.7) — the NPDU on the wire is `TPCI + APDU`, encoded as
/// `total_wire_bytes − 1`. The internal-format frame adds the 6-byte
/// frame header (offset `MSG_TPCI`), so the corresponding internal
/// `msg_len` ceiling is `MSG_TPCI + 1 + max_apdu_length`.
///
/// When `secure_envelope` is `true`, the ceiling shrinks by
/// [`apdu::secure::OVERHEAD`](crate::messages::apdu::secure::OVERHEAD)
/// to leave room for the KNX Data Secure envelope the outgoing frame
/// will carry (spec 03/03/07 Annex C.1.1).
///
/// Used by AL handlers to compare their `Response::msg_len(n)`
/// directly against the ceiling without redoing the header-offset
/// math at each call site.
pub const fn max_outgoing_msg_len(max_apdu_length: u16, secure_envelope: bool) -> usize {
    use crate::messages::apdu::secure::OVERHEAD;
    use crate::messages::knx::offsets::MSG_TPCI;
    let apdu = max_apdu_length as usize;
    let apdu = if secure_envelope { apdu.saturating_sub(OVERHEAD) } else { apdu };
    MSG_TPCI + 1 + apdu
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
