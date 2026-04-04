//! Typed Secure APDU (S-A_Data) frame parser and builder.
//!
//! KNX Data Secure wraps plaintext APDUs in a secure envelope:
//!
//! ```text
//! [Header(6)][TPCI/APCI(2)][SCF(1)][SeqNr(6)][Payload(N)][MAC(4)]
//!  0..6       6..8          8       9..15     15..end-4   end-4..end
//! ```
//!
//! The TPCI/APCI is always `0x03F1` (SecureService). The payload is
//! either plaintext (auth-only) or ciphertext (auth+conf). The MAC is
//! always 4 bytes (truncated AES-CCM tag).
//!
//! # Usage
//!
//! **Incoming (parse + decrypt):**
//! ```rust,ignore
//! let secure = SecureApduRef::parse(buf)?;
//! let seq_nr = secure.seq_nr();
//! let ctx = secure.ccm_context(src_ia);
//! // ... key lookup, then:
//! let mut secure = SecureApduMut::parse(buf)?;
//! ccm::verify_and_decrypt(key, &ctx, secure.scf_byte(), secure.payload_mut(), &secure.mac());
//! let new_len = secure.unwrap_to_plaintext();
//! ```
//!
//! **Outgoing (wrap + encrypt):**
//! ```rust,ignore
//! let new_len = wrap_plaintext(buf, current_len, scf_byte, &seq_nr)?;
//! // ... encrypt payload at buf[PAYLOAD..PAYLOAD+plain_payload_len], append MAC
//! ```

use super::super::knx::offsets;
use crate::crypto::ccm::CcmContext;
use crate::crypto::scf::{InvalidScf, SecurityControlField};

// ============================================================================
// Constants
// ============================================================================

/// Byte offset of the SCF field within a secure frame.
pub const SCF: usize = offsets::MSG_APDU; // 8

/// Byte offset of the 6-byte sequence number.
pub const SEQ_NR: usize = offsets::MSG_APDU + 1; // 9

/// Byte offset where the encrypted/authenticated payload starts.
pub const PAYLOAD: usize = offsets::MSG_APDU + 7; // 15

/// Length of the MAC (truncated AES-CCM authentication tag).
pub const MAC_LEN: usize = 4;

/// Bytes added by the secure envelope beyond the plaintext frame.
///
/// Secure header replaces the 2-byte TPCI/APCI with: TPCI/APCI(2) +
/// SCF(1) + SeqNr(6) = 9 bytes, then appends MAC(4). Net overhead
/// relative to the plaintext frame (which already has TPCI/APCI) is
/// 9 - 2 + 4 = 11 bytes... but the payload *includes* the original
/// TPCI/APCI, so total frame growth is SCF(1) + SeqNr(6) + MAC(4) = 11.
///
/// More precisely: `secure_len = plain_len + OVERHEAD` where `plain_len`
/// is measured from offset 0 (full frame including header).
///
/// In practice, the code measures plaintext from `MSG_TPCI` (offset 6),
/// and the secure frame from `MSG_TPCI` is `plain_payload_len + 13`:
/// TPCI/APCI(2) + SCF(1) + SeqNr(6) + plain_payload_len + MAC(4).
pub const OVERHEAD: usize = 13;

/// Minimum secure frame length (header + SCF + SeqNr + MAC, no payload).
pub const MIN_FRAME_LEN: usize = offsets::MSG_APCI + OVERHEAD; // 19

// ============================================================================
// Error
// ============================================================================

/// Error parsing a secure APDU frame.
#[derive(Debug, Clone, Copy)]
pub enum SecureApduError {
    /// Frame is too short to contain the secure envelope.
    TooShort,
    /// No room for payload between header and MAC.
    NoPayload,
}

// ============================================================================
// Read-only view
// ============================================================================

/// Read-only view of a secure APDU frame in a message buffer.
///
/// Provides named accessors for the SCF, sequence number, payload, and
/// MAC fields without manual byte offset arithmetic.
pub struct SecureApduRef<'a> {
    buf: &'a [u8],
}

impl<'a> SecureApduRef<'a> {
    /// Parse a secure APDU from a raw message buffer.
    ///
    /// The buffer must contain the full KNX message starting at offset 0
    /// (control byte). Returns an error if the frame is too short.
    pub fn parse(buf: &'a [u8]) -> Result<Self, SecureApduError> {
        if buf.len() < MIN_FRAME_LEN {
            return Err(SecureApduError::TooShort);
        }
        let payload_len = buf.len() - PAYLOAD - MAC_LEN;
        if payload_len < 2 {
            // Need at least 2 bytes for the inner TPCI/APCI.
            return Err(SecureApduError::NoPayload);
        }
        Ok(Self { buf })
    }

    /// Raw SCF byte.
    pub fn scf_byte(&self) -> u8 {
        self.buf[SCF]
    }

    /// Parsed Security Control Field.
    pub fn scf(&self) -> Result<SecurityControlField, InvalidScf> {
        SecurityControlField::parse(self.scf_byte())
    }

    /// 6-byte sequence number.
    pub fn seq_nr(&self) -> [u8; 6] {
        let mut seq = [0u8; 6];
        seq.copy_from_slice(&self.buf[SEQ_NR..SEQ_NR + 6]);
        seq
    }

    /// Encrypted (or plaintext, for auth-only) payload between header
    /// and MAC.
    pub fn payload(&self) -> &[u8] {
        &self.buf[PAYLOAD..self.buf.len() - MAC_LEN]
    }

    /// Length of the payload (excluding MAC).
    pub fn payload_len(&self) -> usize {
        self.buf.len() - PAYLOAD - MAC_LEN
    }

    /// 4-byte MAC (authentication tag).
    pub fn mac(&self) -> [u8; 4] {
        let mut mac = [0u8; 4];
        mac.copy_from_slice(&self.buf[self.buf.len() - MAC_LEN..]);
        mac
    }

    /// Destination address from the message header.
    pub fn dst(&self) -> u16 {
        u16::from_be_bytes([self.buf[offsets::MSG_DEST_ADDR], self.buf[offsets::MSG_DEST_ADDR + 1]])
    }

    /// Address type byte (bit 7 of NPDU byte).
    pub fn addr_type(&self) -> u8 {
        self.buf[offsets::MSG_ADDR_TYPE] & 0x80
    }

    /// TPCI/APCI as written in the secure frame (should be 0x03F1).
    pub fn tpci_apci(&self) -> u16 {
        u16::from_be_bytes([self.buf[offsets::MSG_TPCI], self.buf[offsets::MSG_TPCI + 1]])
    }

    /// Build a [`CcmContext`] for crypto operations.
    ///
    /// `src` is the source individual address — for incoming frames, read
    /// from the message header; for outgoing frames, use the device's own
    /// address.
    pub fn ccm_context(&self, src: u16) -> CcmContext {
        CcmContext {
            seq_nr: self.seq_nr(),
            src,
            dst: self.dst(),
            addr_type: self.addr_type(),
            tpci_apci: self.tpci_apci(),
        }
    }
}

// ============================================================================
// Mutable view
// ============================================================================

/// Mutable view of a secure APDU frame for in-place decryption.
pub struct SecureApduMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> SecureApduMut<'a> {
    /// Parse a mutable secure APDU from a raw message buffer.
    pub fn parse(buf: &'a mut [u8]) -> Result<Self, SecureApduError> {
        if buf.len() < MIN_FRAME_LEN {
            return Err(SecureApduError::TooShort);
        }
        Ok(Self { buf })
    }

    /// Raw SCF byte.
    pub fn scf_byte(&self) -> u8 {
        self.buf[SCF]
    }

    /// 6-byte sequence number.
    pub fn seq_nr(&self) -> [u8; 6] {
        let mut seq = [0u8; 6];
        seq.copy_from_slice(&self.buf[SEQ_NR..SEQ_NR + 6]);
        seq
    }

    /// 4-byte MAC (authentication tag).
    pub fn mac(&self) -> [u8; 4] {
        let mut mac = [0u8; 4];
        mac.copy_from_slice(&self.buf[self.buf.len() - MAC_LEN..]);
        mac
    }

    /// Mutable reference to the payload region (for in-place decryption).
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let end = self.buf.len() - MAC_LEN;
        &mut self.buf[PAYLOAD..end]
    }

    /// Immutable reference to the payload region (for auth-only MAC
    /// verification where the payload must not be modified).
    pub fn payload(&self) -> &[u8] {
        &self.buf[PAYLOAD..self.buf.len() - MAC_LEN]
    }

    /// After successful decryption/verification, collapse the secure
    /// frame back to a plaintext frame by moving the decrypted payload
    /// to the TPCI position and returning the new buffer length.
    ///
    /// The caller must resize the buffer to the returned length.
    pub fn unwrap_to_plaintext(self) -> usize {
        let payload_len = self.buf.len() - PAYLOAD - MAC_LEN;
        let plain_start = offsets::MSG_TPCI;
        self.buf.copy_within(PAYLOAD..PAYLOAD + payload_len, plain_start);
        plain_start + payload_len
    }
}

// ============================================================================
// Outgoing: wrap plaintext into secure frame
// ============================================================================

/// Wrap a plaintext message buffer into a secure frame in-place.
///
/// The buffer must contain a complete plaintext message. `buf_len` is
/// the current content length. The buffer's total capacity (`buf.len()`)
/// must be large enough to hold the secure frame (`buf_len + OVERHEAD -
/// header_already_present`... in practice `buf_len + 13 - 6 + 6 =
/// buf_len + 13`... no — the buffer is resized by the caller before
/// passing the slice).
///
/// This function:
/// 1. Shifts the plaintext payload right to make room for SCF + SeqNr
/// 2. Writes the secure TPCI/APCI (0x03F1), SCF, and SeqNr
/// 3. Returns `(payload_start, payload_end, mac_start)` offsets for
///    the caller to encrypt and append the MAC.
///
/// The caller is responsible for:
/// - Expanding the buffer to `buf_len + OVERHEAD` before calling
/// - Encrypting the payload region and writing the MAC after this returns
///
/// Returns `None` if the buffer is too small.
pub fn wrap_plaintext(
    buf: &mut [u8],
    plain_content_len: usize,
    scf_byte: u8,
    seq_nr: &[u8; 6],
) -> Option<SecureFrameLayout> {
    let plain_tpci_start = offsets::MSG_TPCI; // 6
    let plain_end = plain_content_len;
    let plain_payload_len = plain_end - plain_tpci_start;
    let needed_len = plain_tpci_start + plain_payload_len + OVERHEAD;

    if buf.len() < needed_len {
        return None;
    }

    // Shift plaintext payload right to make room for SCF + SeqNr.
    buf.copy_within(plain_tpci_start..plain_end, PAYLOAD);

    // Write secure TPCI/APCI: preserve upper TPCI bits from the
    // plaintext (now at PAYLOAD), set APCI to SecureService (0x03F1).
    let tpci_high = buf[PAYLOAD] & 0xFC;
    buf[offsets::MSG_TPCI] = tpci_high | 0x03;
    buf[offsets::MSG_TPCI + 1] = 0xF1;

    // Write SCF and sequence number.
    buf[SCF] = scf_byte;
    buf[SEQ_NR..SEQ_NR + 6].copy_from_slice(seq_nr);

    let payload_end = PAYLOAD + plain_payload_len;
    let mac_start = payload_end;

    Some(SecureFrameLayout { payload_start: PAYLOAD, payload_end, mac_start })
}

/// Byte offsets into the buffer returned by [`wrap_plaintext`].
///
/// The caller uses these to encrypt the payload region and write the MAC.
#[derive(Debug, Clone, Copy)]
pub struct SecureFrameLayout {
    /// Start of the (plaintext) payload to encrypt.
    pub payload_start: usize,
    /// End of the payload (exclusive).
    pub payload_end: usize,
    /// Where to write the 4-byte MAC.
    pub mac_start: usize,
}
