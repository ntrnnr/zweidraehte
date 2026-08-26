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
/// Plain `[header | TPCI/APCI | data]` becomes
/// `[header | secure TPCI/APCI | SCF(1) | SeqNr(6) | plain APCI | data | MAC(4)]` —
/// a constant +13-byte growth regardless of payload size. The plaintext
/// APCI is preserved inside the encrypted payload so the receiver can
/// recover the service code after decryption; the Transport Control field
/// remains only in the outer TPDU.
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
    /// frame back to a plaintext frame by restoring the outer Transport
    /// Control field, moving the decrypted APDU to the TPCI position, and
    /// returning the new buffer length.
    ///
    /// The caller must resize the buffer to the returned length.
    pub fn unwrap_to_plaintext(self) -> usize {
        let payload_len = self.buf.len() - PAYLOAD - MAC_LEN;
        let plain_start = offsets::MSG_TPCI;
        // Application Layer §2 says an APDU is the TPDU reduced by its
        // Transport Control field. The protected payload therefore carries
        // zeroes in the upper six bits; restore those bits from the secure
        // envelope before handing the plain TPDU back to TL/AL plumbing.
        self.buf[PAYLOAD] = (self.buf[PAYLOAD] & 0x03) | (self.buf[plain_start] & 0xFC);
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

    // Shift the plain APDU right to make room for SCF + SeqNr. The source
    // buffer is a TPDU, so strip its Transport Control field after using it
    // to construct the outer secure header. Application Layer §5.1.3.3
    // specifies P as `000000b | Plain APDU`, not as the complete plain TPDU.
    buf.copy_within(plain_tpci_start..plain_end, PAYLOAD);

    // Write secure TPCI/APCI: preserve upper TPCI bits from the
    // plaintext (now at PAYLOAD), set APCI to SecureService (0x03F1).
    let tpci_high = buf[PAYLOAD] & 0xFC;
    buf[offsets::MSG_TPCI] = tpci_high | 0x03;
    buf[offsets::MSG_TPCI + 1] = 0xF1;
    buf[PAYLOAD] &= 0x03;

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

// ============================================================================
// S-A_Sync frame types
// ============================================================================

/// Byte offsets for S-A_Sync_Req fields within a message buffer.
///
/// Sync request layout (after header):
/// ```text
/// [TPCI/APCI(2)] [SCF(1)] [SeqNr_local(6)] [KNX_Serial(6)] [Challenge_enc(6)] [MAC(4)]
///  6..8           8        9..15             15..21           21..27              27..31
/// ```
///
/// Total frame length = 31 bytes.
pub mod sync {
    use super::*;

    /// Total frame length of an S-A_Sync_Req or S-A_Sync_Res.
    pub const FRAME_LEN: usize = 31;

    /// Byte offset where KNX Serial Number starts in a sync request.
    pub const SERIAL_NUMBER: usize = PAYLOAD; // 15

    /// Byte offset where the encrypted challenge starts in a sync request.
    pub const CHALLENGE: usize = PAYLOAD + 6; // 21

    /// Byte offset where Challenge XOR Random starts in a sync response
    /// (same position as SeqNr in the general secure frame layout).
    pub const CHALLENGE_XOR_RANDOM: usize = SEQ_NR; // 9

    /// Byte offset where the encrypted SeqNr_remote starts in a sync response.
    pub const SEQ_NR_REMOTE: usize = PAYLOAD; // 15

    /// Byte offset where the encrypted SeqNr_local starts in a sync response.
    pub const SEQ_NR_LOCAL: usize = PAYLOAD + 6; // 21
}

/// Read-only view of an S-A_Sync_Req frame.
pub struct SyncReqRef<'a> {
    buf: &'a [u8],
}

impl<'a> SyncReqRef<'a> {
    /// Parse a sync request from a raw message buffer.
    ///
    /// Validates that the frame is exactly 31 bytes.
    pub fn parse(buf: &'a [u8]) -> Result<Self, SecureApduError> {
        if buf.len() < sync::FRAME_LEN {
            return Err(SecureApduError::TooShort);
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

    /// 6-byte SeqNr_local (sender's assumed next SeqNr for the device).
    pub fn seq_nr_local(&self) -> [u8; 6] {
        let mut seq = [0u8; 6];
        seq.copy_from_slice(&self.buf[SEQ_NR..SEQ_NR + 6]);
        seq
    }

    /// 6-byte KNX Serial Number (target device serial for broadcast, or 0 for P2P).
    pub fn knx_serial_number(&self) -> [u8; 6] {
        let mut sn = [0u8; 6];
        sn.copy_from_slice(&self.buf[sync::SERIAL_NUMBER..sync::SERIAL_NUMBER + 6]);
        sn
    }

    /// Mutable slice of the 6-byte encrypted challenge region (for in-place decryption).
    /// Must use `parse_mut` to get a mutable reference.
    pub fn challenge(&self) -> &[u8] {
        &self.buf[sync::CHALLENGE..sync::CHALLENGE + 6]
    }

    /// 4-byte MAC.
    pub fn mac(&self) -> [u8; 4] {
        let mut mac = [0u8; 4];
        mac.copy_from_slice(&self.buf[self.buf.len() - MAC_LEN..]);
        mac
    }

    /// Source address from the message header.
    pub fn src(&self) -> u16 {
        u16::from_be_bytes([self.buf[offsets::MSG_SOURCE_ADDR], self.buf[offsets::MSG_SOURCE_ADDR + 1]])
    }

    /// Destination address from the message header.
    pub fn dst(&self) -> u16 {
        u16::from_be_bytes([self.buf[offsets::MSG_DEST_ADDR], self.buf[offsets::MSG_DEST_ADDR + 1]])
    }

    /// Address type byte (bit 7 of NPDU byte).
    pub fn addr_type(&self) -> u8 {
        self.buf[offsets::MSG_ADDR_TYPE] & 0x80
    }

    /// TPCI/APCI field.
    pub fn tpci_apci(&self) -> u16 {
        u16::from_be_bytes([self.buf[offsets::MSG_TPCI], self.buf[offsets::MSG_TPCI + 1]])
    }

    /// Build a [`CcmContext`] for verifying this sync request.
    ///
    /// The `seq_nr` in the context is the SeqNr_local from the request
    /// (used as the nonce in B0/Ctr blocks).
    pub fn ccm_context(&self) -> CcmContext {
        CcmContext {
            seq_nr: self.seq_nr_local(),
            src: self.src(),
            dst: self.dst(),
            addr_type: self.addr_type(),
            tpci_apci: self.tpci_apci(),
        }
    }
}

/// Read-only view of an S-A_Sync_Res frame.
///
/// This is the tool/client-role counterpart to [`SyncReqRef`]: the side
/// that sent an S-A_Sync_Req parses the device's response with this view,
/// recovers `Random = challenge XOR challenge_xor_random`, and verifies
/// and decrypts the payload with [`ccm::verify_and_decrypt_sync_res`]
/// (nonce = Random, not a sequence number).
///
/// Sync response layout (after header):
/// ```text
/// [TPCI/APCI(2)] [SCF(1)] [Chal^Rand(6)] [SeqNr_remote(6)] [SeqNr_local(6)] [MAC(4)]
///  6..8           8        9..15           15..21             21..27           27..31
/// ```
pub struct SyncResRef<'a> {
    buf: &'a [u8],
}

impl<'a> SyncResRef<'a> {
    /// Parse a sync response from a raw message buffer.
    ///
    /// Validates that the frame is at least 31 bytes.
    pub fn parse(buf: &'a [u8]) -> Result<Self, SecureApduError> {
        if buf.len() < sync::FRAME_LEN {
            return Err(SecureApduError::TooShort);
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

    /// 6-byte Challenge XOR Random field. XOR with the challenge sent in
    /// the S-A_Sync_Req to recover the device's Random (the CCM nonce).
    pub fn challenge_xor_random(&self) -> [u8; 6] {
        let mut cxr = [0u8; 6];
        cxr.copy_from_slice(&self.buf[sync::CHALLENGE_XOR_RANDOM..sync::CHALLENGE_XOR_RANDOM + 6]);
        cxr
    }

    /// The 12-byte encrypted payload: SeqNr_remote(6) + SeqNr_local(6).
    /// Copy for in-place decryption with [`ccm::verify_and_decrypt_sync_res`].
    pub fn payload_enc(&self) -> [u8; 12] {
        let mut payload = [0u8; 12];
        payload.copy_from_slice(&self.buf[sync::SEQ_NR_REMOTE..sync::SEQ_NR_REMOTE + 12]);
        payload
    }

    /// 4-byte MAC.
    pub fn mac(&self) -> [u8; 4] {
        let mut mac = [0u8; 4];
        mac.copy_from_slice(&self.buf[sync::FRAME_LEN - MAC_LEN..sync::FRAME_LEN]);
        mac
    }

    /// Source address from the message header.
    pub fn src(&self) -> u16 {
        u16::from_be_bytes([self.buf[offsets::MSG_SOURCE_ADDR], self.buf[offsets::MSG_SOURCE_ADDR + 1]])
    }

    /// Destination address from the message header.
    pub fn dst(&self) -> u16 {
        u16::from_be_bytes([self.buf[offsets::MSG_DEST_ADDR], self.buf[offsets::MSG_DEST_ADDR + 1]])
    }

    /// Address type byte (bit 7 of NPDU byte).
    pub fn addr_type(&self) -> u8 {
        self.buf[offsets::MSG_ADDR_TYPE] & 0x80
    }

    /// TPCI/APCI field.
    pub fn tpci_apci(&self) -> u16 {
        u16::from_be_bytes([self.buf[offsets::MSG_TPCI], self.buf[offsets::MSG_TPCI + 1]])
    }
}

/// Build an S-A_Sync_Res frame in a buffer.
///
/// Writes header, SCF, challenge_xor_random, and plaintext
/// SeqNr_remote + SeqNr_local. The caller must then encrypt the
/// payload region (bytes 15..27) and write the MAC (bytes 27..31)
/// using [`ccm::encrypt_and_mac_sync_res`].
///
/// `buf` must be at least 31 bytes.
///
/// Returns the byte offset where the MAC should be written (27).
// The arguments are the fields written to the fixed wire layout. Keeping them
// explicit lets callers build the frame without allocating an intermediate.
#[allow(clippy::too_many_arguments)]
pub fn build_sync_response(
    buf: &mut [u8],
    ctrl_byte: u8,
    src: u16,
    dst: u16,
    npdu_byte: u8,
    tpci_high: u8,
    scf_byte: u8,
    challenge_xor_random: &[u8; 6],
    seq_nr_remote: &[u8; 6],
    seq_nr_local: &[u8; 6],
) -> usize {
    assert!(buf.len() >= sync::FRAME_LEN, "buffer too small for sync response");

    // Header: CTRL(1) + SRC(2) + DST(2) + NPDU(1)
    buf[0] = ctrl_byte;
    buf[offsets::MSG_SOURCE_ADDR..offsets::MSG_SOURCE_ADDR + 2].copy_from_slice(&src.to_be_bytes());
    buf[offsets::MSG_DEST_ADDR..offsets::MSG_DEST_ADDR + 2].copy_from_slice(&dst.to_be_bytes());
    buf[offsets::MSG_ADDR_TYPE] = npdu_byte;

    // TPCI/APCI: preserve TPCI high bits, set Secure APCI (0x03F1).
    buf[offsets::MSG_TPCI] = (tpci_high & 0xFC) | 0x03;
    buf[offsets::MSG_TPCI + 1] = 0xF1;

    // SCF
    buf[SCF] = scf_byte;

    // Challenge XOR Random (6 bytes, plaintext — goes where SeqNr normally is)
    buf[SEQ_NR..SEQ_NR + 6].copy_from_slice(challenge_xor_random);

    // Plaintext payload: SeqNr_remote(6) + SeqNr_local(6)
    buf[sync::SEQ_NR_REMOTE..sync::SEQ_NR_REMOTE + 6].copy_from_slice(seq_nr_remote);
    buf[sync::SEQ_NR_LOCAL..sync::SEQ_NR_LOCAL + 6].copy_from_slice(seq_nr_local);

    // Return MAC offset. Caller writes 4 bytes of MAC here.
    sync::FRAME_LEN - MAC_LEN
}

/// Build an S-A_Sync_Req frame in `buf`.
///
/// Writes header + Secure APCI + SCF + SeqNr_local + KNX_Serial +
/// plaintext Challenge. The caller must then encrypt the challenge
/// region (bytes 21..27) and write the MAC (bytes 27..31) using
/// [`ccm::encrypt_and_mac_sync_req`].
///
/// `buf` must be at least 31 bytes.
///
/// Returns the byte offset where the MAC should be written (27).
// This is the request counterpart to `build_sync_response`, with the same
// allocation-free wire-field interface.
#[allow(clippy::too_many_arguments)]
pub fn build_sync_request(
    buf: &mut [u8],
    ctrl_byte: u8,
    src: u16,
    dst: u16,
    npdu_byte: u8,
    tpci_high: u8,
    scf_byte: u8,
    seq_nr_local: &[u8; 6],
    knx_serial_number: &[u8; 6],
    challenge: &[u8; 6],
) -> usize {
    assert!(buf.len() >= sync::FRAME_LEN, "buffer too small for sync request");

    // Header: CTRL(1) + SRC(2) + DST(2) + NPDU(1)
    buf[0] = ctrl_byte;
    buf[offsets::MSG_SOURCE_ADDR..offsets::MSG_SOURCE_ADDR + 2].copy_from_slice(&src.to_be_bytes());
    buf[offsets::MSG_DEST_ADDR..offsets::MSG_DEST_ADDR + 2].copy_from_slice(&dst.to_be_bytes());
    buf[offsets::MSG_ADDR_TYPE] = npdu_byte;

    // TPCI/APCI: preserve TPCI high bits, set Secure APCI (0x03F1).
    buf[offsets::MSG_TPCI] = (tpci_high & 0xFC) | 0x03;
    buf[offsets::MSG_TPCI + 1] = 0xF1;

    // SCF
    buf[SCF] = scf_byte;

    // SeqNr_local (6 bytes — sender's current sending sequence number)
    buf[SEQ_NR..SEQ_NR + 6].copy_from_slice(seq_nr_local);

    // KNX Serial Number (6 bytes — all-zero for P2P, device serial for broadcast)
    buf[sync::SERIAL_NUMBER..sync::SERIAL_NUMBER + 6].copy_from_slice(knx_serial_number);

    // Plaintext challenge (6 bytes — will be encrypted in-place by caller)
    buf[sync::CHALLENGE..sync::CHALLENGE + 6].copy_from_slice(challenge);

    // Return MAC offset. Caller writes 4 bytes of MAC here.
    sync::FRAME_LEN - MAC_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ccm;

    // Annex C.1.4 material: SA = FF00h, DA = FF67h, TPCI/APCI = 43F1h,
    // SCF = 93h (Tool + A+C + SyncRes), Challenge = 000000000003h,
    // Random = AAAAAAAAAAAAh, expected ciphertext 9c023ad25e146470693e638d,
    // expected MAC 5b70cac4 under the spec tool key.
    const TOOL_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    const CHALLENGE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
    const RANDOM: [u8; 6] = [0xAA; 6];
    const SCF_SYNC_RES: u8 = 0x93;

    /// Build the C.1.4 sync response as it would arrive on the wire.
    fn c1_4_frame() -> [u8; sync::FRAME_LEN] {
        let mut cxr = [0u8; 6];
        for i in 0..6 {
            cxr[i] = CHALLENGE[i] ^ RANDOM[i];
        }
        let mut payload: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // SeqNr_remote
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // SeqNr_local
        ];
        let mac =
            ccm::encrypt_and_mac_sync_res(&TOOL_KEY, &RANDOM, 0xFF00, 0xFF67, 0x00, 0x43F1, SCF_SYNC_RES, &mut payload);

        let mut buf = [0u8; sync::FRAME_LEN];
        let mac_offset = build_sync_response(
            &mut buf,
            0xB0,
            0xFF00,
            0xFF67,
            0x0E, // NPDU byte: individual address (bit 7 clear), length field
            0x43,
            SCF_SYNC_RES,
            &cxr,
            &payload[0..6].try_into().expect("6-byte slice"),
            &payload[6..12].try_into().expect("6-byte slice"),
        );
        buf[mac_offset..mac_offset + MAC_LEN].copy_from_slice(&mac);
        buf
    }

    #[test]
    fn sync_res_ref_parses_annex_c1_4() {
        let frame = c1_4_frame();
        let res = SyncResRef::parse(&frame).expect("31-byte frame parses");

        assert_eq!(res.scf_byte(), SCF_SYNC_RES);
        let scf = res.scf().expect("valid SCF");
        assert!(scf.tool_access);
        assert!(scf.confidentiality);
        assert_eq!(res.src(), 0xFF00);
        assert_eq!(res.dst(), 0xFF67);
        assert_eq!(res.addr_type(), 0x00);
        assert_eq!(res.tpci_apci(), 0x43F1);
        assert_eq!(res.mac(), [0x5b, 0x70, 0xca, 0xc4]);
        assert_eq!(res.payload_enc(), [0x9c, 0x02, 0x3a, 0xd2, 0x5e, 0x14, 0x64, 0x70, 0x69, 0x3e, 0x63, 0x8d]);

        // Recover Random from the challenge and decrypt — the full client-side flow.
        let cxr = res.challenge_xor_random();
        let mut random = [0u8; 6];
        for i in 0..6 {
            random[i] = CHALLENGE[i] ^ cxr[i];
        }
        assert_eq!(random, RANDOM);

        let mut payload = res.payload_enc();
        ccm::verify_and_decrypt_sync_res(
            &TOOL_KEY,
            &random,
            res.src(),
            res.dst(),
            res.addr_type(),
            res.tpci_apci(),
            res.scf_byte(),
            &mut payload,
            &res.mac(),
        )
        .expect("C.1.4 MAC verifies");
        assert_eq!(&payload[0..6], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x03], "SeqNr_remote");
        assert_eq!(&payload[6..12], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x04], "SeqNr_local");
    }

    #[test]
    fn sync_res_ref_too_short_rejected() {
        let frame = c1_4_frame();
        assert!(matches!(SyncResRef::parse(&frame[..30]), Err(SecureApduError::TooShort)));
    }

    #[test]
    fn connected_wrap_keeps_transport_control_outside_plain_apdu() {
        let mut frame = [0u8; 32];
        frame[..8].copy_from_slice(&[0xB0, 0x10, 0x02, 0x10, 0x0B, 0x00, 0x4C, 0x00]);

        let layout = wrap_plaintext(&mut frame, 8, 0x90, &[0, 0, 0, 0, 0, 1]).expect("secure frame fits");

        assert_eq!(&frame[6..9], &[0x4F, 0xF1, 0x90], "outer TPDU retains connected S=3");
        assert_eq!(&frame[layout.payload_start..layout.payload_end], &[0x00, 0x00], "P contains only the APDU");
    }

    #[test]
    fn connected_unwrap_restores_transport_control_from_envelope() {
        let mut frame = [0u8; 21];
        frame[6..9].copy_from_slice(&[0x4F, 0xF1, 0x90]);
        frame[PAYLOAD..PAYLOAD + 2].copy_from_slice(&[0x00, 0x00]);

        let len = SecureApduMut::parse(&mut frame).expect("secure frame parses").unwrap_to_plaintext();

        assert_eq!(len, 8);
        assert_eq!(&frame[6..8], &[0x4C, 0x00]);
    }
}
