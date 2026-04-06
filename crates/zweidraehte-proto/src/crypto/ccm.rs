//! KNX-specific AES-128-CCM implementation.
//!
//! Implements the CCM algorithm as specified in KNX spec 03/03/07
//! Annex A, with KNX-specific B0 and Ctr block construction from
//! sections 5.1.3.2 (Figures 100–102).
//!
//! The MAC tag is always 4 bytes (32 bits), which is non-standard
//! for CCM (typically 8 or 16). This is why we implement CCM manually
//! rather than using a generic CCM crate.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

// ============================================================================
// Block Construction (KNX-specific)
// ============================================================================

/// Build the B0 block for CBC-MAC (Figure 100 in the spec).
///
/// ```text
/// Byte:  0..5   6..7   8..9   10   11   12..13   14   15
/// Field: SeqNr  SA     DA     00h  AT   TPCI/AP  00h  q
/// ```
///
/// - `seq_nr`: 6-byte sequence number (or Random for Sync.res)
/// - `src`, `dst`: source/destination individual addresses (big-endian)
/// - `addr_type`: AT byte — `A000EEEEb` where A = address type bit
///   from the KNX frame, EEEE = Extended Frame Format
/// - `tpci_apci`: 2-byte TPCI/APCI field (first 6 bits = TPCI,
///   last 10 bits = Secure APCI 0x3F1)
/// - `payload_len`: length of the payload P in bytes (q)
pub fn block_b0(seq_nr: &[u8; 6], src: u16, dst: u16, addr_type: u8, tpci_apci: u16, payload_len: u8) -> [u8; 16] {
    let mut b0 = [0u8; 16];
    b0[0..6].copy_from_slice(seq_nr);
    b0[6..8].copy_from_slice(&src.to_be_bytes());
    b0[8..10].copy_from_slice(&dst.to_be_bytes());
    // b0[10] = 0x00 (already zero)
    b0[11] = addr_type;
    b0[12..14].copy_from_slice(&tpci_apci.to_be_bytes());
    // b0[14] = 0x00 (already zero)
    b0[15] = payload_len;
    b0
}

/// Build the Ctr_j block for AES-CTR mode (Figure 102 in the spec).
///
/// ```text
/// Byte:  0..5   6..7   8..9   10..13  14    15
/// Field: SeqNr  SA     DA     00..00  01h   j
/// ```
///
/// - `j`: counter value (0 for Ctr0, incremented per block)
pub fn block_ctr(seq_nr: &[u8; 6], src: u16, dst: u16, j: u8) -> [u8; 16] {
    let mut ctr = [0u8; 16];
    ctr[0..6].copy_from_slice(seq_nr);
    ctr[6..8].copy_from_slice(&src.to_be_bytes());
    ctr[8..10].copy_from_slice(&dst.to_be_bytes());
    // ctr[10..13] = 0x00 (already zero)
    ctr[14] = 0x01;
    ctr[15] = j;
    ctr
}

// ============================================================================
// AES-ECB helper
// ============================================================================

/// Encrypt a single 16-byte block with AES-128-ECB.
fn aes_encrypt_block(key: &Aes128, block: &mut [u8; 16]) {
    use aes::cipher::generic_array::GenericArray;
    let b = GenericArray::from_mut_slice(block);
    key.encrypt_block(b);
}

// ============================================================================
// CBC-MAC (Annex A, steps 1–4)
// ============================================================================

/// Compute CBC-MAC over B0, then B1..Bn = PAD16(a | A | P).
///
/// Returns Y_n (the final CBC-MAC output block, 16 bytes).
///
/// - `a`: length of associated data A, as a 2-byte big-endian value
///   (since a < 2^16 - 2^8 for KNX, the "short" encoding is used)
/// - `assoc_data`: the associated data A
/// - `payload`: the payload P
fn cbc_mac(key: &Aes128, b0: &[u8; 16], assoc_data: &[u8], payload: &[u8]) -> [u8; 16] {
    // Step 3: Y0 = AES_K(B0)
    let mut y = *b0;
    aes_encrypt_block(key, &mut y);

    // Steps 2 + 4: Build B1..Bn = PAD16(a | A | P), then
    // Y_i = AES_K(Y_{i-1} XOR B_i) for i = 1..n
    //
    // We stream through the concatenation `a_bytes | A | P` in 16-byte
    // chunks, XOR-ing each chunk with the running Y value before encrypting.

    // The 2-byte length prefix for A.
    let a_len = assoc_data.len() as u16;
    let a_bytes = a_len.to_be_bytes();

    // Chain: [a_bytes(2)] [assoc_data] [payload], padded to 16-byte blocks.
    let mut chain = ChainedXorFeeder::new(&mut y);
    chain.feed(key, &a_bytes);
    chain.feed(key, assoc_data);
    chain.feed(key, payload);
    chain.finish(key);

    y
}

/// Helper that feeds byte streams into the CBC-MAC chain in 16-byte blocks,
/// handling cross-boundary buffering and padding.
struct ChainedXorFeeder<'a> {
    y: &'a mut [u8; 16],
    pos: usize, // position within current 16-byte block
}

impl<'a> ChainedXorFeeder<'a> {
    fn new(y: &'a mut [u8; 16]) -> Self {
        Self { y, pos: 0 }
    }

    /// Feed data into the chain. Processes complete blocks immediately.
    fn feed(&mut self, key: &Aes128, data: &[u8]) {
        for &byte in data {
            self.y[self.pos] ^= byte;
            self.pos += 1;
            if self.pos == 16 {
                aes_encrypt_block(key, self.y);
                self.pos = 0;
            }
        }
    }

    /// Pad the final partial block with zeros and encrypt.
    /// Does nothing if we're exactly on a block boundary.
    fn finish(&mut self, key: &Aes128) {
        if self.pos > 0 {
            // Remaining bytes in y[pos..16] are already XOR'd with 0 (no-op).
            aes_encrypt_block(key, self.y);
            self.pos = 0;
        }
    }
}

// ============================================================================
// CTR mode encryption (Annex A, steps 5–8)
// ============================================================================

/// XOR `data` with the CTR keystream.
///
/// The keystream S is constructed as: `LSB96(S0) | S1 | S2 | ...`
/// where S_j = AES_K(Ctr_j). The first 12 bytes come from S0 bytes
/// 4..16 (the MSB32 of S0 is reserved for the MAC), then full 16-byte
/// blocks from S1 onwards.
fn ctr_crypt(key: &Aes128, seq_nr: &[u8; 6], src: u16, dst: u16, data: &mut [u8]) {
    if data.is_empty() {
        return;
    }

    // S0: use bytes 4..16 (the LSB96 = rightmost 12 bytes)
    let mut s0 = block_ctr(seq_nr, src, dst, 0);
    aes_encrypt_block(key, &mut s0);
    let first_chunk = data.len().min(12);
    for i in 0..first_chunk {
        data[i] ^= s0[4 + i];
    }

    // S1, S2, ...: use all 16 bytes per block
    let mut offset = first_chunk;
    let mut j = 1u8;
    while offset < data.len() {
        let mut s = block_ctr(seq_nr, src, dst, j);
        aes_encrypt_block(key, &mut s);
        let chunk_len = (data.len() - offset).min(16);
        for i in 0..chunk_len {
            data[offset + i] ^= s[i];
        }
        offset += chunk_len;
        j = j.wrapping_add(1);
    }
}

/// Compute S0 = AES_K(Ctr0), used for encrypting the MAC tag.
fn compute_s0(key: &Aes128, seq_nr: &[u8; 6], src: u16, dst: u16) -> [u8; 16] {
    let mut s0 = block_ctr(seq_nr, src, dst, 0);
    aes_encrypt_block(key, &mut s0);
    s0
}

// ============================================================================
// Public API
// ============================================================================

/// Error type for cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CryptoError {
    /// MAC verification failed — the message has been tampered with
    /// or the wrong key was used.
    MacMismatch,
}

/// Parameters for KNX CCM block construction.
///
/// These are extracted from the KNX frame headers by the S-AL before
/// calling the crypto functions.
#[derive(Debug, Clone, Copy)]
pub struct CcmContext {
    /// 6-byte sequence number (or Random for Sync.res).
    pub seq_nr: [u8; 6],
    /// Source individual address.
    pub src: u16,
    /// Destination address (individual or group).
    pub dst: u16,
    /// AT byte: address type + Extended Frame Format bits.
    pub addr_type: u8,
    /// TPCI/APCI field (16 bits: 6-bit TPCI + 10-bit Secure APCI).
    pub tpci_apci: u16,
}

/// Compute a 4-byte MAC for authentication-only mode.
///
/// Per spec 5.1.3.4: A = SCF | 000000b | plain APDU, P = empty.
/// MAC = MSB32(Y_n) XOR MSB32(S0).
///
/// - `scf_byte`: the SCF byte
/// - `apdu_with_prefix`: the `000000b | plain APDU` data (the "plain APDU"
///   portion of the secure frame, including the leading zero bits)
pub fn compute_mac_auth_only(key: &[u8; 16], ctx: &CcmContext, scf_byte: u8, apdu_with_prefix: &[u8]) -> [u8; 4] {
    let cipher = Aes128::new(key.into());

    // For auth-only: P = empty, so q = 0.
    let b0 = block_b0(&ctx.seq_nr, ctx.src, ctx.dst, ctx.addr_type, ctx.tpci_apci, 0);

    // A = SCF | apdu_with_prefix (which is 000000b | plain APCI + data)
    // Construct A by chaining SCF byte + apdu_with_prefix.
    let mut y_n = *&b0;
    aes_encrypt_block(&cipher, &mut y_n);

    let a_len = (1 + apdu_with_prefix.len()) as u16;
    let a_bytes = a_len.to_be_bytes();

    let mut chain = ChainedXorFeeder::new(&mut y_n);
    chain.feed(&cipher, &a_bytes);
    chain.feed(&cipher, &[scf_byte]);
    chain.feed(&cipher, apdu_with_prefix);
    // P is empty, so no payload to feed.
    chain.finish(&cipher);

    // MAC = MSB32(Y_n) XOR MSB32(S0)
    let s0 = compute_s0(&cipher, &ctx.seq_nr, ctx.src, ctx.dst);
    let mut mac = [0u8; 4];
    for i in 0..4 {
        mac[i] = y_n[i] ^ s0[i];
    }
    mac
}

/// Encrypt payload and compute MAC for authentication + confidentiality mode.
///
/// Per spec 5.1.3.5: A = SCF, P = 000000b | plain APDU.
/// The payload is encrypted in-place. Returns the 4-byte MAC.
///
/// - `scf_byte`: the SCF byte (becomes A)
/// - `payload`: the `000000b | plain APDU` data (becomes P, encrypted in-place)
pub fn encrypt_and_mac(key: &[u8; 16], ctx: &CcmContext, scf_byte: u8, payload: &mut [u8]) -> [u8; 4] {
    let cipher = Aes128::new(key.into());

    // q = payload length
    let q = payload.len() as u8;
    let b0 = block_b0(&ctx.seq_nr, ctx.src, ctx.dst, ctx.addr_type, ctx.tpci_apci, q);

    // CBC-MAC: A = SCF (1 byte), P = payload
    let y_n = cbc_mac(&cipher, &b0, &[scf_byte], payload);

    // S0 for MAC encryption
    let s0 = compute_s0(&cipher, &ctx.seq_nr, ctx.src, ctx.dst);

    // MAC = MSB32(Y_n) XOR MSB32(S0)
    let mut mac = [0u8; 4];
    for i in 0..4 {
        mac[i] = y_n[i] ^ s0[i];
    }

    // Encrypt payload with CTR mode (Ctr1, Ctr2, ...)
    ctr_crypt(&cipher, &ctx.seq_nr, ctx.src, ctx.dst, payload);

    mac
}

/// Verify MAC and decrypt payload for authentication + confidentiality mode.
///
/// The payload is decrypted in-place. Returns `Ok(())` if the MAC matches,
/// or `Err(CryptoError::MacMismatch)` if authentication fails.
///
/// On MAC failure, the payload buffer content is undefined (partially
/// decrypted). The caller must not use it.
pub fn verify_and_decrypt(
    key: &[u8; 16],
    ctx: &CcmContext,
    scf_byte: u8,
    payload: &mut [u8],
    received_mac: &[u8; 4],
) -> Result<(), CryptoError> {
    let cipher = Aes128::new(key.into());

    // Step 1: Decrypt payload with CTR mode
    ctr_crypt(&cipher, &ctx.seq_nr, ctx.src, ctx.dst, payload);

    // Step 2: Decrypt received MAC: T_R = LSB32(C) XOR MSB32(S0)
    let s0 = compute_s0(&cipher, &ctx.seq_nr, ctx.src, ctx.dst);
    let mut decrypted_mac = [0u8; 4];
    for i in 0..4 {
        decrypted_mac[i] = received_mac[i] ^ s0[i];
    }

    // Step 3: Recompute CBC-MAC over decrypted payload
    let q = payload.len() as u8;
    let b0 = block_b0(&ctx.seq_nr, ctx.src, ctx.dst, ctx.addr_type, ctx.tpci_apci, q);
    let y_n = cbc_mac(&cipher, &b0, &[scf_byte], payload);

    // Step 4: Compare MSB32(Y_n) with decrypted MAC
    if y_n[0..4] == decrypted_mac[..] { Ok(()) } else { Err(CryptoError::MacMismatch) }
}

/// Verify MAC for authentication-only mode (payload is not encrypted).
///
/// Returns `Ok(())` if the MAC matches.
pub fn verify_mac_auth_only(
    key: &[u8; 16],
    ctx: &CcmContext,
    scf_byte: u8,
    apdu_with_prefix: &[u8],
    received_mac: &[u8; 4],
) -> Result<(), CryptoError> {
    let expected = compute_mac_auth_only(key, ctx, scf_byte, apdu_with_prefix);
    if expected == *received_mac { Ok(()) } else { Err(CryptoError::MacMismatch) }
}

// ============================================================================
// S-A_Sync-specific operations
// ============================================================================

/// Encrypt and MAC an outgoing S-A_Sync_Req.
///
/// Used by the test runner (local S-AL role) to build sync requests.
///
/// - A = SCF(1) + KNX_Serial_Number(6)
/// - P = Challenge(6)
/// - B0/Ctr nonce = SeqNr_local (in `ctx.seq_nr`)
///
/// `challenge` is encrypted in-place. Returns the 4-byte MAC.
pub fn encrypt_and_mac_sync_req(
    key: &[u8; 16],
    ctx: &CcmContext,
    scf_byte: u8,
    serial_number: &[u8; 6],
    challenge: &mut [u8],
) -> [u8; 4] {
    let cipher = Aes128::new(key.into());

    let q = challenge.len() as u8;
    let b0 = block_b0(&ctx.seq_nr, ctx.src, ctx.dst, ctx.addr_type, ctx.tpci_apci, q);

    // A = SCF(1) + SerialNumber(6) = 7 bytes.
    let mut assoc = [0u8; 7];
    assoc[0] = scf_byte;
    assoc[1..7].copy_from_slice(serial_number);

    let y_n = cbc_mac(&cipher, &b0, &assoc, challenge);

    let s0 = compute_s0(&cipher, &ctx.seq_nr, ctx.src, ctx.dst);

    let mut mac = [0u8; 4];
    for i in 0..4 {
        mac[i] = y_n[i] ^ s0[i];
    }

    ctr_crypt(&cipher, &ctx.seq_nr, ctx.src, ctx.dst, challenge);

    mac
}

/// Verify and decrypt an incoming S-A_Sync_Req.
///
/// Per spec 5.3.2 / Annex C.1.3:
/// - A = SCF(1) + KNX_Serial_Number(6)
/// - P = Challenge(6)
/// - B0/Ctr nonce = SeqNr_local from the request (in `ctx.seq_nr`)
///
/// On success, `challenge` contains the decrypted 6-byte challenge.
pub fn verify_and_decrypt_sync_req(
    key: &[u8; 16],
    ctx: &CcmContext,
    scf_byte: u8,
    serial_number: &[u8; 6],
    challenge: &mut [u8],
    received_mac: &[u8; 4],
) -> Result<(), CryptoError> {
    let cipher = Aes128::new(key.into());

    // Decrypt challenge with CTR mode.
    ctr_crypt(&cipher, &ctx.seq_nr, ctx.src, ctx.dst, challenge);

    // Decrypt received MAC with S0.
    let s0 = compute_s0(&cipher, &ctx.seq_nr, ctx.src, ctx.dst);
    let mut decrypted_mac = [0u8; 4];
    for i in 0..4 {
        decrypted_mac[i] = received_mac[i] ^ s0[i];
    }

    // Recompute CBC-MAC: A = SCF | SerialNumber, P = decrypted challenge.
    let q = challenge.len() as u8;
    let b0 = block_b0(&ctx.seq_nr, ctx.src, ctx.dst, ctx.addr_type, ctx.tpci_apci, q);

    // Build A = SCF(1) + SerialNumber(6) = 7 bytes.
    let mut assoc = [0u8; 7];
    assoc[0] = scf_byte;
    assoc[1..7].copy_from_slice(serial_number);

    let y_n = cbc_mac(&cipher, &b0, &assoc, challenge);

    if y_n[0..4] == decrypted_mac[..] { Ok(()) } else { Err(CryptoError::MacMismatch) }
}

/// Encrypt and MAC an outgoing S-A_Sync_Res.
///
/// Per spec 5.3.2 / Annex C.1.4:
/// - A = SCF(1)
/// - P = SeqNr_remote(6) + SeqNr_local(6) = 12 bytes
/// - B0/Ctr nonce = Random (NOT the device's sending SeqNr)
///
/// `random` is the 6-byte random value generated by the device.
/// `payload` is encrypted in-place and must contain SeqNr_remote(6) +
/// SeqNr_local(6) = 12 bytes.
///
/// Returns the 4-byte MAC.
pub fn encrypt_and_mac_sync_res(
    key: &[u8; 16],
    random: &[u8; 6],
    src: u16,
    dst: u16,
    addr_type: u8,
    tpci_apci: u16,
    scf_byte: u8,
    payload: &mut [u8],
) -> [u8; 4] {
    let cipher = Aes128::new(key.into());

    let q = payload.len() as u8;
    let b0 = block_b0(random, src, dst, addr_type, tpci_apci, q);

    // CBC-MAC: A = SCF (1 byte), P = payload.
    let y_n = cbc_mac(&cipher, &b0, &[scf_byte], payload);

    let s0 = compute_s0(&cipher, random, src, dst);

    let mut mac = [0u8; 4];
    for i in 0..4 {
        mac[i] = y_n[i] ^ s0[i];
    }

    // Encrypt payload with CTR mode using Random as nonce.
    ctr_crypt(&cipher, random, src, dst, payload);

    mac
}

/// Verify and decrypt an incoming S-A_Sync_Res.
///
/// Used by the test runner (local S-AL role) to verify sync responses from
/// the DUT. The `random` value is recovered by the caller (challenge XOR
/// challenge_xor_random from the response).
///
/// - A = SCF(1)
/// - P = SeqNr_remote(6) + SeqNr_local(6) = 12 bytes
/// - B0/Ctr nonce = Random
pub fn verify_and_decrypt_sync_res(
    key: &[u8; 16],
    random: &[u8; 6],
    src: u16,
    dst: u16,
    addr_type: u8,
    tpci_apci: u16,
    scf_byte: u8,
    payload: &mut [u8],
    received_mac: &[u8; 4],
) -> Result<(), CryptoError> {
    let cipher = Aes128::new(key.into());

    // Decrypt payload with CTR mode using Random as nonce.
    ctr_crypt(&cipher, random, src, dst, payload);

    // Decrypt received MAC with S0.
    let s0 = compute_s0(&cipher, random, src, dst);
    let mut decrypted_mac = [0u8; 4];
    for i in 0..4 {
        decrypted_mac[i] = received_mac[i] ^ s0[i];
    }

    // Recompute CBC-MAC: A = SCF (1 byte), P = decrypted payload.
    let q = payload.len() as u8;
    let b0 = block_b0(random, src, dst, addr_type, tpci_apci, q);
    let y_n = cbc_mac(&cipher, &b0, &[scf_byte], payload);

    if y_n[0..4] == decrypted_mac[..] { Ok(()) } else { Err(CryptoError::MacMismatch) }
}

// ============================================================================
// Tests using spec Annex C test vectors
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|h| u8::from_str_radix(h, 16).expect("valid hex")).collect()
    }

    // Tool Key used in all Annex C examples.
    const TOOL_KEY: [u8; 16] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

    // ----------------------------------------------------------------
    // C.1.1: S-A_Data-PDU (A+C, PropertyValueWrite, tool access)
    // SA=FF67, DA=FF00, SeqNr=000000000004
    // ----------------------------------------------------------------
    #[test]
    fn annex_c1_1_block_b0() {
        let b0 = block_b0(
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x04],
            0xFF67,
            0xFF00,
            0x00,   // AT: individual address, no EFF
            0x03F1, // TPCI/APCI
            0x16,   // q = 22 bytes
        );
        assert_eq!(b0, [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xFF, 0x67, 0xFF, 0x00, 0x00, 0x00, 0x03, 0xF1, 0x00, 0x16
        ]);
    }

    #[test]
    fn annex_c1_1_block_ctr0() {
        let ctr0 = block_ctr(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x04], 0xFF67, 0xFF00, 0);
        assert_eq!(ctr0, [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xFF, 0x67, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
        ]);
    }

    #[test]
    fn annex_c1_1_intermediate_y0() {
        // Verify Y0 = AES_K(B0)
        let cipher = Aes128::new((&TOOL_KEY).into());
        let mut b0 = block_b0(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x04], 0xFF67, 0xFF00, 0x00, 0x03F1, 0x16);
        aes_encrypt_block(&cipher, &mut b0);
        let expected_y0 = hex("bd 21 61 cb 9d d6 15 a4 43 a6 27 95 2a fb 12 95");
        assert_eq!(&b0[..], expected_y0.as_slice(), "Y0 mismatch");
    }

    #[test]
    fn annex_c1_1_intermediate_cbc_mac() {
        // Verify the full CBC-MAC Y2 value.
        let cipher = Aes128::new((&TOOL_KEY).into());
        let b0 = block_b0(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x04], 0xFF67, 0xFF00, 0x00, 0x03F1, 0x16);
        let payload = hex("03 D7 05 35 10 01 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F");
        let y_n = cbc_mac(&cipher, &b0, &[0x90], &payload);
        let expected_y2 = hex("05 6a 57 e9 95 0c 98 ca e2 99 16 88 ed ed a5 d7");
        assert_eq!(&y_n[..], expected_y2.as_slice(), "Y2 (CBC-MAC final) mismatch");
    }

    #[test]
    fn annex_c1_1_intermediate_s0_and_mac() {
        let cipher = Aes128::new((&TOOL_KEY).into());
        let s0 = compute_s0(&cipher, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x04], 0xFF67, 0xFF00);
        let expected_s0 = hex("08 e5 96 81 64 b0 21 1f 33 09 ea 57 83 34 50 04");
        assert_eq!(&s0[..], expected_s0.as_slice(), "S0 mismatch");

        // MAC = MSB32(Y2) XOR MSB32(S0) = 056a57e9 XOR 08e59681 = 0d8fc168
        let y2 = hex("05 6a 57 e9 95 0c 98 ca e2 99 16 88 ed ed a5 d7");
        let mut mac = [0u8; 4];
        for i in 0..4 {
            mac[i] = y2[i] ^ s0[i];
        }
        assert_eq!(mac, [0x0d, 0x8f, 0xc1, 0x68], "MAC mismatch");
    }

    #[test]
    fn annex_c1_1_intermediate_s1_and_ctr() {
        let cipher = Aes128::new((&TOOL_KEY).into());
        // S1 = AES_K(Ctr1)
        let mut ctr1 = block_ctr(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x04], 0xFF67, 0xFF00, 1);
        aes_encrypt_block(&cipher, &mut ctr1);
        let expected_s1 = hex("68 c3 e7 74 be bb b3 59 13 2a 16 9a 1d db 8d 67");
        assert_eq!(&ctr1[..], expected_s1.as_slice(), "S1 mismatch");
    }

    #[test]
    fn annex_c1_1_encrypt_and_mac() {
        // From Annex C.1.1:
        // A = SCF = 0x90
        // P = 000000b | Plain APDU = 03 D7 05 35 10 01 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
        let scf = 0x90u8;
        let mut payload = hex("03 D7 05 35 10 01 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F");

        let ctx = CcmContext {
            seq_nr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x04],
            src: 0xFF67,
            dst: 0xFF00,
            addr_type: 0x00,
            tpci_apci: 0x03F1,
        };

        let mac = encrypt_and_mac(&TOOL_KEY, &ctx, scf, &mut payload);

        // From spec: C = 6767242a2308ca76a11774214ee4cf5d94909f743d05 | 0d8fc168
        let expected_c = hex("67 67 24 2a 23 08 ca 76 a1 17 74 21 4e e4 cf 5d 94 90 9f 74 3d 05");
        assert_eq!(payload, expected_c.as_slice(), "ciphertext mismatch");

        let expected_mac: [u8; 4] = [0x0d, 0x8f, 0xc1, 0x68];
        assert_eq!(mac, expected_mac, "MAC mismatch");
    }

    #[test]
    fn annex_c1_1_verify_and_decrypt() {
        let scf = 0x90u8;
        let mut ciphertext = hex("67 67 24 2a 23 08 ca 76 a1 17 74 21 4e e4 cf 5d 94 90 9f 74 3d 05");
        let mac: [u8; 4] = [0x0d, 0x8f, 0xc1, 0x68];

        let ctx = CcmContext {
            seq_nr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x04],
            src: 0xFF67,
            dst: 0xFF00,
            addr_type: 0x00,
            tpci_apci: 0x03F1,
        };

        let result = verify_and_decrypt(&TOOL_KEY, &ctx, scf, &mut ciphertext, &mac);
        assert!(result.is_ok(), "MAC verification failed");

        let expected_plain = hex("03 D7 05 35 10 01 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F");
        assert_eq!(ciphertext, expected_plain.as_slice(), "plaintext mismatch after decryption");
    }

    #[test]
    fn annex_c1_1_tampered_mac_rejected() {
        let scf = 0x90u8;
        let mut ciphertext = hex("67 67 24 2a 23 08 ca 76 a1 17 74 21 4e e4 cf 5d 94 90 9f 74 3d 05");
        let mut bad_mac: [u8; 4] = [0x0d, 0x8f, 0xc1, 0x68];
        bad_mac[0] ^= 0x01; // Flip one bit

        let ctx = CcmContext {
            seq_nr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x04],
            src: 0xFF67,
            dst: 0xFF00,
            addr_type: 0x00,
            tpci_apci: 0x03F1,
        };

        let result = verify_and_decrypt(&TOOL_KEY, &ctx, scf, &mut ciphertext, &bad_mac);
        assert_eq!(result, Err(CryptoError::MacMismatch));
    }

    // ----------------------------------------------------------------
    // C.1.2: S-A_Data-PDU (A+C, PropertyValueWrite Response)
    // SA=FF00, DA=FF67, SeqNr=000000000003
    // ----------------------------------------------------------------
    #[test]
    fn annex_c1_2_encrypt_and_mac() {
        let scf = 0x90u8;
        // P = 000000b | Plain APDU
        let mut payload = hex("03 D6 05 35 10 01 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F");

        let ctx = CcmContext {
            seq_nr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
            src: 0xFF00,
            dst: 0xFF67,
            addr_type: 0x00,
            tpci_apci: 0x03F1,
        };

        let mac = encrypt_and_mac(&TOOL_KEY, &ctx, scf, &mut payload);

        let expected_c = hex("70 6f 53 31 05 50 35 57 cb 2b 24 f1 dd 34 1b 60 b7 e0 17 ec d6 b0");
        assert_eq!(payload, expected_c.as_slice(), "ciphertext mismatch");

        let expected_mac: [u8; 4] = [0x68, 0x49, 0xa7, 0x2b];
        assert_eq!(mac, expected_mac, "MAC mismatch");
    }

    // ================================================================
    // Annex C.1.3 — S-A_Sync_Req
    // ================================================================

    #[test]
    fn annex_c1_3_sync_req() {
        // Input from spec:
        // SA = FF67h, DA = FF00h
        // TPCI/APCI = 43F1h (connection-oriented secure)
        // SCF = 92h (Tool + A+C + SyncReq)
        // SeqNr_local = 000000000001h
        // SerialNumber = 000000000000h
        // Challenge = 000000000003h
        let scf = 0x92u8;
        let serial_number: [u8; 6] = [0; 6];
        let mut challenge: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x03];

        let ctx = CcmContext {
            seq_nr: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            src: 0xFF67,
            dst: 0xFF00,
            addr_type: 0x00,
            tpci_apci: 0x43F1,
        };

        // Encrypt: should produce the encrypted challenge + MAC from the spec.
        let mac = encrypt_and_mac_sync_req(&TOOL_KEY, &ctx, scf, &serial_number, &mut challenge);

        let expected_c = hex("c1 cf 45 06 f0 9b");
        assert_eq!(&challenge, expected_c.as_slice(), "sync req ciphertext mismatch");

        let expected_mac: [u8; 4] = [0xd7, 0x9f, 0xab, 0x55];
        assert_eq!(mac, expected_mac, "sync req MAC mismatch");

        // Now verify round-trip: decrypt and verify.
        let result = verify_and_decrypt_sync_req(
            &TOOL_KEY, &ctx, scf, &serial_number, &mut challenge, &expected_mac,
        );
        assert!(result.is_ok(), "sync req verify failed");
        assert_eq!(challenge, [0x00, 0x00, 0x00, 0x00, 0x00, 0x03], "sync req decrypted challenge mismatch");
    }

    // ================================================================
    // Annex C.1.4 — S-A_Sync_Res
    // ================================================================

    #[test]
    fn annex_c1_4_sync_res() {
        // Input from spec:
        // SA = FF00h, DA = FF67h
        // TPCI/APCI = 43F1h
        // SCF = 93h (Tool + A+C + SyncRes)
        // SeqNr_remote = 000000000003h (device's SeqNoSending)
        // SeqNr_local = 000000000004h (next valid SeqNr for Tool Access)
        // Challenge = 000000000003h
        // Random = AA AA AA AA AA AA
        let scf = 0x93u8;
        let random: [u8; 6] = [0xAA; 6];
        let mut payload: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // SeqNr_remote
            0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // SeqNr_local
        ];

        let mac = encrypt_and_mac_sync_res(
            &TOOL_KEY, &random, 0xFF00, 0xFF67, 0x00, 0x43F1, scf, &mut payload,
        );

        let expected_c = hex("9c 02 3a d2 5e 14 64 70 69 3e 63 8d");
        assert_eq!(&payload, expected_c.as_slice(), "sync res ciphertext mismatch");

        let expected_mac: [u8; 4] = [0x5b, 0x70, 0xca, 0xc4];
        assert_eq!(mac, expected_mac, "sync res MAC mismatch");

        // Verify round-trip.
        let result = verify_and_decrypt_sync_res(
            &TOOL_KEY, &random, 0xFF00, 0xFF67, 0x00, 0x43F1, scf,
            &mut payload, &expected_mac,
        );
        assert!(result.is_ok(), "sync res verify failed");
        assert_eq!(&payload[0..6], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x03], "SeqNr_remote mismatch");
        assert_eq!(&payload[6..12], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x04], "SeqNr_local mismatch");
    }
}
