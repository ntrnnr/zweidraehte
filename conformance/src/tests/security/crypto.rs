//! Runner-side secure telegram wrapping and unwrapping.
//!
//! Uses the `zweidraehte_proto::crypto` module (Phase 3) to encrypt/decrypt
//! secure APDUs on the test runner side, simulating what ETS does.

use zweidraehte_proto::crypto::ccm::{self, CcmContext};
use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};

use super::context::SecurityTestContext;
use crate::{InvalidSecurityParam, SecType, SecureParams, SeqSource};

/// Wrap a plaintext telegram in a Secure APDU.
///
/// Takes the resolved plaintext frame bytes (CTRL + SRC + DST + AT/HC +
/// TPCI/APCI + data) and wraps them in a Secure Service frame.
///
/// Returns the complete secure frame ready for injection.
pub fn wrap_secure(plaintext_frame: &[u8], params: &SecureParams, ctx: &mut SecurityTestContext) -> Vec<u8> {
    assert!(plaintext_frame.len() >= 7, "frame too short for wrapping");

    let key = ctx.key(&params.key_name);
    let seq_nr = match &params.seq_source {
        SeqSource::Tool => ctx.next_tool_seq(),
        SeqSource::Table => ctx.current_table_seq(),
        SeqSource::Fixed(val) => super::context::seq_to_bytes(*val),
        SeqSource::Peer(name) => ctx.next_peer_seq(name),
        SeqSource::PeerTable(name) => ctx.current_peer_table_seq(name),
        // The EITT lowering resolves this to `Table` or refuses the
        // telegram; it exists only to keep "unspecified" distinct from
        // "unreadable" while reading the attributes.
        SeqSource::Unpinned(name) => unreachable!("unresolved sequence variable {name} reached the engine"),
    };
    // A `SeqNumOfs` sends a number the counter would not have produced,
    // and the counter has to follow it: EITT stores what was *sent*,
    // plus one ("after sending the telegram the sequence number will be
    // incremented and saved in the table", manual §12.21.4). Leaving the
    // counter where it was means the next telegram replays a number the
    // device has already stored and is dropped as a retransmission —
    // which is what 3.1.11 and 3.1.21, the two "increment by 2" cases,
    // used to do to whatever followed them.
    //
    // Only forwards. The deliberate replays offset backwards on purpose
    // (3.1.22 is "sequence number identical/lower than last known") and
    // must not rewind the counter for the rest of the case.
    let seq_nr = apply_seq_offset(seq_nr, params.seq_offset);
    ctx.note_sent(&params.seq_source, &seq_nr);

    // Build SCF byte.
    let scf = SecurityControlField {
        service: SecureServiceType::Data,
        system_broadcast: params.system_broadcast,
        confidentiality: params.sec_type == SecType::AuthConf,
        tool_access: params.tool_access,
    };
    let scf_byte = scf.encode();

    // Extract frame metadata for crypto context.
    // plaintext_frame layout: CTRL(1) + SRC(2) + DST(2) + AT/HC(1) + TPCI/APCI(2) + data...
    let src = u16::from_be_bytes([plaintext_frame[1], plaintext_frame[2]]);
    let dst = u16::from_be_bytes([plaintext_frame[3], plaintext_frame[4]]);
    let addr_type = plaintext_frame[5] & 0x80;

    // The plaintext TPCI/APCI + data starts at offset 6.
    let plain_apdu = &plaintext_frame[6..];

    // Build the outer Secure TPCI/APCI. Preserve the TPCI bits from the
    // plaintext (upper 6 bits of byte 6), set APCI to Escaped (0x03F1).
    let tpci_high = plain_apdu[0] & 0xFC;
    let secure_tpci_apci = u16::from_be_bytes([tpci_high | 0x03, 0xF1]);

    let ccm_ctx = CcmContext { seq_nr, src, dst, addr_type, tpci_apci: secure_tpci_apci };

    // The payload P is `000000b | Plain APDU` (Application Layer
    // §5.1.3.3). Transport control belongs only to the outer TPDU.
    let mut payload = plain_apdu.to_vec();
    payload[0] &= 0x03;

    let mac = match params.sec_type {
        SecType::AuthConf => {
            // A = SCF, P = plain APDU → encrypt + MAC.
            ccm::encrypt_and_mac(&key, &ccm_ctx, scf_byte, &mut payload)
        }
        SecType::AuthOnly => {
            // A = SCF | plain APDU, P = empty → MAC only.
            ccm::compute_mac_auth_only(&key, &ccm_ctx, scf_byte, &payload)
        }
    };

    // Construct the secure frame:
    // CTRL(1) + SRC(2) + DST(2) + AT/HC(1) + SecureTPCI/APCI(2) + SCF(1) + SeqNr(6) + payload + MAC(4)
    let mut frame = Vec::with_capacity(6 + 2 + 1 + 6 + payload.len() + 4);
    // Header: same CTRL, SRC, DST, AT/HC as plaintext.
    frame.extend_from_slice(&plaintext_frame[..6]);
    // Secure TPCI/APCI.
    frame.push(tpci_high | 0x03);
    frame.push(0xF1);
    // SCF.
    frame.push(scf_byte);
    // Sequence number.
    frame.extend_from_slice(&seq_nr);
    // Encrypted payload (or plaintext for auth-only).
    frame.extend_from_slice(&payload);
    // MAC.
    frame.extend_from_slice(&mac);

    frame
}

/// Rewrite the trailing MAC field from a pattern.
///
/// `None` keeps the computed octet, `Some(b)` overrides it, and a
/// pattern of a length other than four resizes the frame — which is the
/// point for the "one byte too short" and "one byte too long" cases.
fn apply_mac_pattern(frame: &mut Vec<u8>, pattern: &[Option<u8>]) {
    const MAC_LEN: usize = 4;
    if frame.len() < MAC_LEN {
        return;
    }
    let mac_start = frame.len() - MAC_LEN;
    let computed: Vec<u8> = frame[mac_start..].to_vec();
    frame.truncate(mac_start);
    for (i, slot) in pattern.iter().enumerate() {
        // Past the computed MAC a `None` has nothing to keep; the
        // templates only ever pin those octets, so take a zero rather
        // than guess.
        frame.push(slot.or_else(|| computed.get(i).copied()).unwrap_or(0));
    }
}

/// Shift a 48-bit sequence number by a signed offset, saturating at the
/// ends of the range rather than wrapping.
///
/// The templates only ever offset by ±1 and ±2, so saturation never
/// bites in practice; it is here so an offset can never silently turn a
/// low sequence number into a very high one.
fn apply_seq_offset(seq: [u8; 6], offset: i64) -> [u8; 6] {
    if offset == 0 {
        return seq;
    }
    /// Largest value the six-octet sequence number field can hold.
    const SEQ_MAX: u64 = (1 << 48) - 1;
    let value = super::context::seq_from_bytes(&seq);
    super::context::seq_to_bytes(value.saturating_add_signed(offset).min(SEQ_MAX))
}

/// Wrap a secure telegram with an intentionally invalid field.
pub fn wrap_secure_invalid(
    plaintext_frame: &[u8],
    params: &SecureParams,
    ctx: &mut SecurityTestContext,
    invalid: &InvalidSecurityParam,
) -> Vec<u8> {
    if matches!(invalid, InvalidSecurityParam::WrongAddressType) {
        // Build the frame with the correct key and params, but flip
        // the address type bit in the CCM context so the MAC won't
        // verify on the DUT side.
        return wrap_secure_wrong_at(plaintext_frame, params, ctx);
    }

    let mut frame = wrap_secure(plaintext_frame, params, ctx);

    match invalid {
        InvalidSecurityParam::InvalidScf(scf_byte) => {
            // Override the SCF byte (offset 8 in frame: after header(6) + TPCI/APCI(2)).
            if frame.len() > 8 {
                frame[8] = *scf_byte;
            }
        }
        InvalidSecurityParam::InvalidMac(mac_bytes) => {
            // Replace the MAC (last 4 bytes) with the given bytes.
            let len = frame.len();
            if len >= 4 {
                frame[len - 4..].copy_from_slice(mac_bytes);
            }
        }
        InvalidSecurityParam::InvalidCipher => {
            // Corrupt a byte in the ciphertext (first payload byte after SeqNr).
            // SeqNr ends at offset 15 (8+1+6), payload starts at 15.
            if frame.len() > 15 {
                frame[15] ^= 0xFF;
            }
        }
        InvalidSecurityParam::PlainCipher(plain_bytes) => {
            // Replace the ciphertext portion with the given plaintext bytes.
            // In an A+C frame, the encrypted payload starts at offset 15
            // (after SCF(1) + SeqNr(6) = 7 bytes of secure header at offset 8).
            // The MAC occupies the last 4 bytes. We replace the payload between
            // SeqNr and MAC with the given plain bytes.
            let payload_start = 15; // 8 (APDU start in internal fmt) + 1 (SCF) + 6 (SeqNr)
            let mac_len = 4;
            if frame.len() > payload_start + mac_len {
                let payload_end = frame.len() - mac_len;
                let avail = payload_end - payload_start;
                let copy_len = plain_bytes.len().min(avail);
                frame[payload_start..payload_start + copy_len].copy_from_slice(&plain_bytes[..copy_len]);
            }
        }
        InvalidSecurityParam::ScfReservedBits(bits) => {
            if frame.len() > 8 {
                frame[8] |= *bits;
            }
        }
        InvalidSecurityParam::MacPattern(pattern) => {
            apply_mac_pattern(&mut frame, pattern);
        }
        InvalidSecurityParam::WrongAddressType => unreachable!("handled above"),
        InvalidSecurityParam::AppendBytes(extra) => {
            frame.extend_from_slice(extra);
        }
        InvalidSecurityParam::TruncateBytes(n) => {
            let new_len = frame.len().saturating_sub(*n);
            frame.truncate(new_len);
        }
    }

    frame
}

/// Wrap with wrong address type in the CCM context (AT=group instead of individual).
fn wrap_secure_wrong_at(plaintext_frame: &[u8], params: &SecureParams, ctx: &mut SecurityTestContext) -> Vec<u8> {
    use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};

    assert!(plaintext_frame.len() >= 7, "frame too short for wrapping");

    let key = ctx.key(&params.key_name);
    let seq_nr = match &params.seq_source {
        SeqSource::Tool => ctx.next_tool_seq(),
        SeqSource::Table => ctx.current_table_seq(),
        SeqSource::Fixed(val) => super::context::seq_to_bytes(*val),
        SeqSource::Peer(name) => ctx.next_peer_seq(name),
        SeqSource::PeerTable(name) => ctx.current_peer_table_seq(name),
        // The EITT lowering resolves this to `Table` or refuses the
        // telegram; it exists only to keep "unspecified" distinct from
        // "unreadable" while reading the attributes.
        SeqSource::Unpinned(name) => unreachable!("unresolved sequence variable {name} reached the engine"),
    };
    // The counter follows the number actually sent — see `wrap_secure`.
    let seq_nr = apply_seq_offset(seq_nr, params.seq_offset);
    ctx.note_sent(&params.seq_source, &seq_nr);

    let scf = SecurityControlField {
        service: SecureServiceType::Data,
        system_broadcast: params.system_broadcast,
        confidentiality: params.sec_type == SecType::AuthConf,
        tool_access: params.tool_access,
    };
    let scf_byte = scf.encode();

    let src = u16::from_be_bytes([plaintext_frame[1], plaintext_frame[2]]);
    let dst = u16::from_be_bytes([plaintext_frame[3], plaintext_frame[4]]);
    // Use wrong address type: group (0x80) instead of individual (0x00).
    let addr_type = (plaintext_frame[5] & 0x80) ^ 0x80;

    let plain_apdu = &plaintext_frame[6..];
    let tpci_high = plain_apdu[0] & 0xFC;
    let secure_tpci_apci = u16::from_be_bytes([tpci_high | 0x03, 0xF1]);

    let ccm_ctx = ccm::CcmContext { seq_nr, src, dst, addr_type, tpci_apci: secure_tpci_apci };
    let mut payload = plain_apdu.to_vec();
    payload[0] &= 0x03;

    let mac = match params.sec_type {
        SecType::AuthConf => ccm::encrypt_and_mac(&key, &ccm_ctx, scf_byte, &mut payload),
        SecType::AuthOnly => ccm::compute_mac_auth_only(&key, &ccm_ctx, scf_byte, &payload),
    };

    let mut frame = Vec::with_capacity(6 + 2 + 1 + 6 + payload.len() + 4);
    frame.extend_from_slice(&plaintext_frame[..6]);
    frame.push(tpci_high | 0x03);
    frame.push(0xF1);
    frame.push(scf_byte);
    frame.extend_from_slice(&seq_nr);
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&mac);
    frame
}

/// Unwrap a captured secure telegram from the DUT.
///
/// Decrypts the frame and returns the plaintext APDU bytes (TPCI/APCI + data),
/// or `None` if decryption/verification fails.
pub fn unwrap_secure(secure_frame: &[u8], params: &SecureParams, ctx: &mut SecurityTestContext) -> Option<Vec<u8>> {
    // Minimum: CTRL(1) + SRC(2) + DST(2) + AT(1) + TPCI/APCI(2) + SCF(1) + SeqNr(6) + MAC(4) = 19
    if secure_frame.len() < 19 {
        return None;
    }

    let key = ctx.key(&params.key_name);

    // Parse frame header.
    let src = u16::from_be_bytes([secure_frame[1], secure_frame[2]]);
    let dst = u16::from_be_bytes([secure_frame[3], secure_frame[4]]);
    let addr_type = secure_frame[5] & 0x80;
    let tpci_apci = u16::from_be_bytes([secure_frame[6], secure_frame[7]]);

    let scf_byte = secure_frame[8];
    let mut seq_nr = [0u8; 6];
    seq_nr.copy_from_slice(&secure_frame[9..15]);

    // Update table sequence number from the DUT's response.
    let dut_seq = super::context::seq_from_bytes(&seq_nr);
    ctx.update_table_seq(dut_seq);

    let payload_start = 15;
    let mac_start = secure_frame.len() - 4;

    let mut received_mac = [0u8; 4];
    received_mac.copy_from_slice(&secure_frame[mac_start..]);

    let ccm_ctx = CcmContext { seq_nr, src, dst, addr_type, tpci_apci };

    let scf = SecurityControlField::parse(scf_byte).ok()?;

    if scf.confidentiality {
        let mut ciphertext = secure_frame[payload_start..mac_start].to_vec();
        ccm::verify_and_decrypt(&key, &ccm_ctx, scf_byte, &mut ciphertext, &received_mac).ok()?;
        ciphertext[0] = (ciphertext[0] & 0x03) | (secure_frame[6] & 0xFC);
        Some(ciphertext)
    } else {
        let mut plaintext = secure_frame[payload_start..mac_start].to_vec();
        ccm::verify_mac_auth_only(&key, &ccm_ctx, scf_byte, &plaintext, &received_mac).ok()?;
        plaintext[0] = (plaintext[0] & 0x03) | (secure_frame[6] & 0xFC);
        Some(plaintext)
    }
}

// ============================================================================
// S-A_Sync frame wrapping/unwrapping (runner side)
// ============================================================================

/// Build a complete S-A_Sync_Req frame for injection.
///
/// Unlike `wrap_secure` which wraps a plaintext template, this builds
/// the sync frame from scratch since sync requests have a different
/// internal structure (no inner APDU).
///
/// Returns the complete frame in internal format (CTRL + SRC + DST + ...).
// Arguments correspond directly to the fixed sync-request wire fields. A
// parameter bundle would duplicate the protocol builder used below.
#[allow(clippy::too_many_arguments)]
pub fn wrap_sync_req(
    ctrl: u8,
    src: u16,
    dst: u16,
    npdu: u8,
    tpci_high: u8,
    key: &[u8; 16],
    scf_byte: u8,
    seq_nr_local: &[u8; 6],
    serial_number: &[u8; 6],
    challenge: &[u8; 6],
) -> Vec<u8> {
    use zweidraehte_proto::crypto::ccm::{CcmContext, encrypt_and_mac_sync_req};

    let tpci_apci = u16::from_be_bytes([tpci_high | 0x03, 0xF1]);

    let ccm_ctx = CcmContext { seq_nr: *seq_nr_local, src, dst, addr_type: npdu & 0x80, tpci_apci };

    let mut challenge_enc = *challenge;
    let mac = encrypt_and_mac_sync_req(key, &ccm_ctx, scf_byte, serial_number, &mut challenge_enc);

    // Assemble frame: CTRL(1) + SRC(2) + DST(2) + NPDU(1) + TPCI/APCI(2)
    // + SCF(1) + SeqNr_local(6) + SerialNumber(6) + Challenge_enc(6) + MAC(4)
    // = 31 bytes total.
    let mut frame = Vec::with_capacity(31);
    frame.push(ctrl);
    frame.extend_from_slice(&src.to_be_bytes());
    frame.extend_from_slice(&dst.to_be_bytes());
    frame.push(npdu);
    frame.push(tpci_high | 0x03);
    frame.push(0xF1);
    frame.push(scf_byte);
    frame.extend_from_slice(seq_nr_local);
    frame.extend_from_slice(serial_number);
    frame.extend_from_slice(&challenge_enc);
    frame.extend_from_slice(&mac);

    frame
}

/// Wrap a sync request with an intentionally invalid field.
// Keep the invalid-frame helper call-compatible with `wrap_sync_req`; the
// final argument selects the single deliberate corruption.
#[allow(clippy::too_many_arguments)]
pub fn wrap_sync_req_invalid(
    ctrl: u8,
    src: u16,
    dst: u16,
    npdu: u8,
    tpci_high: u8,
    key: &[u8; 16],
    scf_byte: u8,
    seq_nr_local: &[u8; 6],
    serial_number: &[u8; 6],
    challenge: &[u8; 6],
    invalid: &crate::InvalidSecurityParam,
) -> Vec<u8> {
    use crate::InvalidSecurityParam;

    // For WrongAddressType, flip the AT bit in CCM context.
    let effective_npdu = match invalid {
        InvalidSecurityParam::WrongAddressType => npdu ^ 0x80,
        _ => npdu,
    };

    let mut frame =
        wrap_sync_req(ctrl, src, dst, effective_npdu, tpci_high, key, scf_byte, seq_nr_local, serial_number, challenge);

    // For WrongAddressType, the frame header should use the original npdu,
    // but the CCM was computed with flipped AT. Restore original npdu.
    if matches!(invalid, InvalidSecurityParam::WrongAddressType) {
        frame[5] = npdu;
    }

    match invalid {
        InvalidSecurityParam::InvalidScf(scf) => {
            if frame.len() > 8 {
                frame[8] = *scf;
            }
        }
        InvalidSecurityParam::InvalidMac(mac_bytes) => {
            let len = frame.len();
            if len >= 4 {
                frame[len - 4..].copy_from_slice(mac_bytes);
            }
        }
        InvalidSecurityParam::AppendBytes(extra) => {
            frame.extend_from_slice(extra);
        }
        InvalidSecurityParam::TruncateBytes(n) => {
            let new_len = frame.len().saturating_sub(*n);
            frame.truncate(new_len);
        }
        InvalidSecurityParam::ScfReservedBits(bits) => {
            if frame.len() > 8 {
                frame[8] |= *bits;
            }
        }
        InvalidSecurityParam::MacPattern(pattern) => {
            apply_mac_pattern(&mut frame, pattern);
        }
        InvalidSecurityParam::WrongAddressType => { /* Already handled above */ }
        _ => {}
    }

    frame
}

/// Parsed S-A_Sync_Res from the DUT.
pub struct SyncResDecrypted {
    /// The random value the DUT used (recovered from challenge_xor_random).
    pub random: [u8; 6],
    /// Decrypted SeqNr_remote (DUT's Sequence Number Sending).
    pub seq_nr_remote: [u8; 6],
    /// Decrypted SeqNr_local (what DUT expects from us next).
    pub seq_nr_local: [u8; 6],
    /// SCF byte from the response.
    pub scf_byte: u8,
}

/// Parse and verify an S-A_Sync_Res captured from the DUT.
///
/// Takes the original challenge (from the request we sent) to recover
/// the random value. Returns the decrypted fields or None on failure.
pub fn unwrap_sync_res(secure_frame: &[u8], key: &[u8; 16], challenge: &[u8; 6]) -> Option<SyncResDecrypted> {
    if secure_frame.len() < 31 {
        return None;
    }

    let src = u16::from_be_bytes([secure_frame[1], secure_frame[2]]);
    let dst = u16::from_be_bytes([secure_frame[3], secure_frame[4]]);
    let addr_type = secure_frame[5] & 0x80;
    let tpci_apci = u16::from_be_bytes([secure_frame[6], secure_frame[7]]);
    let scf_byte = secure_frame[8];

    // Extract challenge_xor_random (6 bytes at offset 9).
    let mut challenge_xor_random = [0u8; 6];
    challenge_xor_random.copy_from_slice(&secure_frame[9..15]);

    // Recover random: random = challenge XOR challenge_xor_random.
    let mut random = [0u8; 6];
    for i in 0..6 {
        random[i] = challenge[i] ^ challenge_xor_random[i];
    }

    // Extract encrypted payload (12 bytes at offset 15) and MAC (4 bytes at end).
    let mut payload = [0u8; 12];
    payload.copy_from_slice(&secure_frame[15..27]);
    let mut received_mac = [0u8; 4];
    received_mac.copy_from_slice(&secure_frame[27..31]);

    // Verify and decrypt using the recovered random as nonce.
    ccm::verify_and_decrypt_sync_res(
        key,
        &random,
        src,
        dst,
        addr_type,
        tpci_apci,
        scf_byte,
        &mut payload,
        &received_mac,
    )
    .ok()?;

    let mut seq_nr_remote = [0u8; 6];
    let mut seq_nr_local = [0u8; 6];
    seq_nr_remote.copy_from_slice(&payload[0..6]);
    seq_nr_local.copy_from_slice(&payload[6..12]);

    Some(SyncResDecrypted { random, seq_nr_remote, seq_nr_local, scf_byte })
}

/// Parsed S-A_Sync_Req from the DUT.
pub struct SyncReqDecrypted {
    /// Decrypted challenge (6 bytes).
    pub challenge: [u8; 6],
    /// SeqNr_local from the request (6 bytes).
    pub seq_nr_local: [u8; 6],
    /// SCF byte from the request.
    pub scf_byte: u8,
    /// Source address (DUT's IA).
    pub src: u16,
    /// Destination address.
    pub dst: u16,
    /// NPDU/addr_type byte.
    pub addr_type: u8,
    /// TPCI/APCI field.
    pub tpci_apci: u16,
    /// KNX Serial Number field (6 bytes).
    pub serial_number: [u8; 6],
}

/// Parse and verify an S-A_Sync_Req captured from the DUT.
///
/// Returns the decrypted challenge and frame metadata, or None on failure.
pub fn unwrap_sync_req(secure_frame: &[u8], key: &[u8; 16]) -> Option<SyncReqDecrypted> {
    if secure_frame.len() < 31 {
        return None;
    }

    let src = u16::from_be_bytes([secure_frame[1], secure_frame[2]]);
    let dst = u16::from_be_bytes([secure_frame[3], secure_frame[4]]);
    let addr_type = secure_frame[5] & 0x80;
    let tpci_apci = u16::from_be_bytes([secure_frame[6], secure_frame[7]]);
    let scf_byte = secure_frame[8];

    // SeqNr_local at offset 9..15.
    let mut seq_nr_local = [0u8; 6];
    seq_nr_local.copy_from_slice(&secure_frame[9..15]);

    // KNX Serial Number at offset 15..21.
    let mut serial_number = [0u8; 6];
    serial_number.copy_from_slice(&secure_frame[15..21]);

    // Encrypted challenge at offset 21..27, MAC at 27..31.
    let mut challenge = [0u8; 6];
    challenge.copy_from_slice(&secure_frame[21..27]);
    let mut received_mac = [0u8; 4];
    received_mac.copy_from_slice(&secure_frame[27..31]);

    let ccm_ctx = CcmContext { seq_nr: seq_nr_local, src, dst, addr_type, tpci_apci };

    ccm::verify_and_decrypt_sync_req(key, &ccm_ctx, scf_byte, &serial_number, &mut challenge, &received_mac).ok()?;

    Some(SyncReqDecrypted { challenge, seq_nr_local, scf_byte, src, dst, addr_type, tpci_apci, serial_number })
}

/// Build a sync response frame to inject in reply to a DUT-initiated sync request.
///
/// Uses the decrypted challenge from `unwrap_sync_req` to construct a
/// correctly encrypted sync response.
pub fn wrap_sync_res(
    req: &SyncReqDecrypted,
    key: &[u8; 16],
    seq_nr_remote: &[u8; 6],
    seq_nr_local: &[u8; 6],
    response_src: u16,
    override_system_broadcast: Option<bool>,
) -> Vec<u8> {
    // Build response SCF: same T flag, but SyncResponse service.
    // The SBC flag can be overridden for tests that deliberately send
    // a mismatched broadcast/P2P response (e.g., 3.4.5).
    let req_scf = SecurityControlField::parse(req.scf_byte).expect("valid SCF from parsed request");
    let sbc = override_system_broadcast.unwrap_or(req_scf.system_broadcast);
    let response_scf = SecurityControlField {
        service: SecureServiceType::SyncResponse,
        system_broadcast: sbc,
        confidentiality: true,
        tool_access: req_scf.tool_access,
    };
    let response_scf_byte = response_scf.encode();

    // Generate a pseudo-random value for the response. For test purposes
    // we use system time as entropy — cryptographic strength is not needed.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let random: [u8; 6] =
        [(now >> 40) as u8, (now >> 32) as u8, (now >> 24) as u8, (now >> 16) as u8, (now >> 8) as u8, now as u8];

    // challenge_xor_random = challenge XOR random.
    let mut challenge_xor_random = [0u8; 6];
    for i in 0..6 {
        challenge_xor_random[i] = req.challenge[i] ^ random[i];
    }

    // For broadcast responses, dst is 0x0000 (broadcast address).
    // For P2P responses, dst is the DUT's IA (req.src).
    let dst_for_response = if sbc { 0x0000 } else { req.src };

    // CCM authenticates the AT field, not the full NPDU byte. The frame below
    // still carries hop count 6 in its NPDU; those routing bits are deliberately
    // excluded from B0 because a coupler may change them.
    let addr_type = if sbc { 0x80 } else { req.addr_type };

    // Encrypt payload and compute MAC.
    let mut payload = [0u8; 12];
    payload[0..6].copy_from_slice(seq_nr_remote);
    payload[6..12].copy_from_slice(seq_nr_local);

    let tpci_apci = u16::from_be_bytes([0x03, 0xF1]);

    let mac = ccm::encrypt_and_mac_sync_res(
        key,
        &random,
        response_src,
        dst_for_response,
        addr_type,
        tpci_apci,
        response_scf_byte,
        &mut payload,
    );

    // Assemble frame: CTRL(1) + SRC(2) + DST(2) + NPDU(1) + TPCI/APCI(2)
    // + SCF(1) + ChallengeXorRandom(6) + SeqNrRemote_enc(6) + SeqNrLocal_enc(6) + MAC(4)
    // = 31 bytes total.
    let ctrl = if sbc { 0xBC } else { 0xB0 };
    let npdu = if sbc { 0xE1 } else { 0x60 };

    let mut frame = Vec::with_capacity(31);
    frame.push(ctrl);
    frame.extend_from_slice(&response_src.to_be_bytes());
    frame.extend_from_slice(&dst_for_response.to_be_bytes());
    frame.push(npdu);
    frame.push(0x03);
    frame.push(0xF1);
    frame.push(response_scf_byte);
    frame.extend_from_slice(&challenge_xor_random);
    frame.extend_from_slice(&payload[0..6]); // encrypted SeqNr_remote
    frame.extend_from_slice(&payload[6..12]); // encrypted SeqNr_local
    frame.extend_from_slice(&mac);

    frame
}
