//! Runner-side secure telegram wrapping and unwrapping.
//!
//! Uses the `zweidraehte_proto::crypto` module (Phase 3) to encrypt/decrypt
//! secure APDUs on the test runner side, simulating what ETS does.

use zweidraehte_device::crypto::ccm::{self, CcmContext};
use zweidraehte_device::crypto::scf::{SecureServiceType, SecurityControlField};

use crate::{InvalidSecurityParam, SecType, SecureParams, SeqSource};
use super::context::SecurityTestContext;

/// Wrap a plaintext telegram in a Secure APDU.
///
/// Takes the resolved plaintext frame bytes (CTRL + SRC + DST + AT/HC +
/// TPCI/APCI + data) and wraps them in a Secure Service frame.
///
/// Returns the complete secure frame ready for injection.
pub fn wrap_secure(
    plaintext_frame: &[u8],
    params: &SecureParams,
    ctx: &mut SecurityTestContext,
) -> Vec<u8> {
    assert!(plaintext_frame.len() >= 7, "frame too short for wrapping");

    let key = ctx.key(&params.key_name);
    let seq_nr = match params.seq_source {
        SeqSource::Tool => ctx.next_tool_seq(),
        SeqSource::Table => ctx.current_table_seq(),
    };

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

    let ccm_ctx = CcmContext {
        seq_nr,
        src,
        dst,
        addr_type,
        tpci_apci: secure_tpci_apci,
    };

    // The payload P for CCM is the plain TPCI/APCI + data (the entire
    // plaintext APDU that gets protected).
    let mut payload = plain_apdu.to_vec();

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

/// Wrap a secure telegram with an intentionally invalid field.
pub fn wrap_secure_invalid(
    plaintext_frame: &[u8],
    params: &SecureParams,
    ctx: &mut SecurityTestContext,
    invalid: &InvalidSecurityParam,
) -> Vec<u8> {
    match invalid {
        InvalidSecurityParam::WrongAddressType => {
            // Build the frame with the correct key and params, but flip
            // the address type bit in the CCM context so the MAC won't
            // verify on the DUT side.
            return wrap_secure_wrong_at(plaintext_frame, params, ctx);
        }
        _ => {}
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
fn wrap_secure_wrong_at(
    plaintext_frame: &[u8],
    params: &SecureParams,
    ctx: &mut SecurityTestContext,
) -> Vec<u8> {
    use zweidraehte_device::crypto::scf::{SecureServiceType, SecurityControlField};

    assert!(plaintext_frame.len() >= 7, "frame too short for wrapping");

    let key = ctx.key(&params.key_name);
    let seq_nr = match params.seq_source {
        SeqSource::Tool => ctx.next_tool_seq(),
        SeqSource::Table => ctx.current_table_seq(),
    };

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
pub fn unwrap_secure(
    secure_frame: &[u8],
    params: &SecureParams,
    ctx: &mut SecurityTestContext,
) -> Option<Vec<u8>> {
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

    let ccm_ctx = CcmContext {
        seq_nr,
        src,
        dst,
        addr_type,
        tpci_apci,
    };

    let scf = SecurityControlField::parse(scf_byte).ok()?;

    if scf.confidentiality {
        let mut ciphertext = secure_frame[payload_start..mac_start].to_vec();
        ccm::verify_and_decrypt(&key, &ccm_ctx, scf_byte, &mut ciphertext, &received_mac).ok()?;
        Some(ciphertext)
    } else {
        let plaintext = secure_frame[payload_start..mac_start].to_vec();
        ccm::verify_mac_auth_only(&key, &ccm_ctx, scf_byte, &plaintext, &received_mac).ok()?;
        Some(plaintext)
    }
}
