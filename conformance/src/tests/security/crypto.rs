//! Runner-side secure telegram wrapping and unwrapping.
//!
//! Uses the `zweidraehte_proto::crypto` module (Phase 3) to encrypt/decrypt
//! secure APDUs on the test runner side, simulating what ETS does.

use zweidraehte_proto::crypto::ccm;
use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
use zweidraehte_proto::messages::apdu::secure::{self, SecureApduMut, SecureApduRef, SyncReqRef, SyncResRef};
use zweidraehte_proto::messages::knx::{AddressType, ApciCode, KnxMessageBuffer, offsets};

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

    let mut frame = plaintext_frame.to_vec();
    frame.resize(plaintext_frame.len() + secure::OVERHEAD, 0);
    let layout = secure::wrap_plaintext(&mut frame, plaintext_frame.len(), scf_byte, &seq_nr)
        .expect("buffer includes secure overhead");
    let source = KnxMessageBuffer::from_buffer(frame.as_slice()).get_source_addr();
    let envelope = SecureApduRef::parse(&frame).expect("wrapped frame has an APDU");
    let context = envelope.ccm_context(u16::from_be_bytes(source.0));
    let payload = &mut frame[layout.payload_start..layout.payload_end];
    let mac = match params.sec_type {
        SecType::AuthConf => ccm::encrypt_and_mac(&key, &context, scf_byte, payload),
        SecType::AuthOnly => ccm::compute_mac_auth_only(&key, &context, scf_byte, payload),
    };
    frame[layout.mac_start..].copy_from_slice(&mac);

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
    // Protect a frame with the opposite A bit, then restore the transmitted
    // header. Only the authenticated address type is deliberately wrong.
    let mut wrong_header = plaintext_frame.to_vec();
    let mut ctrl2 = KnxMessageBuffer::from_buffer(plaintext_frame).ctrl2_field();
    ctrl2.set_group_addressed(!ctrl2.is_group_addressed());
    wrong_header[offsets::MSG_ADDR_TYPE] = ctrl2.into();
    let mut frame = wrap_secure(&wrong_header, params, ctx);
    frame[offsets::MSG_ADDR_TYPE] = plaintext_frame[offsets::MSG_ADDR_TYPE];
    frame
}

/// Validate the wire service before applying its particular CCM construction.
/// The APDU views validate layout only; neither a plausible length nor a valid
/// MAC substitutes for the expected outer APCI and SCF service.
fn validate_secure_header(frame: &[u8], expected_service: SecureServiceType) -> Option<SecurityControlField> {
    // Decode APCI independently of TPCI, preserving connected transport.
    if KnxMessageBuffer::from_buffer(frame).get_apci_code() != ApciCode::SecureService {
        return None;
    }
    let scf = SecurityControlField::parse(*frame.get(secure::SCF)?).ok()?;
    if scf.service != expected_service || (expected_service != SecureServiceType::Data && !scf.confidentiality) {
        // S-A_Sync always uses authentication + confidentiality (§5.3.2).
        return None;
    }
    Some(scf)
}

/// Unwrap a captured secure telegram from the DUT.
///
/// Decrypts the frame and returns the plaintext APDU bytes (TPCI/APCI + data),
/// or `None` if the envelope is not S-A_Data or decryption/verification fails.
pub fn unwrap_secure(secure_frame: &[u8], params: &SecureParams, ctx: &mut SecurityTestContext) -> Option<Vec<u8>> {
    let scf = validate_secure_header(secure_frame, SecureServiceType::Data)?;
    let message = KnxMessageBuffer::from_buffer(secure_frame);
    let envelope = SecureApduRef::parse(secure_frame).ok()?;

    let key = ctx.key(&params.key_name);
    let source = message.get_source_addr();
    let context = envelope.ccm_context(u16::from_be_bytes(source.0));

    let mac = envelope.mac();
    let mut frame = secure_frame.to_vec();
    let mut plaintext = SecureApduMut::parse(&mut frame).ok()?;
    if scf.confidentiality {
        ccm::verify_and_decrypt(&key, &context, envelope.scf_byte(), plaintext.payload_mut(), &mac).ok()?;
    } else {
        ccm::verify_mac_auth_only(&key, &context, envelope.scf_byte(), plaintext.payload_mut(), &mac).ok()?;
    }
    let len = plaintext.unwrap_to_plaintext();

    // Rejected captures must not move later test expectations. In particular,
    // an untrusted high sequence number becomes usable only after its MAC
    // verifies, including when an expect block tries multiple candidate keys.
    let dut_seq = super::context::seq_from_bytes(&envelope.seq_nr());
    ctx.update_table_seq(dut_seq);
    Some(frame[offsets::MSG_TPCI..len].to_vec())
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
    let mut frame = vec![0; secure::sync::FRAME_LEN];
    let mac_start = secure::build_sync_request(
        &mut frame,
        ctrl,
        src,
        dst,
        npdu,
        tpci_high,
        scf_byte,
        seq_nr_local,
        serial_number,
        challenge,
    );
    let context = SyncReqRef::parse(&frame).expect("fixed-size sync request").ccm_context();
    let mut challenge_enc = *challenge;
    let mac = ccm::encrypt_and_mac_sync_req(key, &context, scf_byte, serial_number, &mut challenge_enc);
    frame[secure::sync::CHALLENGE..mac_start].copy_from_slice(&challenge_enc);
    frame[mac_start..].copy_from_slice(&mac);

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
    validate_secure_header(secure_frame, SecureServiceType::SyncResponse)?;
    let response = SyncResRef::parse(secure_frame).ok()?;
    let challenge_xor_random = response.challenge_xor_random();

    // Recover random: random = challenge XOR challenge_xor_random.
    let mut random = [0u8; 6];
    for i in 0..6 {
        random[i] = challenge[i] ^ challenge_xor_random[i];
    }

    let mut payload = response.payload_enc();

    // Verify and decrypt using the recovered random as nonce.
    ccm::verify_and_decrypt_sync_res(
        key,
        &random,
        response.src(),
        response.dst(),
        response.ctrl2_field().ccm_at(),
        response.tpci_apci(),
        response.scf_byte(),
        &mut payload,
        &response.mac(),
    )
    .ok()?;

    let mut seq_nr_remote = [0u8; 6];
    let mut seq_nr_local = [0u8; 6];
    seq_nr_remote.copy_from_slice(&payload[0..6]);
    seq_nr_local.copy_from_slice(&payload[6..12]);

    Some(SyncResDecrypted { random, seq_nr_remote, seq_nr_local, scf_byte: response.scf_byte() })
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
    validate_secure_header(secure_frame, SecureServiceType::SyncRequest)?;
    let request = SyncReqRef::parse(secure_frame).ok()?;
    let mut challenge = [0u8; 6];
    challenge.copy_from_slice(request.challenge());

    ccm::verify_and_decrypt_sync_req(
        key,
        &request.ccm_context(),
        request.scf_byte(),
        &request.knx_serial_number(),
        &mut challenge,
        &request.mac(),
    )
    .ok()?;

    Some(SyncReqDecrypted {
        challenge,
        seq_nr_local: request.seq_nr_local(),
        scf_byte: request.scf_byte(),
        src: request.src(),
        dst: request.dst(),
        addr_type: if request.ctrl2_field().is_group_addressed() {
            AddressType::Group.into()
        } else {
            AddressType::Individual.into()
        },
        tpci_apci: request.tpci_apci(),
        serial_number: request.knx_serial_number(),
    })
}

/// Build an S-A_Sync_Res frame in internal format for injection.
///
/// The caller supplies the challenge and all response fields independently.
/// In particular, SBC does not override the destination or address type:
/// negative tests must authenticate the routing they actually put on the wire.
// Keep the wire-field order shared with `wrap_sync_req`; no fabricated request
// is needed for an unsolicited response.
#[allow(clippy::too_many_arguments)]
pub fn wrap_sync_res(
    ctrl: u8,
    src: u16,
    dst: u16,
    npdu: u8,
    tpci_high: u8,
    key: &[u8; 16],
    scf_byte: u8,
    seq_nr_remote: &[u8; 6],
    seq_nr_local: &[u8; 6],
    challenge: &[u8; 6],
) -> Vec<u8> {
    // Generate a pseudo-random value for the response. For test purposes
    // we use system time as entropy — cryptographic strength is not needed.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let random: [u8; 6] =
        [(now >> 40) as u8, (now >> 32) as u8, (now >> 24) as u8, (now >> 16) as u8, (now >> 8) as u8, now as u8];

    // challenge_xor_random = challenge XOR random.
    let mut challenge_xor_random = [0u8; 6];
    for i in 0..6 {
        challenge_xor_random[i] = challenge[i] ^ random[i];
    }

    let mut frame = vec![0; secure::sync::FRAME_LEN];
    let mac_start = secure::build_sync_response(
        &mut frame,
        ctrl,
        src,
        dst,
        npdu,
        tpci_high,
        scf_byte,
        &challenge_xor_random,
        seq_nr_remote,
        seq_nr_local,
    );
    let response = SyncResRef::parse(&frame).expect("fixed-size sync response");
    let mut payload = response.payload_enc();
    let mac = ccm::encrypt_and_mac_sync_res(
        key,
        &random,
        response.src(),
        response.dst(),
        response.ctrl2_field().ccm_at(),
        response.tpci_apci(),
        response.scf_byte(),
        &mut payload,
    );
    frame[secure::sync::SEQ_NR_REMOTE..mac_start].copy_from_slice(&payload);
    frame[mac_start..].copy_from_slice(&mac);

    frame
}

#[cfg(test)]
mod data_tests {
    use super::super::variables::{TK1, create_security_context};
    use super::*;
    use zweidraehte_proto::messages::knx::Tpci;

    const PLAIN: [u8; 8] = [0x3C, 0x12, 0x34, 0x56, 0x78, 0x60, 0x03, 0x00];

    /// Deliberately authenticate the wrong envelope using the data CCM
    /// construction. These must fail service validation, not just the MAC.
    fn data_mac_frame(apci: ApciCode, service: SecureServiceType, confidentiality: bool) -> Vec<u8> {
        let scf = SecurityControlField { service, system_broadcast: false, confidentiality, tool_access: true };
        let mut frame = PLAIN.to_vec();
        frame.resize(PLAIN.len() + secure::OVERHEAD, 0);
        let layout =
            secure::wrap_plaintext(&mut frame, PLAIN.len(), scf.encode(), &super::super::context::seq_to_bytes(1000))
                .expect("buffer includes secure overhead");
        KnxMessageBuffer::from_buffer(frame.as_mut_slice()).set_apci_code(apci);
        let context = SecureApduRef::parse(&frame).expect("secure layout").ccm_context(0x1234);
        let payload = &mut frame[layout.payload_start..layout.payload_end];
        let mac = if confidentiality {
            ccm::encrypt_and_mac(&TK1, &context, scf.encode(), payload)
        } else {
            ccm::compute_mac_auth_only(&TK1, &context, scf.encode(), payload)
        };
        frame[layout.mac_start..].copy_from_slice(&mac);

        let mut recovered = frame[layout.payload_start..layout.payload_end].to_vec();
        if confidentiality {
            ccm::verify_and_decrypt(&TK1, &context, scf.encode(), &mut recovered, &mac)
                .expect("negative envelope has a valid data MAC");
        } else {
            ccm::verify_mac_auth_only(&TK1, &context, scf.encode(), &recovered, &mac)
                .expect("negative envelope has a valid data MAC");
        }
        frame
    }

    #[test]
    fn secure_data_rejects_other_outer_services() {
        for confidentiality in [false, true] {
            for apci in [ApciCode::DeviceDescriptorResponse, ApciCode::GroupValueWrite] {
                let frame = data_mac_frame(apci, SecureServiceType::Data, confidentiality);
                let mut context = create_security_context();
                context.table_seq_nr = 17;
                let params = SecureParams::tool_auth_conf("TK1");
                assert!(unwrap_secure(&frame, &params, &mut context).is_none(), "accepted {apci:?}");
                assert_eq!(context.table_seq_nr, 17);
            }
        }
    }

    #[test]
    fn secure_data_rejects_sync_service_codes() {
        for service in [SecureServiceType::SyncRequest, SecureServiceType::SyncResponse] {
            let frame = data_mac_frame(ApciCode::SecureService, service, true);
            let mut context = create_security_context();
            context.table_seq_nr = 17;
            let params = SecureParams::tool_auth_conf("TK1");
            assert!(unwrap_secure(&frame, &params, &mut context).is_none(), "accepted {service:?} as data");
            assert_eq!(context.table_seq_nr, 17);
        }
    }

    #[test]
    fn secure_data_accepts_connected_transport() {
        let mut plain = PLAIN;
        KnxMessageBuffer::from_buffer(plain.as_mut_slice()).set_tpci(Tpci::DataConnected(7));
        for sec_type in [SecType::AuthOnly, SecType::AuthConf] {
            let mut params = SecureParams::tool_auth_conf("TK1");
            params.sec_type = sec_type;
            params.seq_source = SeqSource::Fixed(42);
            let frame = wrap_secure(&plain, &params, &mut create_security_context());
            let mut context = create_security_context();
            assert_eq!(unwrap_secure(&frame, &params, &mut context).as_deref(), Some(&plain[offsets::MSG_TPCI..]));
            assert_eq!(context.table_seq_nr, 43);
        }
    }

    #[test]
    fn rejected_data_cannot_advance_the_observed_sequence() {
        for sec_type in [SecType::AuthOnly, SecType::AuthConf] {
            let mut params = SecureParams::tool_auth_conf("TK1");
            params.sec_type = sec_type;
            params.seq_source = SeqSource::Fixed(1000);
            let authentic = wrap_secure(&PLAIN, &params, &mut create_security_context());

            let mut bad_mac = authentic.clone();
            *bad_mac.last_mut().expect("secure frame has a MAC") ^= 1;
            let mut invalid_scf = authentic.clone();
            invalid_scf[secure::SCF] |= 0x40; // Reserved SCF bit, deliberately invalid.
            let mut truncated = authentic.clone();
            truncated.truncate(secure::PAYLOAD);
            let mut wrong_key = params.clone();
            wrong_key.key_name = "TK2".into();

            for (description, frame, receive_params) in [
                ("bad MAC", &bad_mac, &params),
                ("invalid SCF", &invalid_scf, &params),
                ("truncated payload", &truncated, &params),
                ("wrong key", &authentic, &wrong_key),
            ] {
                let mut context = create_security_context();
                context.table_seq_nr = 17;
                assert!(unwrap_secure(frame, receive_params, &mut context).is_none(), "{description}");
                assert_eq!(context.table_seq_nr, 17, "{description} ({sec_type:?}) changed receive state");

                // A subsequent genuine response still establishes its actual
                // next sequence, rather than inheriting the rejected value.
                let mut valid_params = params.clone();
                valid_params.seq_source = SeqSource::Fixed(42);
                let valid = wrap_secure(&PLAIN, &valid_params, &mut create_security_context());
                assert_eq!(unwrap_secure(&valid, &params, &mut context).as_deref(), Some(&PLAIN[6..]));
                assert_eq!(context.table_seq_nr, 43);
            }
        }
    }

    #[test]
    fn authenticated_data_updates_receive_state_monotonically() {
        for sec_type in [SecType::AuthOnly, SecType::AuthConf] {
            let mut context = create_security_context();
            context.table_seq_nr = 17;
            let mut params = SecureParams::tool_auth_conf("TK1");
            params.sec_type = sec_type;
            for (sequence, expected_next) in [(17, 18), (42, 43), (42, 43), (20, 43)] {
                params.seq_source = SeqSource::Fixed(sequence);
                let frame = wrap_secure(&PLAIN, &params, &mut create_security_context());
                assert_eq!(unwrap_secure(&frame, &params, &mut context).as_deref(), Some(&PLAIN[6..]));
                assert_eq!(context.table_seq_nr, expected_next);
            }
        }
    }
}

#[cfg(test)]
mod sync_tests {
    use super::*;

    #[test]
    fn sync_reception_checks_service_and_security_mode_before_crypto() {
        use super::super::variables::TK1;

        let challenge = [1, 2, 3, 4, 5, 6];
        for service in [SecureServiceType::Data, SecureServiceType::SyncRequest, SecureServiceType::SyncResponse] {
            for confidentiality in [false, true] {
                let scf = SecurityControlField { service, system_broadcast: false, confidentiality, tool_access: true };
                // Both builders deliberately accept arbitrary SCF bytes for
                // negative tests, while computing the real sync-service MAC.
                let request =
                    wrap_sync_req(0x3C, 0x1234, 0x5678, 0x60, 0, &TK1, scf.encode(), &[0; 6], &[0; 6], &challenge);
                let response =
                    wrap_sync_res(0x3C, 0x5678, 0x1234, 0x60, 0, &TK1, scf.encode(), &[0; 6], &[0; 6], &challenge);
                assert_eq!(
                    unwrap_sync_req(&request, &TK1).is_some(),
                    service == SecureServiceType::SyncRequest && confidentiality,
                    "request: {service:?}, confidentiality={confidentiality}"
                );
                assert_eq!(
                    unwrap_sync_res(&response, &TK1, &challenge).is_some(),
                    service == SecureServiceType::SyncResponse && confidentiality,
                    "response: {service:?}, confidentiality={confidentiality}"
                );
            }
        }
    }

    #[test]
    fn sync_request_rejects_another_apci_with_a_valid_mac() {
        use super::super::variables::TK1;

        let challenge = [1, 2, 3, 4, 5, 6];
        let scf = SecurityControlField {
            service: SecureServiceType::SyncRequest,
            system_broadcast: false,
            confidentiality: true,
            tool_access: true,
        };
        let mut request =
            wrap_sync_req(0x3C, 0x1234, 0x5678, 0x60, 0, &TK1, scf.encode(), &[0; 6], &[0; 6], &challenge);
        KnxMessageBuffer::from_buffer(request.as_mut_slice()).set_apci_code(ApciCode::DeviceDescriptorResponse);
        let context = SyncReqRef::parse(&request).expect("sync layout").ccm_context();
        let mut encrypted_challenge = challenge;
        let mac = ccm::encrypt_and_mac_sync_req(&TK1, &context, scf.encode(), &[0; 6], &mut encrypted_challenge);
        let mac_start = secure::sync::FRAME_LEN - secure::MAC_LEN;
        request[secure::sync::CHALLENGE..mac_start].copy_from_slice(&encrypted_challenge);
        request[mac_start..].copy_from_slice(&mac);

        ccm::verify_and_decrypt_sync_req(&TK1, &context, scf.encode(), &[0; 6], &mut encrypted_challenge, &mac)
            .expect("wrong outer APCI has a valid sync MAC");
        assert_eq!(encrypted_challenge, challenge);
        assert!(unwrap_sync_req(&request, &TK1).is_none());
    }

    #[test]
    fn authentication_covers_eff_but_not_hop_count() {
        use super::super::variables::{TK1, create_security_context};
        use zweidraehte_proto::messages::apdu::secure::SecureApduRef;

        let challenge = [1, 2, 3, 4, 5, 6];
        for address_type in [0, 0x80] {
            for eff in 0..16 {
                let npdu = address_type | 0x60 | eff;
                let at = address_type | eff;
                let request = wrap_sync_req(0x3C, 0x1234, 0x5678, npdu, 0, &TK1, 0x92, &[0; 6], &[0; 6], &challenge);
                let response = wrap_sync_res(0x3C, 0x5678, 0x1234, npdu, 0, &TK1, 0x93, &[0; 6], &[0; 6], &challenge);
                assert_eq!(SyncReqRef::parse(&request).expect("request").ccm_context().addr_type, at);
                assert_eq!(SyncResRef::parse(&response).expect("response").ctrl2_field().ccm_at(), at);

                for changed_bits in [0, 0x10, 0x70, 1, 2, 4, 8] {
                    let authenticated = changed_bits & 0x0F == 0;
                    let mut changed_request = request.clone();
                    changed_request[5] ^= changed_bits;
                    assert_eq!(unwrap_sync_req(&changed_request, &TK1).is_some(), authenticated);
                    let mut changed_response = response.clone();
                    changed_response[5] ^= changed_bits;
                    assert_eq!(unwrap_sync_res(&changed_response, &TK1, &challenge).is_some(), authenticated);
                }

                for sec_type in [SecType::AuthOnly, SecType::AuthConf] {
                    let mut context = create_security_context();
                    let mut params = SecureParams::tool_auth_conf("TK1");
                    params.sec_type = sec_type;
                    let plain = [0x3C, 0x12, 0x34, 0x56, 0x78, npdu, 0x03, 0x00];
                    let data = wrap_secure(&plain, &params, &mut context);
                    assert_eq!(SecureApduRef::parse(&data).expect("data").ccm_context(0x1234).addr_type, at);
                    for changed_bits in [0, 0x10, 0x70, 1, 2, 4, 8] {
                        let mut changed_data = data.clone();
                        changed_data[5] ^= changed_bits;
                        assert_eq!(
                            unwrap_secure(&changed_data, &params, &mut context).is_some(),
                            changed_bits & 0x0F == 0
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn sync_request_rejects_invalid_lengths_despite_an_authentic_prefix() {
        let key = [0x42; 16];
        let challenge = [1, 2, 3, 4, 5, 6];
        let frame = wrap_sync_req(0x3C, 0x1234, 0x5678, 0x60, 0, &key, 0x92, &[0; 6], &[0; 6], &challenge);
        assert_eq!(unwrap_sync_req(&frame, &key).expect("authenticated request").challenge, challenge);

        for len in 0..frame.len() {
            assert!(unwrap_sync_req(&frame[..len], &key).is_none(), "truncated to {len} bytes");
        }
        for suffix in [&[0][..], &[0xFF; 16], &frame[27..]] {
            let mut overlong = frame.clone();
            overlong.extend_from_slice(suffix);
            assert!(unwrap_sync_req(&overlong, &key).is_none(), "appended {suffix:02X?}");
        }
    }

    #[test]
    fn sync_response_rejects_invalid_lengths_despite_an_authentic_prefix() {
        let key = [0x42; 16];
        let challenge = [1, 2, 3, 4, 5, 6];
        let frame = wrap_sync_res(0x3C, 0x5678, 0x1234, 0x60, 0, &key, 0x93, &[0; 6], &[0; 6], &challenge);
        assert!(unwrap_sync_res(&frame, &key, &challenge).is_some());

        for len in 0..frame.len() {
            assert!(unwrap_sync_res(&frame[..len], &key, &challenge).is_none(), "truncated to {len} bytes");
        }
        for suffix in [&[0][..], &[0xFF; 16], &frame[27..]] {
            let mut overlong = frame.clone();
            overlong.extend_from_slice(suffix);
            assert!(unwrap_sync_res(&overlong, &key, &challenge).is_none(), "appended {suffix:02X?}");
        }
    }

    #[test]
    fn sync_response_preserves_and_authenticates_its_own_header() {
        use zweidraehte_proto::encoding::tp1::{knx_to_tp1_message_no_checksum, tp1_to_knx_message_no_checksum};

        let key = [0x42; 16];
        let remote = [0, 0, 0, 0, 0, 23];
        let local = [0, 0, 0, 0, 0, 47];
        let challenge = [1, 2, 3, 4, 5, 6];

        for tool_access in [false, true] {
            for system_broadcast in [false, true] {
                let response_scf = SecurityControlField {
                    service: SecureServiceType::SyncResponse,
                    confidentiality: true,
                    tool_access,
                    system_broadcast,
                };

                // Vary priority, hop count, AT and TPCI independently of SBC.
                // Some combinations are protocol negatives, but their MAC is
                // valid: it must not hide the condition under test.
                for (ctrl, npdu, tpci, dst) in [(0x3C, 0x60, 0, 0x1234), (0x34, 0x20, 0x58, 0x1234), (0x30, 0xB0, 0, 0)]
                {
                    let frame = wrap_sync_res(
                        ctrl,
                        0x5678,
                        dst,
                        npdu,
                        tpci,
                        &key,
                        response_scf.encode(),
                        &remote,
                        &local,
                        &challenge,
                    );
                    let wire = knx_to_tp1_message_no_checksum(frame);
                    let [dst_high, dst_low] = dst.to_be_bytes();
                    assert_eq!(&wire[..10], &[
                        ctrl,
                        npdu,
                        0x56,
                        0x78,
                        dst_high,
                        dst_low,
                        24,
                        tpci | 3,
                        0xF1,
                        response_scf.encode()
                    ]);

                    let frame = tp1_to_knx_message_no_checksum(wire);
                    let decoded = unwrap_sync_res(&frame, &key, &challenge).expect("authenticated response");
                    assert_eq!(decoded.seq_nr_remote, remote);
                    assert_eq!(decoded.seq_nr_local, local);
                    assert!(unwrap_sync_res(&frame, &[0x24; 16], &challenge).is_none());
                    assert!(unwrap_sync_res(&frame, &key, &[0; 6]).is_none());

                    for (offset, mask) in [(1, 1), (3, 1), (5, 0x80), (6, 0x04), (8, 0x08)] {
                        let mut tampered = frame.clone();
                        tampered[offset] ^= mask;
                        assert!(unwrap_sync_res(&tampered, &key, &challenge).is_none(), "header offset {offset}");
                    }
                    let mut routed = frame;
                    routed[5] ^= 0x10;
                    assert!(unwrap_sync_res(&routed, &key, &challenge).is_some(), "hop count is not authenticated");
                }
            }
        }
    }
}
