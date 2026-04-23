//! P2P-specific secure frame handling (S-A_Sync_Req / S-A_Sync_Res).
//!
//! Reachable only through [`WithP2p`](super::p2p_feature::WithP2p) —
//! the [`NoP2p`](super::p2p_feature::NoP2p) feature never names these
//! functions, so the monomorphiser drops them for group-only devices.
//!
//! The S-A_Sync protocol is inherently P2P: it aligns sequence numbers
//! between two individual peers. It accepts either the tool key (for
//! ETS-initiated sync during commissioning) or a P2P key from the
//! P2P Key Table (for device-to-device sync). Both branches live here
//! because the sync-state machine is the same; only key lookup differs.

use crate::bcus::system_b::{HasExtensionState, HasSecurityState, SecurityFailureType};
use crate::definition::StackDefinition;
use crate::objects::tables::HasAssociationTable;
use crate::prelude::HasAddressTable;
use crate::storage::SequenceNumberStorage;
use crate::{HasSecureIdentity, StackState};
use zweidraehte_proto::crypto::{
    ccm,
    scf::{SecureServiceType, SecurityControlField},
};
use zweidraehte_proto::messages::{
    apdu::secure::{self, SyncReqRef},
    buffers::{Buffer, MessageBuffer},
    knx::{KnxMessageBuffer, ServiceType, offsets},
};

use crate::logging::warn;

use super::p2p_feature::WithP2p;
use super::{PendingSyncState, SecureApplicationLayer, SecureResult, seq_to_u64, u64_to_seq};

// ========================================================================
// S-A_Sync_Req processing (spec 03/03/07 §5.3.2)
// ========================================================================

/// Process an incoming S-A_Sync_Req and generate an S-A_Sync_Res.
///
/// Implements the remote S-AL side of the sync protocol. The device
/// responds with its sequence numbers so the requester can synchronize.
pub(super) fn process_sync_request<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
    sal: &SecureApplicationLayer<'a, D, SEQ, WithP2p>,
    mut msg: KnxMessageBuffer<Buffer<'static>>,
    scf: SecurityControlField,
    scf_byte: u8,
    src: u16,
    incoming_service_type: ServiceType,
) -> SecureResult
where
    D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    let security_state = sal.inner.state().extension_state();

    // Step 1: Rate limit — ignore if we responded within the
    // rate-limit window (1 s per spec; scaled for fast conformance
    // runs so tests don't burn real wall-clock between syncs).
    if let Some(last) = sal.p2p_state.last_sync_response.get() {
        if embassy_time::Instant::now() - last < sal.p2p_state.sync_rate_limit {
            return SecureResult::Dropped;
        }
    }

    // Step 2: Parse sync request fields.
    let buf = msg.buf_mut();
    let sync_ref = match SyncReqRef::parse(buf) {
        Ok(r) => r,
        Err(_) => {
            warn!("S-AL: sync req frame too short ({} bytes)", buf.len());
            return SecureResult::Dropped;
        }
    };

    let seq_nr_local_received = sync_ref.seq_nr_local();
    let serial_number = sync_ref.knx_serial_number();
    let received_mac = sync_ref.mac();
    let addr_type = sync_ref.addr_type();
    let ccm_ctx = sync_ref.ccm_context();
    drop(sync_ref);

    // Step 3: KNX Serial Number check.
    let device_serial = sal.inner.state().serial_number();
    let is_broadcast = addr_type != 0
        || matches!(incoming_service_type, ServiceType::T_Broadcast_Ind | ServiceType::T_SystemBroadcast_Ind);

    if is_broadcast {
        // Broadcast/system broadcast: serial must be non-zero and match.
        if serial_number == [0u8; 6] || serial_number != *device_serial {
            return SecureResult::Dropped;
        }
    } else {
        // P2P: serial must be all-zero or match the device's serial.
        if serial_number != [0u8; 6] && serial_number != *device_serial {
            return SecureResult::Dropped;
        }
    }

    // Step 4: Key lookup.
    let key = if scf.tool_access {
        let tk = security_state.tool_key();
        if tk != [0u8; 16] { tk } else { sal.inner.state().fdsk().copied().unwrap_or([0u8; 16]) }
    } else {
        // Non-tool: look up P2P key for sender's IA (roles not needed for sync).
        match security_state.p2p_key_for_ia(src) {
            Some((k, _roles)) => k,
            None => {
                warn!("S-AL: sync req — no P2P key for IA {:#06X}", src);
                return SecureResult::Dropped;
            }
        }
    };

    // Step 5: SIAT check (non-tool only).
    if !scf.tool_access {
        use crate::objects::tables::LoadState;
        if security_state.security_load_state() != LoadState::Loaded {
            return SecureResult::Dropped;
        }
        if !security_state.is_in_siat(src) {
            warn!("S-AL: sync req — sender {:#06X} not in SIAT", src);
            sal.log_security_failure_and_maybe_report(SecurityFailureType::RoleError, src, &[]);
            return SecureResult::Dropped;
        }
    }

    // Step 6: Verify and decrypt the challenge.
    let buf = msg.buf_mut();
    let mut challenge = [0u8; 6];
    challenge.copy_from_slice(&buf[secure::sync::CHALLENGE..secure::sync::CHALLENGE + 6]);

    if ccm::verify_and_decrypt_sync_req(&key, &ccm_ctx, scf_byte, &serial_number, &mut challenge, &received_mac)
        .is_err()
    {
        warn!("S-AL: sync req MAC verification failed");
        sal.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
        return SecureResult::Dropped;
    }

    // Step 7: Compute response SeqNr_local.
    //
    // The "stored" value is the last-valid receiving sequence number
    // for this communication partner, read from wear-resistant storage.
    let mut storage = sal.seq_storage.borrow_mut();
    let stored_seq = if scf.tool_access {
        storage.load_tool_receiving_seq().ok().flatten()
    } else {
        storage.load_receiving_seq(src).ok().flatten()
    };
    let stored_val = stored_seq.map(|s| seq_to_u64(&s)).unwrap_or(0);
    let received_val = seq_to_u64(&seq_nr_local_received);

    // If (received - 1) > stored, update stored to (received - 1).
    let new_stored = if received_val > 0 && (received_val - 1) > stored_val {
        let updated = received_val - 1;
        let updated_bytes = u64_to_seq(updated);
        if scf.tool_access {
            let _ = storage.save_tool_receiving_seq(&updated_bytes);
        } else {
            let _ = storage.save_receiving_seq(src, &updated_bytes);
        }
        updated
    } else {
        stored_val
    };

    // Response SeqNr_local = max(received - 1, stored) + 1
    let received_minus_1 = received_val.saturating_sub(1);
    let response_seq_local = received_minus_1.max(new_stored) + 1;
    let response_seq_local_bytes = u64_to_seq(response_seq_local);

    // Step 8: SeqNr_remote = device's own Sequence Number Sending.
    // Use tool counter when T flag is set, regular counter otherwise.
    // Do NOT increment — spec says sync does not alter SeqNoSending.
    let (regular_seq, tool_seq) = storage.load_sending_seqs().unwrap_or(([0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 1]));
    let seq_nr_remote = if scf.tool_access { tool_seq } else { regular_seq };
    drop(storage);

    // Step 9: Generate random.
    let mut random = [0u8; 6];
    sal.inner.state().fill_random(&mut random);

    // Step 10: Build response — reuse the incoming buffer.
    let mut challenge_xor_random = [0u8; 6];
    for i in 0..6 {
        challenge_xor_random[i] = challenge[i] ^ random[i];
    }

    // Build the response SCF: same T, SBC, A+C flags but SyncResponse service.
    let response_scf = SecurityControlField {
        service: SecureServiceType::SyncResponse,
        system_broadcast: scf.system_broadcast,
        confidentiality: true, // Sync always uses A+C.
        tool_access: scf.tool_access,
    };
    let response_scf_byte = response_scf.encode();

    // Swap src/dst for the response.
    let device_addr = u16::from_be_bytes(sal.inner.state().individual_address().0);
    // For broadcast responses, the NL will rewrite dst to 0x0000 on the
    // wire — the CCM context must match what the receiver sees.
    let dst_for_response = if is_broadcast { 0x0000 } else { src };

    let buf = msg.buf_mut();
    let ctrl_byte = buf[0];
    let npdu_byte = buf[offsets::MSG_ADDR_TYPE];
    let tpci_high = buf[offsets::MSG_TPCI];

    let mac_offset = secure::build_sync_response(
        buf,
        ctrl_byte,
        device_addr,
        dst_for_response,
        npdu_byte,
        tpci_high,
        response_scf_byte,
        &challenge_xor_random,
        &seq_nr_remote,
        &response_seq_local_bytes,
    );

    // Encrypt the payload and compute MAC.
    let tpci_apci = u16::from_be_bytes([buf[offsets::MSG_TPCI], buf[offsets::MSG_TPCI + 1]]);
    let mac = ccm::encrypt_and_mac_sync_res(
        &key,
        &random,
        device_addr,
        dst_for_response,
        addr_type,
        tpci_apci,
        response_scf_byte,
        &mut buf[secure::sync::SEQ_NR_REMOTE..secure::sync::SEQ_NR_REMOTE + 12],
    );
    buf[mac_offset..mac_offset + secure::MAC_LEN].copy_from_slice(&mac);
    buf.set_len(secure::sync::FRAME_LEN);

    // Step 11: Set appropriate response service type.
    let response_st = match incoming_service_type {
        ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
        ServiceType::T_Broadcast_Ind => ServiceType::T_Broadcast_Req,
        ServiceType::T_SystemBroadcast_Ind => ServiceType::T_SystemBroadcast_Req,
        _ => ServiceType::T_DataUnack_Req,
    };
    msg.set_service_type(response_st);

    // Step 12: Update rate limit timestamp.
    sal.p2p_state.last_sync_response.set(Some(embassy_time::Instant::now()));

    SecureResult::SyncResponse(msg)
}

// ========================================================================
// S-A_Sync_Res processing (DUT-initiated sync response handling)
// ========================================================================

/// Process an incoming S-A_Sync_Res that may correspond to a pending
/// DUT-initiated sync request.
///
/// If no pending sync exists, or if the response doesn't match (wrong
/// source, wrong flags, expired), the frame is silently dropped.
pub(super) fn process_sync_response<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
    sal: &SecureApplicationLayer<'a, D, SEQ, WithP2p>,
    msg: KnxMessageBuffer<Buffer<'static>>,
    scf: SecurityControlField,
    scf_byte: u8,
    src: u16,
) -> SecureResult
where
    D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    use crate::logging::debug;

    let pending = match sal.p2p_state.pending_sync.get() {
        Some(p) => p,
        None => {
            // No pending sync — unsolicited response, silently drop.
            return SecureResult::Dropped;
        }
    };

    // Step 1: Verify the response is from the expected peer.
    if src != pending.peer_ia {
        warn!("S-AL: sync response from unexpected IA {:#06X} (expected {:#06X})", src, pending.peer_ia);
        return SecureResult::Dropped;
    }

    // Step 2: Verify tool access flag matches.
    if scf.tool_access != pending.tool_access {
        warn!("S-AL: sync response tool flag mismatch");
        return SecureResult::Dropped;
    }

    // Step 3: Check timeout.
    if embassy_time::Instant::now() > pending.deadline {
        warn!("S-AL: sync response arrived after 6s timeout");
        sal.p2p_state.pending_sync.set(None);
        return SecureResult::Dropped;
    }

    // Step 4: Verify broadcast flag matches.
    if scf.system_broadcast != pending.is_broadcast {
        warn!("S-AL: sync response broadcast flag mismatch");
        return SecureResult::Dropped;
    }

    // Step 5: Extract challenge_xor_random and recover the responder's random.
    let buf = msg.buf();
    if buf.len() < secure::sync::FRAME_LEN {
        warn!("S-AL: sync response too short ({} bytes)", buf.len());
        return SecureResult::Dropped;
    }

    let mut challenge_xor_random = [0u8; 6];
    challenge_xor_random
        .copy_from_slice(&buf[secure::sync::CHALLENGE_XOR_RANDOM..secure::sync::CHALLENGE_XOR_RANDOM + 6]);

    let mut remote_random = [0u8; 6];
    for i in 0..6 {
        remote_random[i] = challenge_xor_random[i] ^ pending.challenge[i];
    }

    // Step 6: Extract encrypted payload and MAC, then verify + decrypt.
    let mut payload = [0u8; 12];
    payload.copy_from_slice(&buf[secure::sync::SEQ_NR_REMOTE..secure::sync::SEQ_NR_REMOTE + 12]);

    let mut received_mac = [0u8; 4];
    received_mac.copy_from_slice(&buf[secure::sync::FRAME_LEN - secure::MAC_LEN..secure::sync::FRAME_LEN]);

    let device_addr = u16::from_be_bytes(sal.inner.state().individual_address().0);
    let addr_type = buf[offsets::MSG_ADDR_TYPE];
    let tpci_apci = u16::from_be_bytes([buf[offsets::MSG_TPCI], buf[offsets::MSG_TPCI + 1]]);

    if ccm::verify_and_decrypt_sync_res(
        &pending.key,
        &remote_random,
        src,
        device_addr,
        addr_type,
        tpci_apci,
        scf_byte,
        &mut payload,
        &received_mac,
    )
    .is_err()
    {
        warn!("S-AL: sync response MAC verification failed");
        sal.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
        sal.p2p_state.pending_sync.set(None);
        return SecureResult::Dropped;
    }

    // Step 7: Extract decrypted SeqNr_remote and SeqNr_local.
    let mut seq_nr_remote = [0u8; 6];
    seq_nr_remote.copy_from_slice(&payload[0..6]);
    let mut seq_nr_local = [0u8; 6];
    seq_nr_local.copy_from_slice(&payload[6..12]);

    // Step 8: Update receiving sequence number from SeqNr_remote.
    // SeqNr_remote is what the responder tells us their next sending
    // sequence number will be. We store it as "last valid received".
    let seq_remote_val = seq_to_u64(&seq_nr_remote);
    if seq_remote_val > 0 {
        let mut storage = sal.seq_storage.borrow_mut();
        if pending.tool_access {
            let _ = storage.save_tool_receiving_seq(&seq_nr_remote);
        } else {
            let _ = storage.save_receiving_seq(src, &seq_nr_remote);
        }
    }

    // Step 9: Update sending sequence number from SeqNr_local if higher.
    // SeqNr_local is what the responder thinks our next sending sequence
    // should be. If it's higher than our current value, adopt it.
    let seq_local_val = seq_to_u64(&seq_nr_local);
    if seq_local_val > 0 {
        let mut storage = sal.seq_storage.borrow_mut();
        let (regular, tool) = storage.load_sending_seqs().unwrap_or(([0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 1]));
        let current = if pending.tool_access { &tool } else { &regular };
        let current_val = seq_to_u64(current);
        if seq_local_val > current_val {
            let new_regular = if pending.tool_access { regular } else { seq_nr_local };
            let new_tool = if pending.tool_access { seq_nr_local } else { tool };
            let _ = storage.save_sending_seqs(&new_regular, &new_tool);
        }
    }

    debug!(
        "S-AL: sync response accepted from {:#06X} (remote_seq={}, local_seq={})",
        src,
        seq_to_u64(&seq_nr_remote),
        seq_to_u64(&seq_nr_local)
    );

    // Step 10: Clear pending sync state.
    sal.p2p_state.pending_sync.set(None);

    SecureResult::Dropped // Response consumed, nothing to forward to inner AL.
}

// ========================================================================
// DUT-initiated S-A_Sync.req (spec §5.3.2)
// ========================================================================

/// Initiate an S-A_Sync_Req to a peer.
///
/// Builds and returns the encrypted sync request frame ready for
/// sending. Stores the pending sync state for matching the response.
///
/// Returns `None` if key lookup fails or buffer allocation fails.
pub(super) fn initiate_sync<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
    sal: &SecureApplicationLayer<'a, D, SEQ, WithP2p>,
    peer_ia: u16,
    tool_access: bool,
    is_broadcast: bool,
) -> Option<KnxMessageBuffer<Buffer<'static>>>
where
    D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    use crate::logging::debug;

    let security_state = sal.inner.state().extension_state();

    // Step 1: Key lookup.
    let key = if tool_access {
        let tk = security_state.tool_key();
        if tk != [0u8; 16] { tk } else { sal.inner.state().fdsk().copied().unwrap_or([0u8; 16]) }
    } else {
        match security_state.p2p_key_for_ia(peer_ia) {
            Some((k, _roles)) => k,
            None => {
                warn!("S-AL: initiate_sync — no P2P key for IA {:#06X}", peer_ia);
                return None;
            }
        }
    };

    // Step 2: Get current sending sequence number (don't increment for sync).
    let storage = sal.seq_storage.borrow();
    let (regular, tool_seq) = storage.load_sending_seqs().unwrap_or(([0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 1]));
    let seq_nr_local = if tool_access { tool_seq } else { regular };
    drop(storage);

    // Step 3: Generate random challenge.
    let mut challenge = [0u8; 6];
    sal.inner.state().fill_random(&mut challenge);
    let mut random = [0u8; 6];
    sal.inner.state().fill_random(&mut random);

    // Step 4: Build SCF for sync request.
    let scf = SecurityControlField {
        service: SecureServiceType::SyncRequest,
        system_broadcast: is_broadcast,
        confidentiality: true, // Sync always uses A+C.
        tool_access,
    };
    let scf_byte = scf.encode();

    // Step 5: Allocate buffer and build frame.
    let st = if is_broadcast { ServiceType::T_Broadcast_Req } else { ServiceType::T_DataUnack_Req };
    let buf = sal.inner.buffer_manager().try_alloc_with_size(secure::sync::FRAME_LEN)?;
    let mut msg = KnxMessageBuffer::new(buf, st);

    let device_addr = u16::from_be_bytes(sal.inner.state().individual_address().0);
    let dst = if is_broadcast { 0x0000u16 } else { peer_ia };
    let device_serial = sal.inner.state().serial_number();
    // For P2P, serial number is all-zero. For broadcast, use device serial.
    let serial_for_frame = if is_broadcast { *device_serial } else { [0u8; 6] };

    // CTRL byte: standard frame, no repeat.
    let ctrl = if is_broadcast { 0xBC } else { 0xB0 };
    // NPDU: routing counter = 6, individual addressing.
    let npdu = if is_broadcast { 0xE1 } else { 0x60 };

    let mac_offset = secure::build_sync_request(
        msg.buf_mut(),
        ctrl,
        device_addr,
        dst,
        npdu,
        0x00, // TPCI high bits: connectionless
        scf_byte,
        &seq_nr_local,
        &serial_for_frame,
        &challenge,
    );

    // Step 6: Encrypt challenge and compute MAC.
    let tpci_apci = u16::from_be_bytes([msg.buf()[offsets::MSG_TPCI], msg.buf()[offsets::MSG_TPCI + 1]]);
    let ccm_ctx = ccm::CcmContext { seq_nr: seq_nr_local, src: device_addr, dst, addr_type: npdu & 0x80, tpci_apci };

    let encrypted_challenge = &mut msg.buf_mut()[secure::sync::CHALLENGE..secure::sync::CHALLENGE + 6];
    let mac = ccm::encrypt_and_mac_sync_req(&key, &ccm_ctx, scf_byte, &serial_for_frame, encrypted_challenge);
    msg.buf_mut()[mac_offset..mac_offset + secure::MAC_LEN].copy_from_slice(&mac);
    msg.buf_mut().set_len(secure::sync::FRAME_LEN);

    // Step 7: Store pending sync state.
    sal.p2p_state.pending_sync.set(Some(PendingSyncState {
        peer_ia,
        tool_access,
        challenge,
        random,
        key,
        deadline: embassy_time::Instant::now() + embassy_time::Duration::from_secs(6),
        is_broadcast,
    }));

    debug!("S-AL: initiated sync request to {:#06X} (tool={}, broadcast={})", peer_ia, tool_access, is_broadcast);

    Some(msg)
}
