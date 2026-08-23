//! S-A_Sync handling that lives behind the `P2pFeature` gate.
//!
//! The incoming-sync-request dispatch entry point
//! ([`process_sync_request`]) is *always* reachable — ETS needs the
//! tool-key branch to commission every Data Secure device, regardless
//! of whether the device exposes a P2P key table. The entry point is
//! parameterised over `P2P: P2pFeature` and branches:
//!
//! - `scf.tool_access == true` → inline tool-key handler (no P2P
//!   state touched).
//! - `scf.tool_access == false` → delegate to
//!   `P2P::process_sync_request_p2p`, which is stubbed out on
//!   [`NoP2p`] and delegates to [`process_sync_request_p2p`] below on
//!   [`WithP2p`].
//!
//! The other two entry points ([`process_sync_response`] and
//! [`initiate_sync`]) are genuinely P2P-flow-only: they touch
//! `pending_sync` state that only [`WithP2p`] carries, so they are
//! only reachable through [`WithP2p`]'s trait impl.
//!
//! [`NoP2p`]: super::p2p_feature::NoP2p
//! [`WithP2p`]: super::p2p_feature::WithP2p

use crate::HasExtensionState;
use crate::StackState;
use crate::definition::StackDefinition;
use crate::layers::transport::CEMI_PSEUDO_ADDR;
use crate::objects::tables::{HasAssociationTable, LoadState};
use crate::prelude::HasAddressTable;
use crate::rng::Rng;
use crate::state::{HasSecurityState, SecurityFailureType};
use crate::storage::{SecureDeviceIdentity, SequenceNumberStorage, SiatAccess};
use zweidraehte_proto::crypto::{
    ccm,
    scf::{SecureServiceType, SecurityControlField},
};
use zweidraehte_proto::messages::{
    apdu::secure::{self, SyncReqRef},
    buffers::{Buffer, MessageBuffer},
    knx::{KnxMessageBuffer, ServiceType, Tpci, offsets},
};

use crate::logging::{debug, warn};

use super::p2p_feature::{P2pFeature, WithP2p};
use zweidraehte_proto::security::DEFAULT_SENDING;

use super::{PendingSyncState, SecureApplicationLayer, SecureResult, seq_to_u64, u64_to_seq};

// ========================================================================
// Shared entry point for incoming S-A_Sync_Req (spec 03/03/07 §5.3.2)
// ========================================================================

/// Process an incoming S-A_Sync_Req and generate an S-A_Sync_Res.
///
/// Parameterised over `P2P` so every secure device reaches this path —
/// commissioning tools always send tool-key sync_req, which needs to
/// succeed regardless of whether the device has a P2P key table.
///
/// The non-tool branch delegates to `P2P::process_sync_request_p2p`,
/// which is a no-op on [`NoP2p`] (group-only devices can't verify P2P
/// sync requests anyway, having neither key nor SIAT entry for the
/// sender) and routes through [`process_sync_request_p2p`] on
/// [`WithP2p`].
pub(super) fn process_sync_request<'a, D: StackDefinition, SEQ: SequenceNumberStorage + SiatAccess, P2P: P2pFeature>(
    sal: &SecureApplicationLayer<'a, D, SEQ, P2P>,
    mut msg: KnxMessageBuffer<Buffer<'static>>,
    scf: SecurityControlField,
    scf_byte: u8,
    src: u16,
    incoming_service_type: ServiceType,
) -> SecureResult
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    debug!(
        "S-AL sync_req: src={:#06X} tool={} sbc={} st={:?}",
        src, scf.tool_access, scf.system_broadcast, incoming_service_type
    );

    // Step 1: Rate limit — ignore if we responded within the
    // rate-limit window (1 s per spec; scaled for fast conformance
    // runs so tests don't burn real wall-clock between syncs).
    if let Some(last) = sal.last_sync_response.get() {
        if embassy_time::Instant::now() - last < sal.sync_rate_limit {
            debug!("S-AL sync_req: rate-limited (within window), dropping");
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
            debug!(
                "S-AL sync_req: broadcast serial mismatch (got {:?}, ours {:?}), dropping",
                zweidraehte_util::fmt::Bytes(&serial_number),
                zweidraehte_util::fmt::Bytes(device_serial)
            );
            return SecureResult::Dropped;
        }
    } else {
        // P2P: serial must be all-zero or match the device's serial.
        if serial_number != [0u8; 6] && serial_number != *device_serial {
            debug!(
                "S-AL sync_req: p2p serial mismatch (got {:?}, ours {:?}), dropping",
                zweidraehte_util::fmt::Bytes(&serial_number),
                zweidraehte_util::fmt::Bytes(device_serial)
            );
            return SecureResult::Dropped;
        }
    }

    // Step 4: Tool vs P2P branch. P2P runs through the feature trait
    // so `NoP2p` can elide the P2P-key/SIAT code path entirely.
    if !scf.tool_access {
        return P2P::process_sync_request_p2p(sal, msg, scf, scf_byte, src, incoming_service_type);
    }

    // Tool branch: key lookup (tool_key with FDSK fallback).
    let security_state = sal.inner.state().extension_state();
    let key = {
        let tk = security_state.tool_key();
        if tk != [0u8; 16] {
            debug!("S-AL sync_req: using configured tool key");
            tk
        } else {
            let fdsk =
                *<<D::State as StackState>::Identity as SecureDeviceIdentity>::fdsk(sal.inner.state().identity());
            debug!("S-AL sync_req: tool key empty, falling back to FDSK (present={})", fdsk != [0u8; 16]);
            fdsk
        }
    };

    build_sync_response_for(
        sal,
        msg,
        scf,
        scf_byte,
        src,
        incoming_service_type,
        is_broadcast,
        addr_type,
        serial_number,
        seq_nr_local_received,
        received_mac,
        ccm_ctx,
        key,
    )
}

// ========================================================================
// P2P-only branch of S-A_Sync_Req (reachable only via WithP2p)
// ========================================================================

/// Handle the non-tool branch of an incoming S-A_Sync_Req.
///
/// Called from [`WithP2p::process_sync_request_p2p`] only. Performs
/// the SIAT check and P2P-key lookup that `NoP2p` devices cannot do,
/// then hands off to [`build_sync_response_for`] to produce the
/// encrypted response.
pub(super) fn process_sync_request_p2p<'a, D: StackDefinition, SEQ: SequenceNumberStorage + SiatAccess>(
    sal: &SecureApplicationLayer<'a, D, SEQ, WithP2p>,
    mut msg: KnxMessageBuffer<Buffer<'static>>,
    scf: SecurityControlField,
    scf_byte: u8,
    src: u16,
    incoming_service_type: ServiceType,
) -> SecureResult
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    let security_state = sal.inner.state().extension_state();

    // Re-parse the sync header (the top-level handler parsed once for
    // the serial check, but that reference was dropped). The frame has
    // already been validated for length there.
    let buf = msg.buf_mut();
    let sync_ref = SyncReqRef::parse(buf).expect("already validated length");
    let seq_nr_local_received = sync_ref.seq_nr_local();
    let serial_number = sync_ref.knx_serial_number();
    let received_mac = sync_ref.mac();
    let addr_type = sync_ref.addr_type();
    let ccm_ctx = sync_ref.ccm_context();
    drop(sync_ref);

    let is_broadcast = addr_type != 0
        || matches!(incoming_service_type, ServiceType::T_Broadcast_Ind | ServiceType::T_SystemBroadcast_Ind);

    // SIAT check (non-tool only).
    if security_state.security_load_state() != LoadState::Loaded {
        return SecureResult::Dropped;
    }
    let Some(ia_index) = sal.seq_storage.borrow().siat_index_of(src) else {
        warn!("S-AL: sync req — sender {:#06X} not in SIAT", src);
        sal.log_security_failure_and_maybe_report(SecurityFailureType::RoleError, src, &[]);
        return SecureResult::Dropped;
    };

    // P2P key lookup by the sender's IA_Index (roles not needed for sync).
    let key = match security_state.p2p_key_for_index(ia_index) {
        Some((k, _roles)) => k,
        None => {
            warn!("S-AL: sync req — no P2P key for IA {:#06X} (IA_Index {})", src, ia_index);
            return SecureResult::Dropped;
        }
    };

    build_sync_response_for(
        sal,
        msg,
        scf,
        scf_byte,
        src,
        incoming_service_type,
        is_broadcast,
        addr_type,
        serial_number,
        seq_nr_local_received,
        received_mac,
        ccm_ctx,
        key,
    )
}

// ========================================================================
// Shared response-build helper
// ========================================================================

/// Verify the request's MAC, compute response sequence numbers, and
/// build the encrypted S-A_Sync_Res in-place in the request buffer.
///
/// Invoked by both the tool branch (in [`process_sync_request`]) and
/// the P2P branch ([`process_sync_request_p2p`]). The only per-caller
/// difference is key selection — everything from step 6 onward is
/// identical.
#[allow(clippy::too_many_arguments)]
fn build_sync_response_for<'a, D: StackDefinition, SEQ: SequenceNumberStorage + SiatAccess, P2P: P2pFeature>(
    sal: &SecureApplicationLayer<'a, D, SEQ, P2P>,
    mut msg: KnxMessageBuffer<Buffer<'static>>,
    scf: SecurityControlField,
    scf_byte: u8,
    src: u16,
    incoming_service_type: ServiceType,
    is_broadcast: bool,
    addr_type: u8,
    serial_number: [u8; 6],
    seq_nr_local_received: [u8; 6],
    received_mac: [u8; 4],
    ccm_ctx: ccm::CcmContext,
    key: [u8; 16],
) -> SecureResult
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    // Step 6: Verify and decrypt the challenge.
    //
    // SyncRes must use exactly the request's communication mode. Reject
    // anything else (notably group-addressed SyncReq) before changing replay
    // state; a catch-all connectionless response would hide a routing bug.
    let response_st = match incoming_service_type {
        ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
        ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
        ServiceType::T_Broadcast_Ind => ServiceType::T_Broadcast_Req,
        ServiceType::T_SystemBroadcast_Ind => ServiceType::T_SystemBroadcast_Req,
        _ => return SecureResult::Dropped,
    };

    // The bus TL stamps the sequence its response will use on connected
    // indications. SyncRes is already protected here, before it returns to
    // the TL, so CCM must cover that outgoing TPCI rather than the request's
    // independent receive-side sequence. The local cEMI management path has
    // no bus TL state and deliberately leaves the stamp absent; there the
    // response remains in the request's cEMI transport context.
    let response_tpci = msg.outgoing_tl_seq().map(Tpci::DataConnected).map(Tpci::octet);
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
            if let Err(_e) = storage.save_tool_receiving_seq(&updated_bytes) {
                warn!("S-AL: failed to persist tool receiving SeqNr (sync_req phase) from {:#06X}", src);
            }
        } else {
            if let Err(_e) = storage.save_receiving_seq(src, &updated_bytes) {
                warn!("S-AL: failed to persist receiving SeqNr (sync_req phase) from {:#06X}", src);
            }
        }
        updated
    } else {
        stored_val
    };

    // Response SeqNr_local = max(received - 1, stored) + 1
    let received_minus_1 = received_val.saturating_sub(1);
    let response_seq_local = received_minus_1.max(new_stored) + 1;
    let response_seq_local_bytes = u64_to_seq(response_seq_local);

    // Step 8: SeqNr_remote = device's own single Sequence Number Sending (the
    // one value used on every Secure Link). Do NOT increment — spec says sync
    // does not alter SeqNoSending.
    let seq_nr_remote = storage.load_sending_seq().unwrap_or(DEFAULT_SENDING);
    drop(storage);

    debug!(
        "S-AL sync_res: remote_seq={:?} local_seq={:?} (received={:?} stored_pre={})",
        zweidraehte_util::fmt::Bytes(&seq_nr_remote),
        zweidraehte_util::fmt::Bytes(&response_seq_local_bytes),
        zweidraehte_util::fmt::Bytes(&seq_nr_local_received),
        stored_val
    );

    // Step 9: Generate random.
    let mut random = [0u8; 6];
    <D::Rng as Rng>::fill(&mut random);

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
    //
    // The source must be the address the *requester* used to reach us, not
    // necessarily our bus address: the CCM nonce covers src/dst (see
    // `block_b0` / `ctr_crypt`), so signing with a different address than the
    // peer verifies against corrupts both the MAC and the keystream.
    //
    // On the bus those coincide. On the local cEMI device-management path
    // they do not: that client has no bus address, so the cEMI TL synthesises
    // the frame with source *and* destination `0.0.0` (`CEMI_PSEUDO_ADDR`),
    // and the peer computes its MAC with `0.0.0` as our address. `0.0.0` is
    // never a valid bus source, so a request arriving from it is
    // unambiguously that local path and we answer as `0.0.0` too.
    let cemi_pseudo = u16::from_be_bytes(CEMI_PSEUDO_ADDR.0);
    let device_addr =
        if src == cemi_pseudo { cemi_pseudo } else { u16::from_be_bytes(sal.inner.state().individual_address().0) };
    // For broadcast responses, the NL will rewrite dst to 0x0000 on the
    // wire — the CCM context must match what the receiver sees.
    let dst_for_response = if is_broadcast { 0x0000 } else { src };

    let buf = msg.buf_mut();
    let ctrl_byte = buf[0];
    let npdu_byte = buf[offsets::MSG_ADDR_TYPE];
    let tpci_high = response_tpci.unwrap_or(buf[offsets::MSG_TPCI]);

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

    // Step 11: Preserve the request communication mode selected above.
    msg.set_service_type(response_st);

    // Step 12: Update rate limit timestamp.
    sal.last_sync_response.set(Some(embassy_time::Instant::now()));

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
pub(super) fn process_sync_response<'a, D: StackDefinition, SEQ: SequenceNumberStorage + SiatAccess>(
    sal: &SecureApplicationLayer<'a, D, SEQ, WithP2p>,
    msg: KnxMessageBuffer<Buffer<'static>>,
    scf: SecurityControlField,
    scf_byte: u8,
    src: u16,
) -> SecureResult
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
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
            if let Err(_e) = storage.save_tool_receiving_seq(&seq_nr_remote) {
                warn!("S-AL: failed to persist tool receiving SeqNr (sync_res) from {:#06X}", src);
            }
        } else {
            if let Err(_e) = storage.save_receiving_seq(src, &seq_nr_remote) {
                warn!("S-AL: failed to persist receiving SeqNr (sync_res) from {:#06X}", src);
            }
        }
    }

    // Step 9: Update our Sequence Number Sending from SeqNr_local if higher.
    // SeqNr_local is what the responder expects from us next; if it exceeds our
    // current value we adopt it (raising the one counter used on every Secure
    // Link).
    let seq_local_val = seq_to_u64(&seq_nr_local);
    if seq_local_val > 0 {
        let mut storage = sal.seq_storage.borrow_mut();
        let current_val = seq_to_u64(&storage.load_sending_seq().unwrap_or(DEFAULT_SENDING));
        if seq_local_val > current_val {
            if let Err(_e) = storage.save_sending_seq(&seq_nr_local) {
                warn!("S-AL: failed to persist sending SeqNr (sync_res) from {:#06X}", src);
            }
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
pub(super) fn initiate_sync<'a, D: StackDefinition, SEQ: SequenceNumberStorage + SiatAccess>(
    sal: &SecureApplicationLayer<'a, D, SEQ, WithP2p>,
    peer_ia: u16,
    tool_access: bool,
    is_broadcast: bool,
) -> Option<KnxMessageBuffer<Buffer<'static>>>
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    let security_state = sal.inner.state().extension_state();

    // Step 1: Key lookup.
    let key = if tool_access {
        let tk = security_state.tool_key();
        if tk != [0u8; 16] {
            tk
        } else {
            *<<D::State as StackState>::Identity as SecureDeviceIdentity>::fdsk(sal.inner.state().identity())
        }
    } else {
        // The peer's SIAT position is its IA_Index, which is how the P2P key
        // table names it (03/05/01 §6.3.8.4).
        match sal
            .seq_storage
            .borrow()
            .siat_index_of(peer_ia)
            .and_then(|ia_index| security_state.p2p_key_for_index(ia_index))
        {
            Some((k, _roles)) => k,
            None => {
                warn!("S-AL: initiate_sync — no P2P key for IA {:#06X}", peer_ia);
                return None;
            }
        }
    };

    // Step 2: Get current sending sequence number (don't increment for sync).
    let storage = sal.seq_storage.borrow();
    let seq_nr_local = storage.load_sending_seq().unwrap_or(DEFAULT_SENDING);
    drop(storage);

    // Step 3: Generate random challenge.
    let mut challenge = [0u8; 6];
    <D::Rng as Rng>::fill(&mut challenge);

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
        key,
        deadline: embassy_time::Instant::now() + embassy_time::Duration::from_secs(6),
        is_broadcast,
    }));

    debug!("S-AL: initiated sync request to {:#06X} (tool={}, broadcast={})", peer_ia, tool_access, is_broadcast);

    Some(msg)
}
