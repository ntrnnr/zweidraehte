//! Secure Application Layer (S-AL) wrapper.
//!
//! Wraps the plain [`ApplicationLayer`] to add KNX Data Secure support.
//!
//! - **Incoming**: Detects Secure Service APDUs (APCI 0x03F1), decrypts/
//!   verifies, populates [`AccessContext`], forwards plaintext to inner AL.
//! - **Outgoing**: When the incoming request was secure, encrypts the
//!   response with the same key before forwarding to the TL.
//!
//! [`ApplicationLayer`]: crate::layers::application::ApplicationLayer
//! [`AccessContext`]: zweidraehte_proto::access::AccessContext

use core::cell::{Cell, RefCell};

use crate::{
    HasExtensionState, StackState,
    actor::Request,
    definition::StackDefinition,
    layers::application::{ApplicationLayer, ApplicationLayerService, ApplicationLayerServiceResponse},
    objects::tables::{AssociationTable, HasAssociationTable},
    prelude::HasAddressTable,
    state::{HasSecurityState, SecurityFailureType},
    storage::{SecureDeviceIdentity, SequenceNumberStorage, SiatAccess},
};
use zweidraehte_proto::access::{AccessContext, AccessSource, ClientRole, SecurityMode};
use zweidraehte_proto::address::GroupAddress;
use zweidraehte_proto::crypto::{ccm, scf::SecureServiceType};
use zweidraehte_proto::messages::{
    apdu::{
        network_parameter::NetworkParameterInfoReport,
        secure::{SecureApduMut, SecureApduRef},
    },
    buffers::{Buffer, MessageBuffer},
    builder::{ConfirmationExt, MessageBuilder},
    knx::{ApciCode, DestinationAddress, KnxMessageBuffer, Priority, ServiceType, offsets},
};
use zweidraehte_proto::security::{self, SeqVerdict, policy};

use crate::logging::{debug, warn};
use crate::objects::tables::{AddressTable, LoadState};
use crate::router::Outbox;
use crate::service::Layer;

pub mod group_data;
pub(crate) mod outgoing;
pub mod p2p_feature;
mod p2p_security;

pub use group_data::SecureGroupDataProvider;
pub use p2p_feature::{NoP2p, P2pFeature, WithP2p};

// ============================================================================
// Processing result for try_process_secure
// ============================================================================

/// Result of secure frame processing.
pub enum SecureResult {
    /// Forward the (decrypted) message to the inner Application Layer.
    Forward(KnxMessageBuffer<Buffer<'static>>),
    /// Frame was silently dropped (verification failed, etc.).
    Dropped,
    /// A sync response was generated — push directly to outbox.
    SyncResponse(KnxMessageBuffer<Buffer<'static>>),
}

/// Outcome of applying the outgoing security policy to one AL request.
///
/// A rejected request is retained solely to synthesize its local negative
/// confirmation. It is never forwarded to the transport layer.
enum OutgoingSecurityResult {
    Forward(KnxMessageBuffer<Buffer<'static>>),
    Rejected(KnxMessageBuffer<Buffer<'static>>),
}

// ============================================================================
// Sequence number helpers
// ============================================================================
//
// The 6-octet ⇄ u64 codec is the KNX wire format, so it comes from
// `zweidraehte_proto::security` rather than being spelled a second time here.
// Aliased to the names this module and `p2p_security` already use.

pub(super) use zweidraehte_proto::security::{seq6_to_u64 as seq_to_u64, u64_to_seq6 as u64_to_seq};

/// The durable replay state is part of accepting a secure frame, not merely
/// bookkeeping after acceptance. Distinguishing reads from writes keeps the
/// hot path's diagnostics useful without exposing a storage backend's error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) enum SequenceStateError {
    Load,
    Save,
    Invalid,
    Exhausted,
}

fn load_receiving_sequence<SEQ: SequenceNumberStorage>(
    storage: &SEQ,
    tool_access: bool,
    peer_ia: u16,
) -> Result<Option<[u8; 6]>, SequenceStateError> {
    if tool_access {
        storage.load_tool_receiving_seq().map_err(|_| SequenceStateError::Load)
    } else {
        storage.load_receiving_seq(peer_ia).map_err(|_| SequenceStateError::Load)
    }
}

fn save_receiving_sequence<SEQ: SequenceNumberStorage>(
    storage: &mut SEQ,
    tool_access: bool,
    peer_ia: u16,
    seq: &[u8; 6],
) -> Result<(), SequenceStateError> {
    let result =
        if tool_access { storage.save_tool_receiving_seq(seq) } else { storage.save_receiving_seq(peer_ia, seq) };
    result.map_err(|_| SequenceStateError::Save)
}

/// Validate and durably advance a sender's last-valid counter.
///
/// A caller may deliver plaintext only after this returns `Accept`. Otherwise
/// a replay could be delivered again after a storage failure or reboot.
fn persist_incoming_sequence<SEQ: SequenceNumberStorage>(
    storage: &mut SEQ,
    tool_access: bool,
    peer_ia: u16,
    received: &[u8; 6],
) -> Result<(SeqVerdict, Option<[u8; 6]>), SequenceStateError> {
    let stored = load_receiving_sequence(storage, tool_access, peer_ia)?;
    let verdict = security::check_receiving_seq(received, stored);
    if verdict == SeqVerdict::Accept {
        save_receiving_sequence(storage, tool_access, peer_ia, received)?;
    }
    Ok((verdict, stored))
}

// ============================================================================
// Pending sync state — tracks an outgoing S-A_Sync.req awaiting response
// ============================================================================

/// State for a pending DUT-initiated sync request.
///
/// When the DUT initiates an S-A_Sync_Req, it stores this state to match
/// and verify the subsequent S-A_Sync_Res from the peer. The sync is
/// considered expired after 6 seconds (spec §5.3.2).
#[derive(Clone, Copy)]
pub(super) struct PendingSyncState {
    /// Individual address of the sync target.
    peer_ia: u16,
    /// Whether this sync uses the tool key (T flag).
    tool_access: bool,
    /// Plaintext challenge generated by the DUT (before encryption).
    challenge: [u8; 6],
    /// Key used for the sync request (tool key or P2P key).
    key: [u8; 16],
    /// Deadline after which this pending sync expires (6 seconds from send).
    deadline: embassy_time::Instant,
    /// Whether the request was sent as broadcast.
    is_broadcast: bool,
}

// ============================================================================
// SecureApplicationLayer
// ============================================================================

/// Secure Application Layer wrapper.
///
/// Generics:
/// - `SEQ`: sequence number storage backend. Kept separate from the main
///   device config because sequence numbers change on every outgoing
///   secure frame and need wear-resistant storage (e.g., a dedicated
///   flash sector with wear leveling).
/// - `P2P`: [`P2pFeature`] slot selecting whether KNX Data Secure P2P
///   sync (S-A_Sync_Req / S-A_Sync_Res) is compiled in. Defaults to
///   [`NoP2p`]: no SIAT dispatch, no pending-sync tracker, no code —
///   LLVM elides the stubs through monomorphisation. Devices that need
///   P2P pass [`WithP2p`] explicitly.
pub struct SecureApplicationLayer<
    'a,
    D: StackDefinition,
    SEQ: SequenceNumberStorage + SiatAccess,
    P2P: P2pFeature = NoP2p,
> {
    pub(super) inner: ApplicationLayer<'a, D>,
    /// Borrowed reference to the sequence number storage that lives on
    /// `SecureExtensionState`. Shared with the Security IO augment which
    /// handles PID 59 (PID_SEQUENCE_NUMBER_SENDING) read/write.
    pub(super) seq_storage: &'a RefCell<SEQ>,
    /// Per-instance state owned by the P2P feature slot. For
    /// [`NoP2p`] this is `()` — zero bytes — and the feature trait
    /// methods return `Dropped`/`None` before ever touching it.
    pub(super) p2p_state: P2P::State,
    /// Timestamp of the last outgoing S-A_Sync_Res. Used to enforce
    /// the spec's 1 s rate-limit window, which applies to every sync
    /// response regardless of tool-vs-P2P key usage, so it lives on
    /// the S-AL itself rather than inside `WithP2pState`.
    pub(super) last_sync_response: Cell<Option<embassy_time::Instant>>,
    /// Configured rate-limit window (defaults to 1 s; scaled under the
    /// `conformance` feature). Held here so both the tool-key and P2P
    /// sync-request handlers read from one place.
    pub(super) sync_rate_limit: embassy_time::Duration,
}

impl<'a, D: StackDefinition, SEQ: SequenceNumberStorage + SiatAccess, P2P: P2pFeature>
    SecureApplicationLayer<'a, D, SEQ, P2P>
{
    /// Wrap a plain application layer in KNX Data Security.
    ///
    /// The inner layer is marked Data Secure here rather than by the
    /// caller. A device implements the security profile module exactly
    /// when its application layer is wrapped in this one, and this is
    /// the only constructor, so the two cannot disagree — there is no
    /// way to build a `SecureApplicationLayer` over an unmarked inner
    /// layer, and no way to mark one without wrapping it
    /// (`with_data_secure` is crate-private).
    pub fn new(inner: ApplicationLayer<'a, D>, seq_storage: &'a RefCell<SEQ>) -> Self {
        Self {
            inner: inner.with_data_secure(),
            seq_storage,
            p2p_state: P2P::State::default(),
            last_sync_response: Cell::new(None),
            sync_rate_limit: p2p_feature::default_sync_rate_limit(),
        }
    }

    pub fn inner_mut(&mut self) -> &mut ApplicationLayer<'a, D> {
        &mut self.inner
    }

    /// Reserve the next sending sequence number.
    ///
    /// Thin wrapper over [`outgoing::reserve_next_seq_nr`] that supplies
    /// the shared `seq_storage`.
    fn next_seq_nr(&self, tool_access: bool) -> Option<[u8; 6]> {
        outgoing::reserve_next_seq_nr(self.seq_storage, tool_access)
    }
}

impl<'a, D: StackDefinition, SEQ: SequenceNumberStorage + SiatAccess, P2P: P2pFeature>
    SecureApplicationLayer<'a, D, SEQ, P2P>
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    // ========================================================================
    // GO Security Flag Enforcement
    // ========================================================================

    /// Check whether the received security level matches the GO security flags
    /// for all group objects associated with the given TSAP.
    ///
    /// `received_security_bits` encodes what the frame provides:
    /// - 0x00 = plain (no security)
    /// - 0x01 = authentication only
    /// - 0x03 = authentication + confidentiality
    ///
    /// Returns `true` if the frame should be accepted, `false` if it should
    /// be rejected. The check is **exact match**: the received bits must equal
    /// the GO's required security flag bits (bits 0-1).
    fn check_go_security_flags(&self, tsap: u16, received_security_bits: u8) -> bool {
        let security_state = self.inner.state().extension_state();
        let ast = self.inner.state().ast().borrow();

        // The association table yields wire communication-object numbers;
        // `go_flag_slot` converts each to its position in the positional flag
        // table, and `go_flags_accept` applies the exact-match rule to all of
        // them at once (an object the table does not cover has no requirement).
        policy::go_flags_accept(
            ast.asaps_for_tsap(tsap)
                .map(|asap| security_state.go_security_flags_for(asap.saturating_sub(D::FIRST_ASAP))),
            received_security_bits,
        )
    }

    /// Check GO security flags for a plain (non-secure) group frame.
    ///
    /// At this point the TL has already resolved the destination GA to a TSAP
    /// and stored it in the destination address bytes. We read the TSAP directly
    /// and verify that all associated GOs have security flags = 0x00 (plain allowed).
    /// Returns `true` if the frame should be accepted.
    fn check_plain_group_allowed(&self, msg: &KnxMessageBuffer<Buffer<'static>>) -> bool {
        let buf = msg.buf();
        let tsap = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
        self.check_go_security_flags(tsap, 0x00)
    }

    // ========================================================================
    // Spontaneous Security Report emission (03/05/01 §6.3.11.4)
    // ========================================================================

    /// Record a security failure and, if `PID_SECURITY_REPORT_CONTROL`
    /// (58) is Enabled, broadcast a spontaneous
    /// `A_NetworkParameter_InfoReport` (APCI 0x3DB) per the management
    /// procedure `DMP_InterfaceObjectInfoReport_RCl`.
    ///
    /// Every failure while reporting is enabled emits — 03/05/01
    /// §6.3.11.4: "This shall be done regardless of whether the field
    /// Security Failure is set prior to this security failure or not.
    /// This is, the MaS shall report any security failure, even if a
    /// security failure is reported before or not." Only the tool resets
    /// the Security Failure field itself, in secure communication.
    fn log_security_failure_and_maybe_report(
        &self,
        failure_type: SecurityFailureType,
        source_addr: u16,
        frame_fragment: &[u8],
    ) {
        let security_state = self.inner.state().extension_state();
        security_state.log_security_failure(failure_type, source_addr, frame_fragment);
        if security_state.security_report_enabled() {
            let report = security_state.security_report();
            self.emit_security_report(report);
        }
    }

    /// Build and push a `T_Data_Broadcast` carrying
    /// `A_NetworkParameter_InfoReport` for the Security IO's
    /// PID_SECURITY_REPORT (57).
    ///
    /// Payload layout (03/03/07 §3.2.8, 03/05/01 §6.3.11.4):
    ///   object_type = 0x0011 (Security Interface Object)
    ///   property_id = 57    (PID_SECURITY_REPORT)
    ///   test_info   = 0x00
    ///   test_result = `security_report` byte (DPT_Security_Report)
    fn emit_security_report(&self, security_report: u8) {
        // Security IO type and PID from 03/07/03 (InterfaceObjectType table)
        // and 03/05/01 §6.3 (Security IO property table).
        const SECURITY_IO_TYPE: u16 = 0x0011;
        const PID_SECURITY_REPORT: u8 = 57;

        let payload = [0x00u8, security_report];
        let total_len = NetworkParameterInfoReport::msg_len(payload.len());

        let Some(msg_buf) = self.inner.buffer_manager().try_alloc_with_size(total_len) else {
            warn!("S-AL: no buffer for spontaneous security report");
            return;
        };

        // Broadcast via T_Data_Broadcast (destination 0x0000 as group, the
        // address-type flag in the cEMI ctrl byte distinguishes broadcast
        // from group). Priority = urgent per the management procedure
        // specification (03/05/01 §6.3.11.4). Urgent maps to the 2-bit
        // priority value 10b, which this enum labels `Alarm`
        // (03/03/02 §2.2.3: 00=system, 01=normal, 10=urgent, 11=low).
        //
        // §6.3.11.4 mandates plaintext for the security report broadcast
        // (the report itself is the security-error signalling channel; an
        // unauthenticated party must be able to read it). Stamp Plain
        // explicitly so the `try_encrypt_outgoing` drain leaves it
        // unwrapped even when this fires from inside an outbox-swap
        // window of a secure-incoming flow.
        let msg = MessageBuilder::new_request(
            msg_buf,
            ServiceType::T_Broadcast_Req,
            Priority::Alarm,
            DestinationAddress::Group(GroupAddress::from_bytes(&[0x00, 0x00])),
        )
        .with_required_security(zweidraehte_proto::messages::knx::RequiredSecurity::Plain)
        .with_application(ApciCode::NetworkParameterInfoReport)
        .with_data(|buf| {
            NetworkParameterInfoReport::write(buf, SECURITY_IO_TYPE, PID_SECURITY_REPORT, &payload);
        });

        self.inner.lctx().push_outbox(msg.into_inner());
    }

    /// Try to process an incoming message as a Secure Service APDU.
    fn try_process_secure(&self, mut msg: KnxMessageBuffer<Buffer<'static>>) -> SecureResult {
        // Connection lifecycle primitives carry no APDU. The plain AL consumes
        // them as notifications; security processing has nothing to inspect.
        if matches!(msg.service_type(), ServiceType::T_Connect_Ind | ServiceType::T_Disconnect_Ind) {
            return SecureResult::Forward(msg);
        }

        let apci = msg.get_apci_code();

        if !matches!(apci, ApciCode::SecureService) {
            // For plain group frames, verify that the GO security flags
            // allow plain access. If a GO requires authentication or
            // confidentiality, plain frames must be rejected.
            let st = msg.service_type();

            if matches!(st, ServiceType::T_GroupData_Ind) && !self.check_plain_group_allowed(&msg) {
                let src = u16::from_be_bytes(msg.get_source_addr().0);
                warn!("S-AL: plain group frame rejected — GO requires security");
                self.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
                return SecureResult::Dropped;
            }

            return SecureResult::Forward(msg);
        }

        // Don't try to decrypt confirmation frames — they echo our own
        // outgoing encrypted response and would fail MAC verification.
        let st = msg.service_type();
        if matches!(
            st,
            ServiceType::T_Data_Con
                | ServiceType::T_DataUnack_Con
                | ServiceType::T_GroupData_Con
                | ServiceType::T_Broadcast_Con
                | ServiceType::T_SystemBroadcast_Con
        ) {
            return SecureResult::Forward(msg);
        }

        let security_state = self.inner.state().extension_state();
        let src = u16::from_be_bytes(msg.get_source_addr().0);
        let outgoing_tl_seq = msg.outgoing_tl_seq();
        let buf = msg.buf_mut();

        // Parse the secure frame header in a nested scope so its buffer borrow
        // ends before the message is routed to a service-specific handler.
        let (scf_byte, scf) = {
            let secure_ref = match SecureApduRef::parse(buf) {
                Ok(reference) => reference,
                Err(_) => {
                    warn!("S-AL: secure frame too short ({} bytes)", buf.len());
                    return SecureResult::Dropped;
                }
            };

            let scf_byte = secure_ref.scf_byte();
            let scf = match secure_ref.scf() {
                Ok(scf) => scf,
                Err(_) => {
                    warn!("S-AL: invalid SCF 0x{:02X}", scf_byte);
                    self.log_security_failure_and_maybe_report(SecurityFailureType::ScfError, src, &[]);
                    return SecureResult::Dropped;
                }
            };

            (scf_byte, scf)
        };

        // ================================================================
        // S-A_Sync handling
        // ================================================================

        if scf.service == SecureServiceType::SyncRequest {
            return p2p_security::process_sync_request::<D, SEQ, P2P>(self, msg, scf, scf_byte, src, st);
        }

        if scf.service == SecureServiceType::SyncResponse {
            return P2P::process_sync_response(self, msg, scf, scf_byte, src);
        }

        // From here on, only S-A_Data is handled.
        // Re-parse the secure frame header for data-specific fields.
        let buf = msg.buf_mut();
        let (seq_nr, received_mac, addr_type, mut ctx) = {
            let secure_ref = SecureApduRef::parse(buf).expect("already validated length");

            // Early reject: SeqNr == 0 is always invalid per spec.
            // Full per-sender validation happens after MAC verification below.
            let seq_nr = secure_ref.seq_nr();
            if seq_nr == [0u8; 6] {
                warn!("S-AL: sequence number is zero — rejected");
                self.log_security_failure_and_maybe_report(SecurityFailureType::SeqNrError, src, &[]);
                return SecureResult::Dropped;
            }

            (seq_nr, secure_ref.mac(), secure_ref.addr_type(), secure_ref.ccm_context(src))
        };

        // For group-addressed frames, the TL has replaced the destination GA
        // with the TSAP in MSG_DEST_ADDR. The CCM context was built with the
        // TSAP as `dst`, but the MAC was computed with the original GA. We
        // must restore the original GA for correct MAC verification.
        if addr_type != 0 {
            let tsap = ctx.dst; // Currently holds the TSAP, not the GA.
            let adt = self.inner.state().adt().borrow();
            if let Some(ga) = adt.address(tsap) {
                ctx.dst = u16::from_be_bytes(ga.0);
            }
        }

        // Per KNX spec 03/05/01 §6.3.6-8: if the Security IO load state
        // is not "Loaded", security tables (P2P keys, group keys, SIAT) must
        // not be evaluated. Tool Key is independent of load state.
        if !scf.tool_access && security_state.security_load_state() != LoadState::Loaded {
            warn!(
                "S-AL: security tables not loaded (state={:?}), dropping non-tool frame",
                security_state.security_load_state()
            );
            return SecureResult::Dropped;
        }

        // Per AN158 §2.2.1.5.3.2: tool key access on group communication
        // is forbidden. However, tool key IS allowed on broadcast and system
        // broadcast (spec §5.5.8 Table 10). Only reject tool access when the
        // service type is T_GroupData_Ind (actual group communication).
        if scf.tool_access && matches!(st, ServiceType::T_GroupData_Ind) {
            warn!("S-AL: tool access on group communication rejected");
            self.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
            return SecureResult::Dropped;
        }

        // Every non-tool S-A_Data sender must already be in the SIAT,
        // regardless of whether this is group, broadcast, or point-to-point
        // communication (03/03/07 §5.1.3.5, reception step 1). A missing row
        // is discarded without updating the Security Failures Log. For P2P,
        // the row's position additionally selects the P2P key below.
        let sender_ia_index = if scf.tool_access {
            None
        } else {
            let Some(ia_index) = self.seq_storage.borrow().siat_index_of(src) else {
                warn!("S-AL: sender {:#06X} not in SIAT", src);
                return SecureResult::Dropped;
            };

            Some(ia_index)
        };

        // Look up key (and roles for P2P) based on access type.
        let mut p2p_roles: u16 = 0;
        let key = if scf.tool_access {
            // Tool access: use configured tool key, or FDSK as fallback
            // when the device is in factory state (tool key all zeros).
            let tk = security_state.tool_key();
            if tk != [0u8; 16] {
                debug!("S-AL: decrypt using configured tool key");
                tk
            } else {
                let fdsk =
                    *<<D::State as StackState>::Identity as SecureDeviceIdentity>::fdsk(self.inner.state().identity());
                debug!("S-AL: decrypt using FDSK fallback (tool key empty)");
                fdsk
            }
        } else if addr_type != 0 {
            // Group communication: look up group key by TSAP.
            //
            // At this point in the stack, the TL has already resolved the
            // destination group address to a TSAP and stored it in the
            // destination address bytes (via set_connection_nr). We read
            // the TSAP directly instead of re-resolving through the ADT.
            let tsap = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
            match security_state.group_key_for_index(tsap) {
                Some(k) => k,
                None => {
                    warn!("S-AL: no group key for TSAP {}", tsap);
                    self.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
                    return SecureResult::Dropped;
                }
            }
        } else {
            // P2P non-tool: look up key and roles from P2P key table, by the
            // sender's SIAT index resolved above (the branch that leaves
            // `sender_ia_index` unset is `addr_type != 0`, handled above).
            let ia_index = sender_ia_index.expect("non-tool P2P resolved the sender's IA_Index above");
            match security_state.p2p_key_for_index(ia_index) {
                Some((k, roles)) => {
                    p2p_roles = roles;
                    k
                }
                None => {
                    warn!("S-AL: no P2P key for IA {:#06X} (IA_Index {})", src, ia_index);
                    self.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
                    return SecureResult::Dropped;
                }
            }
        };

        // Decrypt / verify first. The secure envelope is not collapsed until
        // the replay counter has been advanced durably below.
        let mut secure_mut = SecureApduMut::parse(buf).expect("already validated length");

        if scf.confidentiality {
            if ccm::verify_and_decrypt(&key, &ctx, scf_byte, secure_mut.payload_mut(), &received_mac).is_err() {
                warn!("S-AL: MAC verification failed (A+C)");
                self.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
                return SecureResult::Dropped;
            }
        } else if ccm::verify_mac_auth_only(&key, &ctx, scf_byte, secure_mut.payload(), &received_mac).is_err() {
            warn!("S-AL: MAC verification failed (auth-only)");
            self.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
            return SecureResult::Dropped;
        }

        // ================================================================
        // Sequence Number Validation (per spec 03/03/07 §5.3.1)
        // ================================================================
        //
        // After successful MAC verification, compare the received SeqNr
        // against the stored "Last Valid SeqNr" for this sender.
        // Note: SeqNr == 0 was already rejected as an early optimization
        // before MAC verification.
        {
            let mut storage = self.seq_storage.borrow_mut();
            let (verdict, stored) = match persist_incoming_sequence(&mut *storage, scf.tool_access, src, &seq_nr) {
                Ok(result) => result,
                Err(operation) => {
                    warn!(
                        "S-AL: {:?} failure persisting receiving SeqNr from {:#06X} (tool={}); dropping frame",
                        operation, src, scf.tool_access
                    );
                    return SecureResult::Dropped;
                }
            };

            match verdict {
                SeqVerdict::Accept => {}
                SeqVerdict::Retransmission => {
                    // Ignore silently (no failure log per spec). Logged at debug
                    // so an otherwise-invisible drop is diagnosable (e.g. a tool
                    // replaying a SeqNr the device already consumed).
                    debug!(
                        "S-AL: dropping retransmission from {:#06X} (tool={}): SeqNr {} == stored",
                        src,
                        scf.tool_access,
                        security::seq6_to_u64(&seq_nr)
                    );
                    return SecureResult::Dropped;
                }
                SeqVerdict::Replay | SeqVerdict::Invalid => {
                    // The S-AL shall not block further messages from this sender.
                    // Surface the rejection: `log_security_failure_and_maybe_report`
                    // only updates the security-state counter, so without this the
                    // drop is invisible — a tool stuck on a stale SeqNr (e.g. one
                    // behind the value a prior tool/ETS session left in the shared
                    // `tool_receiving_seq`) otherwise looks like an unexplained hang.
                    warn!(
                        "S-AL: replay rejected from {:#06X} (tool={}): SeqNr {} < stored {}; tool must S-A_Sync_Req",
                        src,
                        scf.tool_access,
                        security::seq6_to_u64(&seq_nr),
                        stored.map(|s| security::seq6_to_u64(&s)).unwrap_or(0)
                    );
                    // Drop the seq-storage borrow before the helper call — the
                    // helper doesn't touch seq storage today, but releasing
                    // the outer `RefCell::borrow_mut` guard here keeps the
                    // invariant that only one cell is held across the call.
                    drop(storage);
                    self.log_security_failure_and_maybe_report(SecurityFailureType::SeqNrError, src, &[]);
                    return SecureResult::Dropped;
                }
            }
        }

        let new_len = secure_mut.unwrap_to_plaintext();
        buf.set_len(new_len);

        // ================================================================
        // GO Security Flag Enforcement (group-addressed frames only)
        // ================================================================
        //
        // For non-tool group communication, verify that the received security
        // level exactly matches the GO's required security flags. The rule is
        // exact match: auth-only frames are only accepted by GOs requiring
        // auth-only (flag 0x01), auth+conf by flag 0x03, etc.
        if !scf.tool_access && addr_type != 0 {
            let received_bits = if scf.confidentiality { 0x03 } else { 0x01 };
            // TSAP is in the destination bytes (set by TL's set_connection_nr).
            let tsap = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
            if !self.check_go_security_flags(tsap, received_bits) {
                warn!("S-AL: GO security flag mismatch for TSAP {} (received={:#04X})", tsap, received_bits);
                self.log_security_failure_and_maybe_report(SecurityFailureType::CryptoError, src, &[]);
                return SecureResult::Dropped;
            }
        }

        // Drop the outstanding `buf` borrow before stamping `msg`.
        let _ = buf;

        // Stamp the indication with its incoming security context so any
        // response built via `MessageBuilder::respond_to` inherits the
        // same level + tool-access flag automatically. The drain-time
        // path (`try_encrypt_outgoing` → `encrypt_spontaneous`) then
        // looks up the live key and synthesises a fresh SCF —
        // tool-key rotation handled implicitly because the read of
        // `tool_key()` is post-`set_tool_key`. `outgoing_tl_seq` is
        // already set on `msg` by the TL for connected indications.
        let stamp_level = if scf.confidentiality {
            zweidraehte_proto::messages::knx::RequiredSecurity::AuthConf
        } else {
            zweidraehte_proto::messages::knx::RequiredSecurity::Auth
        };
        msg.set_required_security(stamp_level);
        msg.set_tool_access_required(scf.tool_access);
        // `key` / `scf_byte` / `outgoing_tl_seq` are now reconstructed at
        // drain time from the response buffer's stamps; suppress the
        // unused warnings until the upstream parsing code stops binding
        // them.
        let _ = key;
        let _ = scf_byte;
        let _ = outgoing_tl_seq;

        // Populate AccessContext.
        let security_mode = if scf.confidentiality { SecurityMode::AuthConf } else { SecurityMode::AuthOnly };
        let role = if scf.tool_access {
            ClientRole::Tool
        } else if addr_type == 0 && p2p_roles != 0 {
            // P2P non-tool with assigned roles from the P2P key table.
            ClientRole::Roles(p2p_roles)
        } else {
            ClientRole::Unlisted
        };
        let mut access_ctx = AccessContext::with_security(0, security_mode, role);
        access_ctx.source_addr = src;
        msg.set_access_source(AccessSource::Explicit(access_ctx));

        SecureResult::Forward(msg)
    }

    // ========================================================================
    // Application request routing (intercepts SyncRequest before inner AL)
    // ========================================================================

    /// Handle an application service request, intercepting sync requests.
    ///
    /// `SyncRequest` is handled here by calling `initiate_sync`. All other
    /// requests are forwarded to the inner [`ApplicationLayer`] inside an
    /// outbox-swap window so any spontaneous outbound frames the inner AL
    /// pushes (e.g. a `T_GroupData_Req` from
    /// `ApplicationLayer::send_group_value_request`) flow through
    /// `try_encrypt_outgoing` before they hit the shared outbox.
    /// Without the swap the spontaneous send would bypass the S-AL entirely
    /// and go out plaintext even when the originating GO's
    /// `PID_GO_SECURITY_FLAGS` requires Auth/AuthConf.
    pub fn handle_app_request(&mut self, request: &Request<ApplicationLayerService, ApplicationLayerServiceResponse>) {
        match request.get() {
            ApplicationLayerService::SyncRequest { peer_ia, tool_access, is_broadcast } => {
                if let Some(msg) = P2P::initiate_sync(self, *peer_ia, *tool_access, *is_broadcast) {
                    self.inner.lctx().push_outbox(msg);
                    request.try_reply(ApplicationLayerServiceResponse::SyncInitiated).ok();
                } else {
                    request.try_reply(ApplicationLayerServiceResponse::SyncFailed).ok();
                }
            }
            _ => {
                self.with_outbox_swap(|this| this.inner.handle_app_request(request));
            }
        }
    }

    /// Run `f` against the inner AL with the shared outbox swapped for a
    /// fresh one, then drain the captured frames through
    /// [`Self::try_encrypt_outgoing`] back into the real outbox.
    ///
    /// This is the single chokepoint that lets the S-AL inspect every frame
    /// the inner AL emits, regardless of which entry point produced it
    /// (incoming-frame `process`, user `handle_app_request`, lifecycle
    /// `poll` / `init`). Each entry point uses this helper so a future
    /// spontaneous-output surface added to the inner AL automatically gets
    /// the encryption pass without a new swap site.
    fn with_outbox_swap<F: FnOnce(&mut Self)>(&mut self, f: F) {
        let original = {
            let outbox_cell = &self.inner.lctx().outbox;
            outbox_cell.replace(Outbox::new())
        };

        f(self);

        let mut inner_outbox = self.inner.lctx().outbox.replace(original);

        // Drain the captured queue into the real outbox in a single
        // FIFO pass, encrypting where required. A required-secure frame
        // that cannot be protected is rejected at the S-AL boundary. Feed
        // its negative confirmation straight back into the plain AL so a
        // pending communication object observes the failure instead of
        // remaining busy forever; the confirmation is local and must not
        // enter the lower-layer outbox.
        while let Some(out_msg) = inner_outbox.take_next() {
            match self.try_encrypt_outgoing(out_msg) {
                OutgoingSecurityResult::Forward(out_msg) => self.inner.lctx().outbox.borrow_mut().push(out_msg),
                OutgoingSecurityResult::Rejected(rejected) => {
                    let confirmation = rejected.error().build().into_inner();
                    Layer::<D>::process(&mut self.inner, confirmation);
                }
            }
        }
    }

    /// Encrypt an outgoing message based on its `RequiredSecurity` stamp.
    ///
    /// All decisions come from the buffer itself — there is no
    /// side-channel context. Reactive responses inherit their stamp
    /// from the indication via [`MessageBuilder::respond_to`]
    /// (which `try_process_secure` populates after MAC verification);
    /// spontaneous outputs stamp themselves at construction time.
    /// This matches the §5.5.3.x decision trees in 03/03/07: the
    /// AL-side service primitive carries `par_auth` / `par_conf`, and
    /// the S-AL routes accordingly.
    ///
    /// 1. **`Plain` / `Unspecified`** — emit unchanged. `Plain` is the
    ///    explicit plaintext stamp (e.g. spontaneous security report
    ///    per §6.3.11.4, GO-diagnostics direct-write 0x00).
    ///    `Unspecified` is the implicit default for plain incoming
    ///    flows and for non-secure devices.
    /// 2. **`Auth` / `AuthConf`** — encrypt. Key selection is driven
    ///    by `tool_access_required` (live `tool_key()` read for
    ///    reactive responses to tool-access requests, handling
    ///    `set_tool_key` rotation automatically per TSSJ §3.8.13.1)
    ///    or by destination type otherwise (group key by TSAP, P2P
    ///    key by peer IA).
    ///
    /// Confirmations and frames the secure layer never wraps return
    /// unchanged.
    fn try_encrypt_outgoing(&self, msg: KnxMessageBuffer<Buffer<'static>>) -> OutgoingSecurityResult {
        use zweidraehte_proto::messages::knx::RequiredSecurity;

        // Only ever encrypt downward indications. Confirmations come back
        // up the stack as plaintext metadata; never touch them.
        let st = msg.service_type();
        let is_downward = matches!(
            st,
            ServiceType::T_Data_Req
                | ServiceType::T_DataUnack_Req
                | ServiceType::T_GroupData_Req
                | ServiceType::T_Broadcast_Req
                | ServiceType::T_SystemBroadcast_Req
        );
        if !is_downward {
            return OutgoingSecurityResult::Forward(msg);
        }

        match msg.required_security() {
            RequiredSecurity::Plain | RequiredSecurity::Unspecified => {
                // Producer asked for plaintext, or no security context
                // was stamped (purely plaintext path: incoming plain
                // frame producing a plain response, or a non-secure
                // device's spontaneous output). Either way, no wrap.
                OutgoingSecurityResult::Forward(msg)
            }
            RequiredSecurity::Auth | RequiredSecurity::AuthConf => self.encrypt_spontaneous(msg),
        }
    }

    /// Encrypt a spontaneous outbound message stamped with explicit
    /// `Auth` / `AuthConf` security.
    ///
    /// Unlike the reactive path, there is no incoming SCF to inherit from:
    /// we synthesise the SCF from the requested level and the destination
    /// type, and select the key from the appropriate table:
    ///
    /// - `T_GroupData_Req` → group key by destination TSAP (still a
    ///   ConnectionNr in `MSG_DEST_ADDR`; the TL replaces it with the GA
    ///   later, but `wrap_outgoing` reverse-resolves the GA via the ADT
    ///   for the CCM context).
    /// - `T_Data_Req` / `T_DataUnack_Req` (P2P) → P2P key by the destination
    ///   IA's SIAT index (03/05/01 §6.3.8.4). P2P entries imply Auth+Conf;
    ///   if a caller stamps `Auth` on a P2P frame we honour it but the spec
    ///   convention is AuthConf.
    /// - `T_Broadcast_Req` / `T_SystemBroadcast_Req` → not supported here
    ///   yet (no spontaneous secure broadcast surfaces today; the security
    ///   report is `Plain`). A caller nevertheless requesting security gets
    ///   a negative confirmation.
    ///
    /// [`OutgoingSecurityResult::Rejected`] retains the request so
    /// [`Self::with_outbox_swap`] can return a negative confirmation to the
    /// plain AL. Application Layer §§5.2.1.4 and 5.5.3.3 require that outcome
    /// whenever requested security cannot be provided; forwarding the
    /// unchanged plaintext would be a security downgrade.
    fn encrypt_spontaneous(&self, mut msg: KnxMessageBuffer<Buffer<'static>>) -> OutgoingSecurityResult {
        use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
        use zweidraehte_proto::messages::knx::RequiredSecurity;

        let st = msg.service_type();
        let level = msg.required_security();
        debug_assert!(matches!(level, RequiredSecurity::Auth | RequiredSecurity::AuthConf));

        let security_state = self.inner.state().extension_state();

        // ----------------------------------------------------------------
        // Resolve key + tool_access
        // ----------------------------------------------------------------
        // If the buffer was stamped with `tool_access_required` (set by
        // `try_process_secure` for incoming tool-access frames and
        // propagated to responses by `respond_to`), the key is the
        // current tool key — read live so a `set_tool_key` call during
        // the inner AL's processing of the request is reflected in the
        // response (TSSJ §3.8.13.1).
        let (key, tool_access) = if msg.tool_access_required() {
            (security_state.tool_key(), true)
        } else {
            match st {
                ServiceType::T_GroupData_Req => {
                    let buf = msg.buf();
                    let tsap = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
                    match security_state.group_key_for_index(tsap) {
                        Some(k) => (k, false),
                        None => {
                            warn!(
                                "S-AL: rejecting secure group send to TSAP {} because no group key is configured",
                                tsap
                            );
                            return OutgoingSecurityResult::Rejected(msg);
                        }
                    }
                }
                ServiceType::T_Data_Req | ServiceType::T_DataUnack_Req => {
                    // For an individual-addressed P2P send the destination
                    // bytes hold the peer IA verbatim (not a TSAP — TSAP-style
                    // resolution applies only to group services).
                    let buf = msg.buf();
                    let peer_ia = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
                    match self
                        .seq_storage
                        .borrow()
                        .siat_index_of(peer_ia)
                        .and_then(|ia_index| security_state.p2p_key_for_index(ia_index))
                    {
                        Some((k, _roles)) => (k, false),
                        None => {
                            warn!(
                                "S-AL: rejecting secure P2P send to {:#06X} because no P2P key is configured",
                                peer_ia
                            );
                            return OutgoingSecurityResult::Rejected(msg);
                        }
                    }
                }
                ServiceType::T_Broadcast_Req | ServiceType::T_SystemBroadcast_Req => {
                    // No non-tool spontaneous secure broadcast surface
                    // exists today (the tool-access reactive path covers
                    // any secure broadcast response). Reject it so the
                    // omission cannot turn into a plaintext downgrade.
                    warn!("S-AL: rejecting unsupported spontaneous secure broadcast (st={:?})", st);
                    return OutgoingSecurityResult::Rejected(msg);
                }
                _ => return OutgoingSecurityResult::Rejected(msg),
            }
        };

        // ----------------------------------------------------------------
        // Synthesise SCF and reserve seqnr
        // ----------------------------------------------------------------
        let scf = SecurityControlField {
            service: SecureServiceType::Data,
            // System broadcast SCF bit is set only on T_SystemBroadcast_Req
            // wrappings (which we currently fall back from above). The
            // distinction maps to wire framing, not to which key we used.
            system_broadcast: matches!(st, ServiceType::T_SystemBroadcast_Req),
            confidentiality: matches!(level, RequiredSecurity::AuthConf),
            tool_access,
        };
        let scf_byte = scf.encode();

        let Some(seq_nr) = self.next_seq_nr(tool_access) else {
            warn!("S-AL: sequence number overflow, dropping spontaneous secure frame");
            return OutgoingSecurityResult::Rejected(msg);
        };

        debug!(
            "S-AL: encrypt spontaneous {:?} with key[0..2]={:02x}{:02x} (tool={}, scf=0x{:02x})",
            st, key[0], key[1], tool_access, scf_byte
        );

        // The CCM nonce covers src/dst, so the source must be the address the
        // peer will verify against — see the same reasoning in
        // `p2p_security::build_sync_response_for`. On the local cEMI
        // device-management path the client addresses us as `0.0.0`
        // (`CEMI_PSEUDO_ADDR`) and computes its MACs with that, so an
        // individually-addressed reply going back to `0.0.0` must be signed as
        // `0.0.0` rather than with our bus address.
        let src = {
            let cemi_pseudo = u16::from_be_bytes(crate::layers::transport::CEMI_PSEUDO_ADDR.0);
            let dst = {
                let buf = msg.buf();
                u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]])
            };
            let individually_addressed = matches!(st, ServiceType::T_Data_Req | ServiceType::T_DataUnack_Req);
            if individually_addressed && dst == cemi_pseudo {
                cemi_pseudo
            } else {
                u16::from_be_bytes(self.inner.state().individual_address().0)
            }
        };
        let adt = self.inner.state().adt().borrow();

        let inputs = outgoing::WrapInputs {
            scf_byte,
            key,
            src,
            seq_nr,
            // Connection-oriented reactive responses inherit the TL seq
            // from the indication via `respond_to`; spontaneous group/
            // broadcast sends carry `None`. Both cases just read what
            // the buffer was stamped with.
            outgoing_tl_seq: msg.outgoing_tl_seq(),
            adt: &*adt,
        };

        match outgoing::wrap_outgoing(&mut msg, inputs) {
            Ok(()) => OutgoingSecurityResult::Forward(msg),
            Err(outgoing::WrapError::BufferTooSmall) => OutgoingSecurityResult::Rejected(msg),
            Err(outgoing::WrapError::InvalidScf) => {
                // We just constructed the SCF ourselves — getting here
                // means a bug above. Drop defensively rather than ship a
                // garbled frame.
                warn!("S-AL: synthesised SCF 0x{:02X} unexpectedly invalid", scf_byte);
                OutgoingSecurityResult::Rejected(msg)
            }
        }
    }
}

impl<D: StackDefinition, SEQ: SequenceNumberStorage + SiatAccess, P2P: P2pFeature> Layer<D>
    for SecureApplicationLayer<'_, D, SEQ, P2P>
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as StackState>::Identity: SecureDeviceIdentity,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    const HANDLES: &'static [ServiceType] = <ApplicationLayer<'_, D> as Layer<D>>::HANDLES;

    fn init(&mut self) {
        // The inner AL's `init()` may queue ROI reads up front. The
        // same requirement applies: stamp + encrypt.
        self.with_outbox_swap(|this| Layer::<D>::init(&mut this.inner));
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        Layer::<D>::next_deadline(&self.inner)
    }

    fn poll(&mut self) {
        // Read-on-init reads (`A_GroupValue_Read.req`) and any other
        // spontaneous emissions originating from the inner AL's poll
        // loop need the same encryption pass that frame-driven sends
        // get.
        self.with_outbox_swap(|this| Layer::<D>::poll(&mut this.inner));
    }

    fn process(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) {
        match self.try_process_secure(msg) {
            SecureResult::Forward(msg) => {
                // Run the inner AL inside the same outbox-swap window
                // the spontaneous-output sites (`init`, `poll`,
                // `handle_app_request`) use. The indication has been
                // stamped with its incoming security context (level +
                // tool-access flag); `MessageBuilder::respond_to`
                // propagates these onto each response buffer, and
                // `try_encrypt_outgoing` reads them at drain time.
                // Tool-key rotation falls out for free: the encrypt
                // path reads `tool_key()` after `set_tool_key` has
                // returned, so the WriteConRes for PID_TOOL_KEY
                // encrypts with the newly-set key (TSSJ §3.8.13.1).
                self.with_outbox_swap(|this| Layer::<D>::process(&mut this.inner, msg));
            }
            SecureResult::SyncResponse(msg) => {
                // Sync response is already fully encrypted — push
                // directly.
                self.inner.lctx().push_outbox(msg);
            }
            SecureResult::Dropped => {
                // Verification failed — silently drop.
            }
        }
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::SequenceNumberStorage;

    #[derive(Default)]
    pub struct FaultySequenceStore {
        pub sending: [u8; 6],
        pub receiving: Option<[u8; 6]>,
        pub tool_receiving: Option<[u8; 6]>,
        pub fail_sending_load: bool,
        pub fail_receiving_load: bool,
        pub fail_save: bool,
        pub save_count: usize,
    }

    impl SequenceNumberStorage for FaultySequenceStore {
        type Error = ();

        fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
            if self.fail_sending_load { Err(()) } else { Ok(self.sending) }
        }

        fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
            if self.fail_save {
                return Err(());
            }
            self.sending = *seq;
            self.save_count += 1;
            Ok(())
        }

        fn load_receiving_seq(&self, _peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
            if self.fail_receiving_load { Err(()) } else { Ok(self.receiving) }
        }

        fn save_receiving_seq(&mut self, _peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
            if self.fail_save {
                return Err(());
            }
            self.receiving = Some(*seq);
            self.save_count += 1;
            Ok(())
        }

        fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
            if self.fail_receiving_load { Err(()) } else { Ok(self.tool_receiving) }
        }

        fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
            if self.fail_save {
                return Err(());
            }
            self.tool_receiving = Some(*seq);
            self.save_count += 1;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FaultySequenceStore;
    use super::*;

    #[test]
    fn incoming_sequence_is_accepted_only_after_a_durable_save() {
        let sequence = u64_to_seq(42);
        let mut store = FaultySequenceStore { fail_save: true, ..Default::default() };

        assert_eq!(persist_incoming_sequence(&mut store, false, 0x1101, &sequence), Err(SequenceStateError::Save));
        assert_eq!(store.receiving, None);

        store.fail_save = false;
        assert_eq!(persist_incoming_sequence(&mut store, false, 0x1101, &sequence), Ok((SeqVerdict::Accept, None)));
        assert_eq!(store.receiving, Some(sequence));
    }

    #[test]
    fn incoming_sequence_load_failure_cannot_assume_an_empty_history() {
        let mut store = FaultySequenceStore { fail_receiving_load: true, ..Default::default() };

        assert_eq!(persist_incoming_sequence(&mut store, true, 0x1101, &u64_to_seq(42)), Err(SequenceStateError::Load));
        assert_eq!(store.save_count, 0);
    }
}
