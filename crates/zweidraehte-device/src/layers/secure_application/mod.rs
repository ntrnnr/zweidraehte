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
//! [`AccessContext`]: crate::access::AccessContext

use core::cell::{Cell, RefCell};

use crate::{
    StackState,
    access::{AccessContext, AccessSource, ClientRole, SecurityMode},
    bcus::system_b::{HasExtensionState, HasSecurityState, SecurityFailureType},
    crypto::{
        ccm,
        scf::{SecureServiceType, SecurityControlField},
    },
    definition::StackDefinition,
    layers::application::ApplicationLayer,
    messages::{
        apdu::secure::{self, SecureApduMut, SecureApduRef},
        buffers::{Buffer, MessageBuffer},
        knx::{ApciCode, KnxMessageBuffer, ServiceType, offsets},
    },
    objects::tables::{AssociationTable, HasAssociationTable},
    prelude::HasAddressTable,
    router::{Layer, Outbox},
    storage::SequenceNumberStorage,
};

use crate::logging::warn;

// ============================================================================
// Outgoing security context — tracks whether to encrypt the response
// ============================================================================

/// Tracks the security context of the current incoming request so that
/// the outgoing response can be encrypted with the same parameters.
#[derive(Clone, Copy)]
struct OutgoingSecurityCtx {
    /// Whether the current request was secure and responses should be encrypted.
    active: bool,
    /// The key to use for encrypting the response.
    key: [u8; 16],
    /// SCF byte for the response (same algorithm/tool flag as request).
    scf_byte: u8,
    /// Source address of the original request (becomes destination of response).
    request_src: u16,
    /// TL outgoing sequence number for connection-oriented responses.
    /// When set, the S-AL pre-sets the TPCI to `DataConnected(seq)` before
    /// encrypting so the CCM B0 block includes the correct TPCI bits.
    outgoing_tl_seq: Option<u8>,
}

impl Default for OutgoingSecurityCtx {
    fn default() -> Self {
        Self { active: false, key: [0u8; 16], scf_byte: 0, request_src: 0, outgoing_tl_seq: None }
    }
}

// ============================================================================
// SecureApplicationLayer
// ============================================================================

/// Secure Application Layer wrapper.
///
/// Generic over `SEQ`: the sequence number storage backend. This is
/// kept separate from the main device config because sequence numbers
/// change on every outgoing secure frame and need wear-resistant
/// storage (e.g., dedicated flash sector with wear leveling).
pub struct SecureApplicationLayer<'a, D: StackDefinition, SEQ: SequenceNumberStorage> {
    inner: ApplicationLayer<'a, D>,
    state: &'a D::State,
    /// Security context for encrypting the outgoing response.
    outgoing_ctx: Cell<OutgoingSecurityCtx>,
    /// Borrowed reference to the sequence number storage that lives on
    /// `SecureExtensionState`. Shared with the Security IO augment which
    /// handles PID 59 (PID_SEQUENCE_NUMBER_SENDING) read/write.
    seq_storage: &'a RefCell<SEQ>,
}

impl<'a, D: StackDefinition, SEQ: SequenceNumberStorage> SecureApplicationLayer<'a, D, SEQ> {
    pub fn new(inner: ApplicationLayer<'a, D>, state: &'a D::State, seq_storage: &'a RefCell<SEQ>) -> Self {
        Self { inner, state, outgoing_ctx: Cell::new(OutgoingSecurityCtx::default()), seq_storage }
    }

    pub fn inner_mut(&mut self) -> &mut ApplicationLayer<'a, D> {
        &mut self.inner
    }

    /// Get the next sending sequence number for the given access type
    /// and increment it. Persists the updated value to storage.
    fn next_seq_nr(&self, tool_access: bool) -> [u8; 6] {
        let mut storage = self.seq_storage.borrow_mut();
        let (regular, tool) = storage.load_sending_seqs().unwrap_or(([0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 1]));
        let seq = if tool_access { tool } else { regular };

        // Increment: treat as 48-bit big-endian counter.
        let val = u64::from_be_bytes([0, 0, seq[0], seq[1], seq[2], seq[3], seq[4], seq[5]]);
        let next_bytes = (val.wrapping_add(1)).to_be_bytes();
        let mut next_seq = [0u8; 6];
        next_seq.copy_from_slice(&next_bytes[2..8]);

        // Save both counters with only the relevant one changed.
        if tool_access {
            let _ = storage.save_sending_seqs(&regular, &next_seq);
        } else {
            let _ = storage.save_sending_seqs(&next_seq, &tool);
        }

        seq
    }
}

impl<'a, D: StackDefinition, SEQ: SequenceNumberStorage> SecureApplicationLayer<'a, D, SEQ>
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
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
        let security_state = self.state.extension_state();
        let ast = self.state.ast().borrow();

        for asap in ast.asaps_for_tsap(tsap) {
            // The GO flags table is indexed by 0-based position, written via
            // PID_GO_SECURITY_FLAGS with 1-based property indexing. The ASAP
            // from the association table is the 1-based communication object
            // number, so we subtract 1 to get the 0-based GO flag index.
            let go_index = asap.saturating_sub(1);
            if let Some(go_flag) = security_state.go_security_flags_for(go_index) {
                let required = go_flag & 0x03;
                if required != received_security_bits {
                    return false;
                }
            }
            // If no GO flag entry exists for this ASAP, the GO has no
            // security requirement — accept any security level.
        }

        true
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

    /// Try to process an incoming message as a Secure Service APDU.
    fn try_process_secure(
        &self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> Option<KnxMessageBuffer<Buffer<'static>>> {
        let apci = msg.get_apci_code();

        if !matches!(apci, ApciCode::SecureService) {
            // Not secure — clear any pending outgoing security context.
            self.outgoing_ctx.set(OutgoingSecurityCtx::default());

            // For plain group frames, verify that the GO security flags
            // allow plain access. If a GO requires authentication or
            // confidentiality, plain frames must be rejected.
            let st = msg.service_type();
            if matches!(st, ServiceType::T_GroupData_Ind) {
                if !self.check_plain_group_allowed(&msg) {
                    let src = u16::from_be_bytes(msg.get_source_addr().0);
                    let security_state = self.state.extension_state();
                    warn!("S-AL: plain group frame rejected — GO requires security");
                    security_state.log_security_failure(SecurityFailureType::CryptoError, src, &[]);
                    return None;
                }
            }

            return Some(msg);
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
            return Some(msg);
        }

        let security_state = self.state.extension_state();
        let src = u16::from_be_bytes(msg.get_source_addr().0);
        let outgoing_tl_seq = msg.outgoing_tl_seq();
        let buf = msg.buf_mut();

        // Parse the secure frame header.
        let secure_ref = match SecureApduRef::parse(buf) {
            Ok(r) => r,
            Err(_) => {
                warn!("S-AL: secure frame too short ({} bytes)", buf.len());
                return None;
            }
        };

        let scf_byte = secure_ref.scf_byte();
        let scf = match secure_ref.scf() {
            Ok(scf) => scf,
            Err(_) => {
                warn!("S-AL: invalid SCF 0x{:02X}", scf_byte);
                security_state.log_security_failure(SecurityFailureType::ScfError, src, &[]);
                return None;
            }
        };

        // Only handle S-A_Data for now.
        if scf.service != SecureServiceType::Data {
            warn!("S-AL: sync services not yet implemented");
            return None;
        }

        // Sequence number validation: reject seq_nr == 0 unconditionally.
        // A zero sequence number is always invalid per spec.
        //
        // TODO: full SIAT-based sequence validation (check against last-valid
        // receiving sequence number per sender) is not yet implemented.
        let seq_nr = secure_ref.seq_nr();
        if seq_nr == [0u8; 6] {
            warn!("S-AL: sequence number is zero — rejected");
            security_state.log_security_failure(SecurityFailureType::SeqNrError, src, &[]);
            return None;
        }
        let received_mac = secure_ref.mac();
        let addr_type = secure_ref.addr_type();
        let mut ctx = secure_ref.ccm_context(src);
        drop(secure_ref);

        // For group-addressed frames, the TL has replaced the destination GA
        // with the TSAP in MSG_DEST_ADDR. The CCM context was built with the
        // TSAP as `dst`, but the MAC was computed with the original GA. We
        // must restore the original GA for correct MAC verification.
        if addr_type != 0 {
            use crate::objects::tables::AddressTable;
            let tsap = ctx.dst; // Currently holds the TSAP, not the GA.
            let adt = self.state.adt().borrow();
            if let Some(ga) = adt.get_address(tsap) {
                ctx.dst = u16::from_be_bytes(ga.0);
            }
        }

        // Per KNX spec 03/05/01 §6.3.6-8: if the Security IO load state
        // is not "Loaded", security tables (P2P keys, group keys, SIAT) must
        // not be evaluated. Tool Key is independent of load state.
        if !scf.tool_access {
            use crate::objects::tables::LoadState;
            if security_state.security_load_state() != LoadState::Loaded {
                warn!(
                    "S-AL: security tables not loaded (state={:?}), dropping non-tool frame",
                    security_state.security_load_state()
                );
                return None;
            }
        }

        // Per AN158 §2.2.1.5.3.2: tool key access on group communication
        // is forbidden. Reject frames with tool_access=true that are
        // group-addressed.
        if scf.tool_access && addr_type != 0 {
            warn!("S-AL: tool access on group communication rejected");
            security_state.log_security_failure(SecurityFailureType::CryptoError, src, &[]);
            return None;
        }

        // Look up key based on access type.
        let key = if scf.tool_access {
            // Tool access: use configured tool key, or FDSK as fallback
            // when the device is in factory state (tool key all zeros).
            let tk = security_state.tool_key();
            if tk != [0u8; 16] { tk } else { self.state.fdsk().copied().unwrap_or([0u8; 16]) }
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
                    security_state.log_security_failure(SecurityFailureType::CryptoError, src, &[]);
                    return None;
                }
            }
        } else {
            warn!("S-AL: P2P secure APDU without tool access not yet supported");
            return None;
        };

        // Decrypt / verify, then collapse to plaintext.
        let mut secure_mut = SecureApduMut::parse(buf).expect("already validated length");

        if scf.confidentiality {
            if ccm::verify_and_decrypt(&key, &ctx, scf_byte, secure_mut.payload_mut(), &received_mac).is_err() {
                warn!("S-AL: MAC verification failed (A+C)");
                security_state.log_security_failure(SecurityFailureType::CryptoError, src, &[]);
                return None;
            }
        } else if ccm::verify_mac_auth_only(&key, &ctx, scf_byte, secure_mut.payload(), &received_mac).is_err() {
            warn!("S-AL: MAC verification failed (auth-only)");
            security_state.log_security_failure(SecurityFailureType::CryptoError, src, &[]);
            return None;
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
                security_state.log_security_failure(SecurityFailureType::CryptoError, src, &[]);
                return None;
            }
        }

        // Set outgoing security context so the response gets encrypted.
        self.outgoing_ctx.set(OutgoingSecurityCtx { active: true, key, scf_byte, request_src: src, outgoing_tl_seq });

        // Populate AccessContext.
        let security_mode = if scf.confidentiality { SecurityMode::AuthConf } else { SecurityMode::AuthOnly };
        let role = if scf.tool_access { ClientRole::Tool } else { ClientRole::Unlisted };
        let mut access_ctx = AccessContext::with_security(0, security_mode, role);
        access_ctx.source_addr = src;
        let _ = buf;
        msg.set_access_source(AccessSource::Explicit(access_ctx));

        Some(msg)
    }

    /// Encrypt an outgoing message if the current context requires it.
    ///
    /// Takes a plaintext message from the inner AL's outbox and wraps it
    /// in a Secure APDU if the outgoing security context is active.
    fn try_encrypt_outgoing(&self, mut msg: KnxMessageBuffer<Buffer<'static>>) -> KnxMessageBuffer<Buffer<'static>> {
        let ctx = self.outgoing_ctx.get();
        if !ctx.active {
            return msg;
        }

        // Only encrypt downward indications (to TL), not confirmations coming back up.
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
            return msg;
        }

        // ============================================================
        // Build the secure frame
        // ============================================================
        //
        // The plaintext message has:
        //   buf[MSG_TPCI..MSG_TPCI+2] = plain TPCI/APCI
        //   buf[MSG_APDU..] = plain data
        //
        // The secure frame needs:
        //   buf[MSG_TPCI..MSG_TPCI+2] = Secure TPCI/APCI (0x03F1)
        //   buf[MSG_APDU]   = SCF
        //   buf[MSG_APDU+1..+7] = SeqNr (6 bytes)
        //   buf[MSG_APDU+7..] = encrypted payload + MAC (4 bytes)
        //
        // The "payload" P for A+C = 000000b | plain APDU = the plain
        // TPCI/APCI + data, which is currently at buf[MSG_TPCI..end].

        let buf = msg.buf_mut();

        // For group-addressed responses, look up the outgoing group key
        // based on the destination TSAP (which is still in MSG_DEST_ADDR as
        // a ConnectionNr). The incoming key (ctx.key) was for the receiving
        // GA's TSAP; the outgoing key may differ when the GO has separate
        // send/receive GAs.
        let tool_access = (ctx.scf_byte & 0x80) != 0;
        let encryption_key = if matches!(st, ServiceType::T_GroupData_Req) && !tool_access {
            let out_tsap = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
            let security_state = self.state.extension_state();
            security_state.group_key_for_index(out_tsap).unwrap_or(ctx.key)
        } else {
            ctx.key
        };

        // For connection-oriented responses, pre-set the TPCI sequence
        // number bits on the plaintext before encrypting. The CCM B0
        // block must include the correct TPCI with TL sequence bits
        // (spec 03/03/07 §5.1.3.2 Figure 101). Without this, the MAC
        // would be computed with the plain TPCI (0x00) but the TL later
        // sets the numbered-data TPCI on the already-encrypted frame,
        // causing a mismatch at the receiver.
        if let Some(seq) = ctx.outgoing_tl_seq {
            // DataConnected TPCI: DC=0 (bit 7, Data), N=1 (bit 6, Numbered),
            // seq in bits 5-2. Preserve the lower 2 bits (APCI high).
            let tpci_bits = 0x40 | ((seq & 0x0F) << 2);
            let apci_high = buf[offsets::MSG_TPCI] & 0x03;
            buf[offsets::MSG_TPCI] = tpci_bits | apci_high;
        }

        let plain_content_len = buf.len();
        let needed_len = plain_content_len + secure::OVERHEAD;

        if needed_len > buf.capacity() + offsets::MSG_TPCI {
            warn!("S-AL: buffer too small for secure frame ({} > {})", needed_len, buf.capacity() + offsets::MSG_TPCI);
            return msg; // Fall back to plaintext.
        }

        // Expand buffer so wrap_plaintext has room to shift the payload.
        buf.set_len(needed_len);

        let tool_access = (ctx.scf_byte & 0x80) != 0; // bit 7 = Tool Access flag
        let seq_nr = self.next_seq_nr(tool_access);
        let layout = secure::wrap_plaintext(buf, plain_content_len, ctx.scf_byte, &seq_nr)
            .expect("buffer capacity already verified");

        // Encrypt payload and compute MAC.
        // Use the device's own address for src rather than reading from the
        // buffer — the network layer hasn't filled in MSG_SOURCE_ADDR yet at
        // this point in the outgoing path.
        let src = u16::from_be_bytes(self.state.individual_address().0);
        let secure_ref = SecureApduRef::parse(buf).expect("just built a valid secure frame");
        let mut ccm_ctx = secure_ref.ccm_context(src);

        // For outgoing group responses, MSG_DEST_ADDR still contains the TSAP
        // (ConnectionNr) — the TL hasn't resolved it to the actual GA yet.
        // Reverse-lookup the real GA for the CCM context so the receiver can
        // verify the MAC. Also set the group address type bit in the CCM context.
        if matches!(st, ServiceType::T_GroupData_Req) {
            use crate::objects::tables::AddressTable;
            let tsap = ccm_ctx.dst;
            let adt = self.state.adt().borrow();
            if let Some(ga) = adt.get_address(tsap) {
                ccm_ctx.dst = u16::from_be_bytes(ga.0);
                ccm_ctx.addr_type = 0x80; // Group addressed
            }
        }
        drop(secure_ref);

        let scf = SecurityControlField::parse(ctx.scf_byte).expect("valid SCF from incoming");

        let mac = if scf.confidentiality {
            ccm::encrypt_and_mac(
                &encryption_key,
                &ccm_ctx,
                ctx.scf_byte,
                &mut buf[layout.payload_start..layout.payload_end],
            )
        } else {
            ccm::compute_mac_auth_only(
                &encryption_key,
                &ccm_ctx,
                ctx.scf_byte,
                &buf[layout.payload_start..layout.payload_end],
            )
        };

        buf[layout.mac_start..layout.mac_start + secure::MAC_LEN].copy_from_slice(&mac);

        msg
    }
}

impl<D: StackDefinition, SEQ: SequenceNumberStorage> Layer for SecureApplicationLayer<'_, D, SEQ>
where
    D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    const HANDLES: &'static [ServiceType] = ApplicationLayer::<D>::HANDLES;

    fn process(&mut self, msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        match self.try_process_secure(msg) {
            Some(msg) => {
                // Use a local outbox to intercept outgoing messages.
                let mut local_outbox = Outbox::new();
                self.inner.process(msg, &mut local_outbox);

                // Drain local outbox, encrypting responses if needed.
                while let Some(out_msg) = local_outbox.take_next() {
                    let out_msg = self.try_encrypt_outgoing(out_msg);
                    outbox.push(out_msg);
                }

                // Clear outgoing context after processing.
                self.outgoing_ctx.set(OutgoingSecurityCtx::default());
            }
            None => {
                // Verification failed — silently drop.
            }
        }
    }

    fn next_deadline(&self) -> Option<embassy_time::Instant> {
        self.inner.next_deadline()
    }

    fn poll(&mut self, outbox: &mut Outbox) {
        self.inner.poll(outbox);
    }

    fn init(&mut self) {
        self.inner.init();
    }
}
