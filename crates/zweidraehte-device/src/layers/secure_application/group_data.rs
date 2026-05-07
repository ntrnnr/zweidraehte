//! Secure-aware group-addressed sender.
//!
//! Sibling of [`GroupDataProvider`](crate::layers::application::group_data::GroupDataProvider)
//! for the KNX Data Secure path. Builds a full secure
//! `T_GroupData_Req` frame (SCF + SeqNr + encrypted/authenticated
//! payload + MAC) and queues it on the deferred outbox.
//!
//! Used for *unsolicited* secure group emissions — situations where the
//! triggering request arrives plaintext but the outgoing telegram must
//! be wrapped per the request's security flag bits. The flagship
//! caller is `PID_GO_DIAGNOSTICS` WriteServiceID `0x01` / `0x03`
//! (sections 6.2.7 / 6.2.15 in the KNX Data Security conformance
//! suite); the normal S-AL "respond to incoming secure request" path
//! does not apply because the originating command was plaintext, so
//! the reactive stamp-propagation through `respond_to` would copy
//! `Unspecified` — and the spec mandates explicit Auth/AuthConf for
//! these GO-diagnostics replies regardless.

use zweidraehte_proto::crypto::scf::{SecureServiceType, SecurityControlField};
use zweidraehte_proto::messages::{
    apdu::group_value::{GroupValueReadRequest, GroupValueWriteRequest},
    builder::MessageBuilder,
    knx::{ApciCode, DestinationAddress, Priority, ServiceType},
};

use crate::{
    StackDefinition, StackState,
    bcus::system_b::{HasExtensionState, HasSecurityState, HasSeqStorage},
    context::layer::LayerContext,
    layers::application::capabilities::{GroupValueEncoding, RequestedSecurity, SecureGroupValueAddressedSender},
    logging::warn,
    objects::tables::HasAddressTable,
};

use super::outgoing;

// ============================================================================
// SecureGroupDataProvider
// ============================================================================

/// Borrowed handle combining device state and runtime context for secure
/// group-addressed sends.
///
/// Transient — built on demand via
/// [`ServiceCtx::secure_group_value_sender`](crate::service::ServiceCtx::secure_group_value_sender).
/// Holds no persistent state of its own; every call is a pure function
/// over `state` + `lctx` + CCM primitives.
pub struct SecureGroupDataProvider<'a, D: StackDefinition> {
    state: &'a D::State,
    lctx: &'a LayerContext<D>,
}

impl<'a, D: StackDefinition> SecureGroupDataProvider<'a, D> {
    pub fn new(state: &'a D::State, lctx: &'a LayerContext<D>) -> Self {
        Self { state, lctx }
    }
}

impl<D: StackDefinition> SecureGroupValueAddressedSender for SecureGroupDataProvider<'_, D>
where
    D::State: StackState + HasExtensionState + HasAddressTable,
    <D::State as HasExtensionState>::ES: HasSecurityState + HasSeqStorage,
{
    fn send_group_write_tsap_secure(
        &self,
        tsap: u16,
        priority: Priority,
        encoding: GroupValueEncoding,
        data: &[u8],
        security: RequestedSecurity,
    ) {
        self.send_group_tsap_secure(tsap, priority, Some((encoding, data)), security);
    }

    fn send_group_read_tsap_secure(&self, tsap: u16, priority: Priority, security: RequestedSecurity) {
        self.send_group_tsap_secure(tsap, priority, None, security);
    }
}

impl<D: StackDefinition> SecureGroupDataProvider<'_, D>
where
    D::State: StackState + HasExtensionState + HasAddressTable,
    <D::State as HasExtensionState>::ES: HasSecurityState + HasSeqStorage,
{
    /// Build and queue a secure `A_GroupValue_{Write,Read}`.
    ///
    /// When `value` is `Some`, produces a Write with the given encoding
    /// and payload bytes; when `None`, produces a Read.
    fn send_group_tsap_secure(
        &self,
        tsap: u16,
        priority: Priority,
        value: Option<(GroupValueEncoding, &[u8])>,
        security: RequestedSecurity,
    ) {
        // ============================================================
        // Look up the group key for the destination TSAP.
        // ============================================================
        //
        // The GO-diagnostics handler has already checked this via
        // `has_group_key(tsap)` before dispatching to us, but re-check
        // defensively — the handler and the sender live in different
        // impl blocks and bounds.
        let security_state = self.state.extension_state();
        let Some(key) = security_state.group_key_for_index(tsap) else {
            warn!("SecureGroupDataProvider: no group key for TSAP {}", tsap);
            return;
        };

        // ============================================================
        // Build the plaintext T_GroupData_Req.
        // ============================================================
        //
        // Length sizing comes from the `group_value` APDU serializers in
        // the proto crate, matching the non-secure `GroupDataProvider`.
        // Allocated at plaintext length; `wrap_outgoing` grows the
        // buffer in place by `secure::OVERHEAD` (13 bytes: SCF + SeqNr
        // + MAC + TPCI/APCI shift). The backing capacity is always
        // `BUFFER_SIZE - headroom`, which accommodates the expansion.
        let (plain_msg_len, apci) = match value {
            Some((GroupValueEncoding::Short, _)) => (GroupValueWriteRequest::SHORT_MSG_LEN, ApciCode::GroupValueWrite),
            Some((GroupValueEncoding::Full, data)) => {
                (GroupValueWriteRequest::full_msg_len(data.len()), ApciCode::GroupValueWrite)
            }
            None => (GroupValueReadRequest::MSG_LEN, ApciCode::GroupValueRead),
        };

        let Some(msg_buf) = self.lctx.buffer_manager.try_alloc_with_size(plain_msg_len) else {
            warn!("SecureGroupDataProvider: no buffer for secure GroupValue to TSAP {}", tsap);
            return;
        };

        let builder = MessageBuilder::new_request(
            msg_buf,
            ServiceType::T_GroupData_Req,
            priority,
            DestinationAddress::ConnectionNr(tsap),
        )
        .with_application(apci);

        let mut msg = match value {
            Some((GroupValueEncoding::Short, data)) => builder.with_data(|buf| {
                if let Some(&v) = data.first() {
                    GroupValueWriteRequest::write_short(buf, v);
                }
            }),
            Some((GroupValueEncoding::Full, data)) => builder.with_data(|buf| {
                GroupValueWriteRequest::write_full(buf, data);
            }),
            None => builder.build(),
        };

        // The builder leaves the buffer sized to the plaintext contents;
        // shrink it back to the plaintext length before handing off so
        // `wrap_outgoing` sees the correct `plain_content_len` and
        // expands to `total_len` itself.
        //
        // (The builder's `with_data` / `build` already leave len at
        // `plain_msg_len`; documenting here for future maintainers.)

        // ============================================================
        // SCF byte for a group-addressed unsolicited send.
        // ============================================================
        //
        // Data Security SCF layout (spec 03/03/07 §5.1.3.2, mirrored
        // in [`SecurityControlField::encode`](zweidraehte_proto::crypto::scf::SecurityControlField::encode)):
        //   bit 7    Tool Access (0 = group/P2P key, 1 = tool key)
        //   bit 6    reserved
        //   bits 5-4 SAI: 00 = CCM auth-only, 01 = CCM auth+conf
        //   bit 3    System Broadcast (0 = normal service)
        //   bit 2    reserved
        //   bits 1-0 service: 00 = Data (group or P2P), 10 = SyncReq, 11 = SyncRes
        //
        // For an unsolicited group-data send the composite is thus
        // 0x00 (auth-only) or 0x10 (auth+conf).
        let scf_byte: u8 = match security {
            RequestedSecurity::AuthOnly => 0x00,
            RequestedSecurity::AuthConf => 0x10,
        };
        // Sanity: parse it back so a silent typo-bug yields a clear panic
        // in debug builds rather than a wire-level failure downstream.
        debug_assert!(matches!(SecurityControlField::parse(scf_byte).map(|s| s.service), Ok(SecureServiceType::Data),));

        // ============================================================
        // Reserve sending sequence number (group/table counter, not tool).
        // ============================================================
        let Some(seq_nr) = outgoing::reserve_next_seq_nr(security_state.seq_storage(), false) else {
            warn!("SecureGroupDataProvider: sequence number overflow, dropping send");
            return;
        };

        let src = u16::from_be_bytes(self.state.individual_address().0);
        let adt = self.state.adt().borrow();
        let inputs = outgoing::WrapInputs { scf_byte, key, src, seq_nr, outgoing_tl_seq: None, adt: &*adt };

        match outgoing::wrap_outgoing(&mut msg, inputs) {
            Ok(()) => {
                self.lctx.outbox.borrow_mut().push(msg.into_inner());
            }
            Err(outgoing::WrapError::BufferTooSmall) => {
                // Dropped; `wrap_outgoing` already logged the size mismatch.
            }
            Err(outgoing::WrapError::InvalidScf) => {
                // Synthesised SCF byte rejected — our table is wrong.
                // `debug_assert!` above should have caught this in debug
                // builds; release-build drop is the safe fallback.
                warn!("SecureGroupDataProvider: synthesised SCF 0x{:02X} rejected", scf_byte);
            }
        }
    }
}
