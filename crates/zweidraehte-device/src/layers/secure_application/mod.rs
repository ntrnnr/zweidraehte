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

use core::cell::Cell;

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
    router::{Layer, Outbox},
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
pub struct SecureApplicationLayer<'a, D: StackDefinition> {
    inner: ApplicationLayer<'a, D>,
    state: &'a D::State,
    /// Security context for encrypting the outgoing response.
    outgoing_ctx: Cell<OutgoingSecurityCtx>,
    /// Sending sequence number (regular traffic). Incremented after each
    /// outgoing secure frame. TODO: persist via SequenceNumberStorage.
    seq_nr_sending: Cell<u64>,
}

impl<'a, D: StackDefinition> SecureApplicationLayer<'a, D> {
    pub fn new(inner: ApplicationLayer<'a, D>, state: &'a D::State) -> Self {
        Self {
            inner,
            state,
            outgoing_ctx: Cell::new(OutgoingSecurityCtx::default()),
            seq_nr_sending: Cell::new(1), // Initial value must be non-zero per spec.
        }
    }

    pub fn inner_mut(&mut self) -> &mut ApplicationLayer<'a, D> {
        &mut self.inner
    }

    /// Get the next sending sequence number and increment it.
    fn next_seq_nr(&self) -> [u8; 6] {
        let val = self.seq_nr_sending.get();
        self.seq_nr_sending.set(val.wrapping_add(1));
        let bytes = val.to_be_bytes();
        // Take the lower 6 bytes (48-bit counter).
        let mut seq = [0u8; 6];
        seq.copy_from_slice(&bytes[2..8]);
        seq
    }
}

impl<'a, D: StackDefinition> SecureApplicationLayer<'a, D>
where
    D::State: HasExtensionState + crate::objects::tables::HasAddressTable,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    /// Try to process an incoming message as a Secure Service APDU.
    fn try_process_secure(
        &self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> Option<KnxMessageBuffer<Buffer<'static>>> {
        let apci = msg.get_apci_code();

        if !matches!(apci, ApciCode::SecureService) {
            // Not secure — clear any pending outgoing security context.
            self.outgoing_ctx.set(OutgoingSecurityCtx::default());
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
                security_state.log_security_failure(SecurityFailureType::ScfError, src);
                return None;
            }
        };

        // Only handle S-A_Data for now.
        if scf.service != SecureServiceType::Data {
            warn!("S-AL: sync services not yet implemented");
            return None;
        }

        // TODO: validate seq_nr against last-valid receiving sequence number
        let _seq_nr = secure_ref.seq_nr();
        let received_mac = secure_ref.mac();
        let ctx = secure_ref.ccm_context(src);

        // Look up key based on access type.
        let key = if scf.tool_access {
            // Tool access: use configured tool key, or FDSK as fallback
            // when the device is in factory state (tool key all zeros).
            let tk = security_state.tool_key();
            if tk != [0u8; 16] { tk } else { self.state.fdsk().copied().unwrap_or([0u8; 16]) }
        } else if secure_ref.addr_type() != 0 {
            // Group communication: look up group key by destination group address.
            use crate::address::GroupAddress;
            use crate::objects::tables::{AddressTable, HasAddressTable};

            let ga = GroupAddress::from_bytes(&buf[offsets::MSG_DEST_ADDR..offsets::MSG_DEST_ADDR + 2]);
            let adt = self.state.adt().borrow();
            let tsap = match adt.get_tsap(ga) {
                Some(t) => t,
                None => {
                    warn!("S-AL: group address {:?} not in address table", ga);
                    security_state.log_security_failure(SecurityFailureType::CryptoError, src);
                    return None;
                }
            };
            match security_state.group_key_for_index(tsap) {
                Some(k) => k,
                None => {
                    warn!("S-AL: no group key for TSAP {}", tsap);
                    security_state.log_security_failure(SecurityFailureType::CryptoError, src);
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
                security_state.log_security_failure(SecurityFailureType::CryptoError, src);
                return None;
            }
        } else if ccm::verify_mac_auth_only(&key, &ctx, scf_byte, secure_mut.payload(), &received_mac).is_err() {
            warn!("S-AL: MAC verification failed (auth-only)");
            security_state.log_security_failure(SecurityFailureType::CryptoError, src);
            return None;
        }

        let new_len = secure_mut.unwrap_to_plaintext();
        buf.set_len(new_len);

        // Set outgoing security context so the response gets encrypted.
        self.outgoing_ctx.set(OutgoingSecurityCtx { active: true, key, scf_byte, request_src: src, outgoing_tl_seq });

        // Populate AccessContext.
        let security_mode = if scf.confidentiality { SecurityMode::AuthConf } else { SecurityMode::AuthOnly };
        let role = if scf.tool_access { ClientRole::Tool } else { ClientRole::Unlisted };
        let access_ctx = AccessContext::with_security(0, security_mode, role);
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

        let seq_nr = self.next_seq_nr();
        let layout = secure::wrap_plaintext(buf, plain_content_len, ctx.scf_byte, &seq_nr)
            .expect("buffer capacity already verified");

        // Encrypt payload and compute MAC.
        // Use the device's own address for src rather than reading from the
        // buffer — the network layer hasn't filled in MSG_SOURCE_ADDR yet at
        // this point in the outgoing path.
        let src = u16::from_be_bytes(self.state.individual_address().0);
        let secure_ref = SecureApduRef::parse(buf).expect("just built a valid secure frame");
        let ccm_ctx = secure_ref.ccm_context(src);

        let scf = SecurityControlField::parse(ctx.scf_byte).expect("valid SCF from incoming");

        let mac = if scf.confidentiality {
            ccm::encrypt_and_mac(&ctx.key, &ccm_ctx, ctx.scf_byte, &mut buf[layout.payload_start..layout.payload_end])
        } else {
            ccm::compute_mac_auth_only(&ctx.key, &ccm_ctx, ctx.scf_byte, &buf[layout.payload_start..layout.payload_end])
        };

        buf[layout.mac_start..layout.mac_start + secure::MAC_LEN].copy_from_slice(&mac);

        msg
    }
}

impl<D: StackDefinition> Layer for SecureApplicationLayer<'_, D>
where
    D::State: HasExtensionState,
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
