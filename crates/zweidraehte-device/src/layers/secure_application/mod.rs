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
        ccm::{self, CcmContext},
        scf::{SecureServiceType, SecurityControlField},
    },
    definition::StackDefinition,
    layers::application::ApplicationLayer,
    messages::{
        buffers::{Buffer, MessageBuffer},
        knx::{ApciCode, KnxMessageBuffer, ServiceType, offsets},
    },
    router::{Layer, Outbox},
};

#[cfg(not(feature = "defmt"))]
#[allow(unused_imports)]
use log::{debug, trace, warn};

#[cfg(feature = "defmt")]
use defmt::{debug, trace, warn};

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
}

impl Default for OutgoingSecurityCtx {
    fn default() -> Self {
        Self { active: false, key: [0u8; 16], scf_byte: 0, request_src: 0 }
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
    D::State: HasExtensionState,
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

        let security_state = self.state.extension_state();
        let src = u16::from_be_bytes(msg.get_source_addr().0);
        let buf = msg.buf_mut();
        let buf_len = buf.len();

        if buf_len < offsets::MSG_APCI + 13 {
            warn!("S-AL: secure frame too short ({} bytes)", buf_len);
            return None;
        }

        let scf_byte = buf[offsets::MSG_APDU];
        let scf = match SecurityControlField::parse(scf_byte) {
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

        let mut seq_nr = [0u8; 6];
        seq_nr.copy_from_slice(&buf[offsets::MSG_APDU + 1..offsets::MSG_APDU + 7]);

        let secure_data_start = offsets::MSG_APDU + 7;
        let secure_data_len = buf_len - secure_data_start;

        if secure_data_len < 4 {
            warn!("S-AL: no room for MAC");
            return None;
        }

        let dst = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
        let addr_type = buf[offsets::MSG_ADDR_TYPE] & 0x80;
        let tpci_apci = u16::from_be_bytes([buf[offsets::MSG_TPCI], buf[offsets::MSG_TPCI + 1]]);

        // Look up key. For tool access, use the effective tool key
        // (configured key if non-zero, otherwise FDSK fallback).
        let key = if scf.tool_access {
            security_state.effective_tool_key()
        } else {
            warn!("S-AL: non-tool secure APDU not yet supported");
            return None;
        };

        // Decrypt / Verify.
        let mac_start = buf_len - 4;
        let mut received_mac = [0u8; 4];
        received_mac.copy_from_slice(&buf[mac_start..buf_len]);

        let payload_len = mac_start - secure_data_start;

        let ctx = CcmContext { seq_nr, src, dst, addr_type, tpci_apci };

        if scf.confidentiality {
            let result =
                ccm::verify_and_decrypt(&key, &ctx, scf_byte, &mut buf[secure_data_start..mac_start], &received_mac);
            if result.is_err() {
                warn!("S-AL: MAC verification failed (A+C)");
                security_state.log_security_failure(SecurityFailureType::CryptoError, src);
                return None;
            }
        } else {
            let result =
                ccm::verify_mac_auth_only(&key, &ctx, scf_byte, &buf[secure_data_start..mac_start], &received_mac);
            if result.is_err() {
                warn!("S-AL: MAC verification failed (auth-only)");
                security_state.log_security_failure(SecurityFailureType::CryptoError, src);
                return None;
            }
        }

        // Reconstruct plaintext message.
        if payload_len < 2 {
            warn!("S-AL: decrypted payload too short for APCI");
            return None;
        }

        let plain_start = offsets::MSG_TPCI;
        buf.copy_within(secure_data_start..secure_data_start + payload_len, plain_start);
        let new_len = plain_start + payload_len;
        buf.set_len(new_len);

        // Set outgoing security context so the response gets encrypted.
        self.outgoing_ctx.set(OutgoingSecurityCtx { active: true, key, scf_byte, request_src: src });

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
        let plain_tpci_start = offsets::MSG_TPCI; // 6
        let plain_end = buf.len();
        let plain_len = plain_end - plain_tpci_start; // length of plain TPCI/APCI + data

        // We need room for: secure_header(9) + plain_len + MAC(4)
        // secure_header = TPCI/APCI(2) + SCF(1) + SeqNr(6) = 9 bytes at MSG_TPCI
        // Total from MSG_TPCI: 2 + 1 + 6 + plain_len + 4 = plain_len + 13
        let needed_len = plain_tpci_start + plain_len + 13;

        if needed_len > buf.capacity() + plain_tpci_start {
            warn!("S-AL: buffer too small for secure frame ({} > {})", needed_len, buf.capacity() + plain_tpci_start);
            return msg; // Fall back to plaintext.
        }

        // Step 1: Move the plaintext payload to make room for the secure header.
        // The plaintext is at [6..plain_end]. It needs to be at [15..15+plain_len].
        let payload_dest = offsets::MSG_APDU + 7; // 15

        // Expand buffer first so copy_within has room.
        buf.set_len(needed_len);

        // Shift plaintext right by 9 bytes (payload_dest - plain_tpci_start = 9).
        buf.copy_within(plain_tpci_start..plain_end, payload_dest);

        // Step 2: Write secure header.
        let seq_nr = self.next_seq_nr();

        // Secure TPCI/APCI: keep upper TPCI bits, set APCI to 0x3F1.
        // The TPCI is in the upper 6 bits of buf[6]. For connectionless
        // P2P, TPCI = 0x00. For connection-oriented, preserve the sequence.
        let tpci_high = buf[payload_dest] & 0xFC; // preserve TPCI bits from plaintext
        buf[offsets::MSG_TPCI] = tpci_high | 0x03; // APCI high = 0x03 (escaped)
        buf[offsets::MSG_TPCI + 1] = 0xF1; // APCI low = SecureService

        buf[offsets::MSG_APDU] = ctx.scf_byte; // SCF
        buf[offsets::MSG_APDU + 1..offsets::MSG_APDU + 7].copy_from_slice(&seq_nr); // SeqNr

        // Step 3: Encrypt payload and compute MAC.
        // Use the device's own address for src rather than reading from the
        // buffer — the network layer hasn't filled in MSG_SOURCE_ADDR yet at
        // this point in the outgoing path.
        let src = u16::from_be_bytes(self.state.individual_address().0);
        let dst = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
        let addr_type = buf[offsets::MSG_ADDR_TYPE] & 0x80;
        let tpci_apci_secure = u16::from_be_bytes([buf[offsets::MSG_TPCI], buf[offsets::MSG_TPCI + 1]]);

        let ccm_ctx = CcmContext { seq_nr, src, dst, addr_type, tpci_apci: tpci_apci_secure };

        let scf = SecurityControlField::parse(ctx.scf_byte).expect("valid SCF from incoming");

        let payload_start = payload_dest;
        let payload_end = payload_dest + plain_len;
        let mac_start = payload_end;

        let mac = if scf.confidentiality {
            ccm::encrypt_and_mac(&ctx.key, &ccm_ctx, ctx.scf_byte, &mut buf[payload_start..payload_end])
        } else {
            ccm::compute_mac_auth_only(&ctx.key, &ccm_ctx, ctx.scf_byte, &buf[payload_start..payload_end])
        };

        // Step 4: Append MAC.
        buf[mac_start..mac_start + 4].copy_from_slice(&mac);

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
