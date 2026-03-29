//! Secure Application Layer (S-AL) wrapper.
//!
//! Wraps the plain [`ApplicationLayer`] to add KNX Data Secure support.
//! The wrapper intercepts all messages before the inner AL processes them:
//!
//! - **Incoming**: If the APDU is a Secure Service (APCI 0x03F1), the S-AL
//!   parses the SCF, verifies the sequence number, decrypts/verifies the
//!   MAC, populates the [`AccessContext`] with security metadata (role,
//!   security mode), strips the S-AL wrapper, and forwards the plaintext
//!   APDU to the inner AL.
//! - **Outgoing**: TODO (Phase 4c) — encrypt outgoing frames based on GO
//!   Security Flags.
//!
//! [`ApplicationLayer`]: crate::layers::application::ApplicationLayer
//! [`AccessContext`]: crate::access::AccessContext

use crate::{
    access::{AccessContext, AccessSource, ClientRole, SecurityMode},
    bcus::system_b::{HasExtensionState, HasSecurityState},
    crypto::{
        ccm::{self, CcmContext},
        scf::SecurityControlField,
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
// SecureApplicationLayer
// ============================================================================

/// Secure Application Layer wrapper.
///
/// Wraps the plain [`ApplicationLayer`] and intercepts incoming Secure
/// Service APDUs (APCI 0x03F1) to decrypt/verify them before forwarding
/// the plaintext to the inner AL.
///
/// Requires `D::State` to implement [`HasExtensionState`] with an
/// extension state that implements [`HasSecurityState`], which is
/// automatically satisfied when using [`SecureExtensionState`].
///
/// [`SecureExtensionState`]: crate::bcus::system_b::extensions::security::SecureExtensionState
pub struct SecureApplicationLayer<'a, D: StackDefinition> {
    inner: ApplicationLayer<'a, D>,
    state: &'a D::State,
}

impl<'a, D: StackDefinition> SecureApplicationLayer<'a, D> {
    /// Create a new S-AL wrapping the given plain Application Layer.
    pub fn new(inner: ApplicationLayer<'a, D>, state: &'a D::State) -> Self {
        Self { inner, state }
    }

    /// Get a mutable reference to the inner Application Layer.
    pub fn inner_mut(&mut self) -> &mut ApplicationLayer<'a, D> {
        &mut self.inner
    }
}

impl<'a, D: StackDefinition> SecureApplicationLayer<'a, D>
where
    D::State: HasExtensionState,
    <D::State as HasExtensionState>::ES: HasSecurityState,
{
    /// Try to process an incoming message as a Secure Service APDU.
    ///
    /// Returns `Some(msg)` with the decrypted plaintext message if the
    /// secure APDU was successfully verified, or `None` if verification
    /// failed (the message should be silently dropped).
    ///
    /// If the message is not a Secure Service APDU, returns the message
    /// unchanged via `Some`.
    fn try_process_secure(
        &self,
        mut msg: KnxMessageBuffer<Buffer<'static>>,
    ) -> Option<KnxMessageBuffer<Buffer<'static>>> {
        let apci = msg.get_apci_code();

        if !matches!(apci, ApciCode::SecureService) {
            return Some(msg);
        }

        // ============================================================
        // Parse the Secure ASDU
        // ============================================================

        let src = u16::from_be_bytes(msg.get_source_addr().0);
        let buf = msg.buf_mut();
        let buf_len = buf.len();

        if buf_len < offsets::MSG_APCI + 13 {
            warn!("S-AL: secure frame too short ({} bytes)", buf_len);
            return None;
        }

        let scf_byte = buf[offsets::MSG_APDU]; // offset 8
        let scf = match SecurityControlField::parse(scf_byte) {
            Ok(scf) => scf,
            Err(_) => {
                warn!("S-AL: invalid SCF 0x{:02X}", scf_byte);
                return None;
            }
        };

        let mut seq_nr = [0u8; 6];
        seq_nr.copy_from_slice(&buf[offsets::MSG_APDU + 1..offsets::MSG_APDU + 7]);

        let secure_data_start = offsets::MSG_APDU + 7; // offset 15
        let secure_data_len = buf_len - secure_data_start;

        if secure_data_len < 4 {
            warn!("S-AL: no room for MAC");
            return None;
        }

        let dst = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
        let addr_type = buf[offsets::MSG_ADDR_TYPE] & 0x80;
        let tpci_apci = u16::from_be_bytes([buf[offsets::MSG_TPCI], buf[offsets::MSG_TPCI + 1]]);

        // ============================================================
        // Look up key from security state
        // ============================================================

        let security_state = self.state.extension_state();

        let key = if scf.tool_access {
            security_state.tool_key()
        } else {
            // TODO: group key lookup based on destination GA.
            // For now, only tool access is supported.
            warn!("S-AL: non-tool secure APDU not yet supported");
            return None;
        };

        // ============================================================
        // Decrypt / Verify
        // ============================================================

        let mac_start = buf_len - 4;
        let mut received_mac = [0u8; 4];
        received_mac.copy_from_slice(&buf[mac_start..buf_len]);

        // Payload is between secure_data_start and mac_start.
        let payload_len = mac_start - secure_data_start;

        let ctx = CcmContext { seq_nr, src, dst, addr_type, tpci_apci };

        if scf.confidentiality {
            // Auth + Conf: decrypt payload in-place, verify MAC.
            let result =
                ccm::verify_and_decrypt(&key, &ctx, scf_byte, &mut buf[secure_data_start..mac_start], &received_mac);
            if result.is_err() {
                warn!("S-AL: MAC verification failed (A+C)");
                return None;
            }
        } else {
            // Auth only: verify MAC without decryption.
            // For auth-only: A = SCF | payload, P = empty.
            let result =
                ccm::verify_mac_auth_only(&key, &ctx, scf_byte, &buf[secure_data_start..mac_start], &received_mac);
            if result.is_err() {
                warn!("S-AL: MAC verification failed (auth-only)");
                return None;
            }
        }

        // TODO: Verify sequence number (anti-replay check).
        // For now, accept any sequence number.

        // ============================================================
        // Reconstruct plaintext message
        // ============================================================
        //
        // The decrypted payload at buf[secure_data_start..mac_start] is:
        //   000000b | plain APCI + data
        //
        // We need to rewrite the buffer so the inner AL sees a normal
        // KNX message with the plaintext APDU.
        //
        // The plaintext APDU starts at secure_data_start and is
        // payload_len bytes. The first byte contains the 000000b prefix
        // in the upper 6 bits — the lower 2 bits are the APCI high bits.
        // Combined with the next byte, this forms the plain TPCI/APCI.

        if payload_len < 2 {
            warn!("S-AL: decrypted payload too short for APCI");
            return None;
        }

        // Overwrite TPCI/APCI and data area with the plaintext APDU.
        // The plaintext starts at secure_data_start. We copy it down
        // to offset MSG_TPCI (6), which is where the inner AL expects it.
        let plain_start = offsets::MSG_TPCI; // 6
        buf.copy_within(secure_data_start..secure_data_start + payload_len, plain_start);

        // Truncate the buffer to remove the secure overhead (SCF, SeqNr, MAC).
        let new_len = plain_start + payload_len;
        buf.set_len(new_len);

        // ============================================================
        // Populate AccessContext with security metadata
        // ============================================================

        let security_mode = if scf.confidentiality { SecurityMode::AuthConf } else { SecurityMode::AuthOnly };

        let role = if scf.tool_access {
            ClientRole::Tool
        } else {
            ClientRole::Unlisted // TODO: look up role from P2P key table
        };

        let access_ctx = AccessContext::with_security(0, security_mode, role);
        // Release mutable borrow of buf before calling set_access_source.
        let _ = buf;
        msg.set_access_source(AccessSource::Explicit(access_ctx));

        Some(msg)
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
            Some(msg) => self.inner.process(msg, outbox),
            None => {
                // Verification failed — silently drop.
                // (Security failure logging will be added in Phase 6.)
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
