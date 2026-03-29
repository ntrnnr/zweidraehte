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
    crypto::{ccm::CcmContext, scf::SecurityControlField},
    definition::StackDefinition,
    layers::application::ApplicationLayer,
    messages::{
        buffers::Buffer,
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
/// The security state (key tables, security mode) is accessed through
/// a trait bound on the device state, allowing the S-AL to look up
/// keys without being generic over the table sizes.
pub struct SecureApplicationLayer<'a, D: StackDefinition> {
    /// The inner (plain) Application Layer.
    inner: ApplicationLayer<'a, D>,
}

impl<'a, D: StackDefinition> SecureApplicationLayer<'a, D> {
    /// Create a new S-AL wrapping the given plain Application Layer.
    pub fn new(inner: ApplicationLayer<'a, D>) -> Self {
        Self { inner }
    }

    /// Get a mutable reference to the inner Application Layer.
    pub fn inner_mut(&mut self) -> &mut ApplicationLayer<'a, D> {
        &mut self.inner
    }

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

        // Not a secure APDU — pass through unchanged.
        if !matches!(apci, ApciCode::SecureService) {
            return Some(msg);
        }

        // ============================================================
        // Parse the Secure ASDU
        // ============================================================
        //
        // Wire format after TPCI/APCI (offsets relative to buf start):
        //   [8]      SCF (1 byte)
        //   [9..15]  SeqNr (6 bytes)
        //   [15..]   Secure payload + MAC(4)
        //
        // For Auth+Conf: payload is encrypted ciphertext
        // For Auth-only: payload is plaintext, MAC appended

        // Extract all metadata from immutable references first to avoid
        // borrow conflicts when we need mutable access later.
        let src = u16::from_be_bytes(msg.get_source_addr().0);
        let buf = msg.buf_mut();
        let buf_len = buf.len();

        // Minimum: TPCI/APCI(2) + SCF(1) + SeqNr(6) + MAC(4) = 13 bytes after offset 6
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
        seq_nr.copy_from_slice(&buf[offsets::MSG_APDU + 1..offsets::MSG_APDU + 7]); // [9..15]

        // Secure data starts after SCF + SeqNr.
        let secure_data_start = offsets::MSG_APDU + 7; // offset 15
        let secure_data_len = buf_len - secure_data_start;

        if secure_data_len < 4 {
            warn!("S-AL: no room for MAC");
            return None;
        }

        // Build crypto context from frame metadata.
        let dst = u16::from_be_bytes([buf[offsets::MSG_DEST_ADDR], buf[offsets::MSG_DEST_ADDR + 1]]);
        let addr_type = buf[offsets::MSG_ADDR_TYPE] & 0x80; // AT bit only
        let tpci_apci = u16::from_be_bytes([buf[offsets::MSG_TPCI], buf[offsets::MSG_TPCI + 1]]);

        let ctx = CcmContext { seq_nr, src, dst, addr_type, tpci_apci };

        // ============================================================
        // Look up key
        // ============================================================
        //
        // For now: tool-key-only P2P. If SCF.T is set, use the tool key.
        // TODO: group key lookup for multicast, P2P key table for non-tool.

        // We need the tool key from the security state. Since we can't
        // access the security extension's state through the generic D
        // type system yet (that requires a HasSecurityState trait bound),
        // we'll use a placeholder that always fails for now.
        //
        // TODO Phase 4b+: Add HasSecurityState trait and wire it in.
        // For now this code path logs a warning and drops the frame.
        warn!("S-AL: secure APDU received but key lookup not yet wired (Phase 4b incomplete)");
        let _ = (ctx, scf, secure_data_start, secure_data_len);
        None
    }
}

impl<D: StackDefinition> Layer for SecureApplicationLayer<'_, D> {
    const HANDLES: &'static [ServiceType] = ApplicationLayer::<D>::HANDLES;

    fn process(&mut self, msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        // Check if this is a secure APDU and try to process it.
        match self.try_process_secure(msg) {
            Some(msg) => {
                // Either not a secure APDU (pass-through) or successfully
                // decrypted — forward to the inner AL.
                self.inner.process(msg, outbox);
            }
            None => {
                // Verification failed — silently drop the frame.
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
