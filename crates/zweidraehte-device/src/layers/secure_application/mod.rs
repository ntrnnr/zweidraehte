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
//! - **Outgoing**: If the GO requires security (based on GO Security Flags),
//!   the S-AL encrypts/signs the outgoing APDU before forwarding to the TL.
//!
//! # Phase 4a: Foundation
//!
//! This initial version establishes the wrapper type and secure device
//! builder. All messages are forwarded to the inner AL without security
//! processing — the actual S-AL logic will be added in Phase 4b.
//!
//! [`ApplicationLayer`]: crate::layers::application::ApplicationLayer
//! [`AccessContext`]: crate::access::AccessContext

use crate::{
    definition::StackDefinition,
    layers::application::ApplicationLayer,
    messages::{buffers::Buffer, knx::KnxMessageBuffer},
    router::{self, Layer, Outbox},
};

// ============================================================================
// SecureApplicationLayer — wrapper around ApplicationLayer
// ============================================================================

/// Secure Application Layer wrapper.
///
/// Wraps the plain [`ApplicationLayer`] and intercepts messages to perform
/// KNX Data Secure operations (encryption, decryption, MAC verification).
///
/// In Phase 4a this is a transparent pass-through — all messages are
/// forwarded to the inner AL without modification.
pub struct SecureApplicationLayer<'a, D: StackDefinition> {
    /// The inner (plain) Application Layer.
    inner: ApplicationLayer<'a, D>,
    // Phase 4b will add:
    // security_state: &'a SecurityState<GRP, GO>,
    // seq_storage: &'a RefCell<SS>,
    // seq_tracker: SeqTracker<MAX_PEERS>,
}

impl<'a, D: StackDefinition> SecureApplicationLayer<'a, D> {
    /// Create a new S-AL wrapping the given plain Application Layer.
    pub fn new(inner: ApplicationLayer<'a, D>) -> Self {
        Self { inner }
    }

    /// Get a mutable reference to the inner Application Layer.
    ///
    /// Used by the device model and service input handling to access
    /// AL methods that don't involve security.
    pub fn inner_mut(&mut self) -> &mut ApplicationLayer<'a, D> {
        &mut self.inner
    }
}

impl<D: StackDefinition> Layer for SecureApplicationLayer<'_, D> {
    /// Handle the same service types as the inner AL.
    const HANDLES: &'static [ServiceType] = ApplicationLayer::<D>::HANDLES;

    fn process(&mut self, msg: KnxMessageBuffer<Buffer<'static>>, outbox: &mut Outbox) {
        // Phase 4a: transparent pass-through.
        // Phase 4b will add: check for SecureService APCI, decrypt, verify MAC.
        self.inner.process(msg, outbox);
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

// Re-export ServiceType here so the Layer impl can reference it.
use crate::messages::knx::ServiceType;
