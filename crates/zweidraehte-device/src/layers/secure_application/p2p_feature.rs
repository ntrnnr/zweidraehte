//! Compile-time feature slot for KNX Data Secure P2P communication.
//!
//! Mirrors the `RoutingFeature` / `TunnelingFeature` pattern used by
//! the KNX/IP link layer: two marker types implement the same trait —
//! [`WithP2p`] delegates to the real S-A_Sync handlers, [`NoP2p`]
//! exposes zero-sized state and trivial no-op bodies that LLVM elides
//! entirely.
//!
//! # Why not a marker trait?
//!
//! An earlier iteration used a `HasP2pSecure` marker trait bound on the
//! S-AL impl blocks. That works but forces callers to propagate the
//! bound through every layer of the composition surface (builders,
//! `HasAppRequest` impls, stack aliases). Method resolution also
//! silently falls back to trait methods when the inherent method's
//! bounds don't match — introducing a real runtime bug we hit in the
//! form of infinite recursion in `HasAppRequest::handle_app_request`.
//!
//! The type-state feature approach here keeps the S-AL's method surface
//! identical in both configurations; only the *bodies* differ, and they
//! dispatch through the feature trait unconditionally. The S-AL's
//! `Layer::process` never needs to care whether P2P is on — it just
//! asks the feature. LLVM collapses the `NoP2p` bodies at
//! monomorphisation.
//!
//! # Binary & RAM size impact
//!
//! When [`NoP2p`] is selected:
//! - [`P2pFeature::State`] is `()` — the S-AL's per-instance P2P storage
//!   (pending sync tracker, last-sync-response timestamp) is zero bytes.
//! - All three dispatch methods have bodies that return
//!   `SecureResult::Dropped` / `None` immediately. After inlining the
//!   calls become no-ops.
//! - The real sync handlers in [`super::p2p_security`] are only
//!   monomorphised when `WithP2p` is used, so the P2P key-lookup and
//!   CCM sync-request/response code is never stamped out for group-only
//!   devices.

use core::cell::Cell;

use zweidraehte_proto::crypto::scf::SecurityControlField;
use zweidraehte_proto::messages::{
    buffers::Buffer,
    knx::{KnxMessageBuffer, ServiceType},
};

use crate::HasSecureIdentity;
use crate::bcus::system_b::{HasExtensionState, HasSecurityState};
use crate::definition::StackDefinition;
use crate::objects::tables::HasAssociationTable;
use crate::prelude::HasAddressTable;
use crate::storage::SequenceNumberStorage;

use super::{PendingSyncState, SecureApplicationLayer, SecureResult};

// ============================================================================
// Per-feature state
// ============================================================================

/// State held by the S-AL on behalf of an enabled P2P feature.
///
/// Carries the two `Cell`s that track spec-mandated timing: the
/// 6-second pending-sync deadline for DUT-initiated sync requests and
/// the 1-second rate limit on outgoing sync responses.
pub struct WithP2pState {
    pub(super) pending_sync: Cell<Option<PendingSyncState>>,
    pub(super) last_sync_response: Cell<Option<embassy_time::Instant>>,
    /// Rate-limit window for outgoing S-A_Sync_Res. Defaults to 1 s
    /// per KNX spec. With the `conformance` feature and
    /// `KNX_TIME_DIVISOR > 1`, scaled down so fast-mode tests don't
    /// have to burn real wall-clock between back-to-back syncs.
    pub(super) sync_rate_limit: embassy_time::Duration,
}

/// Spec-mandated rate-limit window between outgoing S-A_Sync_Res frames.
pub(super) const SYNC_RATE_LIMIT_MS: u64 = 1_000;

impl Default for WithP2pState {
    fn default() -> Self {
        // Under the conformance harness we compress protocol-level
        // wall-clock delays by `KNX_TIME_DIVISOR` so fast-mode test
        // runs stay fast; the sync rate-limit window is one of those
        // delays. In production builds the divisor path doesn't
        // exist and the window stays at the spec's 1 s.
        #[cfg(feature = "conformance")]
        let sync_rate_limit = {
            extern crate std;
            let divisor: u64 =
                std::env::var("KNX_TIME_DIVISOR").ok().and_then(|s| s.parse().ok()).filter(|&d| d > 0).unwrap_or(1);
            let scaled = SYNC_RATE_LIMIT_MS / divisor;
            if divisor > 1 {
                crate::logging::info!("S-AL P2P sync rate-limit scaled: divisor={}, window={}ms", divisor, scaled);
            }
            embassy_time::Duration::from_millis(scaled)
        };
        #[cfg(not(feature = "conformance"))]
        let sync_rate_limit = embassy_time::Duration::from_millis(SYNC_RATE_LIMIT_MS);

        Self { pending_sync: Cell::new(None), last_sync_response: Cell::new(None), sync_rate_limit }
    }
}

// ============================================================================
// P2pFeature trait
// ============================================================================

/// Compile-time selection between real P2P support ([`WithP2p`]) and a
/// zero-cost stub ([`NoP2p`]).
pub trait P2pFeature: 'static {
    /// Whether this variant carries the real P2P implementation.
    ///
    /// Consumers can branch on `if P2P::ENABLED` for diagnostic /
    /// introspection code paths; the S-AL itself doesn't need to
    /// because the trait methods already dispatch correctly.
    const ENABLED: bool;

    /// Per-instance state that lives on the S-AL.
    type State: Default;

    /// Dispatch an incoming S-A_Sync_Req, generating an S-A_Sync_Res.
    ///
    /// For [`NoP2p`], this silently drops the frame — the DUT advertises
    /// no P2P capability, so peers have no grounds to send sync requests.
    fn process_sync_request<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        msg: KnxMessageBuffer<Buffer<'static>>,
        scf: SecurityControlField,
        scf_byte: u8,
        src: u16,
        incoming_service_type: ServiceType,
    ) -> SecureResult
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
        Self: Sized;

    /// Dispatch an incoming S-A_Sync_Res that may resolve a pending
    /// DUT-initiated sync.
    fn process_sync_response<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        msg: KnxMessageBuffer<Buffer<'static>>,
        scf: SecurityControlField,
        scf_byte: u8,
        src: u16,
    ) -> SecureResult
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
        Self: Sized;

    /// Initiate an outgoing S-A_Sync_Req to the given peer.
    ///
    /// For [`NoP2p`] returns `None` — group-only devices never sync.
    fn initiate_sync<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        peer_ia: u16,
        tool_access: bool,
        is_broadcast: bool,
    ) -> Option<KnxMessageBuffer<Buffer<'static>>>
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
        Self: Sized;
}

// ============================================================================
// NoP2p — disabled variant
// ============================================================================

/// P2P disabled. Zero state, stub methods.
pub struct NoP2p;

impl P2pFeature for NoP2p {
    const ENABLED: bool = false;
    type State = ();

    fn process_sync_request<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        _sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        _msg: KnxMessageBuffer<Buffer<'static>>,
        _scf: SecurityControlField,
        _scf_byte: u8,
        _src: u16,
        _incoming_service_type: ServiceType,
    ) -> SecureResult
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
    {
        SecureResult::Dropped
    }

    fn process_sync_response<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        _sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        _msg: KnxMessageBuffer<Buffer<'static>>,
        _scf: SecurityControlField,
        _scf_byte: u8,
        _src: u16,
    ) -> SecureResult
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
    {
        SecureResult::Dropped
    }

    fn initiate_sync<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        _sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        _peer_ia: u16,
        _tool_access: bool,
        _is_broadcast: bool,
    ) -> Option<KnxMessageBuffer<Buffer<'static>>>
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
    {
        None
    }
}

// ============================================================================
// WithP2p — enabled variant
// ============================================================================

/// P2P enabled. Delegates to the real handlers in [`super::p2p_security`].
pub struct WithP2p;

impl P2pFeature for WithP2p {
    const ENABLED: bool = true;
    type State = WithP2pState;

    fn process_sync_request<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        msg: KnxMessageBuffer<Buffer<'static>>,
        scf: SecurityControlField,
        scf_byte: u8,
        src: u16,
        incoming_service_type: ServiceType,
    ) -> SecureResult
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
    {
        super::p2p_security::process_sync_request(sal, msg, scf, scf_byte, src, incoming_service_type)
    }

    fn process_sync_response<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        msg: KnxMessageBuffer<Buffer<'static>>,
        scf: SecurityControlField,
        scf_byte: u8,
        src: u16,
    ) -> SecureResult
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
    {
        super::p2p_security::process_sync_response(sal, msg, scf, scf_byte, src)
    }

    fn initiate_sync<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        peer_ia: u16,
        tool_access: bool,
        is_broadcast: bool,
    ) -> Option<KnxMessageBuffer<Buffer<'static>>>
    where
        D::State: HasSecureIdentity + HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as HasExtensionState>::ES: HasSecurityState,
    {
        super::p2p_security::initiate_sync(sal, peer_ia, tool_access, is_broadcast)
    }
}
