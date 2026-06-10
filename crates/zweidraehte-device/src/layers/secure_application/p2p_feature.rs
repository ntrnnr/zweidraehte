//! Compile-time feature slot for KNX Data Secure P2P communication.
//!
//! Mirrors the `RoutingFeature` / `TunnelingFeature` pattern used by
//! the KNX/IP link layer: two marker types implement the same trait —
//! [`WithP2p`] delegates to the real P2P-specific handlers, [`NoP2p`]
//! exposes zero-sized state and trivial no-op bodies that LLVM elides
//! entirely.
//!
//! # Scope
//!
//! The feature gates *only* the genuinely P2P-flow-specific pieces of
//! Data Secure:
//!
//! - `process_sync_request_p2p` — the non-tool branch of an incoming
//!   S-A_Sync_Req, which needs the P2P key table and the SIAT.
//! - `process_sync_response` — matches an incoming S-A_Sync_Res
//!   against `pending_sync` state set by a prior DUT-initiated sync.
//! - `initiate_sync` — allocates the pending-sync slot and emits an
//!   outgoing S-A_Sync_Req.
//!
//! Everything else (incoming tool-key S-A_Sync_Req, which ETS uses for
//! commissioning every secure device) lives directly on
//! [`SecureApplicationLayer`] and works regardless of the selected
//! feature. That path needs only the sync rate-limit state and the
//! tool-receiving sequence slot — both always available.
//!
//! # Binary & RAM size impact
//!
//! When [`NoP2p`] is selected:
//! - [`P2pFeature::State`] is `()` — no `pending_sync` slot.
//! - Both remaining dispatch methods have bodies that return
//!   `SecureResult::Dropped` / `None` immediately. After inlining the
//!   calls become no-ops.
//! - The P2P-specific sync handlers in [`super::p2p_security`] are
//!   only monomorphised when `WithP2p` is used.

use core::cell::Cell;

use zweidraehte_proto::crypto::scf::SecurityControlField;
use zweidraehte_proto::messages::{
    buffers::Buffer,
    knx::{KnxMessageBuffer, ServiceType},
};

use crate::HasExtensionState;
use crate::StackState;
use crate::bcus::system_b::HasSecurityState;
use crate::definition::StackDefinition;
use crate::logging::info;
use crate::objects::tables::HasAssociationTable;
use crate::prelude::HasAddressTable;
use crate::storage::SecureDeviceIdentity;
use crate::storage::SequenceNumberStorage;

use super::{PendingSyncState, SecureApplicationLayer, SecureResult};

// ============================================================================
// Shared sync-rate-limit configuration
// ============================================================================

/// Spec-mandated rate-limit window between outgoing S-A_Sync_Res frames.
pub(super) const SYNC_RATE_LIMIT_MS: u64 = 1_000;

/// Compute the rate-limit duration for new S-AL instances.
///
/// Under the conformance harness we compress protocol-level wall-clock
/// delays by `KNX_TIME_DIVISOR` so fast-mode test runs stay fast; the
/// sync rate-limit window is one of those delays. In production builds
/// the divisor path doesn't exist and the window stays at the spec's
/// 1 s.
pub(super) fn default_sync_rate_limit() -> embassy_time::Duration {
    #[cfg(feature = "conformance")]
    {
        extern crate std;
        let divisor: u64 =
            std::env::var("KNX_TIME_DIVISOR").ok().and_then(|s| s.parse().ok()).filter(|&d| d > 0).unwrap_or(1);
        let scaled = SYNC_RATE_LIMIT_MS / divisor;
        if divisor > 1 {
            info!("S-AL sync rate-limit scaled: divisor={}, window={}ms", divisor, scaled);
        }
        embassy_time::Duration::from_millis(scaled)
    }
    #[cfg(not(feature = "conformance"))]
    {
        embassy_time::Duration::from_millis(SYNC_RATE_LIMIT_MS)
    }
}

// ============================================================================
// Per-feature state
// ============================================================================

/// State held by the S-AL on behalf of an enabled P2P feature.
///
/// Tracks the pending DUT-initiated sync — the 6-second deadline against
/// which an incoming S-A_Sync_Res is matched.
pub struct WithP2pState {
    pub(super) pending_sync: Cell<Option<PendingSyncState>>,
}

impl Default for WithP2pState {
    fn default() -> Self {
        Self { pending_sync: Cell::new(None) }
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

    /// Handle the non-tool branch of an incoming S-A_Sync_Req.
    ///
    /// Called from the shared sync-request handler on
    /// [`SecureApplicationLayer`] when the SCF's tool-access flag is
    /// clear. Needs the P2P key table and SIAT, so it is gated behind
    /// the feature: [`NoP2p`] drops, [`WithP2p`] delegates to
    /// [`super::p2p_security::process_sync_request_p2p`].
    fn process_sync_request_p2p<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        msg: KnxMessageBuffer<Buffer<'static>>,
        scf: SecurityControlField,
        scf_byte: u8,
        src: u16,
        incoming_service_type: ServiceType,
    ) -> SecureResult
    where
        D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as StackState>::Identity: SecureDeviceIdentity,
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
        D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as StackState>::Identity: SecureDeviceIdentity,
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
        D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as StackState>::Identity: SecureDeviceIdentity,
        <D::State as HasExtensionState>::ES: HasSecurityState,
        Self: Sized;
}

// ============================================================================
// NoP2p — disabled variant
// ============================================================================

/// P2P disabled. Zero state, stub methods for the P2P-only dispatches.
///
/// Note: incoming tool-key S-A_Sync_Req is handled directly on
/// [`SecureApplicationLayer`] and works on `NoP2p` devices — ETS still
/// needs to commission them.
pub struct NoP2p;

impl P2pFeature for NoP2p {
    const ENABLED: bool = false;
    type State = ();

    fn process_sync_request_p2p<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        _sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        _msg: KnxMessageBuffer<Buffer<'static>>,
        _scf: SecurityControlField,
        _scf_byte: u8,
        _src: u16,
        _incoming_service_type: ServiceType,
    ) -> SecureResult
    where
        D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as StackState>::Identity: SecureDeviceIdentity,
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
        D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as StackState>::Identity: SecureDeviceIdentity,
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
        D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as StackState>::Identity: SecureDeviceIdentity,
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

    fn process_sync_request_p2p<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        msg: KnxMessageBuffer<Buffer<'static>>,
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
        super::p2p_security::process_sync_request_p2p(sal, msg, scf, scf_byte, src, incoming_service_type)
    }

    fn process_sync_response<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
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
        super::p2p_security::process_sync_response(sal, msg, scf, scf_byte, src)
    }

    fn initiate_sync<'a, D: StackDefinition, SEQ: SequenceNumberStorage>(
        sal: &SecureApplicationLayer<'a, D, SEQ, Self>,
        peer_ia: u16,
        tool_access: bool,
        is_broadcast: bool,
    ) -> Option<KnxMessageBuffer<Buffer<'static>>>
    where
        D::State: HasExtensionState + HasAddressTable + HasAssociationTable,
        <D::State as StackState>::Identity: SecureDeviceIdentity,
        <D::State as HasExtensionState>::ES: HasSecurityState,
    {
        super::p2p_security::initiate_sync(sal, peer_ia, tool_access, is_broadcast)
    }
}
