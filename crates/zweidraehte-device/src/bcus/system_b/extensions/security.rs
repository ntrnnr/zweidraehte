//! System B's Data Secure pairings.
//!
//! The security machinery itself is family-neutral and lives in
//! [`crate::security`] — KNX Data Security is a profile module
//! (06 Profiles v02.02.01 §9.1) composed onto a base profile, not a
//! profile of its own. What belongs to System B is which medium
//! extension each secure state wraps, and how the security table
//! capacities fall out of System B's table byte sizes.
//!
//! Everything the generic module exports is re-exported here so
//! `bcus::system_b::…` keeps naming the whole Data Secure surface.

pub use crate::security::{
    SecureAugmentBundle, SecureExtensionConfig, SecureExtensionState, SecureResources, SecurityAugment,
    SecurityExtensionConfig, SecurityFailuresLog, SecurityState, SecurityTable,
};

use super::{RfExtensionState, RfRetransmitterExtension, Tp1ExtensionState};
use crate::bcus::system_b::SystemBDeviceState;
use crate::security::SecureExtensionState as Secure;

/// TP1 extension state with Data Secure support.
pub type SecureTp1ExtensionState<const GRP: usize, const P2P: usize, const GO: usize> =
    Secure<Tp1ExtensionState, GRP, P2P, GO>;

/// TP1 device state with Data Secure support, sized from raw table byte sizes.
///
/// Used where there is no [`SystemBStackDefinition`](crate::bcus::system_b::SystemBStackDefinition) to project sizes from (the
/// conformance harness, pinned to a custom `Mem`); devices that have one size
/// their state through `SecureTp1StateFor` in `definition.rs` instead.
///
/// `GRP` (group key table capacity) and `GO` (GO security flags table
/// capacity) are **entry counts** derived from the byte-size parameters:
/// the group key table holds one key per address table entry
/// (`(ADT_SIZE - 2) / 2`, inverting the `2 + entries · 2` table layout)
/// and the GO flags table one byte per communication object
/// (`(COT_SIZE - 2) / 2`).
///
/// `P2P` sizes the P2P Key Table. The Security Individual Address Table is **not**
/// a parameter here — its capacity is the `N` of the
/// [`SiatStore`](crate::storage::views::SiatStore) chosen for `SEQ` (the SIAT lives in
/// the sequence store, not as a const generic). Per 03/03/07 §5.3 that `N` must
/// cover the union of P2P and group-secure senders.
pub type SecureTp1DeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D,
    const P2P: usize,
> = SystemBDeviceState<
    ADT_SIZE,
    AST_SIZE,
    COT_SIZE,
    D,
    SecureTp1ExtensionState<{ (ADT_SIZE - 2) / 2 }, P2P, { (COT_SIZE - 2) / 2 }>,
>;

/// KNX-RF extension state with Data Secure support. Wraps the RF Medium Object /
/// Domain Address extension in the secure wrapper.
pub type SecureRfExtensionState<const GRP: usize, const P2P: usize, const GO: usize> =
    Secure<RfExtensionState, GRP, P2P, GO>;

/// KNX-RF **retransmitter** extension state with Data Secure support. As
/// [`SecureRfExtensionState`], but the wrapped inner extension is
/// [`RfRetransmitterExtension`], so the device also gains the PID 57 / PID 74
/// retransmitter surface (`SecureExtensionState<RfRetransmitterExtension<RfExtensionState>, …>`).
pub type SecureRfRetransmitterExtensionState<const GRP: usize, const P2P: usize, const GO: usize> =
    Secure<RfRetransmitterExtension, GRP, P2P, GO>;
