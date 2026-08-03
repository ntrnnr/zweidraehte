//! Optional KNX-RF DoA Retransmitter wrapper extension.
//!
//! Composing this extension turns a KNX-RF device into a Layer-2
//! *retransmitter* (repeater): it re-broadcasts qualifying frames it hears on
//! its Domain Address, bounded by the RF Repetition Counter and de-duplicated
//! by the link-layer history (KNX 03/02/05 §6.1.7, profile 6/4/1 "DoA based RF
//! Retransmitter"). It is a Profile *Module*, not a full device profile — hence
//! a thin wrapper around the base [`RfExtensionState`] rather than a standalone
//! extension.
//!
//! # What it adds
//!
//! - **`PID_RF_RETRANSMITTER` (PID 57)** on the RF Medium Object (Type 19) —
//!   the runtime enable flag (03/05/01 §4.15.9). Defaults to `false`: composing
//!   the extension compiles the repeating behaviour in and advertises the
//!   capability, but the role stays off until ETS writes PID 57.
//! - **`PID_RF_REPEAT_COUNTER` (PID 74)** on the Device Object (Type 0) — the
//!   optional cascade-depth limit (03/02/05 §6.1.7.4). A received frame is
//!   repeated only while its RC is `> 0` and `> limit`. Defaults to 0.
//! - **[`HasRfRetransmitter`]** on the device state, which is the compile-time
//!   gate that makes the `RetransmitEnabled` KNX-RF link-layer policy
//!   selectable (see [`crate::context::RfRetransmitterContext`]).
//!
//! # How PID 57 joins the RF Medium Object
//!
//! `A_PropertyDescription_Read` enumerates an object's properties by *index*.
//! The base [`RfAugment`](super::RfAugment) already provides the RF Medium
//! Object (PIDs 1 and 56), and this augment contributes one more property
//! (PID 57) to the *same* object type via `target_objects` + `intercepts`.
//! Rather than duplicating PIDs 1 and 56 here, the two augments are composed in
//! [`RfRetransmitterAugmentBundle`]: the `#[derive(ServiceRegistry)]` aggregator
//! merges their descriptor tables into one property-index space, rebasing the
//! index-based scan per augment, so the RF Medium Object enumerates PID 1, 56,
//! 57 in declaration order even though the descriptors live in two augments.
//! (This two-augments-per-object support is what the bundle exists for; it is
//! exercised end to end by the `rf_retransmitter_property_scan` integration
//! test.) PID 74 sits on the base Device Object, whose enumeration already
//! merges a single augment's intercepts, so it is intercepted normally.
//!
//! The *behaviour* (the actual repeating) lives in the link layer and is gated
//! by a separate ZST policy generic; this extension only carries the state and
//! interface-object surface. A device opts in by composing this extension
//! (`type ES`) **and** selecting the repeating link layer (`type LLB`).
//!
//! # Composition
//!
//! Like [`SecureExtensionState`](crate::bcus::system_b::SecureExtensionState) it stacks
//! both ways:
//!
//! ```text
//! RfRetransmitterExtension                       // plain RF retransmitter
//! SecureExtensionState<RfRetransmitterExtension>   // + Data Secure
//! ```

use core::cell::Cell;

use serde::{Deserialize, Serialize};

use super::{RfExtensionConfig, RfExtensionState};
use crate::HasSecurityMode;
use crate::StackDefinition;
use crate::bcus::system_b::{Extension, ExtensionConfig, ExtensionState};
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::{
    HasDomainAddress, HasRfDomainAddress, HasRfRetransmitter, PropertyError, WriteResponse, interface_object_augment,
    pid,
};
use crate::restart::EraseCode;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_BinaryInformation, PDT_UnsignedChar};
use zweidraehte_proto::messages::knx::RequiredSecurity;

// ============================================================================
// Persisted Config
// ============================================================================

/// Persisted retransmitter configuration, layered on top of the base RF
/// extension's own config via a tuple (`(RfExtensionConfig, RfRetransmitterConfig)`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RfRetransmitterConfig {
    /// PID_RF_RETRANSMITTER (PID 57): runtime retransmitter-enabled flag.
    ///
    /// Defaults to `false`: composing the extension makes the device *capable*
    /// of repeating (the behaviour is compiled in and the hardware advertises
    /// `IsRFRetransmitter`), but the role stays off until ETS writes PID 57.
    #[serde(default)]
    pub rf_retransmitter: bool,
    /// PID_RF_REPEAT_COUNTER (PID 74): RC cascade-depth limit. Default 0.
    #[serde(default)]
    pub rf_repeat_counter_limit: u8,
}

impl ExtensionConfig for RfRetransmitterConfig {}

// ============================================================================
// Runtime cells
// ============================================================================

/// The retransmitter's own interior-mutable runtime state, factored out so the
/// augment can borrow exactly these cells.
pub struct RetransmitterCells {
    enabled: Cell<bool>,
    rc_limit: Cell<u8>,
}

impl RetransmitterCells {
    fn from_config(config: &RfRetransmitterConfig) -> Self {
        Self { enabled: Cell::new(config.rf_retransmitter), rc_limit: Cell::new(config.rf_repeat_counter_limit) }
    }

    fn reset(&self) {
        let defaults = RfRetransmitterConfig::default();
        self.enabled.set(defaults.rf_retransmitter);
        self.rc_limit.set(defaults.rf_repeat_counter_limit);
    }
}

// ============================================================================
// Wrapper extension state
// ============================================================================

/// Wraps the base KNX-RF medium extension and adds the retransmitter role.
pub struct RfRetransmitterExtension {
    /// The wrapped base RF medium extension (RF Domain Address store).
    pub inner: RfExtensionState,
    /// Retransmitter-specific runtime state (PID 57 / PID 74).
    cells: RetransmitterCells,
}

impl ExtensionState for RfRetransmitterExtension {
    type Config = (RfExtensionConfig, RfRetransmitterConfig);
    type Resources = ();

    fn from_config(config: Self::Config, _resources: ()) -> Self {
        let (inner_cfg, rt_cfg) = config;
        Self { inner: RfExtensionState::from_config(inner_cfg, ()), cells: RetransmitterCells::from_config(&rt_cfg) }
    }

    fn to_config(&self) -> Self::Config {
        (self.inner.to_config(), RfRetransmitterConfig {
            rf_retransmitter: self.cells.enabled.get(),
            rf_repeat_counter_limit: self.cells.rc_limit.get(),
        })
    }

    fn on_erase(&self, code: EraseCode) {
        self.inner.on_erase(code);
        if matches!(code, EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA) {
            self.cells.reset();
        }
    }
}

// ----------------------------------------------------------------------------
// Trait forwarding — the wrapper is transparent to the base RF medium traits.
// ----------------------------------------------------------------------------
//
// `forward_to_field!` (defined in `bcus::system_b`, shared with the secure
// wrapper) generates the pure delegation to `self.inner`. The retransmitter
// is a concrete (non-generic) wrapper, so the generics group is empty.
// There is no persistence side-effect on the wrapper, so no `mark_dirty`
// suffix. `HasRfRetransmitter` is *not* forwarded — its accessors read the
// retransmitter's own `cells`, not the inner extension — so it stays
// hand-written below.

forward_to_field! {
    impl<[]> HasSecurityMode for RfRetransmitterExtension {
        get fn security_mode_enabled(&self) -> bool;
        out fn log_access_denied(&self, source_addr: u16);
        get fn has_group_key(&self, tsap: u16) -> bool;
    } => self.inner
}

forward_to_field! {
    impl<[]> HasGoSecurityView for RfRetransmitterExtension {
        get fn required_security_for_asap(&self, asap: u16) -> RequiredSecurity;
        get fn required_security_for_p2p(&self, peer_ia: u16) -> RequiredSecurity;
        get fn required_security_for_broadcast(&self) -> RequiredSecurity;
        get fn required_security_for_tool_access(&self) -> RequiredSecurity;
    } => self.inner
}

forward_to_field! {
    impl<[]> HasRfDomainAddress for RfRetransmitterExtension {
        get fn rf_domain_address(&self) -> [u8; 6];
        set fn set_rf_domain_address(&self, addr: &[u8; 6]);
    } => self.inner
}

forward_to_field! {
    impl<[]> HasDomainAddress for RfRetransmitterExtension {
        const DOMAIN_ADDRESS_LENGTH: usize = <RfExtensionState as HasDomainAddress>::DOMAIN_ADDRESS_LENGTH;
        out fn domain_address(&self, buf: &mut [u8]);
        set fn set_domain_address(&self, addr: &[u8]);
    } => self.inner
}

// The new role accessor, backed by our own cells.
impl HasRfRetransmitter for RfRetransmitterExtension {
    fn rf_retransmit_enabled(&self) -> bool {
        self.cells.enabled.get()
    }

    fn set_rf_retransmit_enabled(&self, value: bool) {
        self.cells.enabled.set(value);
    }

    fn rf_repeat_counter_limit(&self) -> u8 {
        self.cells.rc_limit.get()
    }

    fn set_rf_repeat_counter_limit(&self, value: u8) {
        self.cells.rc_limit.set(value);
    }
}

// ============================================================================
// Augment — adds the retransmitter role to the RF Medium Object + Device Object
// ============================================================================

/// Adds `PID_RF_RETRANSMITTER` (PID 57) to the RF Medium Object (Type 19) and
/// intercepts the Device Object's `PID_RF_REPEAT_COUNTER` (PID 74).
///
/// It does **not** own the RF Medium Object: the base [`RfAugment`](super::RfAugment)
/// provides that object's `OBJECT_TYPE` (PID 1) and Domain Address (PID 56), and
/// this augment merely contributes PID 57 to the same object type via
/// `target_objects`. The two augments' descriptors for the RF Medium Object are
/// merged into one index space by the [`ServiceRegistry`](crate::service::ServiceRegistry)
/// aggregator (which rebases the index-based `A_PropertyDescription_Read` scan
/// per augment), so the object enumerates PID 1, 56, 57 in order even though the
/// descriptors live in two augments. PID 74 sits on the (base) Device Object and
/// is intercepted normally.
///
/// The extension composes this together with `RfAugment` — see
/// [`RfRetransmitterAugmentBundle`].
#[interface_object_augment(
    target_objects = [InterfaceObjectType::RFMedium, InterfaceObjectType::Device]
)]
pub struct RfRetransmitterAugment<'a> {
    /// Borrow of the retransmitter cells (PID 57 / PID 74).
    pub cells: &'a RetransmitterCells,

    // PID 57 — RF_RETRANSMITTER on the RF Medium Object: 1-bit flag, RW.
    // Contributed to the RF Medium Object that `RfAugment` provides.
    #[io(pid = pid::rf::RF_RETRANSMITTER, pdt = PDT_BinaryInformation, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         target = InterfaceObjectType::RFMedium, intercepts,
         read = |this: &Self| -> [u8; 1] { [this.cells.enabled.get() as u8] },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             if data.is_empty() {
                 return Err(PropertyError::TypeMismatch);
             }
             this.cells.enabled.set(data[0] != 0);
             Ok(WriteResponse::Echo)
         })]
    _rf_retransmitter_io: (),

    // PID 74 — RF_REPEAT_COUNTER on the Device Object: 1 octet, RW (intercept).
    #[io(pid = pid::device::RF_REPEAT_COUNTER, pdt = PDT_UnsignedChar, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         target = InterfaceObjectType::Device, intercepts,
         read = |this: &Self| -> [u8; 1] { [this.cells.rc_limit.get()] },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             if data.is_empty() {
                 return Err(PropertyError::TypeMismatch);
             }
             this.cells.rc_limit.set(data[0]);
             Ok(WriteResponse::Echo)
         })]
    _rf_repeat_counter_io: (),
}

/// The retransmitter extension's augment: the base RF Medium Object
/// ([`RfAugment`](super::RfAugment), PID 1 / 56) plus the retransmitter role
/// ([`RfRetransmitterAugment`], PID 57 / 74), composed so both contribute to the
/// one RF Medium Object. The `ServiceRegistry` merge across the two
/// `#[service(augment)]` fields is what makes a single object's properties span
/// two augments.
#[derive(crate::service::ServiceRegistry)]
pub struct RfRetransmitterAugmentBundle<'a> {
    #[service(augment)]
    pub base: super::RfAugment<'a>,
    #[service(augment)]
    pub retransmitter: RfRetransmitterAugment<'a>,
}

impl Extension<()> for RfRetransmitterExtension {
    type Augment<'a, D: StackDefinition>
        = RfRetransmitterAugmentBundle<'a>
    where
        Self: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, _platform: &'a ()) -> Self::Augment<'a, D>
    where
        (): 'a,
    {
        RfRetransmitterAugmentBundle {
            base: super::RfAugment { state: &self.inner },
            retransmitter: RfRetransmitterAugment { cells: &self.cells },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_proto::properties::PropertyDescriptorSpec;

    // An augment's descriptors are profile-independent specs; this test
    // only reads PIDs off them, so no resolution is needed.
    type DescriptorRow = (InterfaceObjectType, PropertyDescriptorSpec);

    /// Collect the descriptor PIDs from a `DESCRIPTORS` table for one object
    /// type, in declaration order (the order that drives the index-based
    /// `A_PropertyDescription_Read` scan within that augment).
    fn pids_for(table: &[DescriptorRow], object_type: InterfaceObjectType) -> ([u16; 8], usize) {
        let mut out = [0u16; 8];
        let mut n = 0;
        for (t, d) in table {
            if *t == object_type {
                out[n] = d.pid;
                n += 1;
            }
        }
        (out, n)
    }

    // The RF Medium Object's PIDs are deliberately split across two augments:
    // the base `RfAugment` provides OBJECT_TYPE (PID 1) and RF_DOMAIN_ADDRESS
    // (PID 56); this retransmitter augment contributes RF_RETRANSMITTER (PID 57)
    // to the same object type. The `ServiceRegistry` index merge (which rebases
    // the per-object-type index across the two augments) is what makes all three
    // enumerate as 1, 56, 57 — verified end to end by the property-index-scan
    // example and the conformance suite. Here we pin the split contract: the base
    // owns 1 + 56, the retransmitter owns 57, and together they total 3.
    #[test]
    fn rf_medium_object_split_across_base_and_retransmitter() {
        let (base, base_n) = pids_for(super::super::RfAugment::DESCRIPTORS, InterfaceObjectType::RFMedium);
        assert_eq!(&base[..base_n], &[pid::OBJECT_TYPE, pid::rf::RF_DOMAIN_ADDRESS]);

        let (rtx, rtx_n) = pids_for(RfRetransmitterAugment::DESCRIPTORS, InterfaceObjectType::RFMedium);
        assert_eq!(&rtx[..rtx_n], &[pid::rf::RF_RETRANSMITTER]);

        // The merged RF Medium Object enumerates exactly three properties.
        assert_eq!(base_n + rtx_n, 3);
    }

    // PID 74 is intercepted on the (base) Device Object by the retransmitter
    // augment; the base RF augment contributes nothing to the Device Object.
    #[test]
    fn device_object_intercepts_repeat_counter() {
        let (pids, n) = pids_for(RfRetransmitterAugment::DESCRIPTORS, InterfaceObjectType::Device);
        assert_eq!(&pids[..n], &[pid::device::RF_REPEAT_COUNTER]);
    }
}
