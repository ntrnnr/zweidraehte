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
//! # Why it owns the whole RF Medium Object
//!
//! A single interface object's properties cannot be split across two augments:
//! `A_PropertyDescription_Read` enumerates by property *index*, and each augment
//! indexes only its own descriptors, so a property contributed by a second
//! augment is invisible to the index scan. The base [`RfAugment`](super::RfAugment)
//! already provides the RF Medium Object (PIDs 1 and 56), so rather than appending
//! PID 57 to it, this augment **replaces** it: it owns the full RF Medium Object
//! (PID 1, PID 56 delegated to the wrapped state, PID 57) and the wrapper does
//! *not* compose the base `RfAugment`. PID 74 sits on the Device Object, a base
//! object whose enumeration already merges a single augment's intercepts, so it
//! is intercepted normally.
//!
//! The *behaviour* (the actual repeating) lives in the link layer and is gated
//! by a separate ZST policy generic; this extension only carries the state and
//! interface-object surface. A device opts in by composing this extension
//! (`type ES`) **and** selecting the repeating link layer (`type LLB`).
//!
//! # Composition
//!
//! Like [`SecureExtensionState`](super::super::extensions::security) it stacks
//! both ways:
//!
//! ```text
//! RfRetransmitterExtension                       // plain RF retransmitter
//! SecureExtensionState<RfRetransmitterExtension>   // + Data Secure
//! ```

use core::cell::Cell;

use serde::{Deserialize, Serialize};

use super::{RfExtensionConfig, RfExtensionState};
use crate::StackDefinition;
use crate::bcus::system_b::{Extension, ExtensionConfig, ExtensionState, HasSecurityMode};
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::{
    HasDomainAddress, HasRfDomainAddress, HasRfRetransmitter, PropertyError, WriteResponse, interface_object_augment,
    pid,
};
use crate::restart::EraseCode;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{
    InterfaceObjectType, PDT_BinaryInformation, PDT_Generic06, PDT_UnsignedChar, PDT_UnsignedInt,
};
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

impl HasSecurityMode for RfRetransmitterExtension {
    fn security_mode_enabled(&self) -> bool {
        self.inner.security_mode_enabled()
    }

    fn log_access_denied(&self, source_addr: u16) {
        self.inner.log_access_denied(source_addr);
    }

    fn has_group_key(&self, tsap: u16) -> bool {
        self.inner.has_group_key(tsap)
    }
}

impl HasGoSecurityView for RfRetransmitterExtension {
    fn required_security_for_asap(&self, asap: u16) -> RequiredSecurity {
        self.inner.required_security_for_asap(asap)
    }

    fn required_security_for_p2p(&self, peer_ia: u16) -> RequiredSecurity {
        self.inner.required_security_for_p2p(peer_ia)
    }

    fn required_security_for_broadcast(&self) -> RequiredSecurity {
        self.inner.required_security_for_broadcast()
    }

    fn required_security_for_tool_access(&self) -> RequiredSecurity {
        self.inner.required_security_for_tool_access()
    }
}

impl HasRfDomainAddress for RfRetransmitterExtension {
    fn rf_domain_address(&self, out: &mut [u8; 6]) {
        self.inner.rf_domain_address(out);
    }

    fn set_rf_domain_address(&self, addr: &[u8; 6]) {
        self.inner.set_rf_domain_address(addr);
    }
}

impl HasDomainAddress for RfRetransmitterExtension {
    const DOMAIN_ADDRESS_LENGTH: usize = <RfExtensionState as HasDomainAddress>::DOMAIN_ADDRESS_LENGTH;

    fn domain_address(&self, buf: &mut [u8]) {
        self.inner.domain_address(buf);
    }

    fn set_domain_address(&self, addr: &[u8]) {
        self.inner.set_domain_address(addr);
    }
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
// Augment — owns the RF Medium Object (Type 19) and intercepts Device PID 74
// ============================================================================

/// Provides the complete RF Medium Object (PID 1 / 56 / 57) and intercepts the
/// Device Object's `PID_RF_REPEAT_COUNTER` (PID 74).
///
/// It owns the RF Medium Object outright (`additional_objects`) — replacing the
/// base [`RfAugment`](super::RfAugment), which the wrapper does not compose — so
/// all three RF Medium PIDs share one descriptor table and enumerate correctly.
/// PID 56 is delegated to the wrapped [`RfExtensionState`] so the Domain Address
/// store stays single-sourced.
#[interface_object_augment(
    additional_objects = [InterfaceObjectType::RFMedium],
    target_objects = [InterfaceObjectType::Device]
)]
pub struct RfRetransmitterAugment<'a> {
    /// Borrow of the wrapped RF medium state (for the Domain Address, PID 56).
    pub inner: &'a RfExtensionState,
    /// Borrow of the retransmitter cells (PID 57 / PID 74).
    pub cells: &'a RetransmitterCells,

    // PID 1 — OBJECT_TYPE: mandatory on every augment-provided object.
    #[io(pid = pid::OBJECT_TYPE, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         target = InterfaceObjectType::RFMedium,
         read = |_this: &Self| -> [u8; 2] {
             let v: u16 = InterfaceObjectType::RFMedium.into();
             v.to_be_bytes()
         })]
    _object_type_io: (),

    // PID 56 — RF_DOMAIN_ADDRESS on the RF Medium Object: 6-octet, RW, delegated
    // to the wrapped RF state so the Domain Address has a single home.
    #[io(pid = pid::rf::RF_DOMAIN_ADDRESS, pdt = PDT_Generic06, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         target = InterfaceObjectType::RFMedium,
         read = |this: &Self| -> [u8; 6] {
             let mut doa = [0u8; 6];
             this.inner.rf_domain_address(&mut doa);
             doa
         },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             if data.len() < 6 {
                 return Err(PropertyError::BufferTooSmall);
             }
             let mut doa = [0u8; 6];
             doa.copy_from_slice(&data[..6]);
             this.inner.set_rf_domain_address(&doa);
             Ok(WriteResponse::Echo)
         })]
    _rf_domain_address_io: (),

    // PID 57 — RF_RETRANSMITTER on the RF Medium Object: 1-bit flag, RW.
    #[io(pid = pid::rf::RF_RETRANSMITTER, pdt = PDT_BinaryInformation, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         target = InterfaceObjectType::RFMedium,
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

impl Extension<()> for RfRetransmitterExtension {
    type Augment<'a, D: StackDefinition>
        = RfRetransmitterAugment<'a>
    where
        Self: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, _platform: &'a ()) -> Self::Augment<'a, D>
    where
        (): 'a,
    {
        RfRetransmitterAugment { inner: &self.inner, cells: &self.cells }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collect the descriptor PIDs for one object type, preserving the
    /// declaration order that drives `A_PropertyDescription_Read` index scans.
    fn pids_for(object_type: InterfaceObjectType) -> ([u16; 8], usize) {
        let mut out = [0u16; 8];
        let mut n = 0;
        for (t, d) in RfRetransmitterAugment::DESCRIPTORS {
            if *t == object_type {
                out[n] = d.pid;
                n += 1;
            }
        }
        (out, n)
    }

    // Regression: the RF Medium Object's PIDs must all sit in *one* augment's
    // descriptor table, in index order (1, 56, 57). Splitting them across the
    // base `RfAugment` and this augment made PID 57 invisible to the index-based
    // property scan (it landed at local index 0 but was sought at global 2).
    #[test]
    fn rf_medium_object_enumerates_all_three_pids_in_order() {
        let (pids, n) = pids_for(InterfaceObjectType::RFMedium);
        assert_eq!(&pids[..n], &[pid::OBJECT_TYPE, pid::rf::RF_DOMAIN_ADDRESS, pid::rf::RF_RETRANSMITTER]);
    }

    // PID 74 is intercepted on the (base) Device Object, where the container
    // merges a single augment's intercepts into the scan.
    #[test]
    fn device_object_intercepts_repeat_counter() {
        let (pids, n) = pids_for(InterfaceObjectType::Device);
        assert_eq!(&pids[..n], &[pid::device::RF_REPEAT_COUNTER]);
    }
}
