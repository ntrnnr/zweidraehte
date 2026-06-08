//! KNX-RF extension: RF Medium Object, persistent state, and augment.
//!
//! Adds the **RF Medium Object** (Interface Object Type 19 / 0x13) to a System B
//! device, exposing:
//!
//! - `PID_RF_DOMAIN_ADDRESS` (PID 56) — the 6-octet RF Domain Address, mandatory
//!   per KNX 03/05/01 §4.15.8. This is the canonical store the KNX-RF link layer
//!   filters inbound frames against and inserts into domain-addressed
//!   transmissions. (The optional Device-Object mirror, PID 82, is not
//!   implemented.)
//!
//! The optional retransmitter role — `PID_RF_RETRANSMITTER` (PID 57) and
//! `PID_RF_REPEAT_COUNTER` (PID 74), plus the actual Layer-2 repeating
//! behaviour — is *not* part of this base extension. It lives in the
//! compile-time-optional wrapper extension [`retransmitter`], so devices that
//! are not retransmitters carry neither the extra PIDs nor any link-layer code.
//!
//! Mirrors the [`tp1`](super::tp1) extension's shape, but contributes a *new*
//! object (`additional_objects`) rather than intercepting the Device Object.
//! Unlike TP1, the augment is a thin separate struct ([`RfAugment`]) holding a
//! borrow of the state, because an augment-provided object always needs its own
//! `OBJECT_TYPE` (PID 1) entry.

pub mod retransmitter;

pub use retransmitter::{
    RetransmitterCells, RfRetransmitterAugment, RfRetransmitterAugmentBundle, RfRetransmitterConfig,
    RfRetransmitterExtension,
};

use core::cell::Cell;

use serde::{Deserialize, Serialize};

use crate::StackDefinition;
use crate::bcus::system_b::{Extension, ExtensionConfig, ExtensionState, HasSecurityMode, SystemBDeviceState};
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::{
    HasDomainAddress, HasRfDomainAddress, PropertyError, WriteResponse, interface_object_augment, pid,
};
use crate::restart::EraseCode;
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_Generic06, PDT_UnsignedInt};

// ============================================================================
// Defaults
// ============================================================================

/// Factory RF Domain Address. All-zero until configured by ETS/management; per
/// 03/05/01 §4.15.8 the configuration procedures guarantee a unique value is
/// assigned before the device participates in domain-addressed communication.
const fn default_rf_domain_address() -> [u8; 6] {
    [0; 6]
}

// ============================================================================
// Persisted Config
// ============================================================================

/// Persisted KNX-RF extension configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfExtensionConfig {
    /// PID_RF_DOMAIN_ADDRESS (PID 56): 6-octet RF Domain Address.
    #[serde(default = "default_rf_domain_address")]
    pub rf_domain_address: [u8; 6],
}

impl Default for RfExtensionConfig {
    fn default() -> Self {
        Self { rf_domain_address: default_rf_domain_address() }
    }
}

impl ExtensionConfig for RfExtensionConfig {}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime KNX-RF extension state with interior mutability.
///
/// Holds the RF Domain Address behind a `Cell` so the interface-object augment
/// can write it in place; persistence is automatic (a successful property write
/// marks the device dirty, flushing [`to_config`](ExtensionState::to_config)).
pub struct RfExtensionState {
    rf_domain_address: Cell<[u8; 6]>,
}

impl RfExtensionState {
    /// Current RF Domain Address as a byte array (for property reads).
    fn rf_domain_address_bytes(&self) -> [u8; 6] {
        self.rf_domain_address.get()
    }
}

// Plain RF has no Data Secure layer, so the `Plain` defaults are correct.
impl HasGoSecurityView for RfExtensionState {}
impl HasSecurityMode for RfExtensionState {}

impl ExtensionState for RfExtensionState {
    type Config = RfExtensionConfig;
    type Resources = ();

    fn from_config(config: RfExtensionConfig, _resources: ()) -> Self {
        Self { rf_domain_address: Cell::new(config.rf_domain_address) }
    }

    fn to_config(&self) -> RfExtensionConfig {
        RfExtensionConfig { rf_domain_address: self.rf_domain_address.get() }
    }

    fn on_erase(&self, code: EraseCode) {
        if matches!(code, EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA) {
            self.rf_domain_address.set(default_rf_domain_address());
        }
    }
}

// ============================================================================
// RfAugment — provides the RF Medium Object (Type 19)
// ============================================================================

/// Provides the RF Medium Object (Object Type 19) and dispatches its PIDs.
///
/// A passive borrow of [`RfExtensionState`]; the macro-generated property
/// dispatch reads and writes the state's `Cell`s directly.
#[interface_object_augment(additional_objects = [InterfaceObjectType::RFMedium])]
pub struct RfAugment<'a> {
    /// Persisted RF configuration (from extension state).
    pub state: &'a RfExtensionState,

    // PID 1 — OBJECT_TYPE: mandatory on every augment-provided object.
    #[io(pid = pid::OBJECT_TYPE, pdt = PDT_UnsignedInt, access = RO,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 0,
         read = |_this: &Self| -> [u8; 2] {
             let v: u16 = InterfaceObjectType::RFMedium.into();
             v.to_be_bytes()
         })]
    _object_type_io: (),

    // PID 56 — RF_DOMAIN_ADDRESS: 6-octet, RW, non-volatile.
    #[io(pid = pid::rf::RF_DOMAIN_ADDRESS, pdt = PDT_Generic06, access = RW,
         policy = AccessPolicy::READ_OPEN_WRITE_TOOL, rl = 3, wl = 3,
         read = |this: &Self| -> [u8; 6] { this.state.rf_domain_address_bytes() },
         write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
             if data.len() < 6 {
                 return Err(PropertyError::BufferTooSmall);
             }
             let mut doa = [0u8; 6];
             doa.copy_from_slice(&data[..6]);
             this.state.rf_domain_address.set(doa);
             Ok(WriteResponse::Echo)
         })]
    _rf_domain_address_io: (),
}

impl Extension<()> for RfExtensionState {
    type Augment<'a, D: StackDefinition>
        = RfAugment<'a>
    where
        Self: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, _platform: &'a ()) -> Self::Augment<'a, D>
    where
        (): 'a,
    {
        RfAugment { state: self }
    }
}

// ============================================================================
// Domain-address trait impls
// ============================================================================

// The RF-specific 6-octet accessor consumed by the link layer through
// `RfDomainAddressContext`.
impl HasRfDomainAddress for RfExtensionState {
    fn rf_domain_address(&self, out: &mut [u8; 6]) {
        *out = self.rf_domain_address.get();
    }

    fn set_rf_domain_address(&self, addr: &[u8; 6]) {
        self.rf_domain_address.set(*addr);
    }
}

// The medium-generic `HasDomainAddress` (used by `A_DomainAddressSerialNumber`
// services) reports the same 6-octet value for the RF medium. A blanket
// `impl<T: HasRfDomainAddress> HasDomainAddress for T` was considered to fold
// this together with `RfRetransmitterExtension` and the secure wrapper, but it
// collides (coherence) with the `HasDomainAddress for SystemBDeviceState`
// forwarding impl — which must stay, because it also serves KNX/IP extensions
// and marks the device dirty on write. The per-RF-type bridge below is the
// honest cost of keeping that single dirty-tracking forwarding point.
impl HasDomainAddress for RfExtensionState {
    const DOMAIN_ADDRESS_LENGTH: usize = 6;

    fn domain_address(&self, buf: &mut [u8]) {
        let doa = self.rf_domain_address.get();
        let n = buf.len().min(doa.len());
        buf[..n].copy_from_slice(&doa[..n]);
    }

    fn set_domain_address(&self, addr: &[u8]) {
        let mut doa = [0u8; 6];
        let n = addr.len().min(doa.len());
        doa[..n].copy_from_slice(&addr[..n]);
        self.rf_domain_address.set(doa);
    }
}

// ============================================================================
// RF Device State Type Alias
// ============================================================================

/// [`SystemBDeviceState`] specialised with [`RfExtensionState`] for KNX-RF
/// devices.
pub type RfSystemBDeviceState<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D> =
    SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, RfExtensionState>;
