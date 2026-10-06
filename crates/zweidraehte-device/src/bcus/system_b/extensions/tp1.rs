//! TP1 extension: persistent state and augment.
//!
//! Adds PID_MAX_RETRY_COUNT (PID 52) to the Device Object for TP1 devices.
//! The DLL retry parameters encode busy_retry (bits 6-4) and nak_retry
//! (bits 2-0), defaulting to 0x33 (3 busy retries, 3 NAK retries).
//!
//! Like the other extensions ([`rf`](super::rf), [`ip`](super::ip)), the
//! persisted runtime state and its interface-object augment are kept in two
//! structs: [`Tp1ExtensionState`] holds the `Cell`-backed retry count, and
//! [`Tp1Augment`] borrows it (`state: &'a Tp1ExtensionState`) and carries the
//! PID 52 dispatch. `Tp1ExtensionState`'s [`Extension<()>`](crate::bcus::system_b::Extension)
//! impl hands out a `Tp1Augment` from `create_augment`.

use core::cell::Cell;

use crate::HasSecurityMode;
use crate::StackDefinition;
use crate::bcus::system_b::{Extension, ExtensionState, SystemBDeviceState};
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::{HasMaxRetryCount, PropertyError, WriteResponse, interface_object_augment, pid};
use crate::restart::EraseCode;
use crate::sections::{ConfigRecord, ExtensionSections, Section, SectionError, SectionId, ids};
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_Generic01};

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime TP1 extension state with interior mutability.
///
/// Holds the DLL retry count behind a `Cell` so the interface-object augment
/// can write it in place; persistence is automatic (a successful property
/// write marks the device dirty, and the flush finds the changed record).
/// The interface-object surface lives on the separate [`Tp1Augment`], which
/// borrows this state.
pub struct Tp1ExtensionState {
    /// PID_MAX_RETRY_COUNT value: busy_retry (bits 6-4), nak_retry (bits 2-0).
    max_retry_count: Cell<u8>,
}

impl Tp1ExtensionState {
    /// The factory PID_MAX_RETRY_COUNT: 3 busy retries (bits 6-4) and 3 NAK
    /// retries (bits 2-0).
    pub const FACTORY_MAX_RETRY_COUNT: u8 = 0x33;
}

impl ExtensionState for Tp1ExtensionState {
    type Resources = ();

    fn new(_resources: ()) -> Self {
        Self { max_retry_count: Cell::new(Self::FACTORY_MAX_RETRY_COUNT) }
    }

    fn on_erase(&self, code: EraseCode) {
        if matches!(code, EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA) {
            self.max_retry_count.set(Self::FACTORY_MAX_RETRY_COUNT);
        }
    }
}

/// One Record: `[max retry count]`.
impl ExtensionSections for Tp1ExtensionState {
    fn owns(id: SectionId) -> bool {
        id == ids::TP1
    }

    fn for_each_section(&self, f: &mut impl FnMut(Section)) {
        f(ConfigRecord::section::<u8>(ids::TP1));
    }

    fn read_section(&self, _id: SectionId, offset: u16, buf: &mut [u8]) {
        ConfigRecord::read::<u8, 1>(&self.max_retry_count.get(), offset, buf);
    }

    fn apply_section(&self, id: SectionId, offset: u16, bytes: &[u8]) -> Result<(), SectionError> {
        if id != ids::TP1 {
            return Err(SectionError::UnknownSection);
        }
        self.max_retry_count.set(ConfigRecord::decode::<u8, 1>(offset, bytes)?);
        Ok(())
    }

    fn reset_section(&self, _id: SectionId) {
        self.max_retry_count.set(Self::FACTORY_MAX_RETRY_COUNT);
    }
}

// Plain TP1 has no Data Secure layer — every send is plaintext, so the
// trait's `Plain` defaults are correct without any override.
impl HasGoSecurityView for Tp1ExtensionState {}

impl HasSecurityMode for Tp1ExtensionState {}

// ============================================================================
// Tp1Augment — intercepts PID_MAX_RETRY_COUNT (52) on the Device Object
// ============================================================================

/// Adds PID_MAX_RETRY_COUNT (52) to the Device Object for TP1 devices.
///
/// A passive borrow of [`Tp1ExtensionState`]; the macro-generated property
/// dispatch reads and writes the state's `Cell` directly. Unlike
/// [`RfAugment`](super::RfAugment) this is an *intercepting* augment
/// (`target_objects` + `intercepts`): it contributes one property to the
/// existing Device Object rather than providing a new object, so it carries
/// no PID 1 `OBJECT_TYPE` entry.
#[interface_object_augment(target_objects = [InterfaceObjectType::Device])]
pub struct Tp1Augment<'a> {
    /// Persisted TP1 configuration (from extension state).
    pub state: &'a Tp1ExtensionState,

    // Levels 3/3 in Annex A.2.3 for 07B0h and 0705h alike: the controller
    // audience, so a 16-level System 7 device answers 3/3 rather than its
    // free level 15.
    #[io(
        pid = pid::device::MAX_RETRY_COUNT,
        pdt = PDT_Generic01,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = Controller, wl = Controller,
        intercepts,
        read = |this: &Self| [this.state.max_retry_count.get()],
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.is_empty() {
                return Err(PropertyError::TypeMismatch);
            }
            this.state.max_retry_count.set(data[0]);
            Ok(WriteResponse::Echo)
        },
    )]
    _max_retry_count_io: (),
}

// ============================================================================
// Extension — persistence + augmentation
// ============================================================================

impl Extension<()> for Tp1ExtensionState {
    type Augment<'a, D: StackDefinition>
        = Tp1Augment<'a>
    where
        Self: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, _platform: &'a ()) -> Self::Augment<'a, D>
    where
        (): 'a,
    {
        Tp1Augment { state: self }
    }
}

// ============================================================================
// TP1 Device State Type Alias
// ============================================================================

/// Type alias for TP1 device state.
///
/// This is [`SystemBDeviceState`](crate::bcus::system_b::SystemBDeviceState)
/// specialized with [`Tp1ExtensionState`] for TP1 twisted-pair devices.
pub type Tp1SystemBDeviceState<const ADT_SIZE: usize, const AST_SIZE: usize, const COT_SIZE: usize, D> =
    SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, Tp1ExtensionState>;

// ============================================================================
// HasMaxRetryCount — used by TPUART link layer via MaxRetryCountContext
// ============================================================================

impl HasMaxRetryCount for Tp1ExtensionState {
    fn max_retry_count(&self) -> u8 {
        self.max_retry_count.get()
    }

    fn set_max_retry_count(&self, value: u8) {
        self.max_retry_count.set(value);
    }
}

// The `Augment<D>` impl for `Tp1Augment` is generated by the
// `#[interface_object_augment(...)]` attribute on that struct above.

/// Every persistent field survives a reboot through its section.
#[cfg(test)]
mod persistence {
    use super::*;
    use crate::sections::test_support::assert_field_persists;

    fn fresh() -> Tp1ExtensionState {
        Tp1ExtensionState::new(())
    }

    #[test]
    fn max_retry_count() {
        assert_field_persists(fresh, |s| s.set_max_retry_count(0x12), |s| s.max_retry_count());
    }
}
