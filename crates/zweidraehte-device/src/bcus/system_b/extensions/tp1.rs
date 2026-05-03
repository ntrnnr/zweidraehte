//! TP1 extension: persistent state, augment, and configuration.
//!
//! Adds PID_MAX_RETRY_COUNT (PID 52) to the Device Object for TP1 devices.
//! The DLL retry parameters encode busy_retry (bits 6-4) and nak_retry
//! (bits 2-0), defaulting to 0x33 (3 busy retries, 3 NAK retries).
//!
//! `Tp1ExtensionState` implements [`Extension<()>`](crate::bcus::system_b::Extension),
//! providing both persistence and augmentation. It IS its own augment
//! — `create_augment` returns `&self`.
//!
//! ```rust,ignore
//! type ES = Tp1ExtensionState;
//! type InterfaceObjects<'a> = SystemBInterfaceObjectsFor<'a, Self>;
//!
//! fn create_interface_objects<'a>(...) -> Self::InterfaceObjects<'a> {
//!     create_system_b_objects_from_extension::<Self>(state, platform, &Self::memory_layout())
//! }
//! ```

use core::cell::Cell;

use serde::{Deserialize, Serialize};

use crate::bcus::system_b::{Extension, ExtensionConfig, ExtensionState, HasSecurityMode, SystemBDeviceState};
use crate::objects::interface::{
    HasMaxRetryCount, PropertyError, WriteResponse, interface_object_augment, pid,
};
use zweidraehte_proto::access::AccessPolicy;
use zweidraehte_proto::dpt::{InterfaceObjectType, PDT_Generic01};

// ============================================================================
// Default Value
// ============================================================================

/// Default value for PID_MAX_RETRY_COUNT: 3 busy retries (bits 6-4),
/// 3 NAK retries (bits 2-0) = 0x33.
const fn default_max_retry_count() -> u8 {
    0x33
}

// ============================================================================
// Persisted Config
// ============================================================================

/// Persisted TP1 extension configuration.
///
/// Serialized to storage when the device state is saved. Currently contains
/// only the DLL retry parameters, but may grow as more TP1-specific
/// persistent properties are added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tp1ExtensionConfig {
    /// PID_MAX_RETRY_COUNT value: busy_retry (bits 6-4), nak_retry (bits 2-0).
    #[serde(default = "default_max_retry_count")]
    pub max_retry_count: u8,
}

impl Default for Tp1ExtensionConfig {
    fn default() -> Self {
        Self { max_retry_count: default_max_retry_count() }
    }
}

impl ExtensionConfig for Tp1ExtensionConfig {}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime TP1 extension state with interior mutability.
///
/// Bridges the serializable [`Tp1ExtensionConfig`] and the runtime
/// representation used by the TPUART link layer (via `HasMaxRetryCount`)
/// and the interface object augment (via `InterfaceObjectAugment`).
//
// `#[interface_object_augment]` adds PID_MAX_RETRY_COUNT (52) to the Device
// Object. The augment's `get_property_descriptor` is generated automatically
// by the macro, closing the access-policy audit gap that the previous
// hand-written impl left open.
#[interface_object_augment(target_objects = [InterfaceObjectType::Device])]
pub struct Tp1ExtensionState {
    max_retry_count: Cell<u8>,

    #[io(
        pid = pid::MAX_RETRY_COUNT,
        pdt = PDT_Generic01,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = 3, wl = 3,
        intercepts,
        read = |this: &Self| [this.max_retry_count.get()],
        write = |this: &Self, data: &[u8]| -> Result<WriteResponse, PropertyError> {
            if data.is_empty() {
                return Err(PropertyError::TypeMismatch);
            }
            this.max_retry_count.set(data[0]);
            Ok(WriteResponse::Echo)
        },
    )]
    _max_retry_count_io: (),
}


// Plain TP1 has no Data Secure layer — every send is plaintext, so the
// trait's `Plain` defaults are correct without any override.
impl crate::objects::comm::HasGoSecurityView for Tp1ExtensionState {}

impl ExtensionState for Tp1ExtensionState {
    type Config = Tp1ExtensionConfig;
    type Resources = ();

    fn from_config(config: Tp1ExtensionConfig, _resources: ()) -> Self {
        Self { max_retry_count: Cell::new(config.max_retry_count) }
    }

    fn to_config(&self) -> Tp1ExtensionConfig {
        Tp1ExtensionConfig { max_retry_count: self.max_retry_count.get() }
    }

    fn on_erase(&self, code: crate::restart::EraseCode) {
        use crate::restart::EraseCode;
        if matches!(code, EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA) {
            self.max_retry_count.set(default_max_retry_count());
        }
    }
}

impl HasSecurityMode for Tp1ExtensionState {}

// ============================================================================
// Extension — unified persistence + augmentation
// ============================================================================

impl Extension<()> for Tp1ExtensionState {
    type Augment<'a, D: crate::StackDefinition>
        = &'a Tp1ExtensionState
    where
        Self: 'a;

    fn create_augment<'a, D: crate::StackDefinition>(&'a self, _platform: &'a ()) -> Self::Augment<'a, D>
    where
        (): 'a,
    {
        self
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

// `InterfaceObjectAugment` impl is generated by the
// `#[interface_object_augment(...)]` attribute above the struct.
