//! TP1 extension: persistent state, augment, and configuration.
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

use crate::StackDefinition;
// `ExtensionState` here is the derive macro (and trait); it generates the
// `Tp1ExtensionConfig` mirror and the `ExtensionState` impl.
use crate::HasSecurityMode;
use crate::bcus::system_b::{Extension, ExtensionState, SystemBDeviceState};
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::{HasMaxRetryCount, PropertyError, WriteResponse, interface_object_augment, pid};
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
// Runtime State (and the derived persisted Config)
// ============================================================================

/// Runtime TP1 extension state with interior mutability.
///
/// Holds the DLL retry count behind a `Cell` so the interface-object augment
/// can write it in place; persistence is automatic (a successful property
/// write marks the device dirty, flushing
/// [`to_config`](crate::bcus::system_b::ExtensionState::to_config)).
///
/// `#[derive(ExtensionState)]` generates the persisted `Tp1ExtensionConfig`
/// mirror (`Cell<u8>` → `u8`) together with the `from_config` / `to_config` /
/// `on_erase` glue. The interface-object surface lives on the separate
/// [`Tp1Augment`], which borrows this state.
#[derive(ExtensionState)]
#[extension_state(config = Tp1ExtensionConfig)]
pub struct Tp1ExtensionState {
    /// PID_MAX_RETRY_COUNT value: busy_retry (bits 6-4), nak_retry (bits 2-0).
    #[config(serde_default = "default_max_retry_count")]
    #[erase(default = default_max_retry_count())]
    max_retry_count: Cell<u8>,
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

    #[io(
        pid = pid::device::MAX_RETRY_COUNT,
        pdt = PDT_Generic01,
        access = RW,
        policy = AccessPolicy::READ_OPEN_WRITE_TOOL,
        rl = Runtime, wl = Runtime,
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
