//! TP1 extension: persistent state, augment, and configuration.
//!
//! Adds PID_MAX_RETRY_COUNT (PID 52) to the Device Object for TP1 devices.
//! The DLL retry parameters encode busy_retry (bits 6-4) and nak_retry
//! (bits 2-0), defaulting to 0x33 (3 busy retries, 3 NAK retries).
//!
//! `Tp1ExtensionState` implements both [`ExtensionState`] (for persistence)
//! and [`InterfaceObjectAugment`] (for property handling). It IS the augment
//! — pass `state.extension_state()` as the augment parameter:
//!
//! ```rust,ignore
//! type InterfaceObjects<'a> = DefaultSystemBInterfaceObjects<'a, MyState, &'a Tp1ExtensionState>;
//!
//! fn create_interface_objects<'a>(state: &'a Self::State) -> Self::InterfaceObjects<'a> {
//!     create_system_b_objects::<Self, _, _>(state, &Self::memory_layout(), state.extension_state())
//! }
//! ```

use core::cell::Cell;

use serde::{Deserialize, Serialize};

use crate::bcus::system_b::{ExtensionConfig, ExtensionState};
use crate::dpt::{InterfaceObjectType, PDT_Generic01};
use crate::objects::interface::{
    FullPropertyReadRequest, FullPropertyWriteRequest, HasMaxRetryCount, InterfaceObjectAugment,
    PropertyAccess, PropertyDescriptionResponse, PropertyDescriptor, PropertyError, PropertyLookup,
    WriteResponse, pid,
};
use crate::StackState;

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
        Self {
            max_retry_count: default_max_retry_count(),
        }
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
pub struct Tp1ExtensionState {
    max_retry_count: Cell<u8>,
}

impl ExtensionState for Tp1ExtensionState {
    type Config = Tp1ExtensionConfig;

    fn from_config(config: Tp1ExtensionConfig) -> Self {
        Self {
            max_retry_count: Cell::new(config.max_retry_count),
        }
    }

    fn to_config(&self) -> Tp1ExtensionConfig {
        Tp1ExtensionConfig {
            max_retry_count: self.max_retry_count.get(),
        }
    }

    fn factory_reset(&self) {
        self.max_retry_count.set(default_max_retry_count());
    }
}

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

// ============================================================================
// InterfaceObjectAugment — adds PID 52 to the Device Object
// ============================================================================

impl<S: StackState> InterfaceObjectAugment<S> for Tp1ExtensionState {
    fn property_description_read(
        &self,
        _state: &S,
        object_type: InterfaceObjectType,
        object_idx: u16,
        lookup: PropertyLookup,
    ) -> Option<Result<PropertyDescriptionResponse, PropertyError>> {
        if object_type != InterfaceObjectType::Device {
            return None;
        }

        if !matches!(
            lookup,
            PropertyLookup::ByPid(pid::MAX_RETRY_COUNT) | PropertyLookup::ByIndex(0)
        ) {
            return None;
        }

        let desc = PropertyDescriptor::from_type::<PDT_Generic01>(
            pid::MAX_RETRY_COUNT,
            PropertyAccess::ReadWrite,
            3, // read level: unrestricted
            3, // write level: unrestricted
        );
        Some(Ok(PropertyDescriptionResponse::from_descriptor(
            object_idx,
            0,
            &desc,
        )))
    }

    fn property_value_read(
        &self,
        _state: &S,
        object_type: InterfaceObjectType,
        req: &FullPropertyReadRequest,
        buf: &mut [u8],
    ) -> Option<Result<usize, PropertyError>> {
        if object_type != InterfaceObjectType::Device || req.pid != pid::MAX_RETRY_COUNT {
            return None;
        }

        // Element count query (start_idx=0 per KNX spec).
        if req.start_idx == 0 {
            if buf.len() < 2 {
                return Some(Err(PropertyError::BufferTooSmall));
            }
            buf[0] = 0;
            buf[1] = 1; // Single element
            return Some(Ok(2));
        }

        // Non-array data property: start_idx must be 1, count must be 1.
        if req.start_idx != 1 || req.count != 1 {
            return Some(Err(PropertyError::InvalidStartIndex));
        }

        if buf.is_empty() {
            return Some(Err(PropertyError::BufferTooSmall));
        }

        buf[0] = self.max_retry_count();
        Some(Ok(1))
    }

    fn property_value_write(
        &self,
        _state: &S,
        object_type: InterfaceObjectType,
        req: &FullPropertyWriteRequest<'_>,
    ) -> Option<Result<WriteResponse, PropertyError>> {
        if object_type != InterfaceObjectType::Device || req.pid != pid::MAX_RETRY_COUNT {
            return None;
        }

        if req.data.is_empty() {
            return Some(Err(PropertyError::TypeMismatch));
        }

        self.set_max_retry_count(req.data[0]);
        Some(Ok(WriteResponse::Echo))
    }
}
