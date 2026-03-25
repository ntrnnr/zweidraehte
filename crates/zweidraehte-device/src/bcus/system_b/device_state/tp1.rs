//! TP1 link-layer state for KNX twisted-pair devices.
//!
//! Mirrors the [`IpLinkLayerState`](super::IpLinkLayerState) /
//! [`PersistedIpConfig`](crate::bcus::system_b::PersistedIpConfig) pattern
//! but for TP1-specific persistent configuration. Currently this is just the
//! DLL retry parameters (PID_MAX_RETRY_COUNT, PID 52).

use core::cell::Cell;

use serde::{Deserialize, Serialize};

use super::LinkLayerState;
use crate::objects::interface::HasMaxRetryCount;

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

/// Persisted TP1 link-layer configuration.
///
/// Serialized to storage when the device state is saved. Currently contains
/// only the DLL retry parameters, but may grow as more TP1-specific
/// persistent properties are added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tp1LinkLayerConfig {
    /// PID_MAX_RETRY_COUNT value: busy_retry (bits 6-4), nak_retry (bits 2-0).
    #[serde(default = "default_max_retry_count")]
    pub max_retry_count: u8,
}

impl Default for Tp1LinkLayerConfig {
    fn default() -> Self {
        Self {
            max_retry_count: default_max_retry_count(),
        }
    }
}

impl super::super::LinkLayerConfig for Tp1LinkLayerConfig {}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime TP1 link-layer state with interior mutability.
///
/// Bridges the serializable [`Tp1LinkLayerConfig`] and the runtime
/// representation used by interface object augments and the TPUART
/// link layer.
pub struct Tp1LinkLayerState {
    max_retry_count: Cell<u8>,
}

impl LinkLayerState for Tp1LinkLayerState {
    type Config = Tp1LinkLayerConfig;

    fn from_config(config: Tp1LinkLayerConfig) -> Self {
        Self {
            max_retry_count: Cell::new(config.max_retry_count),
        }
    }

    fn to_config(&self) -> Tp1LinkLayerConfig {
        Tp1LinkLayerConfig {
            max_retry_count: self.max_retry_count.get(),
        }
    }

    fn factory_reset(&self) {
        self.max_retry_count.set(default_max_retry_count());
    }
}

// ============================================================================
// HasMaxRetryCount for Tp1LinkLayerState
// ============================================================================

impl HasMaxRetryCount for Tp1LinkLayerState {
    fn max_retry_count(&self) -> u8 {
        self.max_retry_count.get()
    }

    fn set_max_retry_count(&self, value: u8) {
        self.max_retry_count.set(value);
    }
}
