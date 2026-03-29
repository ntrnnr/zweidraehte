//! Security extension: persistent state, augment, and composable wrappers.
//!
//! Adds the KNX Data Secure Security Interface Object (Object Type 0x11)
//! to System B devices. This module is orthogonal to the medium extension
//! (TP1 or IP) — it composes with them via [`SecureExtensionState`].
//!
//! # Architecture
//!
//! Non-secure devices are unaffected. Security is opt-in:
//!
//! ```text
//! SecureExtensionState<Tp1ExtensionState, 64, 32>
//!   ├── inner: Tp1ExtensionState        (medium-specific state)
//!   └── security: SecurityState<64, 32> (security tables + mode)
//!
//! Extension::create_augment() produces:
//!   (Tp1Augment, SecurityAugment)       (tuple augment composition)
//! ```
//!
//! The existing [`create_system_b_objects_with_extra`] function handles
//! the tuple augment composition automatically.
//!
//! [`create_system_b_objects_with_extra`]: crate::bcus::system_b::objects::create_system_b_objects_with_extra
//!
//! # Const Generics
//!
//! - `GRP`: Max group key table entries (typically matches association table size)
//! - `GO`: Max GO security flag entries (typically matches communication object count)

mod augment;

pub use augment::SecurityAugment;

use core::cell::Cell;

use serde::{Deserialize, Serialize};

use crate::StackState;
use crate::bcus::system_b::{Extension, ExtensionConfig, ExtensionState};

// ============================================================================
// Persisted Config
// ============================================================================

/// Persisted security extension configuration.
///
/// Serialized to storage when the device state is saved. Contains the
/// security mode flag, tool key, and load state. Key tables and sequence
/// numbers are handled separately (tables via the load state machine,
/// sequence numbers via [`SequenceNumberStorage`]).
///
/// [`SequenceNumberStorage`]: crate::storage::SequenceNumberStorage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityExtensionConfig {
    /// Whether security mode is enabled on this device.
    #[serde(default)]
    pub security_mode_enabled: bool,

    /// The 16-byte tool key. All zeros when not yet commissioned.
    #[serde(default = "default_tool_key")]
    pub tool_key: [u8; 16],

    /// Load state for the Security Interface Object.
    #[serde(default)]
    pub load_state: u8,
}

fn default_tool_key() -> [u8; 16] {
    [0u8; 16]
}

impl Default for SecurityExtensionConfig {
    fn default() -> Self {
        Self {
            security_mode_enabled: false,
            tool_key: [0u8; 16],
            load_state: 0, // Unloaded
        }
    }
}

impl ExtensionConfig for SecurityExtensionConfig {}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime security state with interior mutability.
///
/// This holds the security mode, tool key, and load state. Key tables
/// (group keys, GO security flags) will be added in Phase 2 with
/// const-generic sizing.
///
/// The const generics `GRP` and `GO` are reserved for Phase 2's table
/// storage. For Phase 1, they don't affect the struct layout — they're
/// present to establish the type signature early so that downstream
/// type aliases don't need to change later.
pub struct SecurityState<const GRP: usize, const GO: usize> {
    security_mode_enabled: Cell<bool>,
    tool_key: Cell<[u8; 16]>,
    load_state: Cell<u8>,
}

impl<const GRP: usize, const GO: usize> SecurityState<GRP, GO> {
    /// Whether the device's Security Mode is currently enabled.
    pub fn security_mode_enabled(&self) -> bool {
        self.security_mode_enabled.get()
    }

    /// Set the security mode.
    pub fn set_security_mode_enabled(&self, enabled: bool) {
        self.security_mode_enabled.set(enabled);
    }

    /// Get the current load state.
    pub fn load_state(&self) -> u8 {
        self.load_state.get()
    }

    /// Set the load state.
    pub fn set_load_state(&self, state: u8) {
        self.load_state.set(state);
    }

    /// Get the tool key.
    pub fn tool_key(&self) -> [u8; 16] {
        self.tool_key.get()
    }

    /// Set the tool key (write-only property, PID 56).
    pub fn set_tool_key(&self, key: [u8; 16]) {
        self.tool_key.set(key);
    }
}

impl<const GRP: usize, const GO: usize> ExtensionState for SecurityState<GRP, GO> {
    type Config = SecurityExtensionConfig;

    fn from_config(config: SecurityExtensionConfig) -> Self {
        Self {
            security_mode_enabled: Cell::new(config.security_mode_enabled),
            tool_key: Cell::new(config.tool_key),
            load_state: Cell::new(config.load_state),
        }
    }

    fn to_config(&self) -> SecurityExtensionConfig {
        SecurityExtensionConfig {
            security_mode_enabled: self.security_mode_enabled.get(),
            tool_key: self.tool_key.get(),
            load_state: self.load_state.get(),
        }
    }

    fn factory_reset(&self) {
        self.security_mode_enabled.set(false);
        self.tool_key.set([0u8; 16]);
        self.load_state.set(0);
    }
}

// ============================================================================
// Composed Extension — wraps a medium extension with security
// ============================================================================

/// Composed extension state that wraps a medium extension (TP1 or IP)
/// with Data Secure support.
///
/// The inner extension handles medium-specific state (e.g., TP1 retry
/// count, IP configuration). The security state handles the Security
/// Interface Object. Both are persisted independently.
///
/// # Non-Secure Devices
///
/// Devices that don't need Data Secure simply use the inner extension
/// directly (e.g., `Tp1ExtensionState`). This wrapper is only used
/// when security is desired.
pub struct SecureExtensionState<Inner: ExtensionState, const GRP: usize, const GO: usize> {
    /// The medium-specific extension state.
    pub inner: Inner,
    /// The security extension state.
    pub security: SecurityState<GRP, GO>,
}

/// Persisted config for the composed extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "InnerConfig: Serialize",
    deserialize = "InnerConfig: serde::de::DeserializeOwned"
))]
pub struct SecureExtensionConfig<InnerConfig: ExtensionConfig> {
    /// Medium-specific persisted config.
    pub inner: InnerConfig,
    /// Security persisted config.
    pub security: SecurityExtensionConfig,
}

impl<InnerConfig: ExtensionConfig> Default for SecureExtensionConfig<InnerConfig> {
    fn default() -> Self {
        Self {
            inner: InnerConfig::default(),
            security: SecurityExtensionConfig::default(),
        }
    }
}

impl<InnerConfig: ExtensionConfig> ExtensionConfig for SecureExtensionConfig<InnerConfig> {}

impl<Inner: ExtensionState, const GRP: usize, const GO: usize> ExtensionState
    for SecureExtensionState<Inner, GRP, GO>
{
    type Config = SecureExtensionConfig<Inner::Config>;

    fn from_config(config: Self::Config) -> Self {
        Self {
            inner: Inner::from_config(config.inner),
            security: SecurityState::from_config(config.security),
        }
    }

    fn to_config(&self) -> Self::Config {
        SecureExtensionConfig {
            inner: self.inner.to_config(),
            security: self.security.to_config(),
        }
    }

    fn factory_reset(&self) {
        self.inner.factory_reset();
        self.security.factory_reset();
    }
}

// ============================================================================
// Extension trait — produces (inner_augment, SecurityAugment) tuple
// ============================================================================

impl<Inner, Platform, const GRP: usize, const GO: usize> Extension<Platform>
    for SecureExtensionState<Inner, GRP, GO>
where
    Inner: Extension<Platform>,
{
    type Augment<'a, S: StackState>
        = (Inner::Augment<'a, S>, SecurityAugment<'a, GRP, GO>)
    where
        Self: 'a,
        Platform: 'a;

    fn create_augment<'a, S: StackState>(
        &'a self,
        platform: &'a Platform,
    ) -> Self::Augment<'a, S>
    where
        Platform: 'a,
    {
        let inner_augment = self.inner.create_augment(platform);
        let security_augment = SecurityAugment::new(&self.security);
        (inner_augment, security_augment)
    }
}

// ============================================================================
// Type Aliases
// ============================================================================

/// TP1 extension state with Data Secure support.
pub type SecureTp1ExtensionState<const GRP: usize, const GO: usize> =
    SecureExtensionState<super::tp1::Tp1ExtensionState, GRP, GO>;

/// TP1 device state with Data Secure support.
pub type SecureTp1DeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P,
    const GRP: usize,
    const GO: usize,
> = crate::bcus::system_b::SystemBDeviceState<
    ADT_SIZE,
    AST_SIZE,
    COT_SIZE,
    P,
    SecureTp1ExtensionState<GRP, GO>,
>;

#[cfg(feature = "knxip")]
/// KNX/IP extension state with Data Secure support.
pub type SecureIpExtensionState<
    const N: usize,
    const CAPS: u16,
    const GRP: usize,
    const GO: usize,
> = SecureExtensionState<super::ip::IpExtensionState<N, CAPS>, GRP, GO>;
