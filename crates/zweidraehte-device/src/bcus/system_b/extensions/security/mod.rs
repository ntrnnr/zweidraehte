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

use core::cell::{Cell, RefCell};

use serde::{Deserialize, Serialize};

use crate::StackState;
use crate::bcus::system_b::{Extension, ExtensionConfig, ExtensionState};
use crate::objects::tables::LoadState;

// ============================================================================
// SecurityTable — const-generic fixed-capacity table
// ============================================================================

/// Fixed-capacity table for security data (group keys, GO security flags).
///
/// Each entry is `ENTRY_SIZE` bytes. Up to `N` entries can be stored.
/// This type is `no_alloc`-compatible — all storage is inline.
///
/// Written by ETS during configuration (via the load state machine),
/// read by the S-AL at runtime for key lookup and GO flag checks.
#[derive(Clone)]
pub struct SecurityTable<const N: usize, const ENTRY_SIZE: usize> {
    /// Entry data. Only entries `0..count` are valid.
    pub(crate) data: [[u8; ENTRY_SIZE]; N],
    count: u16,
}

impl<const N: usize, const ENTRY_SIZE: usize> SecurityTable<N, ENTRY_SIZE> {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self { data: [[0u8; ENTRY_SIZE]; N], count: 0 }
    }

    /// Current number of entries.
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Get entry at 0-based index, or `None` if out of range.
    pub fn get(&self, index: u16) -> Option<&[u8; ENTRY_SIZE]> {
        if index < self.count { Some(&self.data[index as usize]) } else { None }
    }

    /// Read a range of entries into a byte buffer.
    ///
    /// `start` is 0-based. Returns the number of bytes written, or an
    /// error if `start` is out of range or `buf` is too small.
    pub fn read_entries(
        &self,
        start: u16,
        count: u16,
        buf: &mut [u8],
    ) -> Result<usize, crate::objects::interface::PropertyError> {
        use crate::objects::interface::PropertyError;

        if start >= self.count {
            return Err(PropertyError::InvalidStartIndex);
        }
        let end = ((start + count) as usize).min(self.count as usize);
        let actual = end - start as usize;
        let byte_count = actual * ENTRY_SIZE;
        if buf.len() < byte_count {
            return Err(PropertyError::BufferTooSmall);
        }
        for (i, idx) in (start as usize..end).enumerate() {
            let offset = i * ENTRY_SIZE;
            buf[offset..offset + ENTRY_SIZE].copy_from_slice(&self.data[idx]);
        }
        Ok(byte_count)
    }

    /// Write entries from a byte buffer, replacing existing data.
    ///
    /// `start` is 0-based. `data` must be a multiple of `ENTRY_SIZE`.
    /// Validates that the write stays within table capacity and that
    /// the data length is aligned to the entry size.
    pub fn write_entries(&mut self, start: u16, data: &[u8]) -> Result<(), crate::objects::interface::PropertyError> {
        use crate::objects::interface::PropertyError;

        if data.is_empty() {
            return Ok(()); // Nothing to write.
        }
        if data.len() % ENTRY_SIZE != 0 {
            return Err(PropertyError::TypeMismatch);
        }
        let entry_count = data.len() / ENTRY_SIZE;
        let end = start as usize + entry_count;
        if end > N {
            return Err(PropertyError::InvalidStartIndex);
        }
        for i in 0..entry_count {
            let src_offset = i * ENTRY_SIZE;
            self.data[start as usize + i].copy_from_slice(&data[src_offset..src_offset + ENTRY_SIZE]);
        }
        // Update count if we wrote past the current end.
        if end as u16 > self.count {
            self.count = end as u16;
        }
        Ok(())
    }

    /// Clear all entries (reset count to 0).
    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Set the element count directly (for load state machine use).
    pub fn set_count(&mut self, count: u16) {
        self.count = count.min(N as u16);
    }

    /// View active entries as a flat byte slice.
    ///
    /// Returns `count * ENTRY_SIZE` bytes covering entries `0..count`.
    pub fn as_flat_bytes(&self) -> &[u8] {
        let byte_count = self.count as usize * ENTRY_SIZE;
        // The data is [[u8; ENTRY_SIZE]; N], which is contiguous in memory.
        let ptr = self.data.as_ptr() as *const u8;
        // Safety: `byte_count <= N * ENTRY_SIZE`, and the layout of
        // `[[u8; ENTRY_SIZE]; N]` is contiguous bytes.
        unsafe { core::slice::from_raw_parts(ptr, byte_count) }
    }
}

// SecurityTable serialization is handled by SecurityExtensionConfig,
// which stores the table data inline as fixed arrays. The SecurityState
// runtime type uses RefCell<SecurityTable<N, ES>> for interior mutability.

// ============================================================================
// Persisted Config
// ============================================================================

/// Persisted security extension configuration.
///
/// Contains only scalar fields — security mode, tool key, and load state.
/// Security table data (group keys, GO flags) is loaded by ETS through
/// property writes during the configuration phase and is NOT persisted
/// in this config. After a power cycle, the load state will be
/// `Unloaded` and ETS must reload the tables.
///
/// Sequence numbers are stored separately via [`SequenceNumberStorage`]
/// due to their high write frequency.
///
/// [`SequenceNumberStorage`]: crate::storage::SequenceNumberStorage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityExtensionConfig {
    #[serde(default)]
    pub security_mode_enabled: bool,
    #[serde(default = "default_tool_key")]
    pub tool_key: [u8; 16],
    #[serde(default = "default_load_state")]
    pub load_state: LoadState,
}

fn default_tool_key() -> [u8; 16] {
    [0u8; 16]
}

fn default_load_state() -> LoadState {
    LoadState::Unloaded
}

impl Default for SecurityExtensionConfig {
    fn default() -> Self {
        Self { security_mode_enabled: false, tool_key: [0u8; 16], load_state: LoadState::Unloaded }
    }
}

impl ExtensionConfig for SecurityExtensionConfig {}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime security state with interior mutability.
///
/// Holds security mode, tool key, load state, group key table, and
/// GO security flags. Table data is behind `RefCell` for interior
/// mutability during property writes.
pub struct SecurityState<const GRP: usize, const GO: usize> {
    security_mode_enabled: Cell<bool>,
    tool_key: Cell<[u8; 16]>,
    load_state: Cell<LoadState>,
    /// Group key table: GA_index(2) + key(16) = 18 bytes per entry.
    grp_keys: RefCell<SecurityTable<GRP, 18>>,
    /// GO security flags: 1 byte per group object.
    go_flags: RefCell<SecurityTable<GO, 1>>,
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
    pub fn load_state(&self) -> LoadState {
        self.load_state.get()
    }

    /// Set the load state.
    pub fn set_load_state(&self, state: LoadState) {
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

    /// Get a reference to the group key table.
    pub fn grp_keys(&self) -> &RefCell<SecurityTable<GRP, 18>> {
        &self.grp_keys
    }

    /// Get a reference to the GO security flags table.
    pub fn go_flags(&self) -> &RefCell<SecurityTable<GO, 1>> {
        &self.go_flags
    }

    /// Look up a group key by 1-based group address table index.
    ///
    /// The group key table is sorted by GA index (ascending) as written
    /// by ETS, so we use binary search for O(log n) lookup.
    ///
    /// TODO: Verify with the spec (03/05/01) that ETS always writes
    /// entries in ascending GA index order. The Thelsing reference
    /// implementation uses early exit on `index > addressIndex` which
    /// implies sorted order, but this should be confirmed.
    ///
    /// Returns the 16-byte key if found, or `None` if the index is
    /// not in the group key table.
    pub fn group_key_for_index(&self, ga_index: u16) -> Option<[u8; 16]> {
        let table = self.grp_keys.borrow();
        let count = table.count() as usize;

        // Binary search over sorted entries.
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = &table.data[mid];
            let stored_index = u16::from_be_bytes([entry[0], entry[1]]);
            match stored_index.cmp(&ga_index) {
                core::cmp::Ordering::Equal => {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&entry[2..18]);
                    return Some(key);
                }
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Look up GO security flags by 0-based group object index.
    pub fn go_security_flags_for(&self, go_index: u16) -> Option<u8> {
        let table = self.go_flags.borrow();
        table.get(go_index).map(|entry| entry[0])
    }
}

impl<const GRP: usize, const GO: usize> ExtensionState for SecurityState<GRP, GO> {
    type Config = SecurityExtensionConfig;

    fn from_config(config: SecurityExtensionConfig) -> Self {
        Self {
            security_mode_enabled: Cell::new(config.security_mode_enabled),
            tool_key: Cell::new(config.tool_key),
            load_state: Cell::new(config.load_state),
            // Tables start empty — ETS reloads them via property writes.
            grp_keys: RefCell::new(SecurityTable::new()),
            go_flags: RefCell::new(SecurityTable::new()),
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
        self.load_state.set(LoadState::Unloaded);
        self.grp_keys.borrow_mut().clear();
        self.go_flags.borrow_mut().clear();
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
#[serde(bound(serialize = "InnerConfig: Serialize", deserialize = "InnerConfig: serde::de::DeserializeOwned"))]
pub struct SecureExtensionConfig<InnerConfig: ExtensionConfig> {
    /// Medium-specific persisted config.
    pub inner: InnerConfig,
    /// Security persisted config.
    pub security: SecurityExtensionConfig,
}

impl<InnerConfig: ExtensionConfig> Default for SecureExtensionConfig<InnerConfig> {
    fn default() -> Self {
        Self { inner: InnerConfig::default(), security: SecurityExtensionConfig::default() }
    }
}

impl<InnerConfig: ExtensionConfig> ExtensionConfig for SecureExtensionConfig<InnerConfig> {}

impl<Inner: ExtensionState, const GRP: usize, const GO: usize> ExtensionState for SecureExtensionState<Inner, GRP, GO> {
    type Config = SecureExtensionConfig<Inner::Config>;

    fn from_config(config: Self::Config) -> Self {
        Self { inner: Inner::from_config(config.inner), security: SecurityState::from_config(config.security) }
    }

    fn to_config(&self) -> Self::Config {
        SecureExtensionConfig { inner: self.inner.to_config(), security: self.security.to_config() }
    }

    fn factory_reset(&self) {
        self.inner.factory_reset();
        self.security.factory_reset();
    }
}

// ============================================================================
// Extension trait — produces (inner_augment, SecurityAugment) tuple
// ============================================================================

impl<Inner, Platform, const GRP: usize, const GO: usize> Extension<Platform> for SecureExtensionState<Inner, GRP, GO>
where
    Inner: Extension<Platform>,
{
    type Augment<'a, S: StackState>
        = (Inner::Augment<'a, S>, SecurityAugment<'a, GRP, GO>)
    where
        Self: 'a,
        Platform: 'a;

    fn create_augment<'a, S: StackState>(&'a self, platform: &'a Platform) -> Self::Augment<'a, S>
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
> = crate::bcus::system_b::SystemBDeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, P, SecureTp1ExtensionState<GRP, GO>>;

#[cfg(feature = "knxip")]
/// KNX/IP extension state with Data Secure support.
pub type SecureIpExtensionState<const N: usize, const CAPS: u16, const GRP: usize, const GO: usize> =
    SecureExtensionState<super::ip::IpExtensionState<N, CAPS>, GRP, GO>;
