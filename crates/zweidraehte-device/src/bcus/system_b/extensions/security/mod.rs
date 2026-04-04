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
//! SecureExtensionState<Tp1ExtensionState, 64, 8, 32>
//!   ├── inner: Tp1ExtensionState           (medium-specific state)
//!   └── security: SecurityState<64, 8, 32> (security tables + mode)
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
use crate::bcus::system_b::{Extension, ExtensionConfig, ExtensionState, HasSecurityMode};
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
/// Contains scalar fields and the security failures log.
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
    /// Security failures log — spec (03/05/01 §6.3.9.2) requires it to
    /// be saved at power-down and restored at power-up.
    #[serde(default)]
    pub failures_log: SecurityFailuresLog,
}

fn default_tool_key() -> [u8; 16] {
    [0u8; 16]
}

fn default_load_state() -> LoadState {
    LoadState::Unloaded
}

impl Default for SecurityExtensionConfig {
    fn default() -> Self {
        Self {
            security_mode_enabled: false,
            tool_key: [0u8; 16],
            load_state: LoadState::Unloaded,
            failures_log: SecurityFailuresLog::default(),
        }
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
pub struct SecurityState<const GRP: usize, const P2P: usize, const GO: usize> {
    security_mode_enabled: Cell<bool>,
    tool_key: Cell<[u8; 16]>,
    load_state: Cell<LoadState>,
    /// Group key table: GA_index(2) + key(16) = 18 bytes per entry.
    grp_keys: RefCell<SecurityTable<GRP, 18>>,
    /// P2P key table: IA_index(2) + key(16) + role(2) = 20 bytes per entry.
    p2p_keys: RefCell<SecurityTable<P2P, 20>>,
    /// GO security flags: 1 byte per group object.
    go_flags: RefCell<SecurityTable<GO, 1>>,
    /// Security failures log — counters and recent failure entries.
    failures_log: RefCell<SecurityFailuresLog>,
    /// PID_SECURITY_REPORT (57): 1-byte security status bitfield.
    security_report: Cell<u8>,
    /// PID_SECURITY_REPORT_CONTROL (58): whether security reporting is enabled.
    security_report_enabled: Cell<bool>,
}

// ============================================================================
// Security Failures Log
// ============================================================================

/// Security failure type indices (per spec 03/03/07 section 5.4).
///
/// Each type has its own 1-byte counter in the failures log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityFailureType {
    /// Invalid SCF field (unsupported algorithm, reserved bits set).
    ScfError = 0,
    /// Sequence number check failed (replay or out-of-order).
    SeqNrError = 1,
    /// MAC verification failed (wrong key or tampered message).
    CryptoError = 2,
    /// Access denied by access policy after successful verification.
    AccessError = 3,
    /// Sender not found in Security Individual Address Table.
    RoleError = 4,
    /// Other / unspecified failure.
    Other5 = 5,
    Other6 = 6,
    Other7 = 7,
}

/// A single failure log entry recording a security event.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SecurityFailureEntry {
    /// Failure type.
    pub failure_type: u8,
    /// Source individual address of the offending message.
    pub source_addr: u16,
}

/// Security failures log with 8 type counters and a ring buffer of
/// recent failure entries.
///
/// Accessed via Function Property on PID 55:
/// - **StateRead(id=0, info=0)**: Returns 8 failure type counters.
/// - **StateRead(id=1, info=N)**: Returns the Nth most recent failure entry.
/// - **Command(id=0, info=0)**: Clears all counters and entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFailuresLog {
    /// Per-type failure counters (8 types, 1 byte each, saturating at 255).
    counters: [u8; 8],
    /// Ring buffer of recent failure entries.
    entries: [SecurityFailureEntry; 8],
    /// Write index into the ring buffer.
    write_idx: u8,
    /// Number of entries stored (capped at 8).
    count: u8,
}

impl Default for SecurityFailuresLog {
    fn default() -> Self {
        Self { counters: [0; 8], entries: [SecurityFailureEntry::default(); 8], write_idx: 0, count: 0 }
    }
}

impl SecurityFailuresLog {
    /// Record a security failure.
    pub fn log_failure(&mut self, failure_type: SecurityFailureType, source_addr: u16) {
        // Increment the counter for this failure type (saturating).
        let idx = failure_type as usize;
        if idx < 8 {
            self.counters[idx] = self.counters[idx].saturating_add(1);
        }

        // Add to ring buffer.
        let entry = SecurityFailureEntry { failure_type: failure_type as u8, source_addr };
        self.entries[self.write_idx as usize] = entry;
        self.write_idx = (self.write_idx + 1) % 8;
        if self.count < 8 {
            self.count += 1;
        }
    }

    /// Get the 8-byte failure counters.
    pub fn counters(&self) -> &[u8; 8] {
        &self.counters
    }

    /// Get a failure entry by reverse index (0 = most recent).
    pub fn get_by_index(&self, index: u8) -> Option<&SecurityFailureEntry> {
        if index >= self.count {
            return None;
        }
        // Most recent is at (write_idx - 1), second most recent at (write_idx - 2), etc.
        let actual = (self.write_idx as i16 - 1 - index as i16).rem_euclid(8) as usize;
        Some(&self.entries[actual])
    }

    /// Clear all counters and entries.
    pub fn clear(&mut self) {
        self.counters = [0; 8];
        self.count = 0;
        self.write_idx = 0;
    }
}

impl<const GRP: usize, const P2P: usize, const GO: usize> SecurityState<GRP, P2P, GO> {
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

    /// Get a reference to the P2P key table.
    pub fn p2p_keys(&self) -> &RefCell<SecurityTable<P2P, 20>> {
        &self.p2p_keys
    }

    /// Get a reference to the GO security flags table.
    pub fn go_flags(&self) -> &RefCell<SecurityTable<GO, 1>> {
        &self.go_flags
    }

    /// Look up a group key by 1-based group address table index.
    ///
    /// Uses binary search — the spec (03/05/01 §6.3.7.2) requires the
    /// table to be sorted by GA_Index ascending, and §6.3.7.3 requires
    /// the MaC (ETS) to maintain this order.
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

    /// Get a reference to the security failures log.
    pub fn failures_log(&self) -> &RefCell<SecurityFailuresLog> {
        &self.failures_log
    }

    /// Look up GO security flags by 0-based group object index.
    pub fn go_security_flags_for(&self, go_index: u16) -> Option<u8> {
        let table = self.go_flags.borrow();
        table.get(go_index).map(|entry| entry[0])
    }

    /// Get the security report value (PID 57).
    pub fn security_report(&self) -> u8 {
        self.security_report.get()
    }

    /// Set the security report value (PID 57).
    pub fn set_security_report(&self, value: u8) {
        self.security_report.set(value);
    }

    /// Whether security reporting is enabled (PID 58).
    pub fn security_report_enabled(&self) -> bool {
        self.security_report_enabled.get()
    }

    /// Enable or disable security reporting (PID 58).
    pub fn set_security_report_enabled(&self, enabled: bool) {
        self.security_report_enabled.set(enabled);
    }
}

// ============================================================================
// HasSecurityState — trait for accessing security state without const generics
// ============================================================================

/// Trait for device states that have KNX Data Secure support.
///
/// Provides access to security keys and flags without exposing the
/// const-generic table sizes. The S-AL layer requires this trait on
/// `D::State` to look up keys for decryption/encryption.
///
/// Implemented automatically for [`SystemBDeviceState`] when the extension
/// state is [`SecureExtensionState`].
///
/// [`SystemBDeviceState`]: crate::bcus::system_b::SystemBDeviceState
pub trait HasSecurityState {
    /// Whether the device's Security Mode is currently enabled.
    fn security_mode_enabled(&self) -> bool;

    /// Get the 16-byte tool key.
    fn tool_key(&self) -> [u8; 16];

    /// Look up a group key by 1-based group address table index.
    fn group_key_for_index(&self, ga_index: u16) -> Option<[u8; 16]>;

    /// Look up GO security flags by 0-based group object index.
    fn go_security_flags_for(&self, go_index: u16) -> Option<u8>;

    /// Record a security failure in the failures log.
    fn log_security_failure(&self, failure_type: SecurityFailureType, source_addr: u16);

    /// Get the 8-byte failure counters.
    fn failure_counters(&self) -> [u8; 8];

    /// Get a failure entry by reverse index (0 = most recent).
    fn failure_entry(&self, index: u8) -> Option<SecurityFailureEntry>;

    /// Clear all failure counters and entries.
    fn clear_failure_log(&self);
}

/// Blanket impl: any `SecurityState<GRP, P2P, GO>` implements `HasSecurityState`.
impl<const GRP: usize, const P2P: usize, const GO: usize> HasSecurityState for SecurityState<GRP, P2P, GO> {
    fn security_mode_enabled(&self) -> bool {
        self.security_mode_enabled()
    }

    fn tool_key(&self) -> [u8; 16] {
        self.tool_key()
    }

    fn group_key_for_index(&self, ga_index: u16) -> Option<[u8; 16]> {
        self.group_key_for_index(ga_index)
    }

    fn go_security_flags_for(&self, go_index: u16) -> Option<u8> {
        self.go_security_flags_for(go_index)
    }

    fn log_security_failure(&self, failure_type: SecurityFailureType, source_addr: u16) {
        self.failures_log.borrow_mut().log_failure(failure_type, source_addr);
    }

    fn failure_counters(&self) -> [u8; 8] {
        *self.failures_log.borrow().counters()
    }

    fn failure_entry(&self, index: u8) -> Option<SecurityFailureEntry> {
        self.failures_log.borrow().get_by_index(index).copied()
    }

    fn clear_failure_log(&self) {
        self.failures_log.borrow_mut().clear();
    }
}

impl<const GRP: usize, const P2P: usize, const GO: usize> ExtensionState for SecurityState<GRP, P2P, GO> {
    type Config = SecurityExtensionConfig;

    fn from_config(config: SecurityExtensionConfig) -> Self {
        Self {
            security_mode_enabled: Cell::new(config.security_mode_enabled),
            tool_key: Cell::new(config.tool_key),
            load_state: Cell::new(config.load_state),
            // Tables start empty — ETS reloads them via property writes.
            grp_keys: RefCell::new(SecurityTable::new()),
            p2p_keys: RefCell::new(SecurityTable::new()),
            go_flags: RefCell::new(SecurityTable::new()),
            failures_log: RefCell::new(config.failures_log),
            security_report: Cell::new(0),
            security_report_enabled: Cell::new(false),
        }
    }

    fn to_config(&self) -> SecurityExtensionConfig {
        SecurityExtensionConfig {
            security_mode_enabled: self.security_mode_enabled.get(),
            tool_key: self.tool_key.get(),
            load_state: self.load_state.get(),
            failures_log: self.failures_log.borrow().clone(),
        }
    }

    fn factory_reset(&self) {
        self.security_mode_enabled.set(false);
        self.tool_key.set([0u8; 16]);
        self.load_state.set(LoadState::Unloaded);
        self.grp_keys.borrow_mut().clear();
        self.go_flags.borrow_mut().clear();
        self.failures_log.borrow_mut().clear();
    }
}

impl<const GRP: usize, const P2P: usize, const GO: usize> HasSecurityMode for SecurityState<GRP, P2P, GO> {
    fn security_mode_enabled(&self) -> bool {
        self.security_mode_enabled.get()
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
pub struct SecureExtensionState<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> {
    /// The medium-specific extension state.
    pub inner: Inner,
    /// The security extension state.
    pub security: SecurityState<GRP, P2P, GO>,
}

/// `SecureExtensionState` delegates `HasSecurityState` to its inner
/// `SecurityState`, so that `SystemBDeviceState` with a secure extension
/// can satisfy `HasSecurityState` through `HasExtensionState`.
impl<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> HasSecurityState
    for SecureExtensionState<Inner, GRP, P2P, GO>
{
    fn security_mode_enabled(&self) -> bool {
        self.security.security_mode_enabled()
    }

    fn tool_key(&self) -> [u8; 16] {
        self.security.tool_key()
    }

    fn group_key_for_index(&self, ga_index: u16) -> Option<[u8; 16]> {
        self.security.group_key_for_index(ga_index)
    }

    fn go_security_flags_for(&self, go_index: u16) -> Option<u8> {
        self.security.go_security_flags_for(go_index)
    }

    fn log_security_failure(&self, failure_type: SecurityFailureType, source_addr: u16) {
        self.security.failures_log.borrow_mut().log_failure(failure_type, source_addr);
    }

    fn failure_counters(&self) -> [u8; 8] {
        *self.security.failures_log.borrow().counters()
    }

    fn failure_entry(&self, index: u8) -> Option<SecurityFailureEntry> {
        self.security.failures_log.borrow().get_by_index(index).copied()
    }

    fn clear_failure_log(&self) {
        self.security.failures_log.borrow_mut().clear();
    }
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

impl<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> ExtensionState
    for SecureExtensionState<Inner, GRP, P2P, GO>
{
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

impl<Inner: ExtensionState, const GRP: usize, const P2P: usize, const GO: usize> HasSecurityMode
    for SecureExtensionState<Inner, GRP, P2P, GO>
{
    fn security_mode_enabled(&self) -> bool {
        self.security.security_mode_enabled()
    }
}

// ============================================================================
// Extension trait — produces (inner_augment, SecurityAugment) tuple
// ============================================================================

impl<Inner, Platform, const GRP: usize, const P2P: usize, const GO: usize> Extension<Platform>
    for SecureExtensionState<Inner, GRP, P2P, GO>
where
    Inner: Extension<Platform>,
{
    type Augment<'a, S: StackState>
        = (Inner::Augment<'a, S>, SecurityAugment<'a, GRP, P2P, GO>)
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
pub type SecureTp1ExtensionState<const GRP: usize, const P2P: usize, const GO: usize> =
    SecureExtensionState<super::tp1::Tp1ExtensionState, GRP, P2P, GO>;

/// TP1 device state with Data Secure support.
///
/// `GRP` (group key table size) and `GO` (GO security flags table size)
/// are derived from `ADT_SIZE` and `COT_SIZE` respectively, since the
/// group key table is indexed by GA index (one per address table entry)
/// and the GO flags table has one entry per communication object.
pub type SecureTp1DeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P,
    const P2P: usize,
> = crate::bcus::system_b::SystemBDeviceState<
    ADT_SIZE,
    AST_SIZE,
    COT_SIZE,
    P,
    SecureTp1ExtensionState<ADT_SIZE, P2P, COT_SIZE>,
>;

#[cfg(feature = "knxip")]
/// KNX/IP extension state with Data Secure support.
pub type SecureIpExtensionState<const N: usize, const CAPS: u16, const GRP: usize, const P2P: usize, const GO: usize> =
    SecureExtensionState<super::ip::IpExtensionState<N, CAPS>, GRP, P2P, GO>;

#[cfg(feature = "knxip")]
/// KNX/IP device state with Data Secure support.
///
/// Like [`SecureTp1DeviceState`], `GRP` and `GO` are derived from
/// `ADT_SIZE` and `COT_SIZE`. Only `P2P` and the IP-specific `N`
/// (max tunnelling connections) and `CAPS` (capability flags) remain
/// as independent parameters.
pub type SecureIpDeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    P,
    const P2P: usize,
    const N: usize,
    const CAPS: u16,
> = crate::bcus::system_b::SystemBDeviceState<
    ADT_SIZE,
    AST_SIZE,
    COT_SIZE,
    P,
    SecureIpExtensionState<N, CAPS, ADT_SIZE, P2P, COT_SIZE>,
>;
