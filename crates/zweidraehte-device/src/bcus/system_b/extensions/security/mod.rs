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
//!   SecureAugmentBundle {
//!       inner:    Inner::Augment<'a, D>,    (e.g. &Tp1ExtensionState)
//!       security: SecurityAugment<'a, …>,
//!   }
//! ```
//!
//! `SecureAugmentBundle` is a `#[derive(ServiceRegistry)]` struct, so
//! it implements [`Augment<D>`](crate::service::Augment)
//! directly via the macro-emitted forwarding chain. Devices that don't
//! compose any extra augments can spell `type Augments<'a> = <Self::ES
//! as Extension<Self::Platform>>::Augment<'a, Self>` and let the runner
//! call `state.extension_state().create_augment::<Self>(platform)`.
//!
//! # Const Generics
//!
//! - `GRP`: Max Group Key Table entries (typically matches association table size)
//! - `P2P`: Max P2P Key Table entries (zero for group-only secure devices)
//! - `GO`: Max GO security flag entries (typically matches communication object count)
//!
//! The Security Individual Address Table is **not** a const generic on the
//! secure extension. Its capacity is the `N` of the
//! [`SiatStore`](crate::kvstore::SiatStore) chosen for the `SEQ` type parameter
//! — the SIAT is the sequence store (one LastValidSeqNr slot per non-tool secure
//! sender IA, 03/03/07 §5.3), not a separate table.

mod augment;

pub use augment::SecurityAugment;
// Array-property read/write helpers shared with the IP Secure augment
// (PIDs 93/97 use the same SecurityTable count semantics).
#[cfg(feature = "ip-secure")]
pub(in crate::bcus::system_b::extensions) use augment::{read_table_with_count_probe, write_security_table};
use zweidraehte_proto::messages::knx::RequiredSecurity;

use core::cell::{Cell, RefCell};

use serde::{Deserialize, Serialize};

use crate::HasSecurityMode;
use crate::StackDefinition;
use crate::bcus::system_b::{
    Extension, ExtensionConfig, ExtensionState, RfExtensionState, RfRetransmitterExtension, SystemBDeviceState,
    Tp1ExtensionState,
};
use crate::kvstore::SiatAccess;
use crate::logging::debug;
use crate::objects::comm::HasGoSecurityView;
use crate::objects::interface::{
    HasDomainAddress, HasMaxRetryCount, HasRfDomainAddress, HasRfRetransmitter, PropertyError,
};
use crate::objects::tables::LoadState;
use crate::restart::EraseCode;
use crate::state::{HasSecurityState, SecurityFailureEntry, SecurityFailureType};
use crate::storage::{HasSeqStorage, SequenceNumberStorage};

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
///
/// # Key redaction
///
/// The `Debug` impl prints entry counts only and never the raw entry bytes
/// to prevent AES key material from appearing in logs. The `Serialize` and
/// `Deserialize` impls are unaffected — persistence requires real bytes.
#[serde_with::serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityTable<const N: usize, const ENTRY_SIZE: usize> {
    /// Entry data. Only entries `0..count` are valid.
    #[serde_as(as = "[[_; ENTRY_SIZE]; N]")]
    pub(crate) data: [[u8; ENTRY_SIZE]; N],
    count: u16,
}

impl<const N: usize, const ENTRY_SIZE: usize> core::fmt::Debug for SecurityTable<N, ENTRY_SIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Entry data is never shown — it may contain AES key material.
        f.debug_struct("SecurityTable")
            .field("capacity", &N)
            .field("entry_size", &ENTRY_SIZE)
            .field("count", &self.count)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl<const N: usize, const ENTRY_SIZE: usize> Default for SecurityTable<N, ENTRY_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const ENTRY_SIZE: usize> SecurityTable<N, ENTRY_SIZE> {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self { data: [[0u8; ENTRY_SIZE]; N], count: 0 }
    }

    /// Create a table from pre-built entry data and a count.
    ///
    /// Useful for compile-time construction in `knx_stack_config!`.
    /// Entries `0..count` are considered valid; the rest are zero-filled.
    pub const fn from_entries(data: [[u8; ENTRY_SIZE]; N], count: u16) -> Self {
        Self { data, count }
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
    pub fn read_entries(&self, start: u16, count: u16, buf: &mut [u8]) -> Result<usize, PropertyError> {
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
    pub fn write_entries(&mut self, start: u16, data: &[u8]) -> Result<(), PropertyError> {
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
    ///
    /// Also zeroes the backing storage: entries hold key material, and
    /// the full `data` array — not just the active prefix — is what the
    /// persisted config serializes. Stale keys must not survive a clear.
    pub fn clear(&mut self) {
        self.data = [[0u8; ENTRY_SIZE]; N];
        self.count = 0;
    }

    /// Set the element count directly (for load state machine use).
    ///
    /// Zeroes any entries dropped by a shrinking count — same key-material
    /// rationale as [`clear()`](Self::clear): the serialized config carries
    /// the whole `data` array, so truncated entries must not leak old keys
    /// into storage.
    pub fn set_count(&mut self, count: u16) {
        let count = count.min(N as u16);
        for entry in self.data[count as usize..].iter_mut() {
            *entry = [0u8; ENTRY_SIZE];
        }
        self.count = count;
    }

    /// View active entries as a flat byte slice.
    ///
    /// Returns `count * ENTRY_SIZE` bytes covering entries `0..count`.
    pub fn as_flat_bytes(&self) -> &[u8] {
        self.data[..self.count as usize].as_flattened()
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
/// Contains scalar fields, security tables (P2P keys, group keys, GO
/// flags), and the security failures log. Tables persist across
/// Confirmed and Basic restarts per spec (03/05/01 §6.3.6-§6.3.15).
///
/// Sequence numbers are stored separately via [`SequenceNumberStorage`]
/// due to their high write frequency.
///
/// # Key redaction
///
/// The `Debug` impl omits the `tool_key` bytes and delegates table display
/// to `SecurityTable`'s redacted `Debug` impl. `Serialize`/`Deserialize`
/// are unaffected.
///
/// [`SequenceNumberStorage`]: crate::storage::SequenceNumberStorage
#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityExtensionConfig<const GRP: usize, const P2P: usize, const GO: usize> {
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
    /// Group key table: GA_Index(2) + Key(16) = 18 bytes per entry.
    #[serde(default)]
    pub grp_keys: SecurityTable<GRP, 18>,
    /// P2P key table: IA_Index(2) + Key(16) + Roles(2) = 20 bytes per entry.
    ///
    /// Sized by `P2P`. Independent of `SIAT`: the P2P Key Table only
    /// carries an entry when this device has a secure P2P link with
    /// the partner (03/05/01 §6.3.6 NOTE 98); the SIAT by contrast
    /// carries every secure-sender IA — group senders included.
    #[serde(default)]
    pub p2p_keys: SecurityTable<P2P, 20>,
    /// GO security flags: 1 byte per group object.
    #[serde(default)]
    pub go_flags: SecurityTable<GO, 1>,
}

impl<const GRP: usize, const P2P: usize, const GO: usize> core::fmt::Debug for SecurityExtensionConfig<GRP, P2P, GO> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The tool_key field is AES-128 key material — never print raw bytes.
        f.debug_struct("SecurityExtensionConfig")
            .field("security_mode_enabled", &self.security_mode_enabled)
            .field("tool_key", &"[REDACTED]")
            .field("load_state", &self.load_state)
            .field("failures_log", &self.failures_log)
            .field("grp_keys", &self.grp_keys)
            .field("p2p_keys", &self.p2p_keys)
            .field("go_flags", &self.go_flags)
            .finish()
    }
}

// These exist as functions (not consts) because `#[serde(default = "…")]`
// can only name a function path.
fn default_tool_key() -> [u8; 16] {
    [0u8; 16]
}

fn default_load_state() -> LoadState {
    LoadState::Unloaded
}

impl<const GRP: usize, const P2P: usize, const GO: usize> Default for SecurityExtensionConfig<GRP, P2P, GO> {
    fn default() -> Self {
        Self {
            security_mode_enabled: false,
            tool_key: [0u8; 16],
            load_state: LoadState::Unloaded,
            failures_log: SecurityFailuresLog::default(),
            grp_keys: SecurityTable::new(),
            p2p_keys: SecurityTable::new(),
            go_flags: SecurityTable::new(),
        }
    }
}

impl<const GRP: usize, const P2P: usize, const GO: usize> ExtensionConfig for SecurityExtensionConfig<GRP, P2P, GO> {}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime security state with interior mutability.
///
/// Holds security mode, tool key, load state, the group-key, P2P-key, and
/// GO-security-flag tables. Table data is behind `RefCell` for interior
/// mutability during property writes.
///
/// The `from_config`/`to_config` glue is hand-written rather than using
/// `#[derive(ExtensionState)]` because `SecurityState` is not itself an
/// `ExtensionState` — it is embedded inside [`SecureExtensionState`], which is
/// the top-level extension the derive applies to (and which seeds the FDSK in
/// its own `from_config`).
pub struct SecurityState<const GRP: usize, const P2P: usize, const GO: usize> {
    security_mode_enabled: Cell<bool>,
    /// Active tool key. The KNX spec defines this as the negotiated key
    /// for the current MaC↔BDUT session. On a fresh device or after a
    /// factory reset it equals the FDSK supplied by `DeviceIdentity`;
    /// `SystemBDeviceState::new` and `SystemBDeviceState::factory_reset`
    /// seed it from `identity.fdsk()`. Once the MaC writes
    /// `PID_TOOL_KEY` the negotiated value lives here exclusively.
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

/// Security failures log with 4 × 16-bit counters and a ring buffer
/// of recent failure entries.
///
/// Accessed via Function Property on PID 55:
/// - **StateRead(id=0, info=0)**: Returns 4 × 2-byte BE counters (8 bytes).
/// - **StateRead(id=1, info=N)**: Returns the Nth most recent 12-byte entry.
/// - **Command(id=0, info=0)**: Clears all counters and entries.
///
/// Counter layout (4 counters, each 16-bit big-endian):
/// - \[0\] SCF errors (type 0)
/// - \[1\] Crypto/MAC errors (type 1)
/// - \[2\] Sequence number errors (type 2)
/// - \[3\] Access + Role errors (types 3 and 4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFailuresLog {
    /// 4 × 16-bit failure counters (saturating at 0xFFFF).
    counters: [u16; 4],
    /// Ring buffer of recent failure entries.
    entries: [SecurityFailureEntry; 8],
    /// Write index into the ring buffer.
    write_idx: u8,
    /// Number of entries stored (capped at 8).
    count: u8,
}

impl Default for SecurityFailuresLog {
    fn default() -> Self {
        Self { counters: [0; 4], entries: [SecurityFailureEntry::default(); 8], write_idx: 0, count: 0 }
    }
}

impl SecurityFailureType {
    /// Map a failure type to its counter index (0–3).
    ///
    /// Types 0–2 map 1:1 to their respective counters. Types 3 (Role)
    /// and 4 (Access) both map to counter 3.
    fn counter_index(self) -> Option<usize> {
        match self as u8 {
            0..=2 => Some(self as usize),
            3 | 4 => Some(3),
            _ => None,
        }
    }
}

impl SecurityFailuresLog {
    /// Record a security failure.
    ///
    /// `frame_fragment` should be the first 9 bytes of the offending
    /// secure frame (zero-padded if shorter). These are stored in the
    /// entry for diagnostic purposes.
    pub fn log_failure(&mut self, failure_type: SecurityFailureType, source_addr: u16, frame_fragment: &[u8]) {
        // Increment the 16-bit counter for this failure type (saturating).
        if let Some(idx) = failure_type.counter_index() {
            self.counters[idx] = self.counters[idx].saturating_add(1);
        }

        // Build the 9-byte fragment (zero-padded if input is shorter).
        let mut frag = [0u8; 9];
        let copy_len = frame_fragment.len().min(9);
        frag[..copy_len].copy_from_slice(&frame_fragment[..copy_len]);

        // Add to ring buffer.
        let entry = SecurityFailureEntry { source_addr, frame_fragment: frag, failure_type: failure_type as u8 };
        self.entries[self.write_idx as usize] = entry;
        self.write_idx = (self.write_idx + 1) % 8;
        if self.count < 8 {
            self.count += 1;
        }
    }

    /// Get the 4 × 16-bit failure counters.
    pub fn counters(&self) -> &[u16; 4] {
        &self.counters
    }

    /// Serialize counters as 8 bytes (4 × big-endian u16).
    pub fn counters_as_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        for (i, &c) in self.counters.iter().enumerate() {
            buf[i * 2..i * 2 + 2].copy_from_slice(&c.to_be_bytes());
        }
        buf
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
        self.counters = [0; 4];
        self.count = 0;
        self.write_idx = 0;
    }

    /// Overwrite the four 16-bit counters directly. Used by the
    /// manufacturer-specific test PID (203) so the conformance suite can
    /// set them to a known value (typically FFFFh) before provoking
    /// errors to verify the saturating-add behaviour of `log_failure`.
    pub fn set_counters(&mut self, counters: [u16; 4]) {
        self.counters = counters;
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
        // First two and last two bytes make the change visible in the log
        // without leaking the full key. "was_empty=true" would only fire on
        // a device that hasn't been through `from_config` (never happens
        // in production) — on a fresh-boot device the tool_key is
        // pre-seeded to FDSK by the config path.
        #[allow(unused_variables)]
        let old = self.tool_key.get();
        #[allow(unused_variables)]
        let old_zero = old == [0u8; 16];
        debug!(
            "Security: set_tool_key old[0..2]={:02x}{:02x} new[0..2]={:02x}{:02x} old_was_zero={}",
            old[0], old[1], key[0], key[1], old_zero
        );
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

    /// Look up a P2P key by peer individual address.
    ///
    /// Linearly scans the P2P key table. Each entry is 20 bytes:
    /// IA_Index(2) + Key(16) + Roles(2). Returns the 16-byte key and
    /// the role bitmask (R0-R15) if a matching IA is found.
    pub fn p2p_key_for_ia(&self, peer_ia: u16) -> Option<([u8; 16], u16)> {
        let table = self.p2p_keys.borrow();
        let count = table.count() as usize;
        let peer_bytes = peer_ia.to_be_bytes();
        for i in 0..count {
            let entry = &table.data[i];
            if entry[0] == peer_bytes[0] && entry[1] == peer_bytes[1] {
                let mut key = [0u8; 16];
                key.copy_from_slice(&entry[2..18]);
                let roles = u16::from_be_bytes([entry[18], entry[19]]);
                return Some((key, roles));
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

    /// Clear PID_SECURITY_REPORT (57) and PID_SECURITY_REPORT_CONTROL (58).
    ///
    /// Per spec 03/05/01 sections 6.3.11-6.3.12, erase codes 02h, 06h, and
    /// 07h clear the report and set the control to "Disabled".
    pub fn clear_security_report(&self) {
        self.security_report.set(0);
        self.security_report_enabled.set(false);
    }

    /// Reset all security state to factory defaults except the active
    /// tool key, which the caller is expected to seed from
    /// `DeviceIdentity::fdsk()` (per spec 03/05/01 §6.1.4 the tool key
    /// reverts to the FDSK on factory reset). `SystemBDeviceState::
    /// factory_reset` drives this and the FDSK-write together so the
    /// state never ends up with a wiped tool key but no FDSK applied.
    pub fn factory_reset(&self) {
        self.security_mode_enabled.set(false);
        self.tool_key.set([0u8; 16]);
        self.load_state.set(LoadState::Unloaded);
        // Clear all security key tables together (03/05/01 §6.3.4 groups P2P
        // keys, group keys, and the SIAT as the security tables). The SIAT
        // lives in the sequence store and is cleared on its own erase path.
        self.grp_keys.borrow_mut().clear();
        self.p2p_keys.borrow_mut().clear();
        self.go_flags.borrow_mut().clear();
        self.failures_log.borrow_mut().clear();
        self.clear_security_report();
    }
}

// Inherent construction / conversion methods.
//
// `SecurityState` is never used as a top-level `ExtensionState` — it is
// always nested inside `SecureExtensionState`, and `HasSecurityState` is
// implemented on that wrapper directly (forwarding to the inherent
// methods below). Keeping these as inherent methods — rather than a
// trait `impl` on `SecurityState` itself — avoids pulling the trait
// machinery (including `Resources`) into a type that doesn't need it,
// and avoids maintaining two parallel `HasSecurityState` impls.
impl<const GRP: usize, const P2P: usize, const GO: usize> SecurityState<GRP, P2P, GO> {
    pub fn from_config(config: SecurityExtensionConfig<GRP, P2P, GO>) -> Self {
        Self {
            security_mode_enabled: Cell::new(config.security_mode_enabled),
            tool_key: Cell::new(config.tool_key),
            load_state: Cell::new(config.load_state),
            grp_keys: RefCell::new(config.grp_keys),
            p2p_keys: RefCell::new(config.p2p_keys),
            go_flags: RefCell::new(config.go_flags),
            failures_log: RefCell::new(config.failures_log),
            security_report: Cell::new(0),
            security_report_enabled: Cell::new(false),
        }
    }

    pub fn to_config(&self) -> SecurityExtensionConfig<GRP, P2P, GO> {
        SecurityExtensionConfig {
            security_mode_enabled: self.security_mode_enabled.get(),
            tool_key: self.tool_key.get(),
            // FDSK is identity, not persisted state — it gets re-injected
            // from `DeviceIdentity` on every device construction.
            load_state: self.load_state.get(),
            failures_log: self.failures_log.borrow().clone(),
            grp_keys: self.grp_keys.borrow().clone(),
            p2p_keys: self.p2p_keys.borrow().clone(),
            go_flags: self.go_flags.borrow().clone(),
        }
    }

    /// Revert the active tool key to the FDSK.
    ///
    /// Called from `SystemBDeviceState::factory_reset` after the erase
    /// pass has zeroed the key. Spec 03/05/01 §6.1.4 mandates that the
    /// FDSK becomes the active tool key again after a factory reset.
    pub fn reset_tool_key_to_fdsk(&self, fdsk: [u8; 16]) {
        self.tool_key.set(fdsk);
    }
}

impl<const GRP: usize, const P2P: usize, const GO: usize> HasSecurityMode for SecurityState<GRP, P2P, GO> {
    fn security_mode_enabled(&self) -> bool {
        self.security_mode_enabled.get()
    }

    fn log_access_denied(&self, source_addr: u16) {
        self.failures_log.borrow_mut().log_failure(SecurityFailureType::AccessError, source_addr, &[]);
    }

    fn has_group_key(&self, tsap: u16) -> bool {
        self.group_key_for_index(tsap).is_some()
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
pub struct SecureExtensionState<Inner: ExtensionState, SEQ, const GRP: usize, const P2P: usize, const GO: usize> {
    /// The medium-specific extension state.
    pub inner: Inner,
    /// The security extension state.
    pub security: SecurityState<GRP, P2P, GO>,
    /// Sequence number storage for sending counters.
    ///
    /// Shared between the Security IO augment (PID 59 read/write) and
    /// the Secure Application Layer (frame encryption). Wrapped in
    /// `RefCell` for interior mutability since both read and write
    /// through shared references.
    pub seq_storage: RefCell<SEQ>,
    /// Factory Default Setup Key.
    ///
    /// This is the *only* live copy of the FDSK in the device state.
    /// It is consumed from [`SecureResources`] at construction and
    /// re-applied to the security store on every factory reset
    /// (03/05/01 §6.1.4). `SystemBDeviceState` does not duplicate it;
    /// [`HasSecureIdentity::fdsk`] on the device state forwards here.
    fdsk: [u8; 16],
}

/// `SecureExtensionState` delegates `HasSecurityState` to its inner
/// `SecurityState`, so that `SystemBDeviceState` with a secure extension
/// can satisfy `HasSecurityState` through `HasExtensionState`.
impl<Inner: ExtensionState, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const GO: usize>
    HasSeqStorage for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    type SeqStorage = SEQ;

    fn seq_storage(&self) -> &RefCell<SEQ> {
        &self.seq_storage
    }
}

// The secure wrapper is transparent to the medium-specific accessor traits: it
// forwards each to the inner extension so the medium-specific `SystemBDeviceState`
// forwarding impls stay satisfied whether or not a device is wrapped in Data
// Secure. `HasMaxRetryCount` (TP1), `HasDomainAddress` (the generic Domain
// Address used by `A_DomainAddressSerialNumber`), `HasRfDomainAddress` (RF
// Medium Object PID 56, required by the KNX-RF link layer's context trait), and
// `HasRfRetransmitter` (RF Medium Object PID 57 / Device Object PID 74, required
// by the `RetransmitEnabled` link layer) are all pure delegations.
// `forward_to_field!` (defined in `bcus::system_b`) generates the pure
// delegation to `self.inner`; the wrapper takes no persistence side-effect
// here (the device state above is what marks dirty). The six-parameter
// generic header — `Inner: ExtensionState + <bound>` plus `SEQ` and the
// four table-size consts — is the same for every forwarded trait; only the
// `<bound>` and the method set vary. There is no `mark_dirty` on a secure
// wrapper, so no `mark_dirty` suffix.
forward_to_field! {
    impl<[
        Inner: ExtensionState + HasMaxRetryCount, SEQ,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasMaxRetryCount for SecureExtensionState<Inner, SEQ, GRP, P2P, GO> {
        get fn max_retry_count(&self) -> u8;
        set fn set_max_retry_count(&self, value: u8);
    } => self.inner
}

forward_to_field! {
    impl<[
        Inner: ExtensionState + HasDomainAddress, SEQ,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasDomainAddress for SecureExtensionState<Inner, SEQ, GRP, P2P, GO> {
        const DOMAIN_ADDRESS_LENGTH: usize = Inner::DOMAIN_ADDRESS_LENGTH;
        out fn domain_address(&self, buf: &mut [u8]);
        set fn set_domain_address(&self, addr: &[u8]);
    } => self.inner
}

forward_to_field! {
    impl<[
        Inner: ExtensionState + HasRfDomainAddress, SEQ,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasRfDomainAddress for SecureExtensionState<Inner, SEQ, GRP, P2P, GO> {
        out fn rf_domain_address(&self, out: &mut [u8; 6]);
        set fn set_rf_domain_address(&self, addr: &[u8; 6]);
    } => self.inner
}

forward_to_field! {
    impl<[
        Inner: ExtensionState + HasRfRetransmitter, SEQ,
        const GRP: usize, const P2P: usize, const GO: usize,
    ]> HasRfRetransmitter for SecureExtensionState<Inner, SEQ, GRP, P2P, GO> {
        get fn rf_retransmit_enabled(&self) -> bool;
        set fn set_rf_retransmit_enabled(&self, value: bool);
        get fn rf_repeat_counter_limit(&self) -> u8;
        set fn set_rf_repeat_counter_limit(&self, value: u8);
    } => self.inner
}

// ----------------------------------------------------------------------------
// KNX/IP medium-accessor forwarding
// ----------------------------------------------------------------------------
//
// The four KNX/IP link-layer accessor traits (`HasIpExtensionState`,
// `HasRoutingMulticastRebind`, `HasAdditionalIas`, `HasIpSecureView`)
// follow the same conditional-forwarding shape as the medium accessors
// above (`HasDomainAddress` etc.): the impl applies only when `Inner`
// itself provides the trait, so wrapping a TP1/RF extension simply
// doesn't pick them up, while wrapping an IP (Secure) interface extension
// does. They are hand-written rather than `forward_to_field!`-generated
// because they return `&dyn` views / channel references and carry
// default-bodied methods the macro doesn't model.
//
// These let `SecureExtensionState<IpSecureInterfaceExtension<...>, ...>`
// (KNX Data Secure over KNX IP Secure, used by `SecureIpDeviceBuilder`)
// satisfy the IP link layer's `ES` bounds — the composition documented on
// `IpSecureInterfaceExtension`.

#[cfg(feature = "knxip")]
impl<Inner: ExtensionState + crate::ip::HasIpExtensionState, SEQ, const GRP: usize, const P2P: usize, const GO: usize>
    crate::ip::HasIpExtensionState for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    fn ip_state(&self) -> &dyn crate::ip::IpStateView {
        self.inner.ip_state()
    }
}

#[cfg(feature = "knxip")]
impl<
    Inner: ExtensionState + crate::ip::HasRoutingMulticastRebind,
    SEQ,
    const GRP: usize,
    const P2P: usize,
    const GO: usize,
> crate::ip::HasRoutingMulticastRebind for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    fn routing_multicast_rebind_channel(
        &self,
    ) -> &embassy_sync::channel::Channel<embassy_sync::blocking_mutex::raw::NoopRawMutex, core::net::Ipv4Addr, 2> {
        self.inner.routing_multicast_rebind_channel()
    }
}

#[cfg(feature = "knxip")]
impl<Inner: ExtensionState + crate::ip::HasAdditionalIas, SEQ, const GRP: usize, const P2P: usize, const GO: usize>
    crate::ip::HasAdditionalIas for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    fn write_additional_ias_into(&self, buf: &mut [zweidraehte_proto::address::IndividualAddress]) -> usize {
        self.inner.write_additional_ias_into(buf)
    }

    fn additional_ia_is_assigned(&self, addr: zweidraehte_proto::address::IndividualAddress) -> bool {
        self.inner.additional_ia_is_assigned(addr)
    }
}

#[cfg(feature = "knxip")]
impl<Inner: ExtensionState + crate::ip::HasIpSecureView, SEQ, const GRP: usize, const P2P: usize, const GO: usize>
    crate::ip::HasIpSecureView for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    fn ip_secure_view(&self) -> Option<&dyn crate::ip::IpSecureStateView> {
        self.inner.ip_secure_view()
    }
}

impl<Inner: ExtensionState, SEQ: SiatAccess, const GRP: usize, const P2P: usize, const GO: usize> HasSecurityState
    for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    fn security_mode_enabled(&self) -> bool {
        self.security.security_mode_enabled()
    }

    fn security_load_state(&self) -> LoadState {
        self.security.load_state()
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

    fn p2p_key_for_ia(&self, peer_ia: u16) -> Option<([u8; 16], u16)> {
        self.security.p2p_key_for_ia(peer_ia)
    }

    fn is_in_siat(&self, peer_ia: u16) -> bool {
        self.seq_storage.borrow().siat_contains(peer_ia)
    }

    fn log_security_failure(&self, failure_type: SecurityFailureType, source_addr: u16, frame_fragment: &[u8]) -> bool {
        self.security.failures_log.borrow_mut().log_failure(failure_type, source_addr, frame_fragment);
        let prev = self.security.security_report();
        self.security.set_security_report(prev | 0x01);
        (prev & 0x01) == 0
    }

    fn security_report(&self) -> u8 {
        self.security.security_report()
    }

    fn security_report_enabled(&self) -> bool {
        self.security.security_report_enabled()
    }

    fn failure_counters(&self) -> [u8; 8] {
        self.security.failures_log.borrow().counters_as_bytes()
    }

    fn failure_entry(&self, index: u8) -> Option<SecurityFailureEntry> {
        self.security.failures_log.borrow().get_by_index(index).copied()
    }

    fn clear_failure_log(&self) {
        self.security.failures_log.borrow_mut().clear();
    }
}

// ============================================================================
// HasGoSecurityView — secure transmit-side policy
// ============================================================================
//
// Supplies the per-destination required security level that the plain
// Application Layer stamps on outbound buffers via
// `MessageBuilder::with_required_security`. The S-AL reads the stamp at
// outbox drain to apply the §5.5.3.x decision tree.
//
// This is the transmit-side counterpart of the receive-side check
// already implemented in [`SecureApplicationLayer::check_go_security_flags`].
// Both sides consult `PID_GO_SECURITY_FLAGS` (0-based) for groups; both
// must agree on the bit-to-level mapping below.
impl<Inner: ExtensionState, SEQ, const GRP: usize, const P2P: usize, const GO: usize> HasGoSecurityView
    for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    fn required_security_for_asap(&self, asap: u16) -> RequiredSecurity {
        // ASAPs are 1-based at the wire/property layer; the GO flags table is
        // indexed 0-based. An ASAP of 0 (which never appears in a real frame)
        // saturates harmlessly.
        let go_index = asap.saturating_sub(1);

        // Absent entries → no security required for this GO. Spec §6.3.15
        // permits divergent flags across ASAPs sharing a GA — by indexing
        // off the originating ASAP we get the correct level for *this*
        // sending GO regardless of what ETS wrote for siblings.
        let Some(flag) = self.security.go_security_flags_for(go_index) else {
            return RequiredSecurity::Plain;
        };

        // Bits are: b0 = auth, b1 = conf (03/05/01 §6.3.15.3). The
        // (auth=0, conf=1) combination is reserved/undefined — degrade to
        // plaintext rather than silently mismatching the receiver, mirroring
        // how `check_go_security_flags` treats absent entries.
        match flag & 0b11 {
            0b00 => RequiredSecurity::Plain,
            0b01 => RequiredSecurity::Auth,
            0b11 => RequiredSecurity::AuthConf,
            _ => RequiredSecurity::Plain,
        }
    }

    fn required_security_for_p2p(&self, peer_ia: u16) -> RequiredSecurity {
        // Per 03/03/07 §5.5.3.4: P2P sends to a peer with a key entry are
        // mandatory Auth+Conf — the table holds a single key without any
        // auth-only granularity. No entry → plaintext.
        match self.security.p2p_key_for_ia(peer_ia) {
            Some(_) => RequiredSecurity::AuthConf,
            None => RequiredSecurity::Plain,
        }
    }

    fn required_security_for_broadcast(&self) -> RequiredSecurity {
        // Spontaneous broadcasts that the spec marks as Plain (notably the
        // `A_NetworkParameter_InfoReport` security report per §6.3.11.4)
        // call the spontaneous helper directly with `RequiredSecurity::Plain`.
        // Reactive broadcast responses (e.g. `IndividualAddressResponse`)
        // inherit their stamp from the indication via the call site
        // chaining `.with_required_security(ind.required_security())`.
        RequiredSecurity::Plain
    }

    fn required_security_for_tool_access(&self) -> RequiredSecurity {
        // Spontaneous tool-channel sends are Auth+Conf only when the device
        // has been commissioned (security mode set, tool key non-zero). In
        // factory state the tool channel is plain.
        if self.security.security_mode_enabled() { RequiredSecurity::AuthConf } else { RequiredSecurity::Plain }
    }
}

/// Persisted config for the composed extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "InnerConfig: Serialize", deserialize = "InnerConfig: serde::de::DeserializeOwned"))]
pub struct SecureExtensionConfig<InnerConfig: ExtensionConfig, const GRP: usize, const P2P: usize, const GO: usize> {
    /// Medium-specific persisted config.
    pub inner: InnerConfig,
    /// Security persisted config.
    pub security: SecurityExtensionConfig<GRP, P2P, GO>,
}

impl<InnerConfig: ExtensionConfig, const GRP: usize, const P2P: usize, const GO: usize> Default
    for SecureExtensionConfig<InnerConfig, GRP, P2P, GO>
{
    fn default() -> Self {
        Self { inner: InnerConfig::default(), security: SecurityExtensionConfig::default() }
    }
}

impl<InnerConfig: ExtensionConfig, const GRP: usize, const P2P: usize, const GO: usize> ExtensionConfig
    for SecureExtensionConfig<InnerConfig, GRP, P2P, GO>
{
}

/// Non-serialisable construction inputs for [`SecureExtensionState`].
///
/// Bundles the sequence-number storage handle (typically a platform-
/// owned resource such as shared memory or a flash sector mapping) with
/// the Factory Default Setup Key that must be baked into the initial
/// tool key. Both are required at construction time; carrying them
/// through [`ExtensionState::Resources`] removes the need for any
/// post-construction setters.
///
/// `fdsk` is non-optional here: if you are building a
/// `SecureExtensionState`, you are building a Data Secure device, and
/// a Data Secure device has an FDSK. The type system enforces this via
/// the [`SecureDeviceIdentity`](crate::storage::SecureDeviceIdentity)
/// bound at the device-state construction site.
pub struct SecureResources<Inner: ExtensionState, SEQ> {
    /// Inner extension's own resources (e.g. `()` for TP1).
    pub inner: Inner::Resources,
    /// Sequence-number storage handle (see [`SequenceNumberStorage`]).
    pub seq_storage: SEQ,
    /// Factory Default Setup Key. Becomes the initial tool key on a
    /// factory-fresh device and is re-applied by `factory_reset`.
    pub fdsk: [u8; 16],
}

impl<Inner: ExtensionState, SEQ> SecureResources<Inner, SEQ>
where
    Inner::Resources: Default,
{
    /// Build resources for a leaf secure device whose inner medium extension
    /// needs no resources of its own (`Inner::Resources` defaults — e.g. `()`
    /// for TP1/RF). Mirrors [`SystemBStateInit::new`](crate::bcus::system_b::SystemBStateInit::new)
    /// so the `inner: Default::default()` field never has to be spelled at the
    /// call site. Devices whose inner *does* carry resources (e.g. the IP Secure
    /// interface's `IpSecureResources`) construct the struct directly instead.
    pub fn simple(seq_storage: SEQ, fdsk: [u8; 16]) -> Self {
        Self { inner: Default::default(), seq_storage, fdsk }
    }
}

/// Near-exhaustion threshold for the 6-byte (48-bit) tool sending
/// SeqNr: `FF 00 00 00 00 00`. A factory reset re-initialises the
/// counter only at or above this value (03/05/01 §6.1.4 + AN194).
pub(crate) const SEQ_EXHAUSTION_THRESHOLD: u64 = 0xFF_0000_0000_00;

/// Re-init target after a near-exhaustion factory reset. Must be
/// non-zero (seq 0 is rejected per spec) but far below
/// [`SEQ_EXHAUSTION_THRESHOLD`] so the counter has runway before the
/// next reset is required.
pub(crate) const SEQ_REINIT_VALUE: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];

impl<Inner: ExtensionState, SEQ: SequenceNumberStorage, const GRP: usize, const P2P: usize, const GO: usize>
    ExtensionState for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    type Config = SecureExtensionConfig<Inner::Config, GRP, P2P, GO>;
    type Resources = SecureResources<Inner, SEQ>;

    fn from_config(config: Self::Config, resources: Self::Resources) -> Self {
        let security = SecurityState::from_config(config.security);
        // A factory-fresh device (or one that just came out of
        // `factory_reset`) carries a zero tool key in its config; seed
        // the FDSK here so the device starts life with FDSK as the
        // active tool key (spec 03/05/01 §6.1.4). If the persisted
        // config already holds a non-zero key, ETS has written one and
        // we keep it.
        if security.tool_key() == [0u8; 16] {
            security.reset_tool_key_to_fdsk(resources.fdsk);
        }

        Self {
            inner: Inner::from_config(config.inner, resources.inner),
            security,
            seq_storage: RefCell::new(resources.seq_storage),
            fdsk: resources.fdsk,
        }
    }

    fn to_config(&self) -> Self::Config {
        SecureExtensionConfig { inner: self.inner.to_config(), security: self.security.to_config() }
    }

    fn on_erase(&self, code: EraseCode) {
        // Wrapper pass-through contract: the inner (medium) extension
        // sees *every* erase code, not just the factory resets — it
        // decides for itself which codes are relevant. The security
        // handling below is purely additive.
        self.inner.on_erase(code);

        match code {
            EraseCode::FactoryReset | EraseCode::FactoryResetKeepIA => {
                self.security.factory_reset();

                // Spec 03/05/01 §6.1.4: after a factory reset, the FDSK
                // becomes the active tool key again. The extension owns
                // its own copy of the FDSK (moved in via
                // `SecureResources`), so it can self-reset without any
                // parameter plumbing from `SystemBDeviceState`.
                self.security.reset_tool_key_to_fdsk(self.fdsk);

                // Per spec 03/05/01 §6.1.4 + AN194: tool sending SeqNr
                // is re-initialised on factory reset only when the stored
                // value has reached the near-exhaustion threshold.
                // Values below threshold are preserved across reset —
                // receivers have already seen them and would reject any
                // re-init with a lower value as a replay.
                use crate::kvstore::seq6_to_u64;
                let mut storage = self.seq_storage.borrow_mut();
                if let Ok(seq) = storage.load_sending_seq() {
                    // Re-initialise the single Sequence Number Sending only once it
                    // nears exhaustion (spec §5.x); below threshold it is preserved.
                    if seq6_to_u64(&seq) >= SEQ_EXHAUSTION_THRESHOLD {
                        let _ = storage.save_sending_seq(&SEQ_REINIT_VALUE);
                    }
                }
            }
            EraseCode::ResetLinks => {
                self.security.clear_security_report();
            }
            _ => {}
        }
    }
}

impl<Inner: ExtensionState, SEQ, const GRP: usize, const P2P: usize, const GO: usize> HasSecurityMode
    for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
{
    fn security_mode_enabled(&self) -> bool {
        self.security.security_mode_enabled()
    }

    fn log_access_denied(&self, source_addr: u16) {
        self.security.log_access_denied(source_addr);
    }

    fn has_group_key(&self, tsap: u16) -> bool {
        self.security.has_group_key(tsap)
    }
}

// ============================================================================
// Augment bundle — composes the inner medium augment with `SecurityAugment`
// ============================================================================

/// The augment chain that a Data-Secure stack exposes: the inner
/// medium augment (TP1 retry-count borrow, IP Parameter Object, …)
/// plus the [`SecurityAugment`] driving Security IO 0x11.
///
/// The macro-derived [`Augment<D>`](crate::service::Augment)
/// impl walks the two fields in declaration order: the inner medium
/// augment first, then security. Devices use the chain transparently
/// — they don't need to construct this struct themselves; the
/// [`Extension::create_augment`] impl below builds it from a
/// `SecureExtensionState` instance.
#[derive(crate::service::ServiceRegistry)]
pub struct SecureAugmentBundle<
    'a,
    InnerAugment,
    SEQ: SequenceNumberStorage + SiatAccess,
    const GRP: usize,
    const P2P: usize,
    const GO: usize,
> {
    #[service(augment)]
    pub inner: InnerAugment,
    #[service(augment)]
    pub security: SecurityAugment<'a, SEQ, GRP, P2P, GO>,
}

// ============================================================================
// Extension trait — produces SecureAugmentBundle
// ============================================================================

impl<Inner, Platform, SEQ, const GRP: usize, const P2P: usize, const GO: usize> Extension<Platform>
    for SecureExtensionState<Inner, SEQ, GRP, P2P, GO>
where
    Inner: Extension<Platform>,
    SEQ: SequenceNumberStorage + SiatAccess,
{
    type Augment<'a, D: StackDefinition>
        = SecureAugmentBundle<'a, Inner::Augment<'a, D>, SEQ, GRP, P2P, GO>
    where
        Self: 'a,
        Platform: 'a;

    fn create_augment<'a, D: StackDefinition>(&'a self, platform: &'a Platform) -> Self::Augment<'a, D>
    where
        Platform: 'a,
    {
        SecureAugmentBundle {
            inner: self.inner.create_augment::<D>(platform),
            security: SecurityAugment::new(&self.security, &self.seq_storage),
        }
    }
}

// ============================================================================
// Type Aliases
// ============================================================================

/// TP1 extension state with Data Secure support.
pub type SecureTp1ExtensionState<SEQ, const GRP: usize, const P2P: usize, const GO: usize> =
    SecureExtensionState<Tp1ExtensionState, SEQ, GRP, P2P, GO>;

/// TP1 device state with Data Secure support, sized from raw table byte sizes.
///
/// Used where there is no [`SystemBStackDefinition`] to project sizes from (the
/// conformance harness, pinned to a custom `Mem`); devices that have one size
/// their state through `SecureTp1StateFor` in `definition.rs` instead.
///
/// `GRP` (group key table capacity) and `GO` (GO security flags table
/// capacity) are **entry counts** derived from the byte-size parameters:
/// the group key table holds one key per address table entry
/// (`(ADT_SIZE - 2) / 2`, inverting the `2 + entries · 2` table layout)
/// and the GO flags table one byte per communication object
/// (`(COT_SIZE - 2) / 2`).
///
/// `P2P` sizes the P2P Key Table. The Security Individual Address Table is **not**
/// a parameter here — its capacity is the `N` of the
/// [`SiatStore`](crate::kvstore::SiatStore) chosen for `SEQ` (the SIAT lives in
/// the sequence store, not as a const generic). Per 03/03/07 §5.3 that `N` must
/// cover the union of P2P and group-secure senders.
pub type SecureTp1DeviceState<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D,
    SEQ,
    const P2P: usize,
> = SystemBDeviceState<
    ADT_SIZE,
    AST_SIZE,
    COT_SIZE,
    D,
    SecureTp1ExtensionState<SEQ, { (ADT_SIZE - 2) / 2 }, P2P, { (COT_SIZE - 2) / 2 }>,
>;

/// KNX-RF extension state with Data Secure support. Wraps the RF Medium Object /
/// Domain Address extension in the secure wrapper.
pub type SecureRfExtensionState<SEQ, const GRP: usize, const P2P: usize, const GO: usize> =
    SecureExtensionState<RfExtensionState, SEQ, GRP, P2P, GO>;

/// KNX-RF **retransmitter** extension state with Data Secure support. As
/// [`SecureRfExtensionState`], but the wrapped inner extension is
/// [`RfRetransmitterExtension`], so the device also gains the PID 57 / PID 74
/// retransmitter surface (`SecureExtensionState<RfRetransmitterExtension<RfExtensionState>, …>`).
pub type SecureRfRetransmitterExtensionState<SEQ, const GRP: usize, const P2P: usize, const GO: usize> =
    SecureExtensionState<RfRetransmitterExtension, SEQ, GRP, P2P, GO>;

#[cfg(test)]
mod tests {
    use super::SecurityTable;

    /// Truncating via `set_count` must zero the dropped entries — the
    /// persisted config serializes the whole backing array, so stale
    /// key material above the count would otherwise reach storage.
    #[test]
    fn set_count_zeroes_truncated_entries() {
        let mut table: SecurityTable<4, 18> = SecurityTable::new();
        let key_a = [0xAA; 18];
        let key_b = [0xBB; 18];
        let mut data = [0u8; 36];
        data[..18].copy_from_slice(&key_a);
        data[18..].copy_from_slice(&key_b);
        table.write_entries(0, &data).expect("two entries fit in a 4-slot table");
        assert_eq!(table.count(), 2);

        table.set_count(1);
        assert_eq!(table.count(), 1);
        assert_eq!(table.get(0), Some(&key_a));
        // The dropped entry must be gone from the backing array, not
        // just hidden behind the count.
        assert_eq!(table.data[1], [0u8; 18]);
    }

    /// `clear` must zero the whole backing array, same rationale.
    #[test]
    fn clear_zeroes_backing_array() {
        let mut table: SecurityTable<2, 18> = SecurityTable::new();
        table.write_entries(0, &[0xCC; 18]).expect("one entry fits");
        table.clear();
        assert_eq!(table.count(), 0);
        assert_eq!(table.data, [[0u8; 18]; 2]);
    }

    /// `set_count` clamps to capacity and zeroing stays in bounds.
    #[test]
    fn set_count_clamps_to_capacity() {
        let mut table: SecurityTable<2, 8> = SecurityTable::new();
        table.set_count(100);
        assert_eq!(table.count(), 2);
    }
}
