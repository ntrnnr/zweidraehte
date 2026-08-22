//! The Security Interface Object's persisted configuration and runtime state.
//!
//! [`SecurityConfig`] is what a device stores; [`SecurityState`] is the same
//! data behind `Cell`/`RefCell` so a running stack can mutate it through a
//! shared reference. Neither owns a backend, a clock, or a frame buffer — a
//! device supplies persistence and the layer that calls in.

use core::cell::{Cell, RefCell};

use serde::{Deserialize, Serialize};

use crate::messages::apdu::load_control::LoadState;
use crate::security::failures::SecurityFailuresLog;
use crate::security::tables::SecurityTable;

// Entry widths are spelled as literals wherever they appear in a type
// position. Naming them would be nicer to read, but this crate enables
// `generic_const_exprs`, under which a named const in a const-generic argument
// becomes an unevaluated const expression — and normalising its predicates
// cycles back through the very impl that names it.

// ============================================================================
// Persisted Config
// ============================================================================

/// Persisted security configuration.
///
/// Contains scalar fields, security tables (P2P keys, group keys, GO
/// flags), and the security failures log. Tables persist across
/// Confirmed and Basic restarts per spec (03/05/01 §6.3.6-§6.3.15).
///
/// Sequence numbers are stored separately via
/// [`SequenceNumberStorage`](crate::security::SequenceNumberStorage)
/// due to their high write frequency.
///
/// # Key redaction
///
/// The `Debug` impl omits the `tool_key` bytes and delegates table display
/// to `SecurityTable`'s redacted `Debug` impl. `Serialize`/`Deserialize`
/// are unaffected.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityConfig<const GRP: usize, const P2P: usize, const GO: usize> {
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
    /// Sized by `P2P`. Independent of the SIAT: the P2P Key Table only
    /// carries an entry when this device has a secure P2P link with
    /// the partner (03/05/01 §6.3.6 NOTE 98); the SIAT by contrast
    /// carries every secure-sender IA — group senders included.
    #[serde(default)]
    pub p2p_keys: SecurityTable<P2P, 20>,
    /// GO security flags: 1 byte per group object.
    #[serde(default)]
    pub go_flags: SecurityTable<GO, 1>,
    /// PID_SECURITY_REPORT (57). Persisted: 03/05/01 §6.3.11's master-reset
    /// table leaves it untouched by a Confirmed Restart, so it has to
    /// survive one — and a power cycle with it.
    #[serde(default)]
    pub security_report: u8,
    /// PID_SECURITY_REPORT_CONTROL (58). Persisted for the same reason
    /// (§6.3.12: "01h Confirmed Restart — not influenced: the value shall
    /// not change").
    #[serde(default)]
    pub security_report_enabled: bool,
}

impl<const GRP: usize, const P2P: usize, const GO: usize> core::fmt::Debug for SecurityConfig<GRP, P2P, GO> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The tool_key field is AES-128 key material — never print raw bytes.
        f.debug_struct("SecurityConfig")
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

impl<const GRP: usize, const P2P: usize, const GO: usize> Default for SecurityConfig<GRP, P2P, GO> {
    fn default() -> Self {
        Self {
            security_mode_enabled: false,
            tool_key: [0u8; 16],
            load_state: LoadState::Unloaded,
            failures_log: SecurityFailuresLog::default(),
            grp_keys: SecurityTable::new(),
            p2p_keys: SecurityTable::new(),
            go_flags: SecurityTable::new(),
            security_report: 0,
            security_report_enabled: false,
        }
    }
}

// ============================================================================
// Runtime State
// ============================================================================

/// Runtime security state with interior mutability.
///
/// Holds security mode, tool key, load state, the group-key, P2P-key, and
/// GO-security-flag tables. Table data is behind `RefCell` for interior
/// mutability during property writes.
pub struct SecurityState<const GRP: usize, const P2P: usize, const GO: usize> {
    security_mode_enabled: Cell<bool>,
    /// Active tool key. The KNX spec defines this as the negotiated key
    /// for the current MaC↔BDUT session. On a fresh device or after a
    /// factory reset it equals the FDSK supplied by the device identity;
    /// the owning stack seeds it there. Once the MaC writes
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
        // First two bytes make the change visible in the log without leaking
        // the full key. "was_empty=true" would only fire on a device that
        // hasn't been through `from_config` (never happens in production) —
        // on a fresh-boot device the tool_key is pre-seeded to FDSK by the
        // config path.
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
        let entry = search_by_leading_index(&table, ga_index)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(&entry[2..18]);
        Some(key)
    }

    /// Look up a P2P key by 1-based Security Individual Address Table index.
    ///
    /// Each entry is 20 bytes: IA_Index(2) + Key(16) + Roles(2), where the
    /// leading field identifies the communication partner *by its position in
    /// the SIAT* rather than by its address (03/05/01 §6.3.6.2). The caller
    /// resolves the peer IA to that index through the SIAT first.
    ///
    /// Uses binary search — §6.3.6.2 requires the table sorted by IA_Index
    /// ascending and §6.3.6.3 makes the MaC (ETS) maintain that order, exactly
    /// as for the group key table above.
    ///
    /// Returns the 16-byte key and the role bitmask (R0-R15), or `None` if the
    /// index has no key entry — which per NOTE 98 is the normal state for a
    /// partner we only share group communication with.
    pub fn p2p_key_for_index(&self, ia_index: u16) -> Option<([u8; 16], u16)> {
        let table = self.p2p_keys.borrow();
        let entry = search_by_leading_index(&table, ia_index)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(&entry[2..18]);
        let roles = u16::from_be_bytes([entry[18], entry[19]]);
        Some((key, roles))
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

    /// Clear PID_SECURITY_REPORT (57) alone.
    ///
    /// ResetLinks (06h) clears the report but leaves the control alone:
    /// 03/05/01 §6.3.11's master-reset table says "KNX default: cleared"
    /// for the report, while §6.3.12's says "not influenced: no change"
    /// for the control. The two tables agree only on the three full
    /// resets, which go through [`clear_security_report`](Self::clear_security_report).
    pub fn clear_security_report_only(&self) {
        self.security_report.set(0);
    }

    /// Clear PID_SECURITY_REPORT (57) and PID_SECURITY_REPORT_CONTROL (58).
    ///
    /// Per spec 03/05/01 §6.3.11 and §6.3.12, erase codes 02h and 07h and
    /// a local reset clear the report and set the control to "Disabled".
    /// Neither is influenced by a Confirmed Restart (01h), which is why
    /// both are persisted rather than rebuilt at boot.
    pub fn clear_security_report(&self) {
        self.security_report.set(0);
        self.security_report_enabled.set(false);
    }

    /// Reset all security state to factory defaults except the active
    /// tool key, which the caller is expected to seed from the device's
    /// FDSK (per spec 03/05/01 §6.1.4 the tool key reverts to the FDSK on
    /// factory reset). The owning stack drives this and the FDSK-write
    /// together so the state never ends up with a wiped tool key but no
    /// FDSK applied.
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

    /// Build the runtime state from persisted configuration.
    pub fn from_config(config: SecurityConfig<GRP, P2P, GO>) -> Self {
        Self {
            security_mode_enabled: Cell::new(config.security_mode_enabled),
            tool_key: Cell::new(config.tool_key),
            load_state: Cell::new(config.load_state),
            grp_keys: RefCell::new(config.grp_keys),
            p2p_keys: RefCell::new(config.p2p_keys),
            go_flags: RefCell::new(config.go_flags),
            failures_log: RefCell::new(config.failures_log),
            security_report: Cell::new(config.security_report),
            security_report_enabled: Cell::new(config.security_report_enabled),
        }
    }

    /// Snapshot the runtime state back into persistable configuration.
    pub fn to_config(&self) -> SecurityConfig<GRP, P2P, GO> {
        SecurityConfig {
            security_mode_enabled: self.security_mode_enabled.get(),
            tool_key: self.tool_key.get(),
            // FDSK is identity, not persisted state — it gets re-injected
            // from the device identity on every device construction.
            load_state: self.load_state.get(),
            failures_log: self.failures_log.borrow().clone(),
            grp_keys: self.grp_keys.borrow().clone(),
            p2p_keys: self.p2p_keys.borrow().clone(),
            go_flags: self.go_flags.borrow().clone(),
            security_report: self.security_report.get(),
            security_report_enabled: self.security_report_enabled.get(),
        }
    }

    /// Revert the active tool key to the FDSK.
    ///
    /// Called after a factory-reset erase pass has zeroed the key. Spec
    /// 03/05/01 §6.1.4 mandates that the FDSK becomes the active tool key
    /// again after a factory reset.
    pub fn reset_tool_key_to_fdsk(&self, fdsk: [u8; 16]) {
        self.tool_key.set(fdsk);
    }
}

/// Binary search a key table by its leading 2-octet index field.
///
/// Both key tables are sorted by that field and the search is identical; only
/// what the caller reads out of the entry differs.
fn search_by_leading_index<const N: usize, const ENTRY_SIZE: usize>(
    table: &SecurityTable<N, ENTRY_SIZE>,
    wanted: u16,
) -> Option<&[u8; ENTRY_SIZE]> {
    let mut lo = 0usize;
    let mut hi = table.count() as usize;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry = &table.data[mid];
        let stored_index = u16::from_be_bytes([entry[0], entry[1]]);
        match stored_index.cmp(&wanted) {
            core::cmp::Ordering::Equal => return Some(entry),
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestState = SecurityState<4, 4, 4>;

    fn state_with_group_keys(entries: &[(u16, u8)]) -> TestState {
        let mut config: SecurityConfig<4, 4, 4> = SecurityConfig::default();
        for (i, (index, fill)) in entries.iter().enumerate() {
            let mut entry = [*fill; 18];
            entry[..2].copy_from_slice(&index.to_be_bytes());
            config.grp_keys.write_entries(i as u16, &entry).expect("entry fits");
        }
        SecurityState::from_config(config)
    }

    #[test]
    fn group_keys_are_found_by_their_index_field_not_their_position() {
        // Sparse indices: position 2 holds index 7.
        let state = state_with_group_keys(&[(1, 0xA1), (4, 0xA4), (7, 0xA7)]);

        assert_eq!(state.group_key_for_index(7).expect("index 7 present")[15], 0xA7);
        assert_eq!(state.group_key_for_index(4).expect("index 4 present")[15], 0xA4);
        assert!(state.group_key_for_index(2).is_none(), "index 2 is a hole in the table");
        assert!(state.group_key_for_index(0).is_none());
    }

    #[test]
    fn config_round_trips_through_runtime_state() {
        let state = state_with_group_keys(&[(1, 0xA1)]);
        state.set_security_mode_enabled(true);
        state.set_tool_key([0x5A; 16]);
        state.set_load_state(LoadState::Loaded);

        let config = state.to_config();
        let restored: TestState = SecurityState::from_config(config);

        assert!(restored.security_mode_enabled());
        assert_eq!(restored.tool_key(), [0x5A; 16]);
        assert_eq!(restored.load_state(), LoadState::Loaded);
        assert_eq!(restored.group_key_for_index(1).expect("survived the round trip")[15], 0xA1);
    }

    #[test]
    fn factory_reset_wipes_the_tables_and_leaves_the_key_for_the_caller() {
        let state = state_with_group_keys(&[(1, 0xA1)]);
        state.set_security_mode_enabled(true);
        state.set_tool_key([0x5A; 16]);

        state.factory_reset();

        assert!(!state.security_mode_enabled());
        assert_eq!(state.load_state(), LoadState::Unloaded);
        assert!(state.group_key_for_index(1).is_none());
        // The key is zeroed, not FDSK-seeded: that is the caller's second step.
        assert_eq!(state.tool_key(), [0u8; 16]);
        state.reset_tool_key_to_fdsk([0x11; 16]);
        assert_eq!(state.tool_key(), [0x11; 16]);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let state = state_with_group_keys(&[(1, 0xA1)]);
        state.set_tool_key([0x5A; 16]);
        let rendered = format!("{:?}", state.to_config());
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("90"), "0x5A rendered as decimal 90 would mean a leaked key byte");
    }
}

// ============================================================================
// Function-property handlers (03/05/01 §6.3.5, §6.3.9.3)
// ============================================================================
//
// PID_SECURITY_MODE and PID_SECURITY_FAILURES_LOG are served through function
// properties rather than ordinary value reads/writes. The handlers are pure —
// they take the state and the request data and return a (return_code, data)
// pair — so they live here rather than in a device stack, and both stacks
// call the same code.

/// A function-property answer: a return code and the data after it.
#[derive(Debug, Clone)]
pub struct FunctionPropertyAnswer {
    pub return_code: u8,
    pub data: [u8; 12],
    pub data_len: usize,
}

impl FunctionPropertyAnswer {
    fn new(return_code: u8, data: &[u8]) -> Self {
        let mut d = [0u8; 12];
        let len = data.len().min(12);
        d[..len].copy_from_slice(&data[..len]);
        Self { return_code, data: d, data_len: len }
    }

    fn success(data: &[u8]) -> Self {
        Self::new(0x00, data)
    }

    fn reject(code: u8, service_id: u8) -> Self {
        Self::new(code, &[service_id])
    }

    /// The response data as a slice.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

impl<const GRP: usize, const P2P: usize, const GO: usize> SecurityState<GRP, P2P, GO> {
    /// Dispatch `A_FunctionPropertyCommand` for the Security Interface Object.
    pub fn function_command(&self, prop_id: u16, request_data: &[u8]) -> Option<FunctionPropertyAnswer> {
        match prop_id {
            51 => Some(self.security_mode_command(request_data)),
            55 => Some(self.failure_log_command(request_data)),
            _ => None,
        }
    }

    /// Dispatch `A_FunctionPropertyState_Read` for the Security Interface Object.
    pub fn function_state_read(&self, prop_id: u16, request_data: &[u8]) -> Option<FunctionPropertyAnswer> {
        match prop_id {
            51 => Some(self.security_mode_state_read(request_data)),
            55 => Some(self.failure_log_state_read(request_data)),
            _ => None,
        }
    }

    /// PID_SECURITY_MODE command (§6.3.5.1).
    fn security_mode_command(&self, data: &[u8]) -> FunctionPropertyAnswer {
        if data.len() < 3 {
            return FunctionPropertyAnswer::new(0xFF, &[]);
        }
        let (reserved, service_id, service_info) = (data[0], data[1], data[2]);
        if reserved != 0x00 {
            return FunctionPropertyAnswer::reject(0xF8, service_id);
        }
        if service_id != 0x00 {
            return FunctionPropertyAnswer::reject(0xF2, service_id);
        }
        match service_info {
            0x00 | 0x01 => {
                self.set_security_mode_enabled(service_info == 0x01);
                FunctionPropertyAnswer::success(&[service_id])
            }
            _ => FunctionPropertyAnswer::reject(0xF8, service_id),
        }
    }

    /// PID_SECURITY_MODE state read (§6.3.5.2).
    fn security_mode_state_read(&self, data: &[u8]) -> FunctionPropertyAnswer {
        if data.len() < 2 {
            return FunctionPropertyAnswer::new(0xFF, &[]);
        }
        let (reserved, read_service_id) = (data[0], data[1]);
        if reserved != 0x00 {
            return FunctionPropertyAnswer::reject(0xF8, read_service_id);
        }
        if read_service_id != 0x00 {
            return FunctionPropertyAnswer::reject(0xF2, read_service_id);
        }
        let mode = u8::from(self.security_mode_enabled());
        FunctionPropertyAnswer::success(&[0x00, mode])
    }

    /// PID_SECURITY_FAILURES_LOG command (§6.3.9.3.2): clear.
    fn failure_log_command(&self, data: &[u8]) -> FunctionPropertyAnswer {
        if data.len() < 2 {
            return FunctionPropertyAnswer::new(0xFF, &[]);
        }
        let (reserved, service_id) = (data[0], data[1]);
        if reserved != 0x00 {
            return FunctionPropertyAnswer::new(0xF8, &[service_id]);
        }
        if service_id != 0x00 {
            return FunctionPropertyAnswer::new(0xF2, &[service_id]);
        }
        self.failures_log().borrow_mut().clear();
        FunctionPropertyAnswer::success(&[service_id])
    }

    /// PID_SECURITY_FAILURES_LOG state read (§6.3.9.3.1).
    fn failure_log_state_read(&self, data: &[u8]) -> FunctionPropertyAnswer {
        if data.len() < 2 {
            return FunctionPropertyAnswer::new(0xFF, &[]);
        }
        let (reserved, read_service_id) = (data[0], data[1]);
        if reserved != 0x00 {
            return FunctionPropertyAnswer::new(0xF8, &[read_service_id]);
        }
        let log = self.failures_log().borrow();
        match read_service_id {
            0x00 => {
                let mut out = [0u8; 12];
                out[0] = read_service_id;
                let counters = log.counters_as_bytes();
                out[1..9].copy_from_slice(&counters);
                FunctionPropertyAnswer { return_code: 0x00, data: out, data_len: 9 }
            }
            0x01 => {
                let index = data.get(2).copied().unwrap_or(0);
                match log.get_by_index(index) {
                    Some(entry) => {
                        let mut out = [0u8; 12];
                        let mut i = 0;
                        out[i] = read_service_id;
                        i += 1;
                        out[i] = index;
                        i += 1;
                        out[i..i + 2].copy_from_slice(&entry.source_addr.to_be_bytes());
                        i += 2;
                        out[i..i + 9].copy_from_slice(&entry.frame_fragment);
                        i += 9;
                        // failure_type is the 13th byte — check if it fits
                        if i < 12 {
                            out[i] = entry.failure_type;
                            i += 1;
                        }
                        FunctionPropertyAnswer { return_code: 0x00, data: out, data_len: i }
                    }
                    None => FunctionPropertyAnswer::new(0xF8, &[read_service_id]),
                }
            }
            _ => FunctionPropertyAnswer::new(0xF2, &[read_service_id]),
        }
    }
}
