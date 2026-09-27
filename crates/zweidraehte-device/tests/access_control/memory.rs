//! Access control of the memory maps, window by window.
//!
//! The memory services are `3FF/3FF` at service level; what they reach
//! carries its own Access Policy (AN193 v04 §2.2.3), which the memory map
//! enforces. Each window below is read and written by every caller class,
//! with Security Mode off and on, and the outcome is compared against the
//! policy's notation — not against the map.
//!
//! A refusal must be `AccessDenied` whatever the window holds, so the maps
//! check the policy before they resolve the window. Admitted writes put
//! back what a Tool read found there, or land where they are malformed, so
//! the probing changes nothing.

use zweidraehte_device::bcus::system_b::MemoryLayout;
use zweidraehte_device::memory::{MemoryError, MemoryMap};
use zweidraehte_proto::access::{ClientRole, SecurityMode};

use super::spec::{Caller, policy};

/// One memory window as the specification describes it.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    pub name: &'static str,
    /// Where the window is read.
    pub address: u32,
    /// Where it is written: an address whose admitted write has no effect.
    pub write_probe: u32,
    /// `false` for a window no caller may write.
    pub writable: bool,
    /// Access Policy in the spec's notation.
    pub policy: &'static str,
    pub source: &'static str,
}

const TABLES: &str = "AN193 3FF/0CC read + 03/05/01 §4.16.2-§4.18.2 Tool-only write";
const APPLICATION: &str = "AN193 3FF/0CC (R); writes Tool-only as for the tables";

const fn window(name: &'static str, address: u32, policy: &'static str, source: &'static str) -> Window {
    Window { name, address, write_probe: address, writable: true, policy, source }
}

/// The System B windows of `layout`: the three tables and, when the
/// layout has one, the application memory behind them.
pub fn system_b(layout: &MemoryLayout) -> Vec<Window> {
    let mut windows = vec![
        window("address table", layout.adt_address(), "3FF/04C", TABLES),
        window("association table", layout.ast_address(), "3FF/04C", TABLES),
        window("group object table", layout.cot_address(), "3FF/04C", TABLES),
    ];
    if layout.app_size > 0 {
        windows.push(window("application memory", layout.app_address(), "3FF/04C", APPLICATION));
    }
    windows
}

/// The fixed System 7 windows (Resources §4.25-§4.26, 03/05/02 §3.31) and
/// the product's group object table at `cot_address`. The association
/// table and the application segment move with their table references and
/// are unmapped on a fresh device.
pub fn system_7(cot_address: u16) -> Vec<Window> {
    vec![
        window("programming mode", 0x0060, "3FF/0CC", "PID_PROGMODE in memory; AN193 3FF/0CC"),
        window("OptionReg", 0x0100, "3FF/04C", "application resource; AN193 lists none"),
        // A record must start at the window base, so a write one octet in
        // is malformed and changes nothing when admitted.
        Window { write_probe: 0x0105, ..window("load control", 0x0104, "3FF/04C", TABLES) },
        window("RAM", 0x0700, "3FF/04C", "application resource; AN193 lists none"),
        Window { writable: false, ..window("load states", 0xB6EA, "3FF/04C", TABLES) },
        window("address table", 0x4000, "3FF/04C", TABLES),
        window("group object table", u32::from(cot_address), "3FF/04C", TABLES),
    ]
}

pub fn check<S, M: MemoryMap<S>>(
    name: &str,
    map: &M,
    state: &S,
    windows: &[Window],
    max_levels: u8,
    security_modes: &[bool],
    set_security_mode: &dyn Fn(bool),
) {
    let mut failures = Vec::new();

    // The Tool with A+C may read every window in either mode, so its read
    // gives the value an admitted probing write puts back.
    let tool = Caller::secure(SecurityMode::AuthConf, ClientRole::Tool).context();

    for &security_mode in security_modes {
        set_security_mode(security_mode);
        for caller in Caller::all(max_levels) {
            let ctx = caller.context();
            for window in windows {
                let expected = policy(window.policy);
                let at = |what: &str| {
                    format!("{} ({}) {what}, {caller:?}, Security Mode {security_mode}", window.name, window.source)
                };

                let read = map.read(state, window.address, &mut [0u8], ctx);
                let read_admitted = !matches!(read, Err(MemoryError::AccessDenied));
                if read_admitted != expected.permits_read(&caller, security_mode) {
                    failures.push(at(&format!("read admitted={read_admitted} ({read:?})")));
                }

                let mut current = [0u8];
                let _ = map.read(state, window.write_probe, &mut current, tool);
                let write = map.write(state, window.write_probe, &current, ctx);
                let write_admitted = !matches!(write, Err(MemoryError::AccessDenied));
                if write_admitted != expected.permits_write(&caller, security_mode) {
                    failures.push(at(&format!("write admitted={write_admitted} ({write:?})")));
                }
                if !window.writable && write.is_ok() {
                    failures.push(at("write to a read-only window succeeded"));
                }
            }
        }
    }
    set_security_mode(false);

    assert!(failures.is_empty(), "{name} memory: {} failure(s)\n  {}", failures.len(), failures.join("\n  "));
}
