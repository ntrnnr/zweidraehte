//! Memory map for System 7 devices.
//!
//! System 7 management is memory-centric: ETS reaches every resource
//! through `A_Memory_Read/Write` at absolute addresses fixed by the
//! profile (and mirrored in the ETS master data for `MV-0705`):
//!
//! ```text
//! 0060h            programming-mode byte (Resources §4.26.3)
//! 0100h            OptionReg             (Resources §4.25)
//! 0104h            load-control write window, one record ≤ 12 octets
//!                  (03/05/02 §3.31.2 DMP_LoadStateMachineWrite_RCo_Mem)
//! 0700h..07FFh     RAM window ("resources from 0700h")
//! 4000h..          RT8 group address table (fixed, Resources §4.16.9.2)
//! B6EAh..B6EDh     load-state bytes: ADT / AST / APP / APP2
//! product const    group object table (`System7ProductLayout::COT_ADDRESS` —
//!                  no location resource exists for it)
//! dynamic          association table and application segment, each
//!                  located by its own table reference
//! ```
//!
//! The load-control record at 0104h packs the target state machine and
//! the event into its first octet (`[machine:4][event:4]`, machines
//! 1 = address table, 2 = association table, 3 = application program,
//! 4 = PEI program / Application Program 2 — 03/05/02 §3.31); the
//! remaining octets are the same segment records the property-based
//! path carries, so both paths funnel into the same
//! [`AbsoluteAlloc`](crate::objects::tables::AbsoluteAlloc)-flavoured
//! `write_lsm`.

use crate::{
    HasSecurityMode, StackDefinition, StackState,
    device_model::{DeviceModelEvent, DeviceModelNotifier, RunTarget},
    extension::ExtensionState,
    memory::{MemoryError, MemoryMap},
    objects::tables::{HasLoadStateMachine, HasRunStateMachine, LoadAction, RunEvent, TableMemory},
};
use zweidraehte_proto::AccessContext;
use zweidraehte_proto::access::AccessPolicy;

use super::{SYSTEM7_RAM_SIZE, System7DeviceState, System7ProductLayout};

/// Memory map for System 7 devices.
///
/// Stateless: the fixed windows are profile constants and the movable
/// regions are located through each table's own table reference, so
/// there is nothing to configure per device.
#[derive(Debug, Clone, Copy, Default)]
pub struct System7MemoryMap;

impl System7MemoryMap {
    /// Programming-mode byte (Resources §4.26.3.2).
    pub const PROGRAMMING_MODE_ADDR: u16 = 0x0060;
    /// OptionReg (Resources §4.25.2.2).
    pub const OPTION_REG_ADDR: u16 = 0x0100;
    /// Load-control write window (03/05/02 §3.31.2).
    pub const LOAD_CONTROL_ADDR: u16 = 0x0104;
    /// Maximum load-control record length (per the master data's
    /// resource length; the absolute-segment records themselves are
    /// 10 octets — event + type + 8, 03/05/02 §3.31.3).
    pub const LOAD_CONTROL_LEN: usize = 12;
    /// Start of the RAM window ("resources from 0700h").
    pub const RAM_ADDR: u16 = 0x0700;
    /// Fixed location of the RT8 group address table
    /// (Resources §4.16.9.2).
    pub const ADT_ADDR: u16 = 0x4000;
    /// Load-state bytes for ADT / AST / APP / APP2, in that order
    /// (03/05/02 §3.31.2).
    pub const LOAD_STATUS_ADDR: u16 = 0xB6EA;

    pub const fn new() -> Self {
        Self
    }
}

/// `[start, start+len)` contains the whole `[address, address+need)` request?
fn fits(address: u16, need: usize, start: u16, len: usize) -> bool {
    address >= start && (address as usize + need) <= (start as usize + len)
}

impl<
    const ADT_SIZE: usize,
    const AST_SIZE: usize,
    const COT_SIZE: usize,
    D: StackDefinition + System7ProductLayout,
    ES: ExtensionState + HasSecurityMode,
> MemoryMap<System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>> for System7MemoryMap
{
    fn read(
        &self,
        state: &System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>,
        address: u16,
        data: &mut [u8],
        _ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        let need = data.len();

        if fits(address, need, Self::PROGRAMMING_MODE_ADDR, 1) {
            // Bit 0 = prog_mode, bit 7 = parity over the byte (even):
            // both set or both clear.
            data[0] = if state.is_programming_mode() { 0x81 } else { 0x00 };
            return Ok(need);
        }

        if fits(address, need, Self::OPTION_REG_ADDR, 1) {
            data[0] = state.option_reg();
            return Ok(need);
        }

        if fits(address, need, Self::LOAD_CONTROL_ADDR, Self::LOAD_CONTROL_LEN) {
            // The control window is write-only in every procedure that
            // uses it; reads answer zeros rather than failing so a
            // curious tool sees plain memory.
            data.fill(0);
            return Ok(need);
        }

        if fits(address, need, Self::RAM_ADDR, SYSTEM7_RAM_SIZE) {
            let offset = (address - Self::RAM_ADDR) as usize;
            data.copy_from_slice(&state.ram.borrow()[offset..offset + need]);
            return Ok(need);
        }

        if fits(address, need, Self::LOAD_STATUS_ADDR, 4) {
            // One byte per machine: ADT, AST, APP, APP2. The byte uses
            // the same LoadState coding as PID_LOAD_STATE_CONTROL —
            // both views expose the one state machine, and Resources
            // leaves the memory-mapped coding otherwise unspecified.
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = match address - Self::LOAD_STATUS_ADDR + i as u16 {
                    0 => state.adt.borrow().read_lsm()[0],
                    1 => state.ast.borrow().read_lsm()[0],
                    2 => state.app.borrow().read_lsm()[0],
                    3 => state.app2.borrow().read_lsm()[0],
                    _ => unreachable!("fits() bounded the range to 4 bytes"),
                };
            }
            return Ok(need);
        }

        if fits(address, need, Self::ADT_ADDR, ADT_SIZE) {
            let offset = (address - Self::ADT_ADDR) as usize;
            state.adt.borrow().read(offset, data);
            return Ok(need);
        }

        // Movable regions, each anchored by its table reference (0 =
        // not yet located, region unmapped).
        let ast_ref = state.ast.borrow().table_reference() as u16;
        if ast_ref != 0 && fits(address, need, ast_ref, AST_SIZE) {
            state.ast.borrow().read((address - ast_ref) as usize, data);
            return Ok(need);
        }

        // The group object table window is a product constant: the
        // table has no location resource and no load state machine of
        // its own (its segment is allocated to the Application
        // Program's), so nothing at runtime could ever establish a
        // reference for it — see `System7ProductLayout`.
        if fits(address, need, D::COT_ADDRESS, COT_SIZE) {
            state.cot.borrow().read((address - D::COT_ADDRESS) as usize, data);
            return Ok(need);
        }

        let app_ref = state.app.borrow().table_reference() as u16;
        let app_len = state.app.borrow().data_ref().len();
        if app_ref != 0 && fits(address, need, app_ref, app_len) {
            state.app.borrow().read((address - app_ref) as usize, data);
            return Ok(need);
        }

        Err(MemoryError::NotAccessible)
    }

    fn write(
        &self,
        state: &System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>,
        address: u16,
        data: &[u8],
        ctx: AccessContext,
    ) -> Result<usize, MemoryError> {
        let need = data.len();

        // The programming-mode byte is exactly the resource the
        // connectionless individualisation procedures poke, so it sits
        // outside the configuration-write gate below.
        if fits(address, need, Self::PROGRAMMING_MODE_ADDR, 1) {
            // Accept only a parity-consistent byte (even parity, so bit 7
            // mirrors bit 0 when no other bits are set); anything else is
            // a corrupted write and leaves the mode untouched — the write
            // itself still "lands", as on plain memory.
            let byte = data[0];
            if byte == 0x81 || byte == 0x00 {
                state.set_programming_mode(byte & 0x01 != 0);
            }
            return Ok(need);
        }

        if fits(address, need, Self::RAM_ADDR, SYSTEM7_RAM_SIZE) {
            let offset = (address - Self::RAM_ADDR) as usize;
            state.ram.borrow_mut()[offset..offset + need].copy_from_slice(data);
            return Ok(need);
        }

        if fits(address, need, Self::OPTION_REG_ADDR, 1) {
            state.set_option_reg(data[0]);
            return Ok(need);
        }

        if fits(address, need, Self::LOAD_STATUS_ADDR, 4) {
            return Err(MemoryError::WriteProtected);
        }

        // Same policy gate as the System B map: table and application
        // writes are open while Security Mode is off, Tool-only while it
        // is on (03/05/01 §4.16.2 / §4.17.2 / §4.18.2 → 3FF/00C).
        if !AccessPolicy::OPEN_OFF_TOOL_ON.can_write(&ctx, state.security_mode_enabled()) {
            return Err(MemoryError::AccessDenied);
        }

        if address == Self::LOAD_CONTROL_ADDR && need >= 1 && need <= Self::LOAD_CONTROL_LEN {
            return self.write_load_control(state, data);
        }
        if fits(address, need, Self::LOAD_CONTROL_ADDR, Self::LOAD_CONTROL_LEN) {
            // A record not starting at the window base is malformed.
            return Err(MemoryError::NotAccessible);
        }

        if fits(address, need, Self::ADT_ADDR, ADT_SIZE) {
            let offset = (address - Self::ADT_ADDR) as usize;
            state.adt.borrow_mut().write(offset, data);
            return Ok(need);
        }

        let ast_ref = state.ast.borrow().table_reference() as u16;
        if ast_ref != 0 && fits(address, need, ast_ref, AST_SIZE) {
            state.ast.borrow_mut().write((address - ast_ref) as usize, data);
            return Ok(need);
        }

        // Product-constant window; see the read path. Checked before
        // the application's reference window: ETS writes the group
        // object table while the Application Program's only recorded
        // segment is still this one.
        if fits(address, need, D::COT_ADDRESS, COT_SIZE) {
            state.cot.borrow_mut().write((address - D::COT_ADDRESS) as usize, data);
            return Ok(need);
        }

        let app_ref = state.app.borrow().table_reference() as u16;
        let app_len = state.app.borrow().data_ref().len();
        if app_ref != 0 && fits(address, need, app_ref, app_len) {
            state.app.borrow_mut().write((address - app_ref) as usize, data);
            return Ok(need);
        }

        Err(MemoryError::NotAccessible)
    }
}

impl System7MemoryMap {
    /// Handle a record written to the load-control window at 0104h.
    ///
    /// `[machine:4][event:4]` in the first octet, then the same segment
    /// payload the property-based load control carries, so the record
    /// is re-framed as `[event][payload...]` and fed to the target
    /// machine's `write_lsm`. The application machines cascade their
    /// run events exactly like the property path does.
    fn write_load_control<
        const ADT_SIZE: usize,
        const AST_SIZE: usize,
        const COT_SIZE: usize,
        D: StackDefinition,
        ES: ExtensionState + HasSecurityMode,
    >(
        &self,
        state: &System7DeviceState<ADT_SIZE, AST_SIZE, COT_SIZE, D, ES>,
        data: &[u8],
    ) -> Result<usize, MemoryError> {
        let machine = data[0] >> 4;
        let event = data[0] & 0x0F;

        let mut record = [0u8; Self::LOAD_CONTROL_LEN];
        record[0] = event;
        record[1..data.len()].copy_from_slice(&data[1..]);
        let record = &record[..data.len()];

        match machine {
            1 => {
                state.adt.borrow_mut().write_lsm(record, None);
            }
            2 => {
                state.ast.borrow_mut().write_lsm(record, None);
            }
            3 => {
                let action = state.app.borrow_mut().write_lsm(record, None);
                let run_action = match action {
                    LoadAction::LoadEnd => state.app.borrow_mut().handle_run_event(RunEvent::Loaded),
                    LoadAction::Unload => state.app.borrow_mut().handle_run_event(RunEvent::Unloaded),
                    _ => None,
                };
                if let Some(run_action) = run_action {
                    state.notify(DeviceModelEvent::RunAction(RunTarget::Application, run_action));
                }
            }
            4 => {
                let action = state.app2.borrow_mut().write_lsm(record, None);
                let run_action = match action {
                    LoadAction::LoadEnd => state.app2.borrow_mut().handle_run_event(RunEvent::Loaded),
                    LoadAction::Unload => state.app2.borrow_mut().handle_run_event(RunEvent::Unloaded),
                    _ => None,
                };
                if let Some(run_action) = run_action {
                    state.notify(DeviceModelEvent::RunAction(RunTarget::Pei, run_action));
                }
            }
            // An unknown machine nibble: the record lands in plain
            // memory terms (the write succeeds) but drives nothing.
            _ => {}
        }

        Ok(data.len())
    }
}
