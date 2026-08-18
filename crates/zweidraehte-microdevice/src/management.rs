//! The BCU-era management surface: memory services over the flat
//! image, the four-object property server, the property-path load
//! state machines, authorization, device descriptor, and restart.
//!
//! Everything here answers exactly the request sequence a management
//! client sends during a download — the shape is pinned by the MV-0020
//! `Load/all` procedure (the client's mask fixture) and the hardware
//! trace in `BCU2_PLAN.md`: connect, read ManagementStyle, authorize,
//! read DD0, drive the three load state machines through
//! `PID_LOAD_STATE_CONTROL`, then verify-mode memory writes over
//! 0100h–046Fh, RunError clear, restart.

use heapless::Vec;
use zweidraehte_proto::address::IndividualAddress;
use zweidraehte_proto::messages::apdu::load_control::{LoadEvent, LoadSegment, LoadState};
use zweidraehte_proto::pid;

use crate::device::{MAX_AUTH_LEVELS, MAX_LSM, Microdevice, RAM_SIZE};
use crate::family::MicroDeviceFamily;
use crate::frame::apci;

/// A_Key_Response is the one escaped APCI the frame module's shared
/// vocabulary does not carry (nothing else in the workspace sends it).
const APCI_KEY_RESPONSE: u16 = 0x3D4;

/// One reply APDU. `small6` rides in the APCI low octet for the short
/// services; the payload follows.
pub struct Reply {
    pub apci10: u16,
    pub small6: u8,
    pub payload: Vec<u8, 14>,
}

impl Reply {
    pub(crate) fn new(apci10: u16, small6: u8, payload: &[u8]) -> Self {
        let mut p = Vec::new();
        // Payloads are built in this module and never exceed the
        // 15-octet APDU (1 APCI octet + 14 payload octets).
        p.extend_from_slice(payload).expect("management replies fit the BCU2 APDU");
        Self { apci10, small6, payload: p }
    }
}

pub enum ServiceResult {
    None,
    Reply(Reply),
    /// `A_Restart` accepted: the embedder restarts the device after
    /// flushing the output frames.
    Restart,
}

/// One load state machine: the state plus the segment address the last
/// `AllocAbsDataSeg` record announced (read back through
/// `PID_TABLE_REFERENCE`).
#[derive(Debug, Clone, Copy)]
pub struct Lsm {
    pub state: LoadState,
    pub table_ref: u16,
}

impl Lsm {
    const fn new() -> Self {
        Self { state: LoadState::Unloaded, table_ref: 0 }
    }
}

/// Management state that lives outside the EEPROM image — the pieces
/// real mask firmware keeps in system RAM / hidden EEPROM.
pub struct ManagementState {
    /// PID_DEVICE_CONTROL on the device object. Bit 2 is verify mode:
    /// while set, every A_Memory_Write is answered with an
    /// A_Memory_Response reading the bytes back.
    pub device_control: u8,
    /// Authorization level of the active connection (0 = most
    /// privileged). Reset to free access when the connection closes.
    pub auth_level: u8,
    pub auth_keys: [[u8; 4]; MAX_AUTH_LEVELS],
    pub lsm: [Lsm; MAX_LSM],
    /// Per-machine "explicitly stopped" run-state flag (System 7's
    /// RUNCONTROL_STOP → Terminated). Volatile on purpose: a re-powered
    /// device starts a loaded application running again.
    pub run_stopped: [bool; MAX_LSM],
    /// The option register, for families that keep it outside the
    /// EEPROM image (System 7's cell at 0100h). Persistent.
    pub option_reg: u8,
}

impl ManagementState {
    pub fn new() -> Self {
        Self {
            device_control: 0,
            // Until someone authorizes, a connection runs at the least
            // privileged (free access) level. Filled properly by
            // `reset_connection_auth` once the family is known; 15 is
            // the ceiling and safe for every family.
            auth_level: (MAX_AUTH_LEVELS - 1) as u8,
            // Factory state: every level keyed FFFFFFFFh, which is why
            // an A_Authorize with the FF key is granted level 0.
            auth_keys: [[0xFF; 4]; MAX_AUTH_LEVELS],
            lsm: [Lsm::new(); MAX_LSM],
            run_stopped: [false; MAX_LSM],
            option_reg: 0,
        }
    }

    pub fn reset_connection_auth<F: MicroDeviceFamily>(&mut self) {
        self.auth_level = (F::AUTH_LEVELS - 1) as u8;
    }

    pub fn verify_mode(&self) -> bool {
        self.device_control & 0x04 != 0
    }
}

impl Default for ManagementState {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: MicroDeviceFamily> Microdevice<F> {
    /// Dispatch one connection-oriented management APDU.
    pub(crate) fn handle_service(
        &mut self,
        base: u16,
        small6: u8,
        payload: &[u8],
        _source: IndividualAddress,
    ) -> ServiceResult {
        match base {
            apci::DEVICE_DESCRIPTOR_READ => self.device_descriptor_read(small6),
            apci::MEMORY_READ => self.memory_read(small6, payload),
            apci::MEMORY_WRITE => self.memory_write(small6, payload),
            apci::AUTHORIZE_REQUEST => self.authorize(payload),
            0x3D3 /* A_Key_Write */ => self.key_write(payload),
            apci::PROPERTY_VALUE_READ => self.property_value_read(payload),
            apci::PROPERTY_VALUE_WRITE => self.property_value_write(payload),
            apci::PROPERTY_DESCRIPTION_READ => self.property_description_read(payload),
            apci::RESTART => {
                // Only the basic restart exists on these masks; the
                // master-reset variant (escape bit in the low octet)
                // postdates them.
                if small6 == 0 { ServiceResult::Restart } else { ServiceResult::None }
            }
            _ => F::extra_service(base, small6, payload).unwrap_or(ServiceResult::None),
        }
    }

    // ── Memory services ─────────────────────────────────────────────

    /// Map a KNX address to one byte of device memory.
    ///
    /// Reads of unmapped addresses yield 00h and writes to them are
    /// dropped — a management client probing outside the windows gets
    /// the same experience real silicon gives it (whatever the data
    /// bus floats to), just deterministic.
    fn mem_read_byte(&self, addr: u16) -> u8 {
        if let Some(value) = F::special_byte_read(addr, self.eeprom.as_ref(), &self.mgmt) {
            return value;
        }
        let a = usize::from(addr);
        if a < RAM_SIZE {
            self.ram[a]
        } else if let Some(off) = self.eeprom_offset(addr) {
            self.eeprom.as_ref()[off]
        } else if let Some(off) = ram2_offset::<F>(addr) {
            self.ram2[off]
        } else {
            0
        }
    }

    fn mem_write_byte(&mut self, addr: u16, value: u8) {
        if F::special_byte_write(addr, value, self.eeprom.as_mut(), &mut self.mgmt) {
            return;
        }
        let a = usize::from(addr);
        if a < RAM_SIZE {
            // The system status byte guards itself with even parity
            // over the whole octet (bit 7 is the parity bit); the mask
            // firmware drops writes that fail the check, so a corrupted
            // telegram cannot flip programming mode.
            if addr == 0x0060 && !value.count_ones().is_multiple_of(2) {
                return;
            }
            self.ram[a] = value;
        } else if let Some(off) = self.eeprom_offset(addr) {
            self.eeprom.as_mut()[off] = value;
        } else if let Some(off) = ram2_offset::<F>(addr) {
            self.ram2[off] = value;
        }
    }

    fn eeprom_offset(&self, addr: u16) -> Option<usize> {
        let off = usize::from(addr.checked_sub(F::EEPROM_BASE)?);
        (off < F::EEPROM_SIZE).then_some(off)
    }

    fn memory_read(&mut self, count: u8, payload: &[u8]) -> ServiceResult {
        if payload.len() != 2 {
            return ServiceResult::None;
        }
        let addr = u16::from_be_bytes([payload[0], payload[1]]);
        // The 15-octet APDU caps a response at 12 data bytes.
        let count = count.min(12);
        let mut data: Vec<u8, 14> = Vec::new();
        let _ = data.extend_from_slice(payload);
        for i in 0..count {
            let _ = data.push(self.mem_read_byte(addr.wrapping_add(u16::from(i))));
        }
        ServiceResult::Reply(Reply::new(apci::MEMORY_RESPONSE, count, &data))
    }

    fn memory_write(&mut self, count: u8, payload: &[u8]) -> ServiceResult {
        if payload.len() < 2 {
            return ServiceResult::None;
        }
        let addr = u16::from_be_bytes([payload[0], payload[1]]);
        let data = &payload[2..];
        if data.len() != usize::from(count) {
            return ServiceResult::None;
        }
        if !F::memory_write_intercept(addr, data, self.eeprom.as_mut(), &mut self.mgmt) {
            for (i, &byte) in data.iter().enumerate() {
                self.mem_write_byte(addr.wrapping_add(i as u16), byte);
            }
        }
        // Verify mode: answer with the bytes as the memory now holds
        // them, so the client sees exactly what stuck.
        if self.mgmt.verify_mode() {
            return self.memory_read(count, &payload[..2]);
        }
        ServiceResult::None
    }

    // ── Device descriptor ───────────────────────────────────────────

    fn device_descriptor_read(&self, descriptor_type: u8) -> ServiceResult {
        if descriptor_type == 0 {
            return ServiceResult::Reply(Reply::new(apci::DEVICE_DESCRIPTOR_RESPONSE, 0, &F::DD0.to_be_bytes()));
        }
        if descriptor_type == 2
            && let Some(dd2) = F::device_descriptor2(self.eeprom.as_ref(), &self.identity, &self.mgmt)
        {
            return ServiceResult::Reply(Reply::new(apci::DEVICE_DESCRIPTOR_RESPONSE, 2, &dd2));
        }
        // 03/03/07 §3.4.2: an unsupported descriptor type is answered
        // with type 3Fh and no data.
        ServiceResult::Reply(Reply::new(apci::DEVICE_DESCRIPTOR_RESPONSE, 0x3F, &[]))
    }

    // ── Authorization ───────────────────────────────────────────────

    fn authorize(&mut self, payload: &[u8]) -> ServiceResult {
        if payload.len() != 5 {
            return ServiceResult::None;
        }
        let key: [u8; 4] = payload[1..5].try_into().expect("length checked above");
        let free_level = (F::AUTH_LEVELS - 1) as u8;
        let granted = (0..F::AUTH_LEVELS as u8)
            .find(|&level| self.mgmt.auth_keys[usize::from(level)] == key)
            .unwrap_or(free_level);
        self.mgmt.auth_level = granted;
        ServiceResult::Reply(Reply::new(apci::AUTHORIZE_RESPONSE, 0, &[granted]))
    }

    fn key_write(&mut self, payload: &[u8]) -> ServiceResult {
        if payload.len() != 5 {
            return ServiceResult::None;
        }
        let level = payload[0];
        if !F::key_write_level_valid(level) || self.mgmt.auth_level > level {
            // Not privileged enough to set this level's key: answer
            // with FFh, the "not modified" convention.
            return ServiceResult::Reply(Reply::new(APCI_KEY_RESPONSE, 0, &[0xFF]));
        }
        self.mgmt.auth_keys[usize::from(level)] = payload[1..5].try_into().expect("length checked above");
        ServiceResult::Reply(Reply::new(APCI_KEY_RESPONSE, 0, &[level]))
    }

    // ── Property services ───────────────────────────────────────────

    fn property_value_read(&mut self, payload: &[u8]) -> ServiceResult {
        let Some((obj, prop_id, count, start)) = parse_property_header(payload) else {
            return ServiceResult::None;
        };
        let mut reply: Vec<u8, 14> = Vec::new();
        let _ = reply.extend_from_slice(&payload[..4]);
        match self.property_read(obj, prop_id, count, start) {
            Some(data) => {
                let _ = reply.extend_from_slice(&data);
                ServiceResult::Reply(Reply::new(apci::PROPERTY_VALUE_RESPONSE, 0, &reply))
            }
            // Unknown property / bad index: the negative response is
            // the same header with the element count zeroed.
            None => {
                reply[2] = start.to_be_bytes()[0] & 0x0F;
                ServiceResult::Reply(Reply::new(apci::PROPERTY_VALUE_RESPONSE, 0, &reply))
            }
        }
    }

    fn property_value_write(&mut self, payload: &[u8]) -> ServiceResult {
        let Some((obj, prop_id, count, start)) = parse_property_header(payload) else {
            return ServiceResult::None;
        };
        let data = &payload[4..];
        let accepted = self.property_write(obj, prop_id, count, start, data);
        let mut reply: Vec<u8, 14> = Vec::new();
        let _ = reply.extend_from_slice(&payload[..4]);
        if accepted {
            // Positive confirmation carries the property's current
            // value — the read-back a client would get, which for the
            // load-state controls is the machine's new state.
            if let Some(data) = self.property_read(obj, prop_id, count, start) {
                let _ = reply.extend_from_slice(&data);
            }
        } else {
            reply[2] = 0;
        }
        ServiceResult::Reply(Reply::new(apci::PROPERTY_VALUE_RESPONSE, 0, &reply))
    }

    /// Read `count` elements from `start` of a property. Properties on
    /// these masks are all single-element, so anything beyond
    /// `start <= 1, count <= 1` is out of range. Reading element 0
    /// returns the element count (1) as a 16-bit value, per 03/03/07.
    fn property_read(&self, obj: u8, prop_id: u8, count: u8, start: u16) -> Option<Vec<u8, 10>> {
        if start == 0 {
            return (count != 0).then(|| {
                let mut v = Vec::new();
                let _ = v.extend_from_slice(&1u16.to_be_bytes());
                v
            });
        }
        if count != 1 || start != 1 {
            return None;
        }
        let mut v: Vec<u8, 10> = Vec::new();
        match (obj, u16::from(prop_id)) {
            (_, pid::OBJECT_TYPE) if obj < F::OBJECT_COUNT => {
                let _ = v.extend_from_slice(&F::object_type(obj).to_be_bytes());
            }
            // Device object.
            (0, pid::DEVICE_CONTROL) => {
                let _ = v.push(self.mgmt.device_control);
            }
            (0, pid::SERVICE_CONTROL) => {
                let _ = v.extend_from_slice(&[0x00, 0x00]);
            }
            (0, pid::FIRMWARE_REVISION) => {
                let _ = v.push(1);
            }
            (0, pid::SERIAL_NUMBER) => {
                let _ = v.extend_from_slice(&self.identity.serial_number);
            }
            (0, pid::ORDER_INFO) => {
                let _ = v.extend_from_slice(&self.identity.order_info);
            }
            // Table / application objects.
            (_, pid::LOAD_STATE_CONTROL) => {
                let machine = self.lsm_index(obj)?;
                let _ = v.push(self.mgmt.lsm[machine].state.into());
            }
            (_, pid::TABLE_REFERENCE) => {
                let machine = self.lsm_index(obj)?;
                let _ = v.extend_from_slice(&u32::from(self.mgmt.lsm[machine].table_ref).to_be_bytes());
            }
            (_, pid::RUN_STATE_CONTROL) => {
                let state = F::run_state_read(obj, self.eeprom.as_ref(), &self.mgmt)?;
                let _ = v.push(state);
            }
            _ => {
                return F::property_read_hook(
                    obj,
                    u16::from(prop_id),
                    self.eeprom.as_ref(),
                    &self.identity,
                    &self.mgmt,
                );
            }
        }
        Some(v)
    }

    fn property_write(&mut self, obj: u8, prop_id: u8, count: u8, start: u16, data: &[u8]) -> bool {
        if count != 1 || start != 1 {
            return false;
        }
        match (obj, u16::from(prop_id)) {
            (0, pid::DEVICE_CONTROL) if data.len() == 1 => {
                self.mgmt.device_control = data[0];
                true
            }
            (0, pid::SERVICE_CONTROL) if data.len() == 2 => {
                // Accepted and discarded: the controllable services
                // (PEI abort, user program checks) have no equivalent
                // here. TODO: honor the IndividualAddressWriteEnable
                // bit once a client is seen driving it on mask 0020h.
                true
            }
            (_, pid::LOAD_STATE_CONTROL) => {
                let Some(machine) = self.lsm_index(obj) else { return false };
                dispatch_lsm_event::<F>(machine, data, self.eeprom.as_mut(), &mut self.mgmt);
                true
            }
            (_, pid::RUN_STATE_CONTROL) if data.len() == 1 => {
                F::run_state_write(obj, data[0], self.eeprom.as_mut(), &mut self.mgmt)
            }
            _ => F::property_write_hook(obj, u16::from(prop_id), data, self.eeprom.as_mut(), &mut self.mgmt)
                .unwrap_or(false),
        }
    }

    /// Which load state machine an interface object index drives. The
    /// property path works on every family — even where the primary
    /// load-control path is a memory window, `PID_LOAD_STATE_CONTROL`
    /// on the table/application objects stays live (and is what ETS
    /// actually drives on real System 7 silicon).
    fn lsm_index(&self, obj: u8) -> Option<usize> {
        let idx = usize::from(obj.checked_sub(F::LSM_OBJ_BASE)?);
        (idx < F::LSM_COUNT).then_some(idx)
    }

    // ── Property descriptions ───────────────────────────────────────

    fn property_description_read(&self, payload: &[u8]) -> ServiceResult {
        if payload.len() != 3 {
            return ServiceResult::None;
        }
        let (obj, prop_id, prop_idx) = (payload[0], payload[1], payload[2]);
        // [W|PDT][hi][lo][access]: writeable bit + PDT in octet 3, a
        // 12-bit max element count, and the read/write levels.
        let describe = |pdt: u8, writeable: bool, max: u16, levels: u8| {
            let reply = [
                obj,
                prop_id,
                prop_idx,
                if writeable { 0x80 } else { 0x00 } | (pdt & 0x3F),
                (max >> 8) as u8 & 0x0F,
                max as u8,
                levels,
            ];
            ServiceResult::Reply(Reply::new(apci::PROPERTY_DESCRIPTION_RESPONSE, 0, &reply))
        };
        // Only lookup by PID is served; the by-index enumeration ETS
        // uses for object browsing has no client here yet.
        // TODO: by-index enumeration when a tool is seen relying on it.
        const PDT_CONTROL: u8 = 0;
        const PDT_UNSIGNED_INT: u8 = 4;
        const PDT_UNSIGNED_LONG: u8 = 9;
        match u16::from(prop_id) {
            pid::OBJECT_TYPE if obj < F::OBJECT_COUNT => describe(PDT_UNSIGNED_INT, false, 1, 0x30),
            pid::LOAD_STATE_CONTROL if self.lsm_index(obj).is_some() => describe(PDT_CONTROL, true, 1, 0x31),
            pid::RUN_STATE_CONTROL if F::run_state_read(obj, self.eeprom.as_ref(), &self.mgmt).is_some() => {
                describe(PDT_CONTROL, true, 1, 0x31)
            }
            pid::TABLE_REFERENCE if self.lsm_index(obj).is_some() => describe(PDT_UNSIGNED_LONG, false, 1, 0x30),
            // Unknown property: type 0, max 0 — the spec's "does not
            // exist" answer.
            _ => describe(0, false, 0, 0x00),
        }
    }
}

/// Consume one load-control record (03/05/02 §3.31): the event octet,
/// then for `AdditionalLoadControls` the segment record. This parses
/// exactly what `LoadControlRecord` in the proto crate builds — the
/// two sides share the vocabulary so they cannot drift apart.
///
/// A free function rather than a method so a family's memory-window
/// intercept (System 7's load-control window at 0104h) can drive the
/// same state machine the property path drives.
pub(crate) fn dispatch_lsm_event<F: MicroDeviceFamily>(
    machine: usize,
    record: &[u8],
    eeprom: &mut [u8],
    mgmt: &mut ManagementState,
) {
    if machine >= F::LSM_COUNT {
        return;
    }
    let Some(&event) = record.first() else { return };
    let lsm = &mut mgmt.lsm[machine];
    match LoadEvent::from(event) {
        LoadEvent::NoOp => {}
        LoadEvent::StartLoading => {
            lsm.state = LoadState::Loading;
        }
        LoadEvent::LoadCompleted => {
            if lsm.state == LoadState::Loading {
                lsm.state = LoadState::Loaded;
                F::load_completed_side_effect(machine, eeprom, mgmt);
            } else {
                lsm.state = LoadState::Err;
            }
        }
        LoadEvent::Unload => {
            lsm.state = LoadState::Unloaded;
            // Side effect first: a family that locates the resource
            // through `table_ref` (System 7's association table) still
            // needs the reference to reach the blob it is emptying.
            F::unload_side_effect(machine, eeprom, mgmt);
            mgmt.lsm[machine].table_ref = 0;
        }
        LoadEvent::AdditionalLoadControls => {
            if lsm.state != LoadState::Loading {
                lsm.state = LoadState::Err;
                return;
            }
            let Some(&segment_type) = record.get(1) else { return };
            match LoadSegment::from(segment_type) {
                LoadSegment::AbsoluteData => {
                    // AllocAbsDataSeg: [type][start:2BE][length:2BE]
                    // [access][memtype][memattr][reserved]. The
                    // segment lives at a fixed or product-defined
                    // address on these families, so allocation is just
                    // remembering the address for PID_TABLE_REFERENCE.
                    if record.len() >= 4 {
                        lsm.table_ref = u16::from_be_bytes([record[2], record[3]]);
                    }
                }
                // Task records (stack/task/pointer/control blobs)
                // announce the application's identity and entry
                // points. This stack runs no legacy machine code, so
                // they are accepted as informational.
                LoadSegment::AbsoluteStack
                | LoadSegment::AbsoluteTask
                | LoadSegment::AbsolutePointer
                | LoadSegment::TaskCtrl1
                | LoadSegment::TaskCtrl2 => {}
                _ => lsm.state = LoadState::Err,
            }
        }
        _ => lsm.state = LoadState::Err,
    }
}

fn ram2_offset<F: MicroDeviceFamily>(addr: u16) -> Option<usize> {
    let off = usize::from(addr.checked_sub(F::RAM2_BASE)?);
    (off < F::RAM2_SIZE).then_some(off)
}

/// `[obj][pid][count:4|start:12]` — the header every property value
/// service shares.
fn parse_property_header(payload: &[u8]) -> Option<(u8, u8, u8, u16)> {
    if payload.len() < 4 {
        return None;
    }
    let count = payload[2] >> 4;
    let start = (u16::from(payload[2] & 0x0F) << 8) | u16::from(payload[3]);
    Some((payload[0], payload[1], count, start))
}
