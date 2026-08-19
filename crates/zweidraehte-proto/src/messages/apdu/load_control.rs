//! Load/Run State Machine protocol vocabulary.
//!
//! The pure protocol vocabulary of the load and run state machines:
//!
//! - [`LoadState`] / [`RunState`] — the state values read back from
//!   `PID_LOAD_STATE_CONTROL` / `PID_RUN_STATE_CONTROL`.
//! - [`LoadEvent`] / [`RunEvent`] — the control commands written to those
//!   properties (and the internal events the run machine reacts to).
//! - [`LoadSegment`] — the segment selector inside an `AdditionalLoadControls`
//!   load command.
//! - [`load_control_transition`] — the common synchronous Realisation Type 1
//!   transition table.
//!
//! The transition is shared because it is deterministic protocol logic. State
//! ownership, allocation, CRC calculation, persistence, and family-specific
//! side effects remain in the consuming device stacks. Run-state transitions
//! likewise remain stack-specific until their profile semantics are known to
//! agree.

use serde::{Deserialize, Serialize};

create_protocol_enum!(
    /// Load state of an interface object (`PID_LOAD_STATE_CONTROL` readback).
    ///
    /// Includes the four mandatory states and the optional `Unloading` and
    /// `LoadCompleting` states from Resources 03/05/01 Table 92. A particular
    /// device stack need not enter the optional states, but clients must be able
    /// to decode them while polling another device.
    #[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
    pub enum LoadState: u8 {
        Unloaded        , 0x00, "Unloaded";
        Loaded          , 0x01, "Loaded";
        Loading         , 0x02, "Loading";
        Err             , 0x03, "Error";
        Unloading       , 0x04, "Unloading";
        LoadCompleting  , 0x05, "LoadCompleting";
    }
);

create_protocol_enum!(
    /// Load control command written to `PID_LOAD_STATE_CONTROL` (Resources
    /// 03/05/01 Table 93).
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadEvent: u8 {
        NoOp                    , 0x00, "NoOp";
        StartLoading            , 0x01, "StartLoading";
        LoadCompleted           , 0x02, "LoadCompleted";
        AdditionalLoadControls  , 0x03, "AdditionalLoadControls";
        Unload                  , 0x04, "Unload";
        _,                              "Unknown Load Event 0x{:x}";
    }
);

/// Side effect requested by a [`load_control_transition`].
///
/// The action describes protocol intent without prescribing how a stack owns
/// memory or orchestrates other state machines. Consumers integrate the action
/// and returned [`LoadState`] into their own storage and runtime model.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum LoadAction {
    /// No side effect is required.
    None,
    /// Begin a new load operation.
    LoadStart,
    /// Finish the active load operation.
    LoadEnd,
    /// Release the loaded resource.
    Unload,
    /// Process the allocation record following the event octet.
    Alloc,
}

/// Apply an external event to the synchronous Realisation Type 1 load machine.
///
/// This implements the recommended transitions in Resources 03/05/01
/// §4.23.2.3.3 Table 94. Both in-tree device stacks complete unloading and load
/// completion synchronously, so the optional intermediate states
/// [`LoadState::Unloading`] and [`LoadState::LoadCompleting`] are never entered
/// from the four mandatory states. A stack whose transition takes more than two
/// seconds must implement those intermediate transitions instead of using this
/// helper unchanged.
///
/// This function deliberately does not inspect allocation records or mutate
/// storage. A [`LoadAction::Alloc`] result tells the consuming stack to do so;
/// that operation may still replace the returned state with [`LoadState::Err`]
/// when its profile-specific validation fails. Device restart and internal
/// error conditions are separate events and therefore are not represented by
/// [`LoadEvent`].
#[must_use]
pub const fn load_control_transition(state: LoadState, event: LoadEvent) -> (LoadState, LoadAction) {
    match event {
        LoadEvent::NoOp => (state, LoadAction::None),
        LoadEvent::StartLoading => match state {
            LoadState::Unloaded | LoadState::Loaded => (LoadState::Loading, LoadAction::LoadStart),
            LoadState::Loading | LoadState::Err => (state, LoadAction::None),
            LoadState::Unloading | LoadState::LoadCompleting => (LoadState::Err, LoadAction::None),
        },
        LoadEvent::LoadCompleted => match state {
            LoadState::Loading => (LoadState::Loaded, LoadAction::LoadEnd),
            LoadState::Unloaded | LoadState::Loaded | LoadState::Err => (state, LoadAction::None),
            LoadState::Unloading | LoadState::LoadCompleting => (LoadState::Err, LoadAction::None),
        },
        LoadEvent::AdditionalLoadControls => match state {
            LoadState::Loaded | LoadState::Unloading | LoadState::LoadCompleting => (LoadState::Err, LoadAction::None),
            LoadState::Loading => (LoadState::Loading, LoadAction::Alloc),
            LoadState::Unloaded | LoadState::Err => (state, LoadAction::None),
        },
        LoadEvent::Unload => (LoadState::Unloaded, LoadAction::Unload),
        // Unknown event values are ignored, as required for new implementations.
        LoadEvent::Other(_) => (state, LoadAction::None),
    }
}

create_protocol_enum!(
    /// Run state of the Application Program Object (`PID_RUN_STATE_CONTROL`
    /// readback). The application can only run once it is loaded.
    ///
    /// - `Halted` (0x00): not running; the default state when unloaded.
    /// - `Running` (0x01): running normally.
    /// - `Ready` (0x02): intermediate — conditions being checked before running.
    /// - `Terminated` (0x03): explicitly stopped via `RUNCONTROL_STOP`.
    #[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
    pub enum RunState: u8 {
        Halted          , 0x00, "Halted";
        Running         , 0x01, "Running";
        Ready           , 0x02, "Ready";
        Terminated      , 0x03, "Terminated";
    }
);

create_protocol_enum!(
    /// Event driving the run state machine of 03/05/01 §4.24.
    ///
    /// Only the first three are writable to `PID_RUN_STATE_CONTROL` (0x06);
    /// they are the whole of §4.24.2.3.2 Table 96:
    ///
    /// - `Ready` (0x00): no operation — state unchanged.
    /// - `Restart` (0x01): restart the application.
    /// - `Stop` (0x02): stop the application (→ `Terminated` if loaded).
    ///
    /// The rest are internal events raised by the device itself, and reuse
    /// the same byte space because nothing ever encodes them onto the wire:
    ///
    /// - `Loaded` (0x03): the load state machine finished loading.
    /// - `Unloaded` (0x04): the load state machine unloaded.
    /// - `ReadyToRun` (0x05): run conditions evaluated, the application may run.
    ///
    /// The overlap is why `HasRunStateMachine::write_rsm` decodes 0x00–0x02
    /// itself instead of handing the received byte to `RunEvent::from` — a
    /// management client must not be able to drive the internal events.
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum RunEvent: u8 {
        Ready           , 0x00, "Ready";
        Restart         , 0x01, "Restart";
        Stop            , 0x02, "Stop";
        Loaded          , 0x03, "Loaded";
        Unloaded        , 0x04, "Unloaded";
        ReadyToRun      , 0x05, "ReadyToRun";
        _,                      "Unknown Run Event 0x{:x}";
    }
);

create_protocol_enum!(
    /// Segment selector inside an `AdditionalLoadControls` load command.
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadSegment: u8 {
        AbsoluteData            , 0x00, "AbsoluteData";
        AbsoluteStack           , 0x01, "AbsoluteStack";
        AbsoluteTask            , 0x02, "AbsoluteTask";
        AbsolutePointer         , 0x03, "AbsolutePointer";
        TaskCtrl1               , 0x04, "TaskCtrl1";
        TaskCtrl2               , 0x05, "TaskCtrl2";
        RelativeData            , 0x0b, "RelativeData";
        Err                     , 0x0c, "Error";
        _,                              "Unknown Load Segment 0x{:x}";
    }
);

// ============================================================================
// Client-direction record builders (03/05/02 §3.31)
// ============================================================================
//
// A management client drives a load state machine by *writing records*,
// either into `PID_LOAD_STATE_CONTROL` (property path,
// `DM_LoadStateMachineWrite_RCo_IO`) or — on the System 7
// masks — into the memory-mapped load-control window at 0104h
// (`DM_LoadStateMachineWrite_RCo_Mem`, §3.31.2). The two paths carry the
// same payload; the memory path prefixes it with the target machine
// packed into the event octet's high nibble. The device-side consumers
// (`Table::write_lsm`, the System 7 memory map's load-control window)
// parse exactly these bytes.

/// Which load state machine a memory-mapped load-control record
/// addresses (03/05/02 §3.31.2). The numbering is fixed by the profile;
/// on the property path the machine is implied by the interface object
/// written instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LsmMachine {
    AddressTable = 1,
    AssociationTable = 2,
    ApplicationProgram = 3,
    /// PEI program / Application Program 2.
    PeiProgram = 4,
}

// Hand-written rather than `create_protocol_enum!` because the record
// coding relies on the explicit discriminants (`tag()` shifts the
// machine number into the high nibble with a plain cast).
impl TryFrom<u8> for LsmMachine {
    type Error = crate::error::UnrecognizedProtocolCode<u8>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AddressTable),
            2 => Ok(Self::AssociationTable),
            3 => Ok(Self::ApplicationProgram),
            4 => Ok(Self::PeiProgram),
            other => Err(crate::error::UnrecognizedProtocolCode(other)),
        }
    }
}

impl core::fmt::Display for LsmMachine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::AddressTable => "address table",
            Self::AssociationTable => "association table",
            Self::ApplicationProgram => "application program",
            Self::PeiProgram => "PEI program",
        })
    }
}

/// An *AllocAbsDataSeg* record body (§3.31.3): the absolute-segment
/// allocation carried by an `AdditionalLoadControls` event.
///
/// ```text
/// [segment_type:1][start_address:2BE][length:2BE]
/// [access_attributes:1][memory_type:1][memory_attributes:1][reserved 00h]
/// ```
///
/// Access attributes carry the write level in bits 0–3 and the read
/// level in bits 4–7 (0xFF = unrestricted); memory type bits 0–2 name
/// the memory class (3 = EEPROM); memory-attribute bit 7 requests
/// checksum control. The defaults produced by [`Self::eeprom`] mirror
/// what ETS sends for System 7 table segments (and what our knxprod
/// generator emits as `Access="255" MemType="3" SegFlags="128"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbsSegment {
    pub segment_type: LoadSegment,
    pub start_address: u16,
    pub length: u16,
    pub access_attributes: u8,
    pub memory_type: u8,
    pub memory_attributes: u8,
}

impl AbsSegment {
    /// Record length: segment type + 8 payload octets.
    pub const RECORD_LEN: usize = 9;

    /// A plain EEPROM data segment with unrestricted access and
    /// checksum control — the shape every System 7 table/application
    /// segment uses.
    pub fn eeprom(start_address: u16, length: u16) -> Self {
        Self {
            segment_type: LoadSegment::AbsoluteData,
            start_address,
            length,
            access_attributes: 0xFF,
            memory_type: 3,
            memory_attributes: 0x80,
        }
    }

    /// Serialize the record body (without any event octet).
    pub fn write(&self) -> [u8; Self::RECORD_LEN] {
        [
            self.segment_type.into(),
            (self.start_address >> 8) as u8,
            self.start_address as u8,
            (self.length >> 8) as u8,
            self.length as u8,
            self.access_attributes,
            self.memory_type,
            self.memory_attributes,
            0x00, // reserved
        ]
    }

    /// Parse a record body (without any event octet) — the inverse of
    /// [`Self::write`].
    ///
    /// Requires the fields through `length`; the attribute octets are
    /// optional and default to zero when a sender truncates the record
    /// after the address information (real management clients have
    /// been seen doing so, and a device only acts on type, start and
    /// length anyway).
    pub fn parse(body: &[u8]) -> Option<Self> {
        let (&segment_type, rest) = body.split_first()?;
        if rest.len() < 4 {
            return None;
        }
        Some(Self {
            segment_type: LoadSegment::from(segment_type),
            start_address: u16::from_be_bytes([rest[0], rest[1]]),
            length: u16::from_be_bytes([rest[2], rest[3]]),
            access_attributes: rest.get(4).copied().unwrap_or(0),
            memory_type: rest.get(5).copied().unwrap_or(0),
            memory_attributes: rest.get(6).copied().unwrap_or(0),
        })
    }
}

/// An *AllocRelDataSeg* record body: the relative-data allocation
/// System B uses (segment type 0Bh, 03/05/01 Resources §4.23.2).
///
/// Unlike the absolute form, the client states only how much memory it
/// needs; the device picks the address and reports it back through
/// `PID_TABLE_REFERENCE`. The body after the type octet is an
/// `McbData`:
///
/// ```text
/// [segment_type:1][requested_memory_size:4BE][mode:1][fill:1][crc:2BE]
/// ```
///
/// `mode` bit 0 asks the device to pre-fill the segment with `fill`.
/// The CRC is the device's to compute at `LoadCompleted`, so a client
/// writes zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelSegment {
    pub requested_memory_size: u32,
    pub mode: u8,
    pub fill: u8,
}

impl RelSegment {
    /// Record length: segment type + the 8-octet MCB.
    pub const RECORD_LEN: usize = 9;

    /// A plain allocation of `size` bytes, no pre-fill — the shape the
    /// master data's `LdCtrlRelSegment` templates request.
    pub fn new(requested_memory_size: u32) -> Self {
        Self { requested_memory_size, mode: 0, fill: 0 }
    }

    /// Serialize the record body (without any event octet).
    pub fn write(&self) -> [u8; Self::RECORD_LEN] {
        let size = self.requested_memory_size.to_be_bytes();
        [
            LoadSegment::RelativeData.into(),
            size[0],
            size[1],
            size[2],
            size[3],
            self.mode,
            self.fill,
            // CRC: computed by the device on LoadCompleted.
            0x00,
            0x00,
        ]
    }
}

/// Builders for the records written to `PID_LOAD_STATE_CONTROL`
/// (property path — `DM_LoadStateMachineWrite_RCo_IO`). The written
/// value's first octet is the [`LoadEvent`]; an
/// `AdditionalLoadControls` event is followed by its segment record.
pub struct LoadControlRecord;

impl LoadControlRecord {
    /// A bare event (`StartLoading`, `LoadCompleted`, `Unload`, …).
    ///
    /// Always the full 10-octet record — the event octet padded with
    /// zeros to the segment-record length. That is how the vendor
    /// conformance templates spell every bare event (`04 00×9` for an
    /// Unload), and real silicon latches the load-control value as a
    /// complete record; a lone event octet is what a lenient software
    /// implementation accepts, not what certified hardware expects.
    pub fn event(event: LoadEvent) -> [u8; 1 + AbsSegment::RECORD_LEN] {
        let mut record = [0u8; 1 + AbsSegment::RECORD_LEN];
        record[0] = event.into();
        record
    }

    /// An `AdditionalLoadControls` event carrying an absolute-segment
    /// allocation record.
    pub fn abs_segment(segment: &AbsSegment) -> [u8; 1 + AbsSegment::RECORD_LEN] {
        let mut record = [0u8; 1 + AbsSegment::RECORD_LEN];
        record[0] = LoadEvent::AdditionalLoadControls.into();
        record[1..].copy_from_slice(&segment.write());
        record
    }

    /// An `AdditionalLoadControls` event carrying an absolute-task
    /// allocation record: `[03][02][start:2][PEI type]
    /// [application id:5]` — the spelling pinned by a Falcon download
    /// trace (2026-08-13: `03 02 4000 00 0083009515`). Unlike the
    /// data-segment record it announces the application's identity,
    /// not a memory range.
    pub fn task_segment(start_address: u16, pei_type: u8, application_id: [u8; 5]) -> [u8; 10] {
        let [start_hi, start_lo] = start_address.to_be_bytes();
        let [m0, m1, a0, a1, version] = application_id;
        [
            LoadEvent::AdditionalLoadControls.into(),
            LoadSegment::AbsoluteTask.into(),
            start_hi,
            start_lo,
            pei_type,
            m0,
            m1,
            a0,
            a1,
            version,
        ]
    }

    /// An `AdditionalLoadControls` event carrying a relative-data
    /// allocation record (System B).
    pub fn rel_segment(segment: &RelSegment) -> [u8; 1 + RelSegment::RECORD_LEN] {
        let mut record = [0u8; 1 + RelSegment::RECORD_LEN];
        record[0] = LoadEvent::AdditionalLoadControls.into();
        record[1..].copy_from_slice(&segment.write());
        record
    }

    /// A TaskPtr record (segment type 3, 03/05/02 §3.31.2): the BCU2
    /// application's entry points — init, save, and the PEI handler
    /// (the MTXML attribute calls it `SerialPtr`):
    /// `[03][03][initAddr:2][saveAddr:2][PEIhandler:2][reserved:2]`.
    pub fn task_ptr(init_ptr: u16, save_ptr: u16, serial_ptr: u16) -> [u8; 10] {
        let [init_hi, init_lo] = init_ptr.to_be_bytes();
        let [save_hi, save_lo] = save_ptr.to_be_bytes();
        let [serial_hi, serial_lo] = serial_ptr.to_be_bytes();
        [
            LoadEvent::AdditionalLoadControls.into(),
            LoadSegment::AbsolutePointer.into(),
            init_hi,
            init_lo,
            save_hi,
            save_lo,
            serial_hi,
            serial_lo,
            0x00,
            0x00,
        ]
    }

    /// A TaskCtrl1 record (segment type 4, 03/05/02 §3.31.2): where the
    /// BCU2 application's interface-object list lives —
    /// `[03][04][interface object address:2][count:1][reserved:5]`.
    pub fn task_ctrl1(address: u16, count: u8) -> [u8; 10] {
        let [addr_hi, addr_lo] = address.to_be_bytes();
        [
            LoadEvent::AdditionalLoadControls.into(),
            LoadSegment::TaskCtrl1.into(),
            addr_hi,
            addr_lo,
            count,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    }

    /// A TaskCtrl2 record (segment type 5, 03/05/02 §3.31.2): the BCU2
    /// group-object callback and table pointers —
    /// `[03][05][callbackAddr:2][CommObjPtr:2][CommObjSegPtr1:2][CommObjSegPtr2:2]`.
    pub fn task_ctrl2(callback: u16, address: u16, seg0: u16, seg1: u16) -> [u8; 10] {
        let [cb_hi, cb_lo] = callback.to_be_bytes();
        let [addr_hi, addr_lo] = address.to_be_bytes();
        let [s0_hi, s0_lo] = seg0.to_be_bytes();
        let [s1_hi, s1_lo] = seg1.to_be_bytes();
        [
            LoadEvent::AdditionalLoadControls.into(),
            LoadSegment::TaskCtrl2.into(),
            cb_hi,
            cb_lo,
            addr_hi,
            addr_lo,
            s0_hi,
            s0_lo,
            s1_hi,
            s1_lo,
        ]
    }
}

/// Builders for the records written to the System 7 memory-mapped
/// load-control window at 0104h. Identical payloads to
/// [`LoadControlRecord`], but the first octet packs
/// `[machine:4][event:4]` (§3.31.2) since plain memory writes carry no
/// interface-object context to name the target machine.
pub struct MemLoadControlRecord;

impl MemLoadControlRecord {
    fn tag(machine: LsmMachine, event: LoadEvent) -> u8 {
        ((machine as u8) << 4) | (u8::from(event) & 0x0F)
    }

    /// Split a record's first octet into its machine number and load
    /// event — the inverse of the tag every builder here writes.
    ///
    /// The machine comes back as the raw 4-bit number rather than an
    /// [`LsmMachine`]: which numbers exist is a per-device fact (a
    /// device may run more or fewer machines than the four the enum
    /// names), so range checking is the caller's.
    pub fn split_tag(tag: u8) -> (u8, LoadEvent) {
        (tag >> 4, LoadEvent::from(tag & 0x0F))
    }

    /// The memory-mapped record is always 0Bh octets — 03/05/02
    /// §3.31.2 writes `A_Memory_Write (addr = 0104h, length = 0Bh)`
    /// for every event, and real System 7 silicon latches the window
    /// only as that complete record (our own stack is lenient, which
    /// is how shorter spellings survived every software tier).
    pub const RECORD_LEN: usize = 11;

    /// A bare event for the given machine: the tagged octet, then ten
    /// reserved zero octets (03/05/02 §3.31.2, "LoadEvent: Unload").
    pub fn event(machine: LsmMachine, event: LoadEvent) -> [u8; Self::RECORD_LEN] {
        let mut record = [0u8; Self::RECORD_LEN];
        record[0] = Self::tag(machine, event);
        record
    }

    /// An `AdditionalLoadControls` event carrying an absolute-segment
    /// allocation record for the given machine.
    ///
    /// Unlike the property-path record, the memory-mapped spelling
    /// carries a **segment ID** octet between the segment type and
    /// the start address (03/05/02 §3.31.2, "LoadEvent:
    /// AllocAbsDataSeg": `[L3][type][ID][start:2][length:2][access]
    /// [memory type][memory attributes][reserved]`). The ID is 00h
    /// for the single segment per machine this procedure supports.
    pub fn abs_segment(machine: LsmMachine, segment: &AbsSegment) -> [u8; Self::RECORD_LEN] {
        let property_form = segment.write();
        let mut record = [0u8; Self::RECORD_LEN];
        record[0] = Self::tag(machine, LoadEvent::AdditionalLoadControls);
        record[1] = property_form[0]; // segment type
        record[2] = 0x00; // segment ID
        record[3..].copy_from_slice(&property_form[1..]);
        record
    }

    /// The tagged 11-octet spelling of a 10-octet property-path
    /// `AdditionalLoadControls` record: the machine/event tag, then the
    /// property record's payload with the segment ID octet inserted
    /// after the segment type (§3.31.2 spells every additional-control
    /// record `[machine/event][type][ID][payload]`).
    fn additional_control(machine: LsmMachine, property_form: [u8; 10]) -> [u8; Self::RECORD_LEN] {
        let mut record = [0u8; Self::RECORD_LEN];
        record[0] = Self::tag(machine, LoadEvent::AdditionalLoadControls);
        record[1] = property_form[1]; // segment type
        record[2] = 0x00; // segment ID
        record[3..].copy_from_slice(&property_form[2..]);
        record
    }

    /// The task-segment allocation for the memory window, mirroring
    /// [`Self::abs_segment`].
    pub fn task_segment(
        machine: LsmMachine,
        start_address: u16,
        pei_type: u8,
        application_id: [u8; 5],
    ) -> [u8; Self::RECORD_LEN] {
        Self::additional_control(machine, LoadControlRecord::task_segment(start_address, pei_type, application_id))
    }

    /// The TaskPtr record for the memory window (see
    /// [`LoadControlRecord::task_ptr`]).
    pub fn task_ptr(machine: LsmMachine, init_ptr: u16, save_ptr: u16, serial_ptr: u16) -> [u8; Self::RECORD_LEN] {
        Self::additional_control(machine, LoadControlRecord::task_ptr(init_ptr, save_ptr, serial_ptr))
    }

    /// The TaskCtrl1 record for the memory window (see
    /// [`LoadControlRecord::task_ctrl1`]).
    pub fn task_ctrl1(machine: LsmMachine, address: u16, count: u8) -> [u8; Self::RECORD_LEN] {
        Self::additional_control(machine, LoadControlRecord::task_ctrl1(address, count))
    }

    /// The TaskCtrl2 record for the memory window (see
    /// [`LoadControlRecord::task_ctrl2`]).
    pub fn task_ctrl2(
        machine: LsmMachine,
        callback: u16,
        address: u16,
        seg0: u16,
        seg1: u16,
    ) -> [u8; Self::RECORD_LEN] {
        Self::additional_control(machine, LoadControlRecord::task_ctrl2(callback, address, seg0, seg1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_control_transition_follows_recommended_table() {
        use LoadAction::{Alloc, LoadEnd, LoadStart, None, Unload};
        use LoadEvent::{AdditionalLoadControls, LoadCompleted, NoOp, StartLoading};
        use LoadState::{Err, LoadCompleting, Loaded, Loading, Unloaded, Unloading};

        let cases = [
            (Unloaded, NoOp, Unloaded, None),
            (Loaded, NoOp, Loaded, None),
            (Loading, NoOp, Loading, None),
            (Err, NoOp, Err, None),
            (Unloading, NoOp, Unloading, None),
            (LoadCompleting, NoOp, LoadCompleting, None),
            (Unloaded, StartLoading, Loading, LoadStart),
            (Loaded, StartLoading, Loading, LoadStart),
            (Loading, StartLoading, Loading, None),
            (Err, StartLoading, Err, None),
            (Unloading, StartLoading, Err, None),
            (LoadCompleting, StartLoading, Err, None),
            (Unloaded, LoadCompleted, Unloaded, None),
            (Loaded, LoadCompleted, Loaded, None),
            (Loading, LoadCompleted, Loaded, LoadEnd),
            (Err, LoadCompleted, Err, None),
            (Unloading, LoadCompleted, Err, None),
            (LoadCompleting, LoadCompleted, Err, None),
            (Unloaded, AdditionalLoadControls, Unloaded, None),
            (Loaded, AdditionalLoadControls, Err, None),
            (Loading, AdditionalLoadControls, Loading, Alloc),
            (Err, AdditionalLoadControls, Err, None),
            (Unloading, AdditionalLoadControls, Err, None),
            (LoadCompleting, AdditionalLoadControls, Err, None),
            (Unloaded, LoadEvent::Unload, Unloaded, Unload),
            (Loaded, LoadEvent::Unload, Unloaded, Unload),
            (Loading, LoadEvent::Unload, Unloaded, Unload),
            (Err, LoadEvent::Unload, Unloaded, Unload),
            (Unloading, LoadEvent::Unload, Unloaded, Unload),
            (LoadCompleting, LoadEvent::Unload, Unloaded, Unload),
        ];

        for (state, event, expected_state, expected_action) in cases {
            assert_eq!(load_control_transition(state, event), (expected_state, expected_action));
        }
    }

    #[test]
    fn unknown_load_events_are_ignored() {
        let states = [
            LoadState::Unloaded,
            LoadState::Loaded,
            LoadState::Loading,
            LoadState::Err,
            LoadState::Unloading,
            LoadState::LoadCompleting,
        ];

        for event in [LoadEvent::from(0x05), LoadEvent::from(0xFF)] {
            for state in states {
                assert_eq!(load_control_transition(state, event), (state, LoadAction::None));
            }
        }
    }

    #[test]
    fn optional_states_and_unknown_event_codings_match_table_92_and_93() {
        assert_eq!(LoadState::try_from(0x04), Ok(LoadState::Unloading));
        assert_eq!(LoadState::try_from(0x05), Ok(LoadState::LoadCompleting));
        assert_eq!(LoadEvent::from(0x05), LoadEvent::Other(0x05));
    }

    #[test]
    fn abs_segment_record_bytes() {
        // The RT8 address table segment ETS allocates on a System 7
        // download: EEPROM at 4000h, 12 octets.
        let seg = AbsSegment::eeprom(0x4000, 12);
        assert_eq!(seg.write(), [0x00, 0x40, 0x00, 0x00, 0x0C, 0xFF, 0x03, 0x80, 0x00]);
    }

    /// The BCU2 task records, against the §3.31.2 tables (the values
    /// are the MV-0021 master template's / the L&J product's).
    #[test]
    fn bcu2_task_records() {
        // TaskPtr: InitPtr=284, SavePtr=285, SerialPtr=0.
        assert_eq!(LoadControlRecord::task_ptr(284, 285, 0), [
            0x03, 0x03, 0x01, 0x1C, 0x01, 0x1D, 0x00, 0x00, 0x00, 0x00
        ]);
        // TaskCtrl1: Address=0, Count=0.
        assert_eq!(LoadControlRecord::task_ctrl1(0, 0), [0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0]);
        // TaskCtrl2: Callback=20609 (5081h), Address=282, Seg0=Seg1=208.
        assert_eq!(LoadControlRecord::task_ctrl2(20609, 282, 208, 208), [
            0x03, 0x05, 0x50, 0x81, 0x01, 0x1A, 0x00, 0xD0, 0x00, 0xD0
        ]);
        // The memory-window spelling tags the machine and inserts the
        // segment-ID octet.
        assert_eq!(MemLoadControlRecord::task_ptr(LsmMachine::ApplicationProgram, 284, 285, 0), [
            0x33, 0x03, 0x00, 0x01, 0x1C, 0x01, 0x1D, 0x00, 0x00, 0x00, 0x00
        ]);
    }

    /// Bare events are the event octet zero-padded to the 10-octet
    /// record — the exact spelling the vendor conformance templates
    /// use (`04 00×9` for an Unload written to PID_LOAD_STATE_CONTROL).
    #[test]
    fn property_path_records() {
        assert_eq!(LoadControlRecord::event(LoadEvent::StartLoading), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(LoadControlRecord::event(LoadEvent::LoadCompleted), [2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(LoadControlRecord::event(LoadEvent::Unload), [4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let record = LoadControlRecord::abs_segment(&AbsSegment::eeprom(0xB000, 0x0100));
        assert_eq!(record, [0x03, 0x00, 0xB0, 0x00, 0x01, 0x00, 0xFF, 0x03, 0x80, 0x00]);
    }

    #[test]
    fn rel_segment_record_bytes() {
        // The System B templates request e.g. 2 octets for a table
        // whose real size the merged product fragment supplies.
        let seg = RelSegment::new(2);
        assert_eq!(seg.write(), [0x0B, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);

        let record = LoadControlRecord::rel_segment(&RelSegment::new(0x1234));
        assert_eq!(record, [0x03, 0x0B, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn rel_segment_carries_the_fill_request() {
        let seg = RelSegment { requested_memory_size: 4, mode: 1, fill: 0xAA };
        assert_eq!(seg.write(), [0x0B, 0x00, 0x00, 0x00, 0x04, 0x01, 0xAA, 0x00, 0x00]);
    }

    #[test]
    fn memory_path_records_pack_machine_and_event() {
        // [machine:4][event:4] — the System 7 memory map splits these
        // nibbles back apart and feeds `[event][payload]` to the
        // target machine's write_lsm.
        // Bare events are the 0Bh-octet record §3.31.2 spells out:
        // the tag, then ten reserved zeros.
        assert_eq!(MemLoadControlRecord::event(LsmMachine::AddressTable, LoadEvent::StartLoading), [
            0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
        assert_eq!(MemLoadControlRecord::event(LsmMachine::AssociationTable, LoadEvent::LoadCompleted), [
            0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
        assert_eq!(MemLoadControlRecord::event(LsmMachine::ApplicationProgram, LoadEvent::Unload), [
            0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);
        assert_eq!(MemLoadControlRecord::event(LsmMachine::PeiProgram, LoadEvent::Unload), [
            0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);

        // The allocation record carries the segment ID octet the
        // property spelling does not: §3.31.2 AllocAbsDataSeg is
        // [L3][type][ID][start:2][length:2][AA][TT][MM][00].
        let record = MemLoadControlRecord::abs_segment(LsmMachine::AssociationTable, &AbsSegment::eeprom(0x5000, 34));
        assert_eq!(record, [0x23, 0x00, 0x00, 0x50, 0x00, 0x00, 0x22, 0xFF, 0x03, 0x80, 0x00]);
        assert_eq!(record.len(), MemLoadControlRecord::RECORD_LEN, "the window write is always 0Bh octets");
    }

    #[test]
    fn abs_segment_parse_round_trip() {
        let segment = AbsSegment::eeprom(0x4000, 0x0123);
        assert_eq!(AbsSegment::parse(&segment.write()), Some(segment));

        // Truncated after the length: attributes default to zero.
        let truncated = AbsSegment::parse(&segment.write()[..5]).expect("type + start + length are present");
        assert_eq!(truncated.start_address, 0x4000);
        assert_eq!(truncated.length, 0x0123);
        assert_eq!(truncated.access_attributes, 0);

        // Too short to carry the length.
        assert_eq!(AbsSegment::parse(&segment.write()[..4]), None);
    }

    #[test]
    fn mem_record_split_tag_round_trip() {
        let record = MemLoadControlRecord::event(LsmMachine::ApplicationProgram, LoadEvent::StartLoading);
        assert_eq!(MemLoadControlRecord::split_tag(record[0]), (3, LoadEvent::StartLoading));
        // Machine numbers beyond the named four pass through raw.
        assert_eq!(MemLoadControlRecord::split_tag(0x54), (5, LoadEvent::Unload));
    }
}
