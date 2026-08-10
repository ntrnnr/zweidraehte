//! Load/Run State Machine wire enums.
//!
//! The pure protocol vocabulary of the load and run state machines:
//!
//! - [`LoadState`] / [`RunState`] — the state values read back from
//!   `PID_LOAD_STATE_CONTROL` / `PID_RUN_STATE_CONTROL`.
//! - [`LoadEvent`] / [`RunEvent`] — the control commands written to those
//!   properties (and the internal events the run machine reacts to).
//! - [`LoadSegment`] — the segment selector inside an `AdditionalLoadControls`
//!   load command.
//!
//! Only the wire encoding lives here. The state machines that consume and
//! transition these values (`Table<T>`, `RunnableApplication<T>`, the
//! `Has*StateMachine` traits, and the non-wire `LoadAction` / `RunAction` /
//! `LoadError` types) stay in the device crate's `objects::tables`.

use serde::{Deserialize, Serialize};

create_protocol_enum!(
    /// Load state of an interface object (`PID_LOAD_STATE_CONTROL` readback).
    #[derive(Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
    pub enum LoadState: u8 {
        Unloaded        , 0x00, "Unloaded";
        Loaded          , 0x01, "Loaded";
        Loading         , 0x02, "Loading";
        Err             , 0x03, "Error";
    }
);

create_protocol_enum!(
    /// Load control command written to `PID_LOAD_STATE_CONTROL`.
    #[derive(Eq, PartialEq, Copy, Clone)]
    pub enum LoadEvent: u8 {
        NoOp                    , 0x00, "NoOp";
        StartLoading            , 0x01, "StartLoading";
        LoadCompleted           , 0x02, "LoadCompleted";
        AdditionalLoadControls  , 0x03, "AdditionalLoadControls";
        Unload                  , 0x04, "Unload";
        Err                     , 0x05, "Error";
        _,                              "Unknown Load Event 0x{:x}";
    }
);

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
// `DM_LoadStateMachineWrite_RCo_IO`) or — on the System 7 / BIM M112
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
    pub fn event(event: LoadEvent) -> [u8; 1] {
        [event.into()]
    }

    /// An `AdditionalLoadControls` event carrying an absolute-segment
    /// allocation record.
    pub fn abs_segment(segment: &AbsSegment) -> [u8; 1 + AbsSegment::RECORD_LEN] {
        let mut record = [0u8; 1 + AbsSegment::RECORD_LEN];
        record[0] = LoadEvent::AdditionalLoadControls.into();
        record[1..].copy_from_slice(&segment.write());
        record
    }

    /// An `AdditionalLoadControls` event carrying a relative-data
    /// allocation record (System B).
    pub fn rel_segment(segment: &RelSegment) -> [u8; 1 + RelSegment::RECORD_LEN] {
        let mut record = [0u8; 1 + RelSegment::RECORD_LEN];
        record[0] = LoadEvent::AdditionalLoadControls.into();
        record[1..].copy_from_slice(&segment.write());
        record
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

    /// A bare event for the given machine.
    pub fn event(machine: LsmMachine, event: LoadEvent) -> [u8; 1] {
        [Self::tag(machine, event)]
    }

    /// An `AdditionalLoadControls` event carrying an absolute-segment
    /// allocation record for the given machine.
    pub fn abs_segment(machine: LsmMachine, segment: &AbsSegment) -> [u8; 1 + AbsSegment::RECORD_LEN] {
        let mut record = [0u8; 1 + AbsSegment::RECORD_LEN];
        record[0] = Self::tag(machine, LoadEvent::AdditionalLoadControls);
        record[1..].copy_from_slice(&segment.write());
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_segment_record_bytes() {
        // The RT8 address table segment ETS allocates on a System 7
        // download: EEPROM at 4000h, 12 octets.
        let seg = AbsSegment::eeprom(0x4000, 12);
        assert_eq!(seg.write(), [0x00, 0x40, 0x00, 0x00, 0x0C, 0xFF, 0x03, 0x80, 0x00]);
    }

    #[test]
    fn property_path_records() {
        assert_eq!(LoadControlRecord::event(LoadEvent::StartLoading), [0x01]);
        assert_eq!(LoadControlRecord::event(LoadEvent::LoadCompleted), [0x02]);
        assert_eq!(LoadControlRecord::event(LoadEvent::Unload), [0x04]);

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
        assert_eq!(MemLoadControlRecord::event(LsmMachine::AddressTable, LoadEvent::StartLoading), [0x11]);
        assert_eq!(MemLoadControlRecord::event(LsmMachine::AssociationTable, LoadEvent::LoadCompleted), [0x22]);
        assert_eq!(MemLoadControlRecord::event(LsmMachine::ApplicationProgram, LoadEvent::Unload), [0x34]);
        assert_eq!(MemLoadControlRecord::event(LsmMachine::PeiProgram, LoadEvent::Unload), [0x44]);

        let record = MemLoadControlRecord::abs_segment(LsmMachine::AssociationTable, &AbsSegment::eeprom(0x5000, 34));
        assert_eq!(record[0], 0x23);
        assert_eq!(&record[1..], &AbsSegment::eeprom(0x5000, 34).write());
        // Fits the 12-octet load-control window with room to spare.
        assert!(record.len() <= 12);
    }
}
