//! The download instruction IR.
//!
//! A deliberately small, executable vocabulary — the intersection of
//! what the 03/05/02 download procedures need and what our management
//! surface can perform. Procedure *sources* (parsed master data,
//! product `LoadProcedures`) all compile down to this; the
//! [`Downloader`](super::Downloader) only ever sees IR.
//!
//! Load state machines retain the address form their procedure used.
//! Classic machines use an interface-object index; profile modules can
//! exist only in the extended `(object type, occurrence)` address space.
//! The memory-mapped path accepts only the indexed form and narrows it to
//! `LsmMachine` when it packs the record nibble.

use zweidraehte_proto::messages::apdu::load_control::{AbsSegment, LoadEvent, RelSegment};

/// The protocol address of a load state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LsmTarget {
    /// An indexed interface object. On the legacy memory path this is also
    /// the load-machine nibble.
    Index(u8),
    /// An extended interface object reached by type and one-based occurrence.
    ObjectType { object_type: u16, occurrence: u16 },
}

impl From<u8> for LsmTarget {
    fn from(value: u8) -> Self {
        Self::Index(value)
    }
}

impl core::fmt::Display for LsmTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Index(index) => write!(f, "{index}"),
            Self::ObjectType { object_type, occurrence } => {
                write!(f, "object type {object_type:#06X}, occurrence {occurrence}")
            }
        }
    }
}

/// The application identity a task-segment record announces:
/// `[manufacturer:2][application number:2][version:1]` plus the PEI
/// type — resolved from the product, because the load-procedure XML
/// carries only the address and ETS synthesizes the rest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TaskIdentity {
    pub application_id: [u8; 5],
    pub pei_type: u8,
}

/// One step of a download procedure.
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    /// Marker: the procedure runs on an open transport connection.
    /// The engine executes inside one, so this is a no-op — kept in
    /// the IR so converted master-data procedures stay recognizably
    /// congruent with their source (`LdCtrlConnect`).
    Connect,
    /// Marker counterpart to [`Self::Connect`] (`LdCtrlDisconnect`);
    /// the orchestration closes the connection after the run.
    Disconnect,
    /// Read a property and require an exact value — the device
    /// identity guard (`LdCtrlCompareProp` with inline data).
    CompareProperty { obj_idx: u8, prop_id: u16, expected: Vec<u8> },
    /// Drive a load state machine: `StartLoading`, `LoadCompleted`,
    /// `Unload` (`LdCtrlLoad` / `LdCtrlLoadCompleted` /
    /// `LdCtrlUnload`). The engine verifies the resulting state.
    LsmEvent { lsm: LsmTarget, event: LoadEvent },
    /// Allocate an absolute segment on a machine in `Loading`
    /// (`LdCtrlAbsSegment` → the §3.31.3 AllocAbsDataSeg record).
    AbsSegment { lsm: LsmTarget, segment: AbsSegment },
    /// Allocate a relative segment (`LdCtrlRelSegment`, System B): the
    /// client asks for a size, the device picks the address and reports
    /// it through `PID_TABLE_REFERENCE`.
    RelSegment { lsm: LsmTarget, segment: RelSegment },
    /// Announce the task segment (`LdCtrlTaskSegment`). The record
    /// carries the application's identity — the XML holds only the
    /// address, and ETS stamps in PEI type and ApplicationID from the
    /// program element (Falcon trace 2026-08-13:
    /// `03 02 4000 00 0083009515`), so the IR carries them resolved.
    /// System 7 devices accept the record without acting on it; ETS
    /// sends it, so faithful procedures include it.
    TaskSegment { lsm: LsmTarget, address: u16, pei_type: u8, application_id: [u8; 5] },
    /// Write `length` bytes from the assembled device image at
    /// `address` — the explicit form of ETS's implicit data phase, and
    /// the lowering of a mask template's `LdCtrlWriteMem` without
    /// inline data. The window is a span of *device* memory; only the
    /// parts the image covers are written.
    WriteImage { address: u16, length: u16, verify: bool },
    /// Read device memory into the image's gaps (`LdCtrlLoadImageMem`,
    /// the BCU-era masks): bytes the compile step produced stay, bytes
    /// it did not are taken from the device — so a later
    /// [`Self::WriteImage`] over the same span writes them back
    /// unchanged.
    ReadIntoImage { address: u16, length: u16 },
    /// Write literal bytes (`LdCtrlWriteMem` with inline data).
    WriteMemory { address: u16, data: Vec<u8>, verify: bool },
    /// Read memory and require an exact value (`LdCtrlCompareMem`).
    CompareMemory { address: u16, expected: Vec<u8> },
    /// Write the object's relative image content
    /// (`LdCtrlWriteRelMem`, System B): the bytes compiled for this
    /// interface object, placed at the base the device allocated.
    WriteRelImage { obj_idx: u8, offset: u32, length: u32, verify: bool },
    /// Read a property into the tool's working image
    /// (`LdCtrlLoadImageProp`). Used to pick up an existing
    /// allocation's base address before a partial download, so the
    /// tables are rewritten in place rather than reallocated.
    LoadImageProperty { obj_idx: u8, prop_id: u16 },
    /// Write a property value (`LdCtrlWriteProp` with inline data).
    WriteProperty { obj_idx: u8, prop_id: u16, start_idx: u16, count: u16, data: Vec<u8>, verify: bool },
    /// Resolve a property-backed parameter data block during compilation
    /// (`LdCtrlWriteProp` without `InlineData`).
    WritePropertyData { target: LsmTarget, prop_id: u16, start_idx: u16, count: u16, verify: bool },
    /// Confirmed AN163 property write addressed by object type and
    /// occurrence. Synthesized security configuration uses this for the
    /// Security IO tables.
    WritePropertyExt {
        object_type: u16,
        occurrence: u16,
        prop_id: u16,
        start_idx: u16,
        count: u16,
        data: Vec<u8>,
        verify: bool,
    },
    /// Extended function-property command addressed by type/occurrence.
    FunctionPropertyExt { object_type: u16, occurrence: u16, prop_id: u16, service_id: u8, service_info: u8 },
    /// The BCU2 application's entry points (`LdCtrlTaskPtr` → the
    /// §3.31.2 TaskPtr record, segment type 3). Like
    /// [`Self::TaskSegment`], an informational record: it does not
    /// transition the machine, so the engine sends it without a state
    /// poll.
    TaskPointers { lsm: LsmTarget, init_ptr: u16, save_ptr: u16, serial_ptr: u16 },
    /// The BCU2 application's interface-object list (`LdCtrlTaskCtrl1`
    /// → TaskCtrl1 record, segment type 4).
    TaskControl1 { lsm: LsmTarget, address: u16, count: u8 },
    /// The BCU2 group-object callback and table pointers
    /// (`LdCtrlTaskCtrl2` → TaskCtrl2 record, segment type 5).
    TaskControl2 { lsm: LsmTarget, callback: u16, address: u16, seg0: u16, seg1: u16 },
    /// Basic restart (`LdCtrlRestart` on the BCU-era procedures); the
    /// device reboots and the transport connection dies with it.
    Restart,
    /// Confirmed restart (master reset erase code 01h). System B gives the
    /// otherwise unqualified `LdCtrlRestart` this meaning; unlike a basic
    /// restart it returns the device's required processing time.
    ConfirmedRestart,
    /// Fixed wait (`LdCtrlDelay`).
    Delay { milliseconds: u32 },
    /// Error-mapping window (`LdCtrlMapError`): `mapped == 0` opens a
    /// window in which a failing instruction is tolerated instead of
    /// aborting the run; `mapped == original` closes it. The templates
    /// use this around steps that legitimately fail on some devices —
    /// MV-07B0's Unload-all guards `LdCtrlUnload LsmIdx="5"` this way,
    /// because not every 07B0 device has a fifth machine.
    ///
    /// ETS matches the *specific* numeric error code; our errors are
    /// typed rather than numbered, so the interpreter tolerates any
    /// failure inside the window. Every published window spans exactly
    /// one instruction, so the loss of precision is theoretical.
    MapError { original: u32, mapped: u32 },
}

impl Instruction {
    /// A short human label for progress displays — what a UI shows
    /// while the step runs, phrased for someone watching a download,
    /// not for someone debugging the IR.
    pub fn describe(&self) -> String {
        match self {
            Self::Connect => "Connect and authorize".to_string(),
            Self::Disconnect => "Disconnect".to_string(),
            Self::CompareProperty { prop_id, .. } => format!("Check device identity (PID {prop_id})"),
            Self::LsmEvent { lsm, event } => {
                let verb = match event {
                    LoadEvent::StartLoading => "Start loading",
                    LoadEvent::LoadCompleted => "Finish loading",
                    LoadEvent::Unload => "Unload",
                    _ => "Signal",
                };
                format!("{verb} machine {lsm}")
            }
            Self::AbsSegment { lsm, segment } => {
                format!("Allocate {} bytes at {:#06X} (machine {lsm})", segment.length, segment.start_address)
            }
            Self::RelSegment { lsm, segment } => {
                format!("Request {} bytes on object {lsm}", segment.requested_memory_size)
            }
            Self::TaskSegment { lsm, address, .. } => format!("Announce task at {address:#06X} (machine {lsm})"),
            Self::WriteImage { address, length, .. } => format!("Write {length} bytes at {address:#06X}"),
            Self::ReadIntoImage { address, length } => {
                format!("Read {length} bytes at {address:#06X} from the device")
            }
            Self::WriteMemory { address, data, .. } => format!("Write {} bytes at {address:#06X}", data.len()),
            Self::CompareMemory { address, .. } => format!("Verify memory at {address:#06X}"),
            Self::WriteRelImage { obj_idx, .. } => format!("Write object {obj_idx}'s table"),
            Self::LoadImageProperty { obj_idx, prop_id } => {
                format!("Read back object {obj_idx}'s property {prop_id}")
            }
            Self::WriteProperty { obj_idx, prop_id, .. } => format!("Write object {obj_idx}'s property {prop_id}"),
            Self::WritePropertyData { target, prop_id, .. } => {
                format!("Write {target}'s parameter property {prop_id}")
            }
            Self::WritePropertyExt { object_type, occurrence, prop_id, .. } => {
                format!("Write type {object_type:#06X}/{occurrence} property {prop_id}")
            }
            Self::FunctionPropertyExt { object_type, occurrence, prop_id, .. } => {
                format!("Command type {object_type:#06X}/{occurrence} property {prop_id}")
            }
            Self::TaskPointers { lsm, .. } => format!("Announce task pointers (machine {lsm})"),
            Self::TaskControl1 { lsm, .. } => format!("Announce task control block 1 (machine {lsm})"),
            Self::TaskControl2 { lsm, .. } => format!("Announce task control block 2 (machine {lsm})"),
            Self::Restart => "Restart the device".to_string(),
            Self::ConfirmedRestart => "Confirmed restart the device".to_string(),
            Self::Delay { milliseconds } => format!("Wait {milliseconds} ms"),
            Self::MapError { .. } => "Adjust error tolerance".to_string(),
        }
    }
}

// ============================================================================
// Master-data conversion (feature `master-data`)
// ============================================================================

mod convert {
    use super::Instruction;
    use super::LsmTarget;
    use super::TaskIdentity;
    use crate::error::{Error, Result};
    use zweidraehte_knxprod::schema as ld;
    use zweidraehte_proto::messages::apdu::load_control::{AbsSegment, LoadEvent, LoadSegment, RelSegment};

    /// Convert a load-control stream into executable IR.
    ///
    /// Takes a plain `&[LoadControl]` because the two sources spell
    /// the same vocabulary in different wrappers: master data has
    /// `Procedure`, product MTXML has `LoadProcedure`. One converter
    /// serves both.
    ///
    /// Only the instruction subset a remote download can perform is
    /// executable; unresolvable tool-side scaffolding (`Merge`,
    /// coupler filter tables) returns
    /// [`Error::UnsupportedInstruction`] — `Merge` in particular must
    /// be resolved by [`assemble`](crate::download::assemble) before
    /// execution, never reached at run time. A control that needs no
    /// runtime counterpart at all (`SetControlVariable`) converts to
    /// nothing.
    pub fn controls_to_instructions(controls: &[ld::LoadControl], task: TaskIdentity) -> Result<Vec<Instruction>> {
        controls.iter().filter_map(|control| convert_control(control, task).transpose()).collect()
    }

    /// Preserve exactly one of the two address forms admitted by the schema.
    fn lsm(lsm_idx: Option<u8>, object_type: Option<u16>, occurrence: Option<u8>) -> Result<LsmTarget> {
        match (lsm_idx, object_type, occurrence) {
            (Some(index), None, None) => Ok(LsmTarget::Index(index)),
            (None, Some(object_type), Some(occurrence)) if occurrence != 0 => {
                Ok(LsmTarget::ObjectType { object_type, occurrence: u16::from(occurrence) })
            }
            (None, Some(_), Some(0)) => Err(Error::Parse("load state machine occurrence must be one-based")),
            (None, Some(_), None) => Err(Error::Parse("load state machine object type has no occurrence")),
            (None, None, _) => Err(Error::Parse("load state machine has no address")),
            _ => Err(Error::Parse("load state machine mixes index and object-type addressing")),
        }
    }

    fn hex_bytes(s: &str) -> Result<Vec<u8>> {
        if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Parse("InlineData is not an even-length hex string"));
        }
        Ok(s.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("chunks of an ASCII-checked str"), 16)
                    .expect("both chars verified as hex digits")
            })
            .collect())
    }

    fn convert_control(control: &ld::LoadControl, task: TaskIdentity) -> Result<Option<Instruction>> {
        use ld::LoadControl as C;
        Ok(Some(match control {
            C::LdCtrlConnect(_) => Instruction::Connect,
            C::LdCtrlDisconnect(_) => Instruction::Disconnect,
            C::LdCtrlRestart(_) => Instruction::Restart,
            C::LdCtrlDelay(d) => Instruction::Delay { milliseconds: d.milli_seconds },
            C::LdCtrlLoad(l) => {
                Instruction::LsmEvent { lsm: lsm(l.lsm_idx, l.obj_type, l.occurrence)?, event: LoadEvent::StartLoading }
            }
            C::LdCtrlLoadCompleted(l) => Instruction::LsmEvent {
                lsm: lsm(l.lsm_idx, l.obj_type, l.occurrence)?,
                event: LoadEvent::LoadCompleted,
            },
            C::LdCtrlUnload(l) => {
                Instruction::LsmEvent { lsm: lsm(l.lsm_idx, l.obj_type, l.occurrence)?, event: LoadEvent::Unload }
            }
            C::LdCtrlAbsSegment(s) => Instruction::AbsSegment {
                lsm: s.lsm_idx.into(),
                segment: AbsSegment {
                    segment_type: LoadSegment::from(s.seg_type),
                    start_address: s.address,
                    length: s.size,
                    access_attributes: s.access,
                    memory_type: s.mem_type,
                    memory_attributes: s.seg_flags,
                },
            },
            C::LdCtrlTaskSegment(t) => Instruction::TaskSegment {
                lsm: t.lsm_idx.into(),
                address: t.address,
                pei_type: task.pei_type,
                application_id: task.application_id,
            },
            C::LdCtrlCompareProp(p) => {
                let obj_idx = p.obj_idx.ok_or(Error::UnsupportedInstruction("CompareProp by ObjType not supported"))?;
                let expected = match (&p.inline_data, &p.range) {
                    (Some(data), None) => hex_bytes(data)?,
                    // Range comparisons need typed decoding of the
                    // property value — not needed by any procedure we
                    // execute today.
                    _ => return Err(Error::UnsupportedInstruction("CompareProp without inline data")),
                };
                Instruction::CompareProperty { obj_idx, prop_id: p.prop_id as u16, expected }
            }
            C::LdCtrlWriteMem(w) => {
                if w.address_space.is_some() {
                    // LcFilter / LcSlave are line-coupler address
                    // spaces reached through different services.
                    return Err(Error::UnsupportedInstruction("WriteMem into a non-standard address space"));
                }
                let address = u16::try_from(w.address).map_err(|_| Error::Parse("WriteMem address beyond 16 bits"))?;
                match &w.inline_data {
                    Some(data) => Instruction::WriteMemory { address, data: hex_bytes(data)?, verify: w.verify },
                    // Without inline data the bytes come from the
                    // assembled image; the size in the template is a
                    // clamp-to-blob upper bound.
                    None => Instruction::WriteImage {
                        address,
                        length: u16::try_from(w.size).unwrap_or(u16::MAX),
                        verify: w.verify,
                    },
                }
            }
            C::LdCtrlCompareMem(cm) => Instruction::CompareMemory {
                address: u16::try_from(cm.address).map_err(|_| Error::Parse("CompareMem address beyond 16 bits"))?,
                expected: hex_bytes(&cm.inline_data)?,
            },
            C::LdCtrlWriteProp(w) => {
                let target = match (w.obj_idx, w.obj_type) {
                    (Some(index), None) => LsmTarget::Index(index),
                    (None, Some(object_type)) => {
                        LsmTarget::ObjectType { object_type, occurrence: w.occurrence.unwrap_or(0) }
                    }
                    (None, None) => return Err(Error::Parse("WriteProp has no object address")),
                    (Some(_), Some(_)) => return Err(Error::Parse("WriteProp mixes object addressing modes")),
                };
                let start_idx = w.start_element.unwrap_or(1);
                let count = w.count.unwrap_or(1);
                let verify = w.verify.unwrap_or(false);
                match (&w.inline_data, target) {
                    (Some(data), LsmTarget::Index(obj_idx)) => Instruction::WriteProperty {
                        obj_idx,
                        prop_id: w.prop_id,
                        start_idx,
                        count,
                        data: hex_bytes(data)?,
                        verify,
                    },
                    (Some(data), LsmTarget::ObjectType { object_type, occurrence }) => Instruction::WritePropertyExt {
                        object_type,
                        occurrence,
                        prop_id: w.prop_id,
                        start_idx,
                        count,
                        data: hex_bytes(data)?,
                        verify,
                    },
                    (None, target) => {
                        Instruction::WritePropertyData { target, prop_id: w.prop_id, start_idx, count, verify }
                    }
                }
            }
            C::LdCtrlRelSegment(r) => Instruction::RelSegment {
                lsm: lsm(r.lsm_idx, r.obj_type, r.occurrence)?,
                segment: RelSegment { requested_memory_size: r.size, mode: r.mode, fill: r.fill },
            },
            C::LdCtrlWriteRelMem(w) => {
                let obj_idx = w.obj_idx.ok_or(Error::UnsupportedInstruction("WriteRelMem by ObjType not supported"))?;
                // `Size` in the templates is a clamp-to-blob upper
                // bound (1 MiB); the image decides the real length.
                Instruction::WriteRelImage { obj_idx, offset: w.offset, length: w.size, verify: w.verify }
            }
            C::LdCtrlLoadImageProp(p) => {
                let obj_idx =
                    p.obj_idx.ok_or(Error::UnsupportedInstruction("LoadImageProp by ObjType not supported"))?;
                Instruction::LoadImageProperty { obj_idx, prop_id: p.prop_id as u16 }
            }
            C::LdCtrlLoadImageMem(m) => Instruction::ReadIntoImage {
                address: u16::try_from(m.address).map_err(|_| Error::Parse("LoadImageMem address beyond 16 bits"))?,
                length: u16::try_from(m.size).map_err(|_| Error::Parse("LoadImageMem size beyond 16 bits"))?,
            },
            C::LdCtrlMerge(_) => {
                return Err(Error::UnsupportedInstruction("Merge splice points must be resolved before execution"));
            }
            C::LdCtrlMapError(m) => Instruction::MapError { original: m.original_error, mapped: m.mapped_error },
            // Tool-side variables with no runtime counterpart in this
            // IR. `EnableVerifyOnWriteDirect` is redundant with the
            // per-write `Verify` attributes — every published template
            // that toggles it also spells the matching flag on each
            // `LdCtrlWriteMem` (MV-0012 and MV-0021 both) — and
            // `EnableSegmentWrite` gates ETS's implicit segment writes,
            // which our compile step already makes explicit
            // `WriteImage` instructions where (and only where) they
            // belong.
            C::LdCtrlSetControlVariable(_) => return Ok(None),
            C::LdCtrlMasterReset(_) => {
                return Err(Error::UnsupportedInstruction("MasterReset inside procedures not yet implemented"));
            }
            C::LdCtrlClearLCFilterTable(_) => {
                return Err(Error::UnsupportedInstruction("line-coupler filter tables not supported"));
            }
            C::LdCtrlTaskPtr(t) => Instruction::TaskPointers {
                lsm: t.lsm_idx.into(),
                init_ptr: t.init_ptr,
                save_ptr: t.save_ptr,
                serial_ptr: t.serial_ptr,
            },
            C::LdCtrlTaskCtrl1(t) => Instruction::TaskControl1 {
                lsm: t.lsm_idx.into(),
                address: t.address,
                count: u8::try_from(t.count).map_err(|_| Error::Parse("TaskCtrl1 count beyond one octet"))?,
            },
            C::LdCtrlTaskCtrl2(t) => Instruction::TaskControl2 {
                lsm: t.lsm_idx.into(),
                callback: t.callback,
                address: t.address,
                seg0: t.seg0,
                seg1: t.seg1,
            },
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The MV-0705 Unload-all template converts 1:1 into IR —
        /// the whole System 7 mask contribution, straight from the
        /// master data with nothing hardcoded alongside it.
        #[test]
        fn converts_system7_unload_all() {
            let master: zweidraehte_knxprod::MasterData =
                crate::download::mask::fixtures::MV_0705.parse().expect("fixture is valid master data");
            let mv = master.get_mask_version("MV-0705").expect("fixture defines MV-0705");
            let procedure = mv.find_procedure("Unload", "all").expect("fixture defines Unload all");

            let instructions = controls_to_instructions(&procedure.controls, Default::default())
                .expect("every element is convertible");
            assert_eq!(instructions, vec![
                Instruction::Connect,
                Instruction::LsmEvent { lsm: 1.into(), event: LoadEvent::Unload },
                Instruction::LsmEvent { lsm: 2.into(), event: LoadEvent::Unload },
                Instruction::LsmEvent { lsm: 3.into(), event: LoadEvent::Unload },
                Instruction::LsmEvent { lsm: 4.into(), event: LoadEvent::Unload },
                Instruction::Disconnect,
            ]);
        }

        #[test]
        fn inline_data_decodes_and_validates() {
            assert_eq!(hex_bytes("00AaFf").expect("valid hex"), vec![0x00, 0xAA, 0xFF]);
            assert!(hex_bytes("0").is_err(), "odd length");
            assert!(hex_bytes("zz").is_err(), "not hex");
        }

        /// The MV-0012 Load-all template converts as-is: no LSM
        /// instructions at all, the `SetControlVariable` dropped (its
        /// verify intent is already on every write), the
        /// `LoadImageMem` snapshot as `ReadIntoImage`, and the
        /// image-sourced writes as verifying `WriteImage` windows.
        #[test]
        fn converts_bcu1_load_all() {
            let master: zweidraehte_knxprod::MasterData =
                crate::download::mask::fixtures::MV_0012.parse().expect("fixture is valid master data");
            let mv = master.get_mask_version("MV-0012").expect("fixture defines MV-0012");
            let procedure = mv.find_procedure("Load", "all").expect("fixture defines Load all");

            let instructions = controls_to_instructions(&procedure.controls, Default::default())
                .expect("every element is convertible");
            assert_eq!(instructions, vec![
                Instruction::Connect,
                // RunError (010Dh) ← 00: halt the application.
                Instruction::WriteMemory { address: 0x010D, data: vec![0x00], verify: true },
                // Snapshot the GA-table length (0116h) for the case
                // where the image does not cover it.
                Instruction::ReadIntoImage { address: 0x0116, length: 1 },
                // GA-table length ← 01: mute group communication.
                Instruction::WriteMemory { address: 0x0116, data: vec![0x01], verify: true },
                Instruction::WriteImage { address: 0x0100, length: 1, verify: true },
                Instruction::WriteImage { address: 0x0104, length: 9, verify: true },
                Instruction::WriteImage { address: 0x010E, length: 8, verify: true },
                Instruction::WriteImage { address: 0x0119, length: 230, verify: true },
                // Zero the RAM-flags areas (00CEh / 00D7h).
                Instruction::WriteMemory { address: 0x00CE, data: vec![0; 9], verify: true },
                Instruction::WriteMemory { address: 0x00D7, data: vec![0; 9], verify: true },
                // GA-table length ← the compiled value: unmute.
                Instruction::WriteImage { address: 0x0116, length: 1, verify: true },
                // RunError ← FF: all error flags clear (active low).
                Instruction::WriteMemory { address: 0x010D, data: vec![0xFF], verify: true },
                Instruction::Restart,
            ]);
        }

        /// The BCU2 task records convert to their dedicated
        /// instructions (previously a hard rejection).
        #[test]
        fn converts_bcu2_task_records() {
            let controls = vec![
                ld::LoadControl::LdCtrlTaskPtr(ld::LdCtrlTaskPtr {
                    lsm_idx: 3,
                    init_ptr: 284,
                    save_ptr: 285,
                    serial_ptr: 0,
                }),
                ld::LoadControl::LdCtrlTaskCtrl1(ld::LdCtrlTaskCtrl1 { lsm_idx: 3, address: 0, count: 0 }),
                ld::LoadControl::LdCtrlTaskCtrl2(ld::LdCtrlTaskCtrl2 {
                    lsm_idx: 3,
                    callback: 20609,
                    address: 282,
                    seg0: 208,
                    seg1: 208,
                }),
            ];
            let instructions = controls_to_instructions(&controls, Default::default()).expect("task records convert");
            assert_eq!(instructions, vec![
                Instruction::TaskPointers { lsm: 3.into(), init_ptr: 284, save_ptr: 285, serial_ptr: 0 },
                Instruction::TaskControl1 { lsm: 3.into(), address: 0, count: 0 },
                Instruction::TaskControl2 { lsm: 3.into(), callback: 20609, address: 282, seg0: 208, seg1: 208 },
            ]);
        }

        /// System B's relative-allocation controls now convert.
        #[test]
        fn system_b_controls_convert() {
            let rel = ld::LoadControl::LdCtrlRelSegment(ld::LdCtrlRelSegment {
                lsm_idx: Some(3),
                size: 8192,
                mode: 0,
                fill: 0,
                ..Default::default()
            });
            assert_eq!(
                convert_control(&rel, Default::default()).expect("converts"),
                Some(Instruction::RelSegment {
                    lsm: 3.into(),
                    segment: RelSegment { requested_memory_size: 8192, mode: 0, fill: 0 },
                })
            );

            let write = ld::LoadControl::LdCtrlWriteRelMem(ld::LdCtrlWriteRelMem {
                obj_idx: Some(3),
                offset: 0,
                // The templates' clamp-to-blob upper bound; the image
                // decides the real length.
                size: 1_048_576,
                verify: true,
                ..Default::default()
            });
            assert_eq!(
                convert_control(&write, Default::default()).expect("converts"),
                Some(Instruction::WriteRelImage { obj_idx: 3, offset: 0, length: 1_048_576, verify: true })
            );

            let image = ld::LoadControl::LdCtrlLoadImageProp(ld::LdCtrlLoadImageProp {
                obj_idx: Some(4),
                prop_id: 7,
                ..Default::default()
            });
            assert_eq!(
                convert_control(&image, Default::default()).expect("converts"),
                Some(Instruction::LoadImageProperty { obj_idx: 4, prop_id: 7 })
            );
        }

        /// Secure profiles address their Security IO by object type because
        /// it need not appear in the device's indexed object roster.
        #[test]
        fn object_type_addressing_is_preserved() {
            let control = ld::LoadControl::LdCtrlUnload(ld::LdCtrlUnload {
                lsm_idx: None,
                obj_type: Some(17),
                occurrence: Some(1),
            });
            assert_eq!(
                convert_control(&control, Default::default()).expect("converts"),
                Some(Instruction::LsmEvent {
                    lsm: LsmTarget::ObjectType { object_type: 17, occurrence: 1 },
                    event: LoadEvent::Unload,
                })
            );
        }

        #[test]
        fn mixed_lsm_addressing_is_rejected() {
            let control = ld::LoadControl::LdCtrlUnload(ld::LdCtrlUnload {
                lsm_idx: Some(5),
                obj_type: Some(17),
                occurrence: Some(1),
            });
            assert!(matches!(convert_control(&control, Default::default()), Err(Error::Parse(_))));
        }

        /// Merge points must be resolved at assembly time; reaching the
        /// converter with one is a bug worth failing loudly on.
        #[test]
        fn merge_points_never_reach_the_converter() {
            let control = ld::LoadControl::LdCtrlMerge(ld::LdCtrlMerge { merge_id: 1 });
            assert!(matches!(convert_control(&control, Default::default()), Err(Error::UnsupportedInstruction(_))));
        }
    }
}

pub use convert::controls_to_instructions;
