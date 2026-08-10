//! The download instruction IR.
//!
//! A deliberately small, executable vocabulary — the intersection of
//! what the 03/05/02 download procedures need and what our management
//! surface can perform. Procedure *sources* (parsed master data,
//! product `LoadProcedures`) all compile down to this; the
//! [`Downloader`](super::Downloader) only ever sees IR.
//!
//! Load state machines are addressed by their **index**, not by the
//! four-variant `LsmMachine`: System B has five (1 = address table,
//! 2 = association table, 3 = group object table, 4 = application
//! program, 5 = PEI program), and on that family the index is also the
//! interface-object index the property path writes to. The
//! memory-mapped path narrows the index to `LsmMachine` when it packs
//! the record nibble, and rejects anything outside 1–4 there.

use zweidraehte_proto::messages::apdu::load_control::{AbsSegment, LoadEvent, RelSegment};

/// A load state machine, by index.
///
/// On System B this is also the interface object index carrying
/// `PID_LOAD_STATE_CONTROL`; on System 7 it is the nibble in the
/// memory-mapped record.
pub type LsmIndex = u8;

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
    LsmEvent { lsm: LsmIndex, event: LoadEvent },
    /// Allocate an absolute segment on a machine in `Loading`
    /// (`LdCtrlAbsSegment` → the §3.31.3 AllocAbsDataSeg record).
    AbsSegment { lsm: LsmIndex, segment: AbsSegment },
    /// Allocate a relative segment (`LdCtrlRelSegment`, System B): the
    /// client asks for a size, the device picks the address and reports
    /// it through `PID_TABLE_REFERENCE`.
    RelSegment { lsm: LsmIndex, segment: RelSegment },
    /// Announce the task segment address (`LdCtrlTaskSegment`).
    /// System 7 devices accept the record without acting on it; ETS
    /// sends it, so faithful procedures include it.
    TaskSegment { lsm: LsmIndex, address: u16 },
    /// Write `length` bytes from the assembled device image at
    /// `address` (the explicit form of ETS's implicit data phase).
    WriteImage { address: u16, length: u16 },
    /// Write literal bytes (`LdCtrlWriteMem` with inline data).
    WriteMemory { address: u16, data: Vec<u8>, verify: bool },
    /// Read memory and require an exact value (`LdCtrlCompareMem`).
    CompareMemory { address: u16, expected: Vec<u8> },
    /// Write the object's relative image content
    /// (`LdCtrlWriteRelMem`, System B): the bytes compiled for this
    /// interface object, placed at the base the device allocated.
    WriteRelImage { obj_idx: u8, offset: u32, verify: bool },
    /// Read a property into the tool's working image
    /// (`LdCtrlLoadImageProp`). Used to pick up an existing
    /// allocation's base address before a partial download, so the
    /// tables are rewritten in place rather than reallocated.
    LoadImageProperty { obj_idx: u8, prop_id: u16 },
    /// Write a property value (`LdCtrlWriteProp` with inline data).
    WriteProperty { obj_idx: u8, prop_id: u16, data: Vec<u8>, verify: bool },
    /// Basic restart (`LdCtrlRestart`); the device reboots and the
    /// transport connection dies with it.
    Restart,
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

// ============================================================================
// Master-data conversion (feature `master-data`)
// ============================================================================

mod convert {
    use super::Instruction;
    use super::LsmIndex;
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
    /// executable; the tool-side scaffolding (`Merge`,
    /// `SetControlVariable`, BCU2 task plumbing) returns
    /// [`Error::UnsupportedInstruction`] — `Merge` in particular must
    /// be resolved by [`assemble`](crate::download::assemble) before
    /// execution, never reached at run time.
    pub fn controls_to_instructions(controls: &[ld::LoadControl]) -> Result<Vec<Instruction>> {
        controls.iter().map(convert_control).collect()
    }

    /// A load state machine must be named by index; the
    /// `ObjType`+`Occurrence` form the master data also permits would
    /// need an object-type lookup on the live device.
    fn lsm(lsm_idx: Option<u8>) -> Result<LsmIndex> {
        lsm_idx.ok_or(Error::UnsupportedInstruction("load state machine addressed by object type, not by index"))
    }

    fn hex_bytes(s: &str) -> Result<Vec<u8>> {
        if s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
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

    fn convert_control(control: &ld::LoadControl) -> Result<Instruction> {
        use ld::LoadControl as C;
        Ok(match control {
            C::LdCtrlConnect(_) => Instruction::Connect,
            C::LdCtrlDisconnect(_) => Instruction::Disconnect,
            C::LdCtrlRestart(_) => Instruction::Restart,
            C::LdCtrlDelay(d) => Instruction::Delay { milliseconds: d.milli_seconds },
            C::LdCtrlLoad(l) => Instruction::LsmEvent { lsm: lsm(l.lsm_idx)?, event: LoadEvent::StartLoading },
            C::LdCtrlLoadCompleted(l) => {
                Instruction::LsmEvent { lsm: lsm(l.lsm_idx)?, event: LoadEvent::LoadCompleted }
            }
            C::LdCtrlUnload(l) => Instruction::LsmEvent { lsm: lsm(l.lsm_idx)?, event: LoadEvent::Unload },
            C::LdCtrlAbsSegment(s) => Instruction::AbsSegment {
                lsm: s.lsm_idx,
                segment: AbsSegment {
                    segment_type: LoadSegment::from(s.seg_type),
                    start_address: s.address,
                    length: s.size,
                    access_attributes: s.access,
                    memory_type: s.mem_type,
                    memory_attributes: s.seg_flags,
                },
            },
            C::LdCtrlTaskSegment(t) => Instruction::TaskSegment { lsm: t.lsm_idx, address: t.address },
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
                    None => Instruction::WriteImage { address, length: u16::try_from(w.size).unwrap_or(u16::MAX) },
                }
            }
            C::LdCtrlCompareMem(cm) => Instruction::CompareMemory {
                address: u16::try_from(cm.address).map_err(|_| Error::Parse("CompareMem address beyond 16 bits"))?,
                expected: hex_bytes(&cm.inline_data)?,
            },
            C::LdCtrlWriteProp(w) => {
                let obj_idx = w.obj_idx.ok_or(Error::UnsupportedInstruction("WriteProp by ObjType not supported"))?;
                let data = match &w.inline_data {
                    Some(data) => hex_bytes(data)?,
                    None => return Err(Error::UnsupportedInstruction("WriteProp without inline data")),
                };
                Instruction::WriteProperty {
                    obj_idx,
                    prop_id: w.prop_id as u16,
                    data,
                    verify: w.verify.unwrap_or(false),
                }
            }
            C::LdCtrlRelSegment(r) => Instruction::RelSegment {
                lsm: lsm(r.lsm_idx)?,
                segment: RelSegment { requested_memory_size: r.size, mode: r.mode, fill: r.fill },
            },
            C::LdCtrlWriteRelMem(w) => {
                let obj_idx = w.obj_idx.ok_or(Error::UnsupportedInstruction("WriteRelMem by ObjType not supported"))?;
                // `Size` in the templates is a clamp-to-blob upper
                // bound (1 MiB); the image decides the real length.
                Instruction::WriteRelImage { obj_idx, offset: w.offset, verify: w.verify }
            }
            C::LdCtrlLoadImageProp(p) => {
                let obj_idx =
                    p.obj_idx.ok_or(Error::UnsupportedInstruction("LoadImageProp by ObjType not supported"))?;
                Instruction::LoadImageProperty { obj_idx, prop_id: p.prop_id as u16 }
            }
            C::LdCtrlLoadImageMem(_) => {
                return Err(Error::UnsupportedInstruction("LoadImageMem (BCU1 image preload) not implemented"));
            }
            C::LdCtrlMerge(_) => {
                return Err(Error::UnsupportedInstruction("Merge splice points must be resolved before execution"));
            }
            C::LdCtrlMapError(m) => Instruction::MapError { original: m.original_error, mapped: m.mapped_error },
            C::LdCtrlSetControlVariable(_) => {
                return Err(Error::UnsupportedInstruction("SetControlVariable not yet implemented"));
            }
            C::LdCtrlMasterReset(_) => {
                return Err(Error::UnsupportedInstruction("MasterReset inside procedures not yet implemented"));
            }
            C::LdCtrlClearLCFilterTable(_) => {
                return Err(Error::UnsupportedInstruction("line-coupler filter tables not supported"));
            }
            C::LdCtrlTaskPtr(_) | C::LdCtrlTaskCtrl1(_) | C::LdCtrlTaskCtrl2(_) => {
                return Err(Error::UnsupportedInstruction("BCU2 task records not supported"));
            }
        })
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

            let instructions = controls_to_instructions(&procedure.controls).expect("every element is convertible");
            assert_eq!(instructions, vec![
                Instruction::Connect,
                Instruction::LsmEvent { lsm: 1, event: LoadEvent::Unload },
                Instruction::LsmEvent { lsm: 2, event: LoadEvent::Unload },
                Instruction::LsmEvent { lsm: 3, event: LoadEvent::Unload },
                Instruction::LsmEvent { lsm: 4, event: LoadEvent::Unload },
                Instruction::Disconnect,
            ]);
        }

        #[test]
        fn inline_data_decodes_and_validates() {
            assert_eq!(hex_bytes("00AaFf").expect("valid hex"), vec![0x00, 0xAA, 0xFF]);
            assert!(hex_bytes("0").is_err(), "odd length");
            assert!(hex_bytes("zz").is_err(), "not hex");
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
            assert_eq!(convert_control(&rel).expect("converts"), Instruction::RelSegment {
                lsm: 3,
                segment: RelSegment { requested_memory_size: 8192, mode: 0, fill: 0 },
            });

            let write = ld::LoadControl::LdCtrlWriteRelMem(ld::LdCtrlWriteRelMem {
                obj_idx: Some(3),
                offset: 0,
                // The templates' clamp-to-blob upper bound; the image
                // decides the real length.
                size: 1_048_576,
                verify: true,
                ..Default::default()
            });
            assert_eq!(convert_control(&write).expect("converts"), Instruction::WriteRelImage {
                obj_idx: 3,
                offset: 0,
                verify: true,
            });

            let image = ld::LoadControl::LdCtrlLoadImageProp(ld::LdCtrlLoadImageProp {
                obj_idx: Some(4),
                prop_id: 7,
                ..Default::default()
            });
            assert_eq!(convert_control(&image).expect("converts"), Instruction::LoadImageProperty {
                obj_idx: 4,
                prop_id: 7,
            });
        }

        /// A machine named by object type rather than index still has
        /// nowhere to go — the IR carries indexes.
        #[test]
        fn object_type_addressing_is_rejected_typed() {
            let control = ld::LoadControl::LdCtrlUnload(ld::LdCtrlUnload {
                lsm_idx: None,
                obj_type: Some(6),
                occurrence: Some(1),
            });
            assert!(matches!(convert_control(&control), Err(Error::UnsupportedInstruction(_))));
        }

        /// Merge points must be resolved at assembly time; reaching the
        /// converter with one is a bug worth failing loudly on.
        #[test]
        fn merge_points_never_reach_the_converter() {
            let control = ld::LoadControl::LdCtrlMerge(ld::LdCtrlMerge { merge_id: 1 });
            assert!(matches!(convert_control(&control), Err(Error::UnsupportedInstruction(_))));
        }
    }
}

pub use convert::controls_to_instructions;
