//! Translate each already selected control into explicit execution operations.

use super::*;
use crate::commissioning::catalog::profile::ResourceManagementStyle;
use crate::commissioning::error::CompileError;
use crate::commissioning::procedure::LoadEffect;
use crate::commissioning::procedure::operands::{load_endpoint, pure_property_address};
use zweidraehte_proto::messages::apdu::load_control::{
    AbsSegment, LoadControlRecord, LoadEvent, LoadSegment, LoadState, LsmMachine, MemLoadControlRecord, RelSegment,
};

impl ProcedureLowerer<'_> {
    pub(super) fn lower_executable_control(
        &mut self,
        control: &LoadControl,
        path: &ControlPath,
    ) -> Result<ProcedureOperation, CompileError> {
        Ok(match control {
            LoadControl::LdCtrlConnect(_) => ProcedureOperation::Connect,
            LoadControl::LdCtrlDisconnect(_) => ProcedureOperation::Disconnect,
            LoadControl::LdCtrlRestart(_) => ProcedureOperation::Restart { kind: self.context.restart_kind },
            LoadControl::LdCtrlMasterReset(control) => {
                ProcedureOperation::MasterReset { erase_code: control.erase_code, channel: control.channel_number }
            }
            LoadControl::LdCtrlDelay(control) => {
                ProcedureOperation::Delay { milliseconds: u32::from(control.milli_seconds) }
            }
            LoadControl::LdCtrlClearCachedObjectTypes(_) => ProcedureOperation::ClearCache,
            LoadControl::LdCtrlClearLCFilterTable(control) => ProcedureOperation::ClearLineCouplerFilter {
                address: if control.use_function_prop.unwrap_or(false) {
                    let objects: Vec<_> = self
                        .context
                        .profile
                        .interface_objects()
                        .iter()
                        .filter(|object| object.object_type == Some(6))
                        .collect();
                    // Coupler masks such as MV-0912 declare no interface
                    // objects; their procedures address the router object by
                    // type, so the function property does the same.
                    let index = match objects.as_slice() {
                        [] => None,
                        [object] => object.index,
                        _ => return Err(CompileError::at(path, "router object is ambiguous")),
                    };
                    let object = index.map_or(
                        crate::commissioning::catalog::profile::ObjectSelector::Type {
                            object_type: 6,
                            occurrence: crate::commissioning::catalog::profile::Occurrence::Zero,
                        },
                        |index| crate::commissioning::catalog::profile::ObjectSelector::Index {
                            index: u16::from(index),
                        },
                    );
                    Some(pure_property_address(&object, 56).map_err(|error| error.with_path(path))?)
                } else {
                    None
                },
            },

            LoadControl::LdCtrlLoad(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                let record = self.event_record(&target, LoadEvent::StartLoading, LoadState::Loading, path)?;
                ProcedureOperation::LoadRecord(record)
            }
            LoadControl::LdCtrlUnload(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                let record = self.event_record(&target, LoadEvent::Unload, LoadState::Unloaded, path)?;
                ProcedureOperation::LoadRecord(record)
            }
            LoadControl::LdCtrlLoadCompleted(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                let record = self.event_record(&target, LoadEvent::LoadCompleted, LoadState::Loaded, path)?;
                ProcedureOperation::LoadRecord(record)
            }
            LoadControl::LdCtrlMaxLength(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                let size = u16::try_from(control.size)
                    .map_err(|_| CompileError::at(path, "maximum segment length exceeds 16 bits"))?;
                let [hi, lo] = size.to_be_bytes();
                let property = [u8::from(LoadEvent::AdditionalLoadControls), 10, hi, lo, 0, 0, 0, 0, 0, 0];
                let record = self.record(
                    &target,
                    &property,
                    |machine| {
                        let tag = MemLoadControlRecord::event(machine, LoadEvent::AdditionalLoadControls)[0];
                        vec![tag, 10, 0, hi, lo, 0, 0, 0, 0, 0, 0]
                    },
                    Some(LoadState::Loading),
                    path,
                )?;
                ProcedureOperation::LoadRecord(record)
            }
            LoadControl::LdCtrlAbsSegment(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                let segment_type = LoadSegment::from(control.seg_type);
                if !matches!(segment_type, LoadSegment::AbsoluteData | LoadSegment::AbsoluteStack) {
                    return Err(CompileError::at(path, "absolute allocation requires a data or stack segment"));
                }
                let segment = AbsSegment {
                    segment_type,
                    start_address: control.address,
                    length: control.size,
                    access_attributes: control.access,
                    memory_type: control.mem_type,
                    memory_attributes: control.seg_flags,
                };
                let mut record = self.record(
                    &target,
                    &LoadControlRecord::abs_segment(&segment),
                    |machine| MemLoadControlRecord::abs_segment(machine, &segment).to_vec(),
                    Some(LoadState::Loading),
                    path,
                )?;
                record.effect = LoadEffect::Invalidate {
                    location: ImageLocation::standard_memory(u32::from(control.address)),
                    length: u32::from(control.size),
                };
                let transfers = if control.mem_type & 3 == 3 {
                    let location = ImageLocation::standard_memory(u32::from(control.address));
                    // Native geometry gates and clips the implicit transfer at
                    // execution: preceding LoadImage controls can create it.
                    // The declaration and its conservative extent stay intact.
                    vec![MemoryTransfer {
                        target: memory::memory_target(
                            self.context.profile,
                            self.context.standard_memory_service,
                            &location,
                            u32::from(control.size),
                            path,
                        )?,
                        data: OperationData::ImageWindow { location, maximum: u32::from(control.size) },
                        extent: OperationExtent::bytes(u32::from(control.size)),
                        policy: WriteIntent::AbsoluteSegment,
                    }]
                } else {
                    Vec::new()
                };
                ProcedureOperation::AbsoluteSegment { record, transfers }
            }
            LoadControl::LdCtrlRelSegment(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                // Master Data sizes are lower bounds for project-dependent tables.
                let size = control.size;
                let segment = RelSegment { requested_memory_size: size, mode: control.mode, fill: control.fill };
                let (write, status, machine) =
                    load_endpoint(self.context.profile, &target, self.context.standard_memory_service)
                        .map_err(|error| error.with_path(path))?;
                if machine.is_some() || !matches!(write.target, OperationTarget::Property { .. }) {
                    return Err(CompileError::at(path, "relative allocation requires property load control"));
                }
                let record = LoadRecord {
                    write,
                    bytes: LoadControlRecord::rel_segment(&segment).to_vec(),
                    poll: Some((status, LoadState::Loading)),
                    effect: LoadEffect::Invalidate {
                        location: ImageLocation {
                            space: crate::commissioning::image::ImageSpace::RelativeMemory {
                                object: machine_object(&target),
                            },
                            offset: 0,
                        },
                        length: size,
                    },
                };
                self.parsed.allocations.push(RelativeAllocation {
                    step: self.parsed.program.steps.len(),
                    object: machine_object(&target),
                    segment,
                });
                ProcedureOperation::LoadRecord(record)
            }
            LoadControl::LdCtrlTaskSegment(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                // Simple management installs the product identity in its
                // image, but announces a compatibility task to the load
                // machine. LSM management announces the product itself.
                // Resolve this from the selected management style rather
                // than the procedure's Master Data/product ownership.
                let identity = if self.context.profile.management_style() == Some(ResourceManagementStyle::Simple) {
                    ApplicationIdentity { application_id: [0xff, 0xff, 0, 0, 0xff], pei_type: 1 }
                } else {
                    self.context.application_identity
                };
                let record = self.record(
                    &target,
                    &LoadControlRecord::task_segment(control.address, identity.pei_type, identity.application_id),
                    |machine| {
                        MemLoadControlRecord::task_segment(
                            machine,
                            control.address,
                            identity.pei_type,
                            identity.application_id,
                        )
                        .to_vec()
                    },
                    None,
                    path,
                )?;
                ProcedureOperation::LoadRecord(record)
            }
            LoadControl::LdCtrlTaskPtr(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                let record = self.record(
                    &target,
                    &LoadControlRecord::task_ptr(control.init_ptr, control.save_ptr, control.serial_ptr),
                    |machine| {
                        MemLoadControlRecord::task_ptr(machine, control.init_ptr, control.save_ptr, control.serial_ptr)
                            .to_vec()
                    },
                    None,
                    path,
                )?;
                ProcedureOperation::LoadRecord(record)
            }
            LoadControl::LdCtrlTaskCtrl1(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                let record = self.record(
                    &target,
                    &LoadControlRecord::task_ctrl1(control.address, control.count),
                    |machine| MemLoadControlRecord::task_ctrl1(machine, control.address, control.count).to_vec(),
                    None,
                    path,
                )?;
                ProcedureOperation::LoadRecord(record)
            }
            LoadControl::LdCtrlTaskCtrl2(control) => {
                let target = load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
                let record = self.record(
                    &target,
                    &LoadControlRecord::task_ctrl2(control.callback, control.address, control.seg0, control.seg1),
                    |machine| {
                        MemLoadControlRecord::task_ctrl2(
                            machine,
                            control.callback,
                            control.address,
                            control.seg0,
                            control.seg1,
                        )
                        .to_vec()
                    },
                    None,
                    path,
                )?;
                ProcedureOperation::LoadRecord(record)
            }

            LoadControl::LdCtrlSetControlVariable(control) => {
                let variable = control_variable(&control.name)
                    .ok_or_else(|| CompileError::at(path, format!("unknown control variable {:?}", control.name)))?;
                ProcedureOperation::SetControlVariable { variable, value: control.value }
            }
            LoadControl::LdCtrlMapError(control) => ProcedureOperation::MapError {
                filter: control.ld_ctrl_filter,
                original: control.original_error,
                mapped: control.mapped_error,
            },
            LoadControl::LdCtrlProgressText(control) => {
                let text = self.progress_text(control.text_id, control.message_ref.as_deref(), path)?;
                ProcedureOperation::ProgressText(text)
            }

            LoadControl::LdCtrlDeclarePropDesc(control) => {
                let object = object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
                let address = pure_property_address(&object, control.prop_id).map_err(|error| error.with_path(path))?;
                if control.prop_type.trim().is_empty() {
                    return Err(CompileError::at(path, "property descriptor has an empty PropType"));
                }
                ProcedureOperation::DeclarePropertyDescriptor {
                    address,
                    property_data_type: control.prop_type.clone(),
                    maximum_elements: control.max_elements,
                    read_access: control.read_access,
                    write_access: control.write_access,
                    writable: control.writable,
                }
            }

            LoadControl::LdCtrlInvokeFunctionProp(control) => {
                let object = object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
                ProcedureOperation::FunctionProperty(FunctionPropertyOperation::Invoke {
                    address: pure_property_address(&object, control.prop_id).map_err(|error| error.with_path(path))?,
                    data: decode_optional_hex(control.inline_data.as_deref(), path)?.unwrap_or_default(),
                    effect: LoadEffect::InvalidateAll,
                })
            }
            LoadControl::LdCtrlReadFunctionProp(control) => {
                let object = object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
                ProcedureOperation::FunctionProperty(FunctionPropertyOperation::ReadResult {
                    address: pure_property_address(&object, control.prop_id).map_err(|error| error.with_path(path))?,
                })
            }

            LoadControl::LdCtrlWriteProp(control) => {
                return self.lower_property_write(control, path);
            }
            LoadControl::LdCtrlCompareProp(control) => {
                return self.lower_property_compare(control, path);
            }
            LoadControl::LdCtrlLoadImageProp(control) => {
                return self.lower_property_image_read(control, path);
            }
            LoadControl::LdCtrlWriteMem(_) | LoadControl::LdCtrlWriteRelMem(_) => {
                return self.lower_memory_write(control, path);
            }
            LoadControl::LdCtrlCompareMem(_) | LoadControl::LdCtrlCompareRelMem(_) => {
                return self.lower_memory_compare(control, path);
            }
            LoadControl::LdCtrlLoadImageMem(_) | LoadControl::LdCtrlLoadImageRelMem(_) => {
                return self.lower_memory_image_read(control, path);
            }
            LoadControl::Choose(_) | LoadControl::LdCtrlMerge(_) => {
                unreachable!("composition resolves choices and merges before lowering")
            }
        })
    }
    fn event_record(
        &self,
        target: &LoadMachineTarget,
        event: LoadEvent,
        expected: LoadState,
        path: &ControlPath,
    ) -> Result<LoadRecord, CompileError> {
        let mut record = self.record(
            target,
            &LoadControlRecord::event(event),
            |machine| MemLoadControlRecord::event(machine, event).to_vec(),
            Some(expected),
            path,
        )?;
        if event == LoadEvent::Unload {
            record.effect = LoadEffect::InvalidateAll;
        }
        Ok(record)
    }

    fn record(
        &self,
        target: &LoadMachineTarget,
        property: &[u8],
        memory: impl FnOnce(LsmMachine) -> Vec<u8>,
        expected: Option<LoadState>,
        path: &ControlPath,
    ) -> Result<LoadRecord, CompileError> {
        let (mut write, status, machine) =
            load_endpoint(self.context.profile, target, self.context.standard_memory_service)
                .map_err(|error| error.with_path(path))?;
        let bytes = machine.map_or_else(|| property.to_vec(), memory);
        write.extent = if matches!(write.target, OperationTarget::Property { .. }) {
            OperationExtent::property(bytes.len() as u32, 1)
        } else {
            OperationExtent::bytes(bytes.len() as u32)
        };
        Ok(LoadRecord { write, bytes, poll: expected.map(|expected| (status, expected)), effect: LoadEffect::None })
    }
}
