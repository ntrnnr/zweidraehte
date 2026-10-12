//! Native partial-download filtering and transformations for authored controls.

use super::*;
use crate::commissioning::catalog::profile::ObjectSelector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AutoControl {
    Keep,
    Omit,
    WriteMemory { address: u32, size: u32 },
}

#[cfg(test)]
mod tests;

impl ProcedureLowerer<'_> {
    pub(super) fn omit_absent_secondary_application_control(&self, control: &LoadControl) -> bool {
        // Partial System B parameter downloads are finalized after product
        // procedures are spliced in. With no secondary application, only these
        // explicitly indexed index-5 controls are removed, including `all` and
        // `par` annotations, on TP, RF and IP firmware alike. Type selectors
        // and relative-memory writes keep their own semantics.
        if self.context.applicability.full
            || !self.context.applicability.sections.contains(ProgramSections::PARAMETERS)
            || self.context.application_program_2_present
            || !self.context.profile.has_system_b_firmware()
        {
            return false;
        }

        match control {
            LoadControl::LdCtrlLoad(value) => value.lsm_idx == Some(5),
            LoadControl::LdCtrlUnload(value) => value.lsm_idx == Some(5),
            LoadControl::LdCtrlLoadCompleted(value) => value.lsm_idx == Some(5),
            LoadControl::LdCtrlWriteProp(value) => value.obj_idx == Some(5),
            LoadControl::LdCtrlLoadImageProp(value) => value.obj_idx == Some(5),
            LoadControl::LdCtrlCompareProp(value) => value.obj_idx == Some(5),
            _ => false,
        }
    }

    pub(super) fn partial_auto_control(
        &self,
        control: &LoadControl,
        path: &ControlPath,
    ) -> Result<AutoControl, CompileError> {
        use AutoControl::{Keep, Omit, WriteMemory};

        if matches!(
            control,
            LoadControl::LdCtrlTaskPtr(_) | LoadControl::LdCtrlTaskCtrl1(_) | LoadControl::LdCtrlTaskCtrl2(_)
        ) {
            return Ok(Omit);
        }

        macro_rules! target {
            ($control:expr) => {
                load_machine_target($control.lsm_idx, $control.obj_type, $control.occurrence, path)?
            };
        }

        let target = match control {
            LoadControl::LdCtrlLoad(value) => target!(value),
            LoadControl::LdCtrlLoadCompleted(value) => target!(value),
            LoadControl::LdCtrlUnload(value) => target!(value),
            LoadControl::LdCtrlAbsSegment(value) => target!(value),
            LoadControl::LdCtrlRelSegment(value) => target!(value),
            LoadControl::LdCtrlTaskSegment(value) => target!(value),
            _ => return Ok(Keep),
        };
        let object_type = match machine_object(&target) {
            ObjectSelector::Type { object_type, .. } => Some(object_type),
            ObjectSelector::Index { index } => {
                let objects: Vec<_> = self
                    .context
                    .profile
                    .interface_objects()
                    .iter()
                    .filter(|object| object.index.map(u16::from) == Some(index))
                    .collect();

                match objects.as_slice() {
                    [] => None,
                    [object] => object.object_type,
                    _ => return Err(CompileError::at(path, "partial load machine index has ambiguous object types")),
                }
            }
        };
        let group = self.context.applicability.sections.contains(ProgramSections::GROUP_COMMUNICATION);
        let secondary = self.context.application_program_2_present;
        let parameters = self.context.applicability.sections.contains(ProgramSections::PARAMETERS);

        let selected = match control {
            LoadControl::LdCtrlUnload(_) => match object_type {
                Some(1 | 2) => group,
                Some(3 | 4 | 9) => false,
                _ => true,
            },
            LoadControl::LdCtrlLoad(_) | LoadControl::LdCtrlLoadCompleted(_) => match object_type {
                Some(1 | 2 | 9) => group,
                Some(4) => parameters && secondary,
                _ => true,
            },
            LoadControl::LdCtrlTaskSegment(_) => match object_type {
                Some(1 | 2 | 9) => group,
                Some(3 | 4) => false,
                _ => true,
            },
            LoadControl::LdCtrlRelSegment(_) => match object_type {
                Some(1 | 2 | 9) => group,
                Some(4) => secondary,
                _ => true,
            },
            LoadControl::LdCtrlAbsSegment(value) => match object_type {
                Some(1 | 2 | 9) => group,
                Some(3 | 4) => {
                    if (object_type == Some(4) && !(parameters && secondary))
                        || !self.auto_segment_write
                        || value.mem_type & 3 != 3
                    {
                        return Ok(Omit);
                    }

                    return Ok(WriteMemory { address: u32::from(value.address), size: u32::from(value.size) });
                }
                _ => true,
            },
            _ => unreachable!("partial machine controls were selected above"),
        };

        Ok(if selected { Keep } else { Omit })
    }
}
