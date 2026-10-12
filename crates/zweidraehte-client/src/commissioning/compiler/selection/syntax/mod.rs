//! Shared source annotations and operand grammar for the selected parser.
//! The test audit uses the same helpers when checking every authored branch.

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence};
use crate::commissioning::error::CompileError;
use crate::commissioning::image::{ImageLocation, ImageSpace};
use crate::commissioning::procedure::{
    ControlPath, ControlVariable, ErrorAction, ErrorHandler, LoadControlCause, LoadMachineTarget,
};
#[cfg(test)]
use zweidraehte_ets_files::schema::LoadProcedure;
use zweidraehte_ets_files::schema::{LoadControl, OnError};

mod comparison;
mod expressions;
pub(in crate::commissioning) use comparison::parse_range;
pub(in crate::commissioning) use expressions::parameter_test_matches;
#[cfg(test)]
pub(in crate::commissioning) use expressions::{TestOperator, compare_parameter};
#[cfg(test)]
mod audit;

pub(in crate::commissioning) struct ControlMetadata<'a> {
    pub applies_to: Option<&'a str>,
    pub internal_description: Option<&'a str>,
    pub on_errors: &'a [OnError],
    // Keep code errors dormant until applicability selects the control.
    pub code: Result<u8, CompileError>,
}

pub(in crate::commissioning) fn control_metadata(control: &LoadControl) -> Option<ControlMetadata<'_>> {
    macro_rules! metadata {
        ($control:expr, $code:expr) => {
            Some(ControlMetadata {
                applies_to: $control.applies_to.as_deref(),
                internal_description: $control.internal_description.as_deref(),
                on_errors: &$control.on_errors,
                code: $code,
            })
        };
    }

    match control {
        LoadControl::LdCtrlUnload(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 2)),
        LoadControl::LdCtrlLoad(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 1)),
        LoadControl::LdCtrlMaxLength(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 4)),
        LoadControl::LdCtrlClearCachedObjectTypes(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlLoadCompleted(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 3)),
        LoadControl::LdCtrlAbsSegment(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 4)),
        LoadControl::LdCtrlRelSegment(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 4)),
        LoadControl::LdCtrlTaskSegment(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 4)),
        LoadControl::LdCtrlTaskPtr(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 4)),
        LoadControl::LdCtrlTaskCtrl1(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 4)),
        LoadControl::LdCtrlTaskCtrl2(control) => metadata!(control, compact_lsm_code(control.lsm_idx, 4)),
        LoadControl::LdCtrlWriteProp(control) => metadata!(
            control,
            Ok(if control.obj_idx.is_none() {
                0xF0
            } else if control.verify {
                6
            } else {
                5
            })
        ),
        LoadControl::LdCtrlCompareProp(control) => {
            metadata!(control, Ok(if control.obj_idx.is_some() { 7 } else { 0xF0 }))
        }
        LoadControl::LdCtrlLoadImageProp(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlInvokeFunctionProp(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlReadFunctionProp(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlWriteMem(control) => metadata!(
            control,
            memory_record_prefix(control.address_space.as_deref())
                .map(|prefix| prefix | if control.verify { 9 } else { 8 })
        ),
        LoadControl::LdCtrlCompareMem(control) => {
            metadata!(control, memory_record_prefix(control.address_space.as_deref()).map(|prefix| prefix | 10))
        }
        LoadControl::LdCtrlLoadImageMem(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlWriteRelMem(control) => metadata!(
            control,
            Ok(if control.obj_idx.is_none() {
                0xF0
            } else if control.verify {
                0x79
            } else {
                0x78
            })
        ),
        LoadControl::LdCtrlCompareRelMem(control) => {
            metadata!(control, Ok(if control.obj_idx.is_some() { 0x7A } else { 0xF0 }))
        }
        LoadControl::LdCtrlLoadImageRelMem(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlConnect(control) => metadata!(control, Ok(12)),
        LoadControl::LdCtrlDisconnect(control) => metadata!(control, Ok(13)),
        LoadControl::LdCtrlRestart(control) => metadata!(control, Ok(14)),
        LoadControl::LdCtrlMasterReset(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlDelay(control) => metadata!(control, Ok(15)),
        LoadControl::LdCtrlSetControlVariable(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlMapError(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlProgressText(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlDeclarePropDesc(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlClearLCFilterTable(control) => metadata!(control, Ok(0xF0)),
        LoadControl::LdCtrlMerge(control) => {
            metadata!(control, Err(CompileError::invalid("composition control has no executable load-control code")))
        }
        LoadControl::Choose(_) => None,
    }
}

fn compact_lsm_code(machine_index: Option<u8>, operation: u8) -> Result<u8, CompileError> {
    let Some(machine_index) = machine_index else {
        return Ok(0xF0);
    };

    if machine_index > 0x0F {
        return Err(CompileError::invalid(format!(
            "load-state-machine index {machine_index} does not fit the registered record"
        )));
    }

    Ok((machine_index << 4) | operation)
}

fn memory_record_prefix(address_space: Option<&str>) -> Result<u8, CompileError> {
    match address_space.unwrap_or("Standard") {
        "Standard" => Ok(0x00),
        "LcSlave" => Ok(0x10),
        "LcFilter" => Ok(0x20),
        "User" => Ok(0x30),
        unknown => Err(CompileError::invalid(format!("unknown load-control address space {unknown:?}"))),
    }
}

pub(in crate::commissioning) fn control_variable(name: &str) -> Option<ControlVariable> {
    match name {
        "EnableSegmentWrite" => Some(ControlVariable::EnableSegmentWrite),
        "EnableVerifyOnWriteDirect" => Some(ControlVariable::EnableVerifyOnWriteDirect),
        "EnableOptimisticWrite" => Some(ControlVariable::EnableOptimisticWrite),
        "EnableMemoryAutoVerify" => Some(ControlVariable::EnableMemoryAutoVerify),
        _ => None,
    }
}

pub(in crate::commissioning) fn lower_error_handlers(
    handlers: &[OnError],
    path: &ControlPath,
) -> Result<Vec<ErrorHandler>, CompileError> {
    handlers
        .iter()
        .map(|handler| {
            let cause = match handler.cause.as_str() {
                "ResourceNotFound" => LoadControlCause::ResourceNotFound,
                "CompareMismatch" => LoadControlCause::CompareMismatch,
                unknown => {
                    return Err(CompileError::at(path, format!("unknown OnError cause {unknown:?}")));
                }
            };

            let action = if handler.ignore.unwrap_or(false) {
                ErrorAction::Ignore
            } else {
                ErrorAction::FailWithMessage { message_reference: handler.message_ref.clone() }
            };

            Ok(ErrorHandler { cause, action })
        })
        .collect()
}

pub(in crate::commissioning) fn decode_optional_hex(
    value: Option<&str>,
    path: &ControlPath,
) -> Result<Option<Vec<u8>>, CompileError> {
    value.map(|value| decode_hex(value).map_err(|message| CompileError::at(path, message))).transpose()
}

pub(in crate::commissioning) fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!("hex data has odd length {}", value.len()));
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("hex data {value:?} contains a non-hexadecimal character"));
    }

    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("ASCII-checked hexadecimal pair");
            u8::from_str_radix(pair, 16).expect("validated hexadecimal pair")
        })
        .collect())
}

/// The bytes a memory write sends: the first `Size` bytes of its inline data.
///
/// Catalogue products ship `LdCtrlWriteMem Size="2"` with eleven inline bytes
/// whose tail is leftover text (M-00EE_A-4301: `00EE` followed by ASCII). `Size`
/// is the declared extent, as for `WriteProp`, which already truncates longer
/// inline data to its element extent. Shorter data cannot fill the extent and
/// stays an error.
///
/// TODO: confirm with a bus capture of a reference download that exactly the
/// leading `Size` bytes are sent.
pub(in crate::commissioning) fn declared_write_payload(
    mut data: Vec<u8>,
    size: u32,
    description: &str,
    path: &ControlPath,
) -> Result<Vec<u8>, CompileError> {
    if data.len() < size as usize {
        return Err(CompileError::at(
            path,
            format!("{description} has only {} bytes but Size declares {size}", data.len()),
        ));
    }

    data.truncate(size as usize);
    Ok(data)
}

pub(in crate::commissioning) fn require_exact_length(
    actual: usize,
    expected: u32,
    description: &str,
    path: &ControlPath,
) -> Result<(), CompileError> {
    if actual != expected as usize {
        return Err(CompileError::at(path, format!("{description} has {actual} bytes, expected {expected}")));
    }

    Ok(())
}

pub(in crate::commissioning) fn authored_property_wire_length(
    data: &[u8],
    count: u16,
    description: &str,
    path: &ControlPath,
) -> Result<u32, CompileError> {
    if count == 0 {
        return Err(CompileError::at(path, format!("{description} declares zero property elements")));
    }
    if data.is_empty() {
        return Err(CompileError::at(path, format!("{description} is empty")));
    }
    if !data.len().is_multiple_of(usize::from(count)) {
        return Err(CompileError::at(
            path,
            format!("{description} has {} bytes, which cannot encode {count} equal-width elements", data.len()),
        ));
    }

    u32::try_from(data.len()).map_err(|_| CompileError::at(path, format!("{description} length does not fit the plan")))
}

pub(in crate::commissioning) fn object_selector(
    object_index: Option<u8>,
    object_type: Option<u16>,
    occurrence: Option<u16>,
    path: &ControlPath,
) -> Result<ObjectSelector, CompileError> {
    parse_object_selector(object_index, object_type, occurrence).map_err(|message| CompileError::at(path, message))
}

pub(in crate::commissioning) fn parse_object_selector(
    object_index: Option<u8>,
    object_type: Option<u16>,
    occurrence: Option<u16>,
) -> Result<ObjectSelector, &'static str> {
    match (object_index, object_type, occurrence) {
        (Some(index), None, None) => Ok(ObjectSelector::Index { index: u16::from(index) }),
        (None, Some(object_type), occurrence) => {
            Ok(ObjectSelector::Type { object_type, occurrence: Occurrence::from_option(occurrence) })
        }
        (Some(_), None, Some(_)) => Err("object-index selector also declares an occurrence"),
        (Some(_), Some(_), _) => Err("control mixes object-index and object-type selectors"),
        (None, None, Some(_)) => Err("control declares an occurrence without an object type"),
        (None, None, None) => Err("control has no object selector"),
    }
}

pub(in crate::commissioning) fn load_machine_target(
    machine_index: Option<u8>,
    object_type: Option<u16>,
    occurrence: Option<u16>,
    path: &ControlPath,
) -> Result<LoadMachineTarget, CompileError> {
    object_selector(machine_index, object_type, occurrence, path).map(|selector| match selector {
        ObjectSelector::Index { index } => LoadMachineTarget::Index(index),
        selector => LoadMachineTarget::Object(selector),
    })
}

pub(in crate::commissioning) fn machine_object(machine: &LoadMachineTarget) -> ObjectSelector {
    match machine {
        LoadMachineTarget::Index(index) => ObjectSelector::Index { index: *index },
        LoadMachineTarget::Object(object) => object.clone(),
    }
}

pub(in crate::commissioning) fn memory_location(
    address_space: Option<&str>,
    address: u32,
    path: &ControlPath,
) -> Result<ImageLocation, CompileError> {
    parse_memory_location(address_space, address).ok_or_else(|| {
        CompileError::at(path, format!("unknown load-control address space {:?}", address_space.unwrap_or("Standard")))
    })
}

pub(in crate::commissioning) fn parse_memory_location(
    address_space: Option<&str>,
    address: u32,
) -> Option<ImageLocation> {
    let space = match address_space.unwrap_or("Standard") {
        "Standard" => ImageSpace::StandardMemory,
        "User" => ImageSpace::UserMemory,
        "LcSlave" => ImageSpace::LineCouplerSlave,
        "LcFilter" => ImageSpace::LineCouplerFilter,
        _ => return None,
    };
    Some(ImageLocation { space, offset: address })
}

/// Audit every authored branch without needing project parameters or an image.
#[cfg(test)]
pub fn validate_procedure_syntax(root_path: ControlPath, procedure: &LoadProcedure) -> Result<(), CompileError> {
    audit::validate_syntax_controls(&procedure.controls, &root_path)
}
