//! Audit every authored branch against the supported operand grammar.

use super::comparison::parse_range;
use super::expressions::comparison_expression;
use super::{
    control_metadata, control_variable, decode_optional_hex, load_machine_target, lower_error_handlers,
    memory_location, object_selector, require_exact_length,
};
use crate::commissioning::error::CompileError;
use crate::commissioning::procedure::ControlPath;
use crate::commissioning::procedure::parse_applies_to_token;
use zweidraehte_ets_files::schema::LoadControl;

pub(in crate::commissioning) fn validate_syntax_controls(
    controls: &[LoadControl],
    parent_path: &ControlPath,
) -> Result<(), CompileError> {
    for (index, control) in controls.iter().enumerate() {
        validate_syntax_control(control, &parent_path.child(index))?;
    }

    Ok(())
}

pub(in crate::commissioning) fn validate_syntax_control(
    control: &LoadControl,
    path: &ControlPath,
) -> Result<(), CompileError> {
    if let LoadControl::Choose(choice) = control {
        if choice.param_ref_id.trim().is_empty() {
            return Err(CompileError::at(path, "choose has an empty ParamRefId"));
        }

        let mut default_seen = false;
        for (index, branch) in choice.when.iter().enumerate() {
            let branch_path = path.child(index);

            if branch.is_default == Some(true) && std::mem::replace(&mut default_seen, true) {
                return Err(CompileError::at(path, "choose has more than one default branch"));
            }

            match (branch.test.as_deref(), branch.is_default == Some(true)) {
                (None, false) => {
                    return Err(CompileError::at(
                        &branch_path,
                        "choose branch has neither a test nor default=\"true\"",
                    ));
                }
                (Some(test), _) => validate_choose_test_syntax(test, &branch_path)?,
                (None, true) => {}
            }

            validate_syntax_controls(&branch.controls, &branch_path)?;
        }

        return Ok(());
    }

    let metadata = control_metadata(control).expect("only choose lacks common control metadata");
    validate_applies_to_syntax(metadata.applies_to, path)?;
    let handlers = lower_error_handlers(metadata.on_errors, path)?;

    if matches!(control, LoadControl::LdCtrlMerge(_)) {
        if !handlers.is_empty() {
            return Err(CompileError::at(path, "LdCtrlMerge cannot attach OnError to a non-executable splice point"));
        }

        return Ok(());
    }

    metadata.code.map_err(|error| error.with_path(path))?;

    match control {
        LoadControl::LdCtrlLoad(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlUnload(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlLoadCompleted(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlMaxLength(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlAbsSegment(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlRelSegment(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlTaskSegment(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlTaskPtr(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlTaskCtrl1(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlTaskCtrl2(control) => {
            load_machine_target(control.lsm_idx, control.obj_type, control.occurrence, path)?;
        }

        LoadControl::LdCtrlWriteProp(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
            if control.trim == Some(true) {
                return Err(CompileError::at(
                    path,
                    "WriteProp Trim=true has no defined project-20 through project-23 load-control semantics",
                ));
            }

            decode_optional_hex(control.inline_data.as_deref(), path)?;
        }
        LoadControl::LdCtrlCompareProp(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
            validate_comparison_syntax(
                control.inline_data.as_deref(),
                control.mask.as_deref(),
                control.range.as_deref(),
                None,
                path,
            )?;
        }
        LoadControl::LdCtrlLoadImageProp(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlInvokeFunctionProp(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
            decode_optional_hex(control.inline_data.as_deref(), path)?;
        }
        LoadControl::LdCtrlReadFunctionProp(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
        }
        LoadControl::LdCtrlDeclarePropDesc(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
            if control.prop_type.trim().is_empty() {
                return Err(CompileError::at(path, "property descriptor has an empty PropType"));
            }
        }

        LoadControl::LdCtrlWriteMem(control) => {
            memory_location(control.address_space.as_deref(), control.address, path)?;
            validate_address_extent(control.address, control.size, "memory", path)?;

            if let Some(data) = decode_optional_hex(control.inline_data.as_deref(), path)? {
                require_exact_length(data.len(), control.size, "WriteMem InlineData", path)?;
            }
        }
        LoadControl::LdCtrlCompareMem(control) => {
            memory_location(control.address_space.as_deref(), control.address, path)?;
            validate_address_extent(control.address, control.size, "memory", path)?;
            validate_comparison_syntax(
                control.inline_data.as_deref(),
                control.mask.as_deref(),
                control.range.as_deref(),
                Some(control.size),
                path,
            )?;
        }
        LoadControl::LdCtrlLoadImageMem(control) => {
            memory_location(control.address_space.as_deref(), control.address, path)?;
            validate_address_extent(control.address, control.size, "memory", path)?;
        }
        LoadControl::LdCtrlWriteRelMem(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
            validate_address_extent(control.offset, control.size, "relative memory", path)?;

            if let Some(data) = decode_optional_hex(control.inline_data.as_deref(), path)? {
                require_exact_length(data.len(), control.size, "WriteRelMem InlineData", path)?;
            }
        }
        LoadControl::LdCtrlCompareRelMem(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
            validate_address_extent(control.offset, control.size, "relative memory", path)?;
            validate_comparison_syntax(
                control.inline_data.as_deref(),
                control.mask.as_deref(),
                control.range.as_deref(),
                Some(control.size),
                path,
            )?;
        }
        LoadControl::LdCtrlLoadImageRelMem(control) => {
            object_selector(control.obj_idx, control.obj_type, control.occurrence, path)?;
            validate_address_extent(control.offset, control.size, "relative memory", path)?;
        }

        LoadControl::LdCtrlSetControlVariable(control) => {
            control_variable(&control.name)
                .ok_or_else(|| CompileError::at(path, format!("unknown control variable {:?}", control.name)))?;
        }
        LoadControl::LdCtrlProgressText(control) => {
            if control.text_id.is_none() && control.message_ref.is_none() {
                return Err(CompileError::at(path, "progress control has neither MessageRef nor TextId"));
            }
            if control.message_ref.as_ref().is_some_and(|reference| reference.trim().is_empty()) {
                return Err(CompileError::at(path, "progress control has an empty MessageRef"));
            }
        }

        LoadControl::LdCtrlClearCachedObjectTypes(_)
        | LoadControl::LdCtrlConnect(_)
        | LoadControl::LdCtrlDisconnect(_)
        | LoadControl::LdCtrlRestart(_)
        | LoadControl::LdCtrlMasterReset(_)
        | LoadControl::LdCtrlDelay(_)
        | LoadControl::LdCtrlMapError(_)
        | LoadControl::LdCtrlClearLCFilterTable(_) => {}

        LoadControl::LdCtrlMerge(_) | LoadControl::Choose(_) => {
            unreachable!("composition controls were handled before executable validation")
        }
    }

    Ok(())
}

pub(in crate::commissioning) fn validate_applies_to_syntax(
    applies_to: Option<&str>,
    path: &ControlPath,
) -> Result<(), CompileError> {
    for token in applies_to.unwrap_or("auto").split(',').map(str::trim) {
        if token.is_empty() {
            return Err(CompileError::at(path, "AppliesTo contains an empty token"));
        }
        if parse_applies_to_token(token).is_none() {
            return Err(CompileError::at(path, format!("unknown AppliesTo token {token:?}")));
        }
    }

    Ok(())
}

pub(in crate::commissioning) fn validate_choose_test_syntax(
    test: &str,
    path: &ControlPath,
) -> Result<(), CompileError> {
    let test = test.trim();
    if test.is_empty() {
        return Err(CompileError::at(path, "choose test is empty"));
    }

    if let Some((_, operand)) = comparison_expression(test)
        && operand.is_empty()
    {
        return Err(CompileError::at(path, format!("choose test {test:?} has no operand")));
    }

    Ok(())
}

pub(in crate::commissioning) fn validate_comparison_syntax(
    inline: Option<&str>,
    mask: Option<&str>,
    range: Option<&str>,
    expected_length: Option<u32>,
    path: &ControlPath,
) -> Result<(), CompileError> {
    let inline = decode_optional_hex(inline, path)?;

    if let Some(range) = range {
        if inline.is_some() || mask.is_some() {
            return Err(CompileError::at(path, "range comparison cannot also declare InlineData or Mask"));
        }

        parse_range(range).map_err(|message| CompileError::at(path, message))?;
        return Ok(());
    }

    if let (Some(data), Some(expected_length)) = (inline.as_ref(), expected_length) {
        require_exact_length(data.len(), expected_length, "comparison InlineData", path)?;
    }

    let mask = decode_optional_hex(mask, path)?;
    let comparison_length = inline.as_ref().map(|data| data.len() as u32).or(expected_length);
    if let (Some(mask), Some(comparison_length)) = (mask, comparison_length)
        && mask.len() != comparison_length as usize
    {
        return Err(CompileError::at(
            path,
            format!("comparison mask has {} bytes, expected {comparison_length}", mask.len()),
        ));
    }

    Ok(())
}

pub(in crate::commissioning) fn validate_address_extent(
    start: u32,
    length: u32,
    address_space: &str,
    path: &ControlPath,
) -> Result<(), CompileError> {
    start.checked_add(length).ok_or_else(|| {
        CompileError::at(
            path,
            format!("{address_space} range {start:#x} + {length:#x} exceeds the 32-bit address space"),
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::compiler::binding::procedure::test_support::root_path;
    use crate::commissioning::compiler::selection::syntax::validate_procedure_syntax;
    use zweidraehte_ets_files::schema::{LdCtrlChoose, LdCtrlMerge, LdCtrlWhen, LdCtrlWriteMem, LoadProcedure};

    #[test]
    fn syntax_audit_walks_unselected_nested_branches() {
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![LoadControl::Choose(LdCtrlChoose {
                param_ref_id: "P-1".to_owned(),
                internal_description: None,
                when: vec![
                    LdCtrlWhen { test: None, is_default: Some(true), internal_description: None, controls: Vec::new() },
                    LdCtrlWhen {
                        test: Some("1".to_owned()),
                        is_default: None,
                        internal_description: None,
                        controls: vec![LoadControl::LdCtrlWriteMem(LdCtrlWriteMem {
                            address_space: Some("FutureSpace".to_owned()),
                            address: 0,
                            size: 1,
                            verify: false,
                            inline_data: Some("00".to_owned()),
                            ..Default::default()
                        })],
                    },
                ],
            })],
        };

        let error = validate_procedure_syntax(root_path(), &procedure)
            .expect_err("unknown tokens in an unselected branch must remain visible to the audit");

        let path = error.path.expect("syntax failures retain a control path");
        assert_eq!(path.control_indices, vec![0, 1, 0]);
    }

    #[test]
    fn syntax_audit_validates_merge_metadata() {
        let procedure = LoadProcedure {
            merge_id: None,
            controls: vec![LoadControl::LdCtrlMerge(LdCtrlMerge {
                applies_to: Some("future".to_owned()),
                merge_id: 3,
                ..Default::default()
            })],
        };

        let error = validate_procedure_syntax(root_path(), &procedure)
            .expect_err("unknown merge applicability must not be skipped");

        assert!(error.to_string().contains("unknown AppliesTo token"));
    }
}
