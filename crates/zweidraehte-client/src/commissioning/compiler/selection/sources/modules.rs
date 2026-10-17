//! Expand module fragments without changing their authored definitions.

use crate::commissioning::compiler::binding::procedure::InstantiatedModuleProcedure;
use crate::commissioning::error::CompileError;
use crate::commissioning::procedure::ProcedureSourceId;
use std::collections::BTreeSet;
use zweidraehte_ets_files::product::{MaterializedModule, MaterializedModuleArgument, ProductData};
use zweidraehte_ets_files::schema::LoadControl;

pub(super) fn instantiate(
    product: &ProductData,
    modules: &[MaterializedModule],
) -> Result<Vec<InstantiatedModuleProcedure>, CompileError> {
    let mut result = Vec::new();
    let mut instances = BTreeSet::new();
    // The materialized roster is ordered input. Do not sort or allocate its
    // arguments again: those values already include allocator arithmetic.
    for module in modules {
        if !instances.insert(&module.instance_id) {
            return Err(CompileError::invalid(format!("duplicate module instance {}", module.instance_id)));
        }
        let fragments = product.module_load_procedures(&module.definition_id).ok_or_else(|| {
            CompileError::invalid(format!(
                "unknown module definition {} for {}",
                module.definition_id, module.instance_id
            ))
        })?;
        let mut ids = BTreeSet::new();
        for (source_index, authored) in fragments.iter().enumerate() {
            let merge_id =
                authored.merge_id.ok_or_else(|| CompileError::invalid("module procedure requires MergeId"))?;
            if !ids.insert(merge_id) {
                return Err(CompileError::invalid(format!(
                    "duplicate module MergeId {merge_id} in {}",
                    module.definition_id
                )));
            }
            let mut procedure = authored.clone();
            expand(product, module, &mut procedure.controls)?;
            result.push(InstantiatedModuleProcedure {
                source: ProcedureSourceId::Module {
                    application_id: product.id().to_owned(),
                    definition_id: module.definition_id.clone(),
                    instance_id: module.instance_id.clone(),
                    source_index,
                    merge_id,
                },
                procedure,
            });
        }
    }
    Ok(result)
}

fn base(
    product: &ProductData,
    module: &MaterializedModule,
    argument: &str,
    relative: u32,
    maximum: u32,
) -> Result<u32, CompileError> {
    let value =
        product.module_argument_name(&module.definition_id, argument).and_then(|name| module.arguments.get(name));
    let Some(MaterializedModuleArgument::Numeric(value)) = value else {
        return Err(CompileError::invalid(format!(
            "module {} requires numeric argument {argument}",
            module.instance_id
        )));
    };
    u32::try_from(*value)
        .ok()
        .and_then(|value| value.checked_add(relative))
        .filter(|value| *value <= maximum)
        .ok_or_else(|| {
            CompileError::invalid(format!(
                "module {} argument {argument} exceeds its control address range",
                module.instance_id
            ))
        })
}

fn address(
    product: &ProductData,
    module: &MaterializedModule,
    index: &mut Option<u8>,
    occurrence: &mut Option<u16>,
    index_base: &mut Option<String>,
    occurrence_base: &mut Option<String>,
) -> Result<(), CompileError> {
    if let Some(argument) = index_base.take() {
        *index = Some(base(product, module, &argument, u32::from(index.unwrap_or(0)), u32::from(u8::MAX))? as u8);
    }
    if let Some(argument) = occurrence_base.take() {
        *occurrence =
            Some(base(product, module, &argument, u32::from(occurrence.unwrap_or(0)), u32::from(u16::MAX))? as u16);
    }
    Ok(())
}

fn expand(
    product: &ProductData,
    module: &MaterializedModule,
    controls: &mut [LoadControl],
) -> Result<(), CompileError> {
    for control in controls {
        macro_rules! resolve {
            ($value:expr) => {
                address(
                    product,
                    module,
                    &mut $value.obj_idx,
                    &mut $value.occurrence,
                    &mut $value.base_obj_idx,
                    &mut $value.base_occurrence,
                )?
            };
        }
        match control {
            LoadControl::LdCtrlWriteProp(value) => {
                resolve!(value);
                if let Some(argument) = value.base_start_element.take() {
                    value.start_element = Some(base(
                        product,
                        module,
                        &argument,
                        u32::from(value.start_element.unwrap_or(1)),
                        u32::from(u16::MAX),
                    )? as u16);
                }
            }
            LoadControl::LdCtrlCompareProp(value) => {
                resolve!(value);
                if let Some(argument) = value.base_start_element.take() {
                    value.start_element = Some(base(
                        product,
                        module,
                        &argument,
                        u32::from(value.start_element.unwrap_or(1)),
                        u32::from(u16::MAX),
                    )? as u16);
                }
            }
            LoadControl::LdCtrlInvokeFunctionProp(value) => resolve!(value),
            LoadControl::LdCtrlReadFunctionProp(value) => resolve!(value),
            // A module choice tests the parameter of one concrete instance.
            // Procedure parameters are keyed by plain ParameterRef ID, so a
            // lookup could silently test another instance or the root program.
            // TODO: carry instance-qualified procedure selectors before
            // admitting conditional module fragments.
            LoadControl::Choose(_) => {
                return Err(CompileError::unsupported(format!(
                    "module {} has a conditional load procedure; instance-aware parameter selection is unsupported",
                    module.instance_id
                )));
            }
            LoadControl::LdCtrlDelay(_)
            | LoadControl::LdCtrlProgressText(_)
            | LoadControl::LdCtrlDeclarePropDesc(_)
            | LoadControl::LdCtrlMerge(_) => {}
            _ => return Err(CompileError::invalid("control is outside the module procedure vocabulary")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::error::CompileErrorKind;
    use std::collections::BTreeMap;
    use zweidraehte_ets_files::schema::*;

    fn product() -> ProductData {
        let program = ApplicationProgram {
            id: "M-00FA_A-0001-01-0000".into(),
            mask_version: "MV-0705".into(),
            module_defs: Some(ModuleDefs {
                module_defs: vec![ModuleDef {
                    id: "channel".into(),
                    name: "Channel".into(),
                    internal_description: None,
                    dynamic: None,
                    arguments: Some(ModuleDefArguments {
                        arguments: ["Index", "Occurrence", "Element"]
                            .into_iter()
                            .map(|name| ModuleDefArgument {
                                id: name.to_lowercase(),
                                name: name.into(),
                                allocates: None,
                                alignment: None,
                                arg_type: None,
                            })
                            .collect(),
                    }),
                    static_section: ModuleDefStatic {
                        load_procedures: Some(LoadProcedures {
                            procedures: vec![LoadProcedure {
                                merge_id: Some(4),
                                controls: vec![
                                    LoadControl::LdCtrlWriteProp(LdCtrlWriteProp {
                                        obj_idx: Some(1),
                                        prop_id: 208,
                                        base_obj_idx: Some("index".into()),
                                        count: Some(164),
                                        inline_data: Some("".into()),
                                        applies_to: Some("par".into()),
                                        ..Default::default()
                                    }),
                                    LoadControl::LdCtrlCompareProp(LdCtrlCompareProp {
                                        obj_type: Some(9),
                                        occurrence: Some(2),
                                        prop_id: 208,
                                        start_element: Some(12),
                                        base_occurrence: Some("occurrence".into()),
                                        base_start_element: Some("element".into()),
                                        ..Default::default()
                                    }),
                                ],
                            }],
                        }),
                        ..Default::default()
                    },
                }],
            }),
            ..Default::default()
        };
        ProductData::from_program(&program).expect("synthetic module product")
    }

    fn module(id: &str, index: i64) -> MaterializedModule {
        MaterializedModule {
            instance_id: id.into(),
            definition_id: "channel".into(),
            arguments: BTreeMap::from([
                ("Index".into(), MaterializedModuleArgument::Numeric(index)),
                ("Occurrence".into(), MaterializedModuleArgument::Numeric(10)),
                ("Element".into(), MaterializedModuleArgument::Numeric(20)),
            ]),
        }
    }

    #[test]
    fn instances_resolve_bases_in_roster_order_without_mutating_authored_controls() {
        let product = product();
        let fragments = instantiate(&product, &[module("second", 7), module("first", 6)]).expect("bounded bases");
        for (fragment, expected, id) in [(&fragments[0], 8, "second"), (&fragments[1], 7, "first")] {
            assert!(matches!(&fragment.source, ProcedureSourceId::Module { instance_id, .. } if instance_id == id));
            assert!(matches!(&fragment.procedure.controls[0], LoadControl::LdCtrlWriteProp(value)
                if value.obj_idx == Some(expected) && value.base_obj_idx.is_none()
                    && value.inline_data.as_deref() == Some("") && value.count == Some(164)
                    && value.applies_to.as_deref() == Some("par")));
            assert!(matches!(&fragment.procedure.controls[1], LoadControl::LdCtrlCompareProp(value)
                if value.occurrence == Some(12) && value.start_element == Some(32)
                    && value.base_occurrence.is_none() && value.base_start_element.is_none()));
        }
        assert!(matches!(&product.module_load_procedures("channel").expect("known definition")[0].controls[0],
            LoadControl::LdCtrlWriteProp(value) if value.obj_idx == Some(1) && value.base_obj_idx.as_deref() == Some("index")));
    }

    #[test]
    fn invalid_or_missing_numeric_bases_and_duplicate_instances_fail() {
        let product = product();
        for (name, value) in [
            ("Index", MaterializedModuleArgument::Numeric(-1)),
            ("Index", MaterializedModuleArgument::Numeric(255)),
            ("Occurrence", MaterializedModuleArgument::Numeric(65535)),
            ("Element", MaterializedModuleArgument::Numeric(65535)),
            ("Index", MaterializedModuleArgument::Text("six".into())),
        ] {
            let mut instance = module("channel-1", 6);
            instance.arguments.insert(name.into(), value);
            assert!(instantiate(&product, &[instance]).is_err());
        }
        let mut instance = module("channel-1", 6);
        instance.arguments.remove("Index");
        assert!(instantiate(&product, &[instance]).is_err());
        assert!(instantiate(&product, &[module("same", 6), module("same", 7)]).is_err());
    }

    #[test]
    fn conditional_module_fragments_are_unsupported_rather_than_rekeyed() {
        let mut program = ApplicationProgram { id: "M-00FA_A-0001-01-0000".into(), ..Default::default() };
        program.module_defs = Some(ModuleDefs {
            module_defs: vec![ModuleDef {
                id: "channel".into(),
                name: "Channel".into(),
                internal_description: None,
                dynamic: None,
                arguments: None,
                static_section: ModuleDefStatic {
                    load_procedures: Some(LoadProcedures {
                        procedures: vec![LoadProcedure {
                            merge_id: Some(4),
                            controls: vec![LoadControl::Choose(LdCtrlChoose {
                                param_ref_id: "channel_P-1_R-1".into(),
                                ..Default::default()
                            })],
                        }],
                    }),
                    ..Default::default()
                },
            }],
        });
        let product = ProductData::from_program(&program).expect("synthetic conditional module");
        let instance = MaterializedModule {
            instance_id: "channel-1".into(),
            definition_id: "channel".into(),
            arguments: BTreeMap::new(),
        };

        let error = instantiate(&product, &[instance]).expect_err("instance-aware selectors are absent");
        assert_eq!(error.kind, CompileErrorKind::Unsupported);
        assert!(error.message.contains("conditional load procedure"), "{}", error.message);
    }
}
