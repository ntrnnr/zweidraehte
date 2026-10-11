//! Select one published procedure source, then prepare the requested scope.

use crate::commissioning::error::{CompileError, CompileErrorKind};
use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections};
mod peiprog;
mod ranking;

use super::{ProcedureApplicability, ProcedureComposition, ProcedureRequest};
use crate::commissioning::compiler::binding::procedure::ProcedureInput;

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ProcedureId, ResolvedProfile};
use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::procedure::ProcedureSourceId;
use peiprog::{omit_absent_peiprog_partial_block, procedure_writes_peiprog_identity};
use std::collections::BTreeSet;
use zweidraehte_ets_files::product::LoadProcedureStyle;
use zweidraehte_ets_files::schema::LoadControl;
use zweidraehte_ets_files::schema::master_data::Procedure as MasterDataProcedure;

const DOWNLOAD_SCOPES: [(&str, ProgramSections); 7] = [
    ("ap1", ProgramSections::APPLICATION_PROGRAM_1),
    ("ap2", ProgramSections::APPLICATION_PROGRAM_2),
    ("par", ProgramSections::PARAMETERS),
    ("grp", ProgramSections::GROUP_COMMUNICATION),
    ("cfg", ProgramSections::CONFIGURATION),
    ("par,grp", ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION)),
    ("all", ProgramSections::all()),
];

pub(in crate::commissioning) fn select_procedure<'a>(
    resolved: &'a ProgramCompiler<'_>,
) -> Result<(ProcedureRequest, ProcedureInput<'a>), CompileError> {
    let profile = &resolved.profile;
    let product = resolved.input.device.product();
    let (procedure_type, mut sections, mut full, automatic) = match resolved.input.intent {
        CommissioningIntent::Unload(_) => ("Unload", ProgramSections::all(), true, false),
        CommissioningIntent::Download(mode) | CommissioningIntent::AssignAddressAndDownload(mode) => match mode {
            DownloadMode::Full => ("Load", ProgramSections::all(), true, false),
            DownloadMode::Partial(sections) => ("Load", sections, false, false),
            DownloadMode::Automatic => {
                let sections = resolved.input.options.automatic_sections.ok_or_else(|| {
                    CompileError::missing_evidence("automatic download requires explicitly resolved program sections")
                })?;
                ("Load", sections, sections == ProgramSections::all(), true)
            }
        },
        CommissioningIntent::AssignAddress => unreachable!("address assignment has no authored procedure"),
    };
    if sections.is_empty() {
        return Err(CompileError::invalid("the requested download contains no program sections"));
    }
    let mut subtype = if full {
        "all"
    } else if let Some((subtype, _)) =
        DOWNLOAD_SCOPES.iter().find(|(subtype, scope)| *subtype != "all" && *scope == sections)
    {
        *subtype
    } else {
        // Combined sections need not have a named published subtype. Source
        // selection below retains their actual applicability independently.
        "all"
    };
    let is_download = procedure_type == "Load";
    if is_download && !full && sections.contains(ProgramSections::APPLICATION_PROGRAM_2) {
        return Err(CompileError::invalid(format!(
            "product {} has no Application Program 2 in its selected hardware relation",
            product.id()
        )));
    }

    // Automatic scope may widen to a published superset. Retain the source
    // selected here: neither composition nor image binding selects it again.
    let mut selected = None;
    let mut empty_configuration_source = false;
    if is_download && !full && !automatic {
        match ranking::select_partial_source(profile, sections)? {
            Some((source, source_subtype)) => {
                selected = Some(source);
                subtype = source_subtype;
            }
            None => {
                empty_configuration_source = true;
                subtype = "cfg";
            }
        }
    }
    if automatic {
        if product.load_procedure_style() == LoadProcedureStyle::Product {
            full = true;
            subtype = "all";
        } else {
            let mut candidates: Vec<_> =
                DOWNLOAD_SCOPES.into_iter().filter(|(_, scope)| scope.contains(sections)).collect();
            candidates.sort_by_key(|(subtype, scope)| (scope.extra_section_count(sections), *subtype == "all"));
            for (candidate, scope) in candidates {
                match select_master_procedure(profile, "Load", candidate) {
                    Ok(source) => {
                        selected = Some(source);
                        sections = scope;
                        subtype = candidate;
                        full = candidate == "all";
                        break;
                    }
                    Err(error) if error.kind == CompileErrorKind::MissingProcedure => {}
                    Err(error) => return Err(error),
                }
            }
            if selected.is_none() {
                // Preserve the requested subtype's diagnostic if no safe
                // published superset exists.
                select_master_procedure(profile, procedure_type, subtype)?;
                unreachable!("an exact procedure is also a superset candidate");
            }
        }
    }

    // Load/ap1 is the complete single-application path on merged profiles.
    // It retains full applicability for parameters, groups and configuration;
    // only its reported semantic section set excludes the unused PEI program.
    if is_download && full {
        sections = primary_application_program_sections();
        if product.load_procedure_style() != LoadProcedureStyle::Product {
            match select_master_procedure(profile, "Load", "ap1") {
                Ok(source) => {
                    selected = Some(source);
                    subtype = "ap1";
                }
                Err(error)
                    if error.kind == CompileErrorKind::MissingProcedure
                        && product.load_procedure_style() == LoadProcedureStyle::Default => {}
                Err(error) => return Err(error),
            }
        }
    }
    let request = ProcedureRequest {
        procedure_type,
        subtype,
        applicability: ProcedureApplicability { full, automatic: true, sections },
    };
    let is_full_download = is_download && full;

    let (source, composition, controls, mut product_merge_fragments) = if empty_configuration_source {
        (
            ProcedureSourceId::Generated { name: "empty application configuration source".to_owned() },
            ProcedureComposition::Default,
            &[] as &[LoadControl],
            Vec::new(),
        )
    } else if is_full_download && product.load_procedure_style() == LoadProcedureStyle::Product {
        let [procedure] = product.load_procedures() else {
            return Err(CompileError::invalid(format!(
                "product {product} has an invalid load-procedure definition: {reason}",
                product = product.id().to_owned(),
                reason = "ProductProcedure requires exactly one complete load procedure".to_owned()
            )));
        };

        if procedure.merge_id.is_some() {
            return Err(CompileError::invalid(format!(
                "product {product} has an invalid load-procedure definition: {reason}",
                product = product.id().to_owned(),
                reason = "the complete ProductProcedure declares a MergeId".to_owned()
            )));
        }

        (
            ProcedureSourceId::Product { product_id: product.id().to_owned(), source_index: 0, merge_id: None },
            ProcedureComposition::ProductOwned,
            procedure.controls.as_slice(),
            Vec::new(),
        )
    } else {
        let (procedure_id, source) = match selected {
            Some(source) => source,
            None => select_master_procedure(profile, procedure_type, subtype)?,
        };
        let is_download = request.procedure_type == "Load";

        let (composition, product_merge_fragments) = match product.load_procedure_style() {
            LoadProcedureStyle::Merged if is_download => {
                if product.load_procedures().iter().any(|procedure| procedure.merge_id.is_none()) {
                    return Err(CompileError::invalid(format!(
                        "product {product} has an invalid load-procedure definition: {reason}",
                        product = product.id().to_owned(),
                        reason = "MergedProcedure contains a fragment without MergeId".to_owned()
                    )));
                }

                (ProcedureComposition::Merged, product.load_procedures().iter().collect::<Vec<_>>())
            }
            LoadProcedureStyle::Default if is_download && !product.load_procedures().is_empty() => {
                return Err(CompileError::invalid(format!(
                    "product {product} has an invalid load-procedure definition: {reason}",
                    product = product.id().to_owned(),
                    reason = "DefaultProcedure product unexpectedly contains load procedures".to_owned()
                )));
            }
            _ => (ProcedureComposition::Default, Vec::new()),
        };

        (ProcedureSourceId::MasterData(procedure_id), composition, source.controls.as_slice(), product_merge_fragments)
    };
    // Shape validation examines every authored branch. Reuse its merge set
    // for partial-fragment selection and the exact legacy Peiprog contract.
    let mut merge_ids = BTreeSet::new();
    collect_merge_ids(controls, &mut merge_ids);
    let omitted_controls = if request.procedure_type == "Load"
        && !request.applicability.full
        && matches!(request.subtype, "par" | "par,grp")
        && (merge_ids.contains(&3) || merge_ids.contains(&5))
    {
        let omitted = omit_absent_peiprog_partial_block(profile, controls)?;
        merge_ids.remove(&3);
        merge_ids.remove(&5);
        omitted
    } else {
        Vec::new()
    };
    // A partial source exposes only its own merge points; full paths still
    // account for every supplied fragment, including complete Load/ap1.
    if composition == ProcedureComposition::Merged && !request.applicability.full {
        product_merge_fragments.retain(|fragment| fragment.merge_id.is_some_and(|id| merge_ids.contains(&id)));
    }
    let download_stamps = if request.procedure_type == "Load" {
        crate::commissioning::catalog::rules::resolved_download_stamp_resources(
            profile,
            resolved.standard_memory_service,
        )?
    } else {
        Vec::new()
    };
    let peiprog_identity_reference = omitted_controls.is_empty()
        && procedure_writes_peiprog_identity(profile, controls, &product_merge_fragments, &merge_ids)?;

    let input = ProcedureInput {
        profile,
        procedure_id: source,
        composition,
        controls,
        product_merge_fragments,
        omitted_controls,
        parameter_values: &resolved.input.device.configuration().procedure_parameters,
        applicability: request.applicability,
        configuration_anchor: profile.configuration_anchor(),
        download_stamps,
        property_parameters: product.property_parameters(),
        peiprog_identity_reference,
        progress_messages_by_reference: &resolved.input.options.progress_messages_by_reference,
        progress_messages_by_id: &resolved.input.options.progress_messages_by_id,
        initial_tool_state: crate::commissioning::compiler::binding::facts::initial_tool_state(product)?,
        standard_memory_service: resolved.standard_memory_service,
        restart_kind: resolved.restart_kind,
        application_identity: product.application_identity(),
        secure_only: resolved.input.facts.target.is_some_and(|target| target.credential.is_secure()),
    };
    Ok((request, input))
}

pub(super) fn collect_merge_ids(controls: &[LoadControl], merge_ids: &mut BTreeSet<u8>) {
    for control in controls {
        match control {
            LoadControl::LdCtrlMerge(control) => {
                merge_ids.insert(control.merge_id);
            }
            LoadControl::Choose(choice) => {
                for branch in &choice.when {
                    collect_merge_ids(&branch.controls, merge_ids);
                }
            }
            _ => {}
        }
    }
}

pub(super) fn control_object_selector(control: &LoadControl) -> Option<ObjectSelector> {
    macro_rules! selector {
        ($control:expr, $index:ident) => {
            selector_from_parts($control.$index, $control.obj_type, $control.occurrence)
        };
    }

    match control {
        LoadControl::LdCtrlUnload(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlLoad(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlMaxLength(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlLoadCompleted(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlAbsSegment(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlRelSegment(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlTaskSegment(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlTaskPtr(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlTaskCtrl1(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlTaskCtrl2(control) => selector!(control, lsm_idx),
        LoadControl::LdCtrlWriteProp(control) => selector!(control, obj_idx),
        LoadControl::LdCtrlCompareProp(control) => selector!(control, obj_idx),
        LoadControl::LdCtrlLoadImageProp(control) => selector!(control, obj_idx),
        LoadControl::LdCtrlInvokeFunctionProp(control) => selector!(control, obj_idx),
        LoadControl::LdCtrlReadFunctionProp(control) => selector!(control, obj_idx),
        LoadControl::LdCtrlWriteRelMem(control) => selector!(control, obj_idx),
        LoadControl::LdCtrlCompareRelMem(control) => selector!(control, obj_idx),
        LoadControl::LdCtrlLoadImageRelMem(control) => selector!(control, obj_idx),
        LoadControl::LdCtrlDeclarePropDesc(control) => selector!(control, obj_idx),
        _ => None,
    }
}

pub(super) fn selector_from_parts(
    index: Option<u8>,
    object_type: Option<u16>,
    occurrence: Option<u16>,
) -> Option<ObjectSelector> {
    match (index, object_type) {
        (Some(index), None) => Some(ObjectSelector::Index { index: u16::from(index) }),
        (None, Some(object_type)) => {
            Some(ObjectSelector::Type { object_type, occurrence: Occurrence::from_option(occurrence) })
        }
        _ => None,
    }
}

pub(super) fn count_property_writes(controls: &[LoadControl], object: &ObjectSelector, property_id: u16) -> usize {
    controls
        .iter()
        .map(|control| match control {
            LoadControl::LdCtrlWriteProp(control)
                if selector_from_parts(control.obj_idx, control.obj_type, control.occurrence).as_ref()
                    == Some(object)
                    && control.prop_id == property_id =>
            {
                1
            }
            LoadControl::Choose(choice) => {
                choice.when.iter().map(|branch| count_property_writes(&branch.controls, object, property_id)).sum()
            }
            _ => 0,
        })
        .sum()
}

pub(crate) fn primary_application_program_sections() -> ProgramSections {
    ProgramSections::APPLICATION_PROGRAM_1
        .union(ProgramSections::PARAMETERS)
        .union(ProgramSections::GROUP_COMMUNICATION)
        .union(ProgramSections::CONFIGURATION)
}

fn select_master_procedure<'a>(
    profile: &'a ResolvedProfile,
    procedure_type: &str,
    subtype: &str,
) -> Result<(ProcedureId, &'a MasterDataProcedure), CompileError> {
    let matches: Vec<_> = profile
        .source()
        .procedures
        .iter()
        .flat_map(|procedures| &procedures.procedures)
        .enumerate()
        .filter(|(_, procedure)| {
            procedure.allows_remote()
                && procedure.procedure_type == procedure_type
                && procedure.procedure_sub_type.as_deref() == Some(subtype)
        })
        .collect();

    match matches.as_slice() {
        [] => Err(CompileError::missing_procedure(format!(
            "profile {mask} variant {variant} has no exact {procedure_type}/{subtype} procedure",
            mask = profile.mask().full_id.clone(),
            variant = profile.variant().source_index,
            procedure_type = procedure_type.to_owned(),
            subtype = subtype.to_owned()
        ))),
        [(source_index, procedure)] => Ok((
            ProcedureId {
                procedure_type: procedure.procedure_type.clone(),
                subtype: procedure.procedure_sub_type.clone(),
                management_style: profile.management_style(),
                source_index: *source_index,
            },
            *procedure,
        )),
        procedures => Err(CompileError::invalid(format!(
            "profile {mask} variant {variant} has ambiguous {procedure_type}/{subtype} procedures at {source_indices:?}",
            mask = profile.mask().full_id.clone(),
            variant = profile.variant().source_index,
            procedure_type = procedure_type.to_owned(),
            subtype = subtype.to_owned(),
            source_indices = procedures.iter().map(|(index, _)| *index).collect::<Vec<_>>()
        ))),
    }
}
