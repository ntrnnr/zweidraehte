//! Select one published procedure source, then prepare the requested scope.

use crate::commissioning::error::{CompileError, CompileErrorKind};
use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections};
mod modules;
mod peiprog;
mod ranking;

use super::{ProcedureApplicability, ProcedureComposition, ProcedureRequest};
use crate::commissioning::compiler::binding::procedure::ProcedureInput;

use crate::commissioning::catalog::profile::{ObjectSelector, Occurrence, ProcedureId, ResolvedProfile};
use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::procedure::ProcedureSourceId;
use peiprog::{omit_absent_peiprog_partial_block, procedure_writes_peiprog_identity};
use std::collections::BTreeSet;
use zweidraehte_ets_files::product::{ApplicationProgram2Binding, LoadProcedureStyle};
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
    let has_application_program_2 = product.secondary_application().is_some();
    if is_download && !full && sections.contains(ProgramSections::APPLICATION_PROGRAM_2) && !has_application_program_2 {
        return Err(CompileError::invalid(format!(
            "product {} has no Application Program 2 in its selected hardware relation",
            product.id()
        )));
    }

    // Automatic scope may widen to a published superset. Retain the source
    // selected here: neither composition nor image binding selects it again.
    let mut selected = None;
    let mut empty_configuration_source = false;
    if is_download && !full && !automatic && product.load_procedure_style() != LoadProcedureStyle::Product {
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
    // The reference chooses its mask procedure by whether the second
    // application slot is occupied, so a bound PEI Program keeps `all`.
    if is_download && full && !has_application_program_2 {
        sections = primary_application_program_sections();
        if product.load_procedure_style() != LoadProcedureStyle::Product {
            match select_master_procedure(profile, "Load", "ap1") {
                Ok(source) => {
                    selected = Some(source);
                    subtype = "ap1";
                }
                // Masks without a single-application path (couplers and
                // routers) keep the complete `all` procedure for default and
                // merged products alike.
                Err(error) if error.kind == CompileErrorKind::MissingProcedure => {}
                Err(error) => return Err(error),
            }
        }
    }
    let request = ProcedureRequest {
        procedure_type,
        subtype,
        applicability: ProcedureApplicability { full, automatic: true, sections },
    };
    let (source, composition, controls, mut product_merge_fragments) = if empty_configuration_source {
        (
            ProcedureSourceId::Generated { name: "empty application configuration source".to_owned() },
            ProcedureComposition::Default,
            &[] as &[LoadControl],
            Vec::new(),
        )
    } else if is_download && product.load_procedure_style() == LoadProcedureStyle::Product {
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

                let mut ids = BTreeSet::new();
                for fragment in product.load_procedures() {
                    let id = fragment.merge_id.expect("merged fragments have ids");
                    if !ids.insert(id) {
                        return Err(CompileError::invalid(format!("product defines MergeId {id} more than once")));
                    }
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
        match omit_absent_peiprog_partial_block(profile, controls)? {
            Some(omitted) => {
                merge_ids.remove(&3);
                merge_ids.remove(&5);
                omitted
            }
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    // A product publishes fragments for several mask procedures. Even a full
    // Load selects only its own splice points: MV-091A reserves MergeId 5 for
    // Unload. Passing that unrelated fragment to lowering invents a missing
    // Load splice point instead of following the selected mask procedure.
    if composition == ProcedureComposition::Merged {
        product_merge_fragments.retain(|fragment| fragment.merge_id.is_some_and(|id| merge_ids.contains(&id)));
    }
    let download_stamps = if request.procedure_type == "Load" {
        if product.secondary_application().is_some() {
            crate::commissioning::catalog::rules::resolved_download_stamp_resources_with_pei_program(
                profile,
                resolved.standard_memory_service,
            )?
        } else {
            crate::commissioning::catalog::rules::resolved_download_stamp_resources(
                profile,
                resolved.standard_memory_service,
            )?
        }
    } else {
        Vec::new()
    };
    // A bound secondary PEI Program contributes its fragments at the same
    // merge points as the primary application.
    let secondary = product.secondary_application();
    let mut secondary_merge_fragments = Vec::new();
    let mut secondary_product_procedure = None;
    if let Some(secondary) = secondary
        && request.procedure_type == "Load"
    {
        if composition == ProcedureComposition::ProductOwned
            && secondary.load_procedure_style() == LoadProcedureStyle::Product
        {
            let [procedure] = secondary.load_procedures() else {
                return Err(CompileError::invalid(format!(
                    "secondary PEI Program {} requires exactly one complete product procedure",
                    secondary.id()
                )));
            };
            if procedure.merge_id.is_some() {
                return Err(CompileError::invalid(format!(
                    "secondary PEI Program {} complete product procedure declares a MergeId",
                    secondary.id()
                )));
            }
            secondary_product_procedure = Some(procedure);
        } else if composition != ProcedureComposition::Merged
            || secondary.load_procedure_style() != LoadProcedureStyle::Merged
        {
            return Err(CompileError::unsupported(format!(
                "secondary PEI Program {} composes only into a merged mask procedure",
                secondary.id()
            )));
        }
        if secondary_product_procedure.is_none() {
            secondary_merge_fragments = secondary.load_procedures().iter().collect();
        }
        if secondary_merge_fragments.iter().any(|procedure| procedure.merge_id.is_none()) {
            return Err(CompileError::invalid(format!(
                "secondary PEI Program {} contains a fragment without MergeId",
                secondary.id()
            )));
        }
        let mut ids = BTreeSet::new();
        for fragment in &secondary_merge_fragments {
            let id = fragment.merge_id.expect("secondary fragments have ids");
            if !ids.insert(id) {
                return Err(CompileError::invalid(format!(
                    "secondary application defines MergeId {id} more than once"
                )));
            }
        }
        secondary_merge_fragments.retain(|fragment| fragment.merge_id.is_some_and(|id| merge_ids.contains(&id)));
    }
    let peiprog_identity_reference = omitted_controls.is_empty()
        && procedure_writes_peiprog_identity(profile, controls, &product_merge_fragments, &merge_ids)?;

    // A coupler at a device address (x.y.z, z != 0) runs as a repeater and
    // keeps no group filter. The reference then drops the first filter-table
    // clear of a mask procedure it takes as published (DefaultProcedure
    // products); couplers at x.y.0 and merged procedures keep it. The filter
    // write that follows owns no bytes and is skipped on its own.
    //
    // TODO: A segment coupler keeps the clear at a device address too; the
    // configuration does not represent segment-coupler operation yet.
    let mut omitted_controls = omitted_controls;
    if is_download
        && composition == ProcedureComposition::Default
        && resolved.input.device.configuration().individual_address.device() != 0
        && let Some(index) =
            controls.iter().position(|control| matches!(control, LoadControl::LdCtrlClearLCFilterTable(_)))
    {
        omitted_controls.push(index);
    }

    let module_procedures = modules::instantiate(product, resolved.input.device.modules())?;
    let input = ProcedureInput {
        profile,
        procedure_id: source,
        composition,
        controls,
        product_merge_fragments,
        secondary_merge_fragments,
        secondary_product_procedure,
        secondary_application_id: secondary.map(|secondary| secondary.id()),
        module_procedures_are_empty: module_procedures.is_empty(),
        module_procedures,
        omitted_controls,
        parameter_values: &resolved.input.device.configuration().procedure_parameters,
        applicability: request.applicability,
        configuration_anchor: profile.configuration_anchor(),
        download_stamps,
        property_parameters: product.property_parameters(),
        peiprog_identity_reference,
        application_program_2_present: matches!(
            product.application_program_2(),
            ApplicationProgram2Binding::Present { .. }
        ),
        progress_messages_by_reference: &resolved.input.options.progress_messages_by_reference,
        progress_messages_by_id: &resolved.input.options.progress_messages_by_id,
        message_sources: std::iter::once(product).chain(secondary).collect(),
        initial_tool_state: crate::commissioning::compiler::binding::facts::initial_tool_state(product)?,
        standard_memory_service: resolved.standard_memory_service,
        restart_kind: resolved.restart_kind,
        application_identity: crate::commissioning::compiler::application_identity::download_identity(product),
        secondary_application_identity: secondary
            .map(crate::commissioning::compiler::application_identity::download_identity),
        // The reference adds a Data Security profile for a secure-enabled
        // application and an options profile for its application options;
        // either may admit extended property services.
        // TODO: RF multi end devices add a third such profile on masks the
        // reference selects by identifier prefix; that selection is not
        // established, so those devices locate the object instead.
        extended_property_descriptions: product.supports_data_secure()
            || product.programming_options().supports_extended_property_services().value,
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
            Some(ObjectSelector::Type { object_type, occurrence: Occurrence::from_schema(occurrence) })
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

pub(in crate::commissioning::compiler) fn select_master_procedure<'a>(
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
