//! installed contract evidence for binding and revalidation.

use crate::commissioning::catalog::SelectedResource;
use crate::commissioning::catalog::profile::{ReadAccess, ResolvedProfile};
use crate::commissioning::compiler::image::application_identity_resource_value;
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::operands::{MemoryService, StandardMemoryService};
use crate::commissioning::procedure::{
    FunctionPropertyOperation, NormalizedProcedure, OperationTarget, ProcedureOperation,
};
use crate::commissioning::runtime::prepared::{BoundRead, ReadExpectation};
use zweidraehte_ets_files::product::ProductData;
use zweidraehte_proto::messages::apdu::load_control::LoadState;
use zweidraehte_proto::pid;

pub(in crate::commissioning) fn partial_installed_state_requirements(
    plan: &CompiledProgram,
    product: &ProductData,
) -> Result<Vec<BoundRead>> {
    let Some(sections) = plan.program_sections() else { return Ok(Vec::new()) };
    if plan.is_full_program_scope() || !sections_reuse_application_state(sections) {
        return Ok(Vec::new());
    }

    if sections.contains(ProgramSections::APPLICATION_PROGRAM_2) {
        return Err(Diagnostic::preparation("partial download selects AP2, which is unsupported"));
    }
    let selects_application = sections.contains(ProgramSections::APPLICATION_PROGRAM_1);
    let has_ap1_contract_resource =
        plan.profile().resource_names().any(|name| matches!(name, "ApplicationId" | "ApplicationLoadStatus"));
    let procedure = plan.procedure().ok_or_else(|| {
        Diagnostic::preparation(format!(
            "partial download for profile {} has no normalized procedure from which to prove application semantics",
            plan.profile().mask()
        ))
    })?;
    let procedure_targets_application = normalized_procedure_targets_application(plan.profile(), procedure)?;
    if !selects_application && !has_ap1_contract_resource && !procedure_targets_application {
        return Ok(Vec::new());
    }

    let identity = exact_partial_resource(plan.profile(), "ApplicationId", &[4, 5])?;
    let status = exact_partial_resource(plan.profile(), "ApplicationLoadStatus", &[1])?;
    let (identity, status) = match (identity, status) {
        (Some(identity), Some(status)) => (identity, status),
        (None, None) => {
            return Err(Diagnostic::preparation(format!(
                "partial download for profile {} targets AP1 state but resolves no ApplicationLoadStatus/ApplicationId pair",
                plan.profile().mask(),
            )));
        }
        _ => {
            return Err(Diagnostic::preparation(format!(
                "partial download for profile {} resolves only one of ApplicationLoadStatus and ApplicationId",
                plan.profile().mask(),
            )));
        }
    };
    let expected = application_identity_resource_value(
        identity.name(),
        identity.length(),
        &product.application_identity().application_id,
    )
    .map_err(|error| Diagnostic::preparation(error.to_string()))?
    .to_vec();
    let minimum_service =
        if plan.management_secure() { StandardMemoryService::Extended } else { StandardMemoryService::Classic };
    let mut requirements = Vec::new();
    for (resource, expected) in [(status, vec![LoadState::Loaded.into()]), (identity, expected)] {
        let service = resource.read(minimum_service).map_err(|error| Diagnostic::preparation(error.to_string()))?;
        if !matches!(
            service.target,
            OperationTarget::Property { .. }
                | OperationTarget::Memory {
                    service: MemoryService::Classic
                        | MemoryService::Extended
                        | MemoryService::Standard
                        | MemoryService::User,
                    ..
                }
        ) {
            return Err(Diagnostic::preparation(format!(
                "partial-download resource {} has no live readable online location",
                resource.id
            )));
        }
        requirements.push(BoundRead {
            resource: resource.id,
            service,
            expected: ReadExpectation::Exact(Some(expected)),
        });
    }
    Ok(requirements)
}

pub(in crate::commissioning) fn sections_reuse_application_state(sections: ProgramSections) -> bool {
    sections.contains(ProgramSections::APPLICATION_PROGRAM_1)
        || sections.contains(ProgramSections::APPLICATION_PROGRAM_2)
        || sections.contains(ProgramSections::PARAMETERS)
        || sections.contains(ProgramSections::GROUP_COMMUNICATION)
}

pub(in crate::commissioning) fn exact_partial_resource<'a>(
    profile: &'a ResolvedProfile,
    name: &str,
    allowed_lengths: &[u32],
) -> Result<Option<SelectedResource<'a>>> {
    let Some(resource) = profile.resource(name).map_err(|error| Diagnostic::preparation(error.to_string()))? else {
        return Ok(None);
    };

    if resource.access_rights().map_err(|error| Diagnostic::preparation(error.to_string()))?.read != ReadAccess::Runtime
    {
        return Err(Diagnostic::preparation(format!(
            "partial-download resource {} ({name}) is not runtime-readable",
            resource.id
        )));
    }
    if !allowed_lengths.contains(&resource.length()) {
        return Err(Diagnostic::preparation(format!(
            "partial-download resource {} ({name}) has width {}, expected one of {allowed_lengths:?}",
            resource.id,
            resource.length()
        )));
    }

    Ok(Some(resource))
}

pub(in crate::commissioning) fn application_resource_name(name: &str) -> bool {
    name.starts_with("Application") || name.starts_with("Peiprog")
}

pub(in crate::commissioning) fn normalized_procedure_targets_application(
    profile: &ResolvedProfile,
    procedure: &NormalizedProcedure,
) -> Result<bool> {
    use crate::commissioning::procedure::operands::{MemoryAddress, PropertyAddress, pure_property_address};
    let mut selectors = Vec::new();
    for name in profile.resource_names().filter(|name| application_resource_name(name)) {
        if let Some(resource) = profile.resource(name).map_err(|error| Diagnostic::preparation(error.to_string()))?
            && let Some(object) =
                resource.object_selector().map_err(|error| Diagnostic::preparation(error.to_string()))?
        {
            selectors.push(pure_property_address(&object, 0)?);
        }
    }
    let belongs = |address: PropertyAddress| {
        match address {
        PropertyAddress::Indexed {object_index,property_id}=>u16::from(property_id)==pid::PROGRAM_VERSION
            || selectors.iter().any(|candidate|matches!(candidate,PropertyAddress::Indexed {object_index:index,..} if *index==object_index)),
        PropertyAddress::Extended {object_type,object_instance,property_id}=>property_id==pid::PROGRAM_VERSION
            || selectors.iter().any(|candidate|matches!(candidate,PropertyAddress::Extended {object_type:kind,object_instance:instance,..} if *kind==object_type && *instance==object_instance)),
    }
    };
    fn target_application(target: &OperationTarget, belongs: &impl Fn(PropertyAddress) -> bool) -> bool {
        match target {
            OperationTarget::Property { address, .. } => belongs(*address),
            OperationTarget::Memory { address: MemoryAddress::Pointer { read, .. }, .. } => {
                target_application(&read.target, belongs)
            }
            _ => false,
        }
    }
    Ok(procedure.steps.iter().any(|step| match &step.operation {
        ProcedureOperation::LoadRecord(record) | ProcedureOperation::AbsoluteSegment { record, .. } => {
            target_application(&record.write.target, &belongs)
        }
        ProcedureOperation::ReadIntoImage { target, .. }
        | ProcedureOperation::LoadImage { target, .. }
        | ProcedureOperation::Write { target, .. }
        | ProcedureOperation::Compare { target, .. } => target_application(target, &belongs),
        ProcedureOperation::FunctionProperty(
            FunctionPropertyOperation::Invoke { address, .. } | FunctionPropertyOperation::ReadResult { address, .. },
        )
        | ProcedureOperation::DeclarePropertyDescriptor { address, .. } => belongs(*address),
        _ => false,
    }))
}
