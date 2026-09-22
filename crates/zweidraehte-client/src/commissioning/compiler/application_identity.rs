//! Resolve the selected hardware relation before application work is composed.

use crate::commissioning::catalog::profile::{ManagementModel, ResolvedProfile};
use crate::commissioning::error::CompileError;
use zweidraehte_ets_files::product::{ApplicationProgram2Binding, ProductData};

/// Resolve AP2 from the selected hardware relation, never from the primary
/// application's procedure or the fixed PEI Program interface object.
///
/// Profiles without PEI Program semantics do not need package metadata to
/// prove an irrelevant negative. A relation which positively declares AP2,
/// however, still fails closed: compiling and loading its separate secondary
/// application definition is not implemented yet.
pub(crate) fn validate_application_metadata(
    profile: &ResolvedProfile,
    product: &ProductData,
) -> Result<(), CompileError> {
    let reason = match product.application_program_2() {
        ApplicationProgram2Binding::Absent { .. } => return Ok(()),
        ApplicationProgram2Binding::Present { application_program_id, .. } => format!(
            "Hardware.xml declares secondary application {application_program_id:?}, but secondary PEI Program compilation is not implemented"
        ),
        ApplicationProgram2Binding::Unbound if profile_requires_application_program_2_metadata(profile) =>
            "no authoritative .knxprod CatalogItem/Product/Hardware2Program relation is bound; live commissioning requires the complete package because loose application MTXML cannot prove AP2 absent"
                .to_owned(),
        ApplicationProgram2Binding::Unbound => return Ok(()),
    };
    Err(CompileError::invalid(format!("product {} application program 2 metadata: {reason}", product.id())))
}

fn profile_requires_application_program_2_metadata(profile: &ResolvedProfile) -> bool {
    profile.management_model() == ManagementModel::SystemB
        && profile.resource_names().any(|name| name.starts_with("Peiprog"))
}
