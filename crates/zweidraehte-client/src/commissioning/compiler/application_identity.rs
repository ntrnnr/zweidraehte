//! Resolve the selected hardware relation before application work is composed.

use crate::commissioning::catalog::profile::{ManagementModel, ResolvedProfile};
use crate::commissioning::error::CompileError;
use zweidraehte_ets_files::product::{ApplicationProgram2Binding, ProductData};

/// Resolve AP2 from the selected hardware relation, never from the primary
/// application's procedure or the fixed PEI Program interface object.
///
/// Profiles without PEI Program semantics do not need package metadata to
/// prove an irrelevant negative. A relation which positively declares AP2
/// compiles only with the extracted secondary PEI Program bound; otherwise it
/// fails closed rather than omitting the program.
pub(crate) fn validate_application_metadata(
    profile: &ResolvedProfile,
    product: &ProductData,
) -> Result<(), CompileError> {
    let reason = match product.application_program_2() {
        ApplicationProgram2Binding::Absent { .. } => return Ok(()),
        // A loader that extracted the secondary PEI Program bound its content;
        // segments, identity and merge fragments then compile with AP1.
        ApplicationProgram2Binding::Present { application_program_id, .. }
            if product.secondary_application().is_some_and(|secondary| secondary.id() == application_program_id) =>
        {
            return Ok(());
        }
        ApplicationProgram2Binding::Present { application_program_id, .. } => format!(
            "Hardware.xml declares secondary application {application_program_id:?}, but its PEI Program content is not bound"
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
