//! Resolve the selected hardware relation before application work is composed.

use crate::commissioning::catalog::profile::{ManagementModel, ResolvedProfile};
use crate::commissioning::error::CompileError;
use zweidraehte_ets_files::product::{ApplicationIdentity, ApplicationProgram2Binding, ProductData};

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

/// The manufacturer a `LegacyPatchManufacturerIdInTaskSegment` application
/// downloads under when the target's current application identity is not
/// known: the reference falls back to these two octets.
const LEGACY_PATCHED_MANUFACTURER: [u8; 2] = [0x00, 0x02];

/// The application identity a download writes for `product`.
///
/// `LegacyPatchManufacturerIdInTaskSegment` makes the reference replace the
/// manufacturer of every task segment and of the `ApplicationId` (or
/// `PeiprogId`) resource with the target's own, read from its current
/// application identity, and with 00 02 when it has none. The 56 catalog
/// programs that set the option are MV-0701 devices by manufacturer 0x0002,
/// including OEM programs filed under M-0007 and M-002C.
// TODO: Use the target's current application manufacturer once compilation
// receives it as an observation; until then the fallback applies.
pub(in crate::commissioning) fn download_identity(product: &ProductData) -> ApplicationIdentity {
    let mut identity = product.application_identity();
    if product.programming_options().legacy_patch_manufacturer_id_in_task_segment().value {
        identity.application_id[..2].copy_from_slice(&LEGACY_PATCHED_MANUFACTURER);
    }
    identity
}

#[cfg(test)]
mod tests {
    use super::*;
    use zweidraehte_ets_files::product::fixtures::SYSTEM7_MTXML;

    #[test]
    fn legacy_patched_applications_download_under_the_fallback_manufacturer() {
        let plain = ProductData::from_mtxml_str(SYSTEM7_MTXML).expect("fixture parses");
        assert_eq!(download_identity(&plain), plain.application_identity(), "no option, no patch");

        let xml =
            SYSTEM7_MTXML.replacen("<Code>", r#"<Options LegacyPatchManufacturerIdInTaskSegment="true" /><Code>"#, 1);
        let patched = ProductData::from_mtxml_str(&xml).expect("patched fixture parses");
        let authored = patched.application_identity().application_id;
        let downloaded = download_identity(&patched);
        assert_eq!(&authored[..2], &[0x00, 0xfa]);
        assert_eq!(downloaded.application_id, [0x00, 0x02, authored[2], authored[3], authored[4]]);
        assert_eq!(downloaded.pei_type, patched.application_identity().pei_type);
    }
}
