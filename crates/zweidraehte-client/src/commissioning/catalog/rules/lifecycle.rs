//! Family lifecycle and stamp contracts used during final lowering.

use crate::commissioning::error::CompileError;

use crate::commissioning::catalog::profile::{ObjectSelector, ResolvedProfile};
use crate::commissioning::image::{ImageLocation, ImageSpace, SparseDeviceImage};
use crate::commissioning::input::UnloadMode;
use crate::commissioning::procedure::{
    ControlPath, DownloadStampOutput, NormalizedProcedure, ProcedureOperation, ProcedureSourceId, ProcedureStep,
    ToolState,
};
use std::collections::BTreeSet;

pub(crate) fn compile_confirmed_unload(
    profile: &ResolvedProfile,
    mode: UnloadMode,
    initial_state: ToolState,
    secure_only: bool,
) -> Result<NormalizedProcedure, CompileError> {
    let (name, erase_code) = match mode {
        UnloadMode::Application => ("application-reset", 7),
        UnloadMode::AllConfiguration => ("complete-factory-reset", 2),
    };
    let source = ProcedureSourceId::Generated { name: name.to_owned() };
    let base_path = ControlPath {
        mask_id: profile.mask.full_id.clone(),
        variant_index: profile.variant.source_index,
        procedure: source.clone(),
        contribution: None,
        control_indices: Vec::new(),
    };
    let affected = match mode {
        UnloadMode::Application => BTreeSet::from([
            zweidraehte_project::ProgrammingSection::ApplicationProgram1,
            zweidraehte_project::ProgrammingSection::ApplicationProgram2,
            zweidraehte_project::ProgrammingSection::Parameters,
            zweidraehte_project::ProgrammingSection::GroupCommunication,
            zweidraehte_project::ProgrammingSection::Configuration,
        ]),
        UnloadMode::AllConfiguration => BTreeSet::from([
            zweidraehte_project::ProgrammingSection::Address,
            zweidraehte_project::ProgrammingSection::ApplicationProgram1,
            zweidraehte_project::ProgrammingSection::ApplicationProgram2,
            zweidraehte_project::ProgrammingSection::Parameters,
            zweidraehte_project::ProgrammingSection::GroupCommunication,
            zweidraehte_project::ProgrammingSection::Configuration,
        ]),
    };
    let step = |index, operation| {
        let sections =
            matches!(&operation, ProcedureOperation::MasterReset { .. }).then(|| affected.clone()).unwrap_or_default();
        ProcedureStep {
            path: base_path.child(index),
            source_control_code: None,
            sections,
            operation,
            on_error: Vec::new(),
            secure_only,
        }
    };
    let procedure = NormalizedProcedure {
        id: source,
        initial_state,
        stamp_output: DownloadStampOutput::default(),
        steps: vec![
            step(0, ProcedureOperation::Connect),
            step(1, ProcedureOperation::MasterReset { erase_code, channel: 0 }),
        ],
    };
    procedure.validate()?;

    Ok(procedure)
}

/// System B flavour 1 loads property bytes into the working image and selects
/// stamps from that final image. A read of an address/association stamp is not
/// itself a request to return that value as a persisted download stamp.
pub(crate) fn validate_download_stamp_output(
    profile: &ResolvedProfile,
    image: &SparseDeviceImage,
    procedure: &mut NormalizedProcedure,
) -> Result<(), CompileError> {
    let failure = |reason| {
        CompileError::invalid(format!(
            "profile {mask} cannot capture its download stamps before restart: {reason}",
            mask = profile.mask.full_id.clone()
        ))
    };
    let DownloadStampOutput::ImageProperties(bindings) = &procedure.stamp_output else {
        return Ok(());
    };
    let flavour = profile.feature("DownloadStamp")?.unwrap_or(0);
    let end = super::stamps::download_stamp_end(profile, flavour)?
        .ok_or_else(|| failure("image stamp output requires enabled download stamps".into()))?;
    let eligible_space = |location: &ImageLocation| {
        matches!(&location.space,
            ImageSpace::Property { object: ObjectSelector::Index { index }, property_id: 27 }
            if (3..end).contains(&u32::from(*index)))
    };
    let require_binding = |location: &ImageLocation, byte_length: u32| {
        let binding = bindings.iter().find(|binding| binding.image_location == *location).ok_or_else(|| {
            failure(format!("eligible stamp property at {location:?} has no final output resource binding"))
        })?;
        if binding.read.extent.byte_length != byte_length {
            return Err(failure(format!(
                "eligible stamp property at {location:?} does not match its output byte length"
            )));
        }
        Ok(())
    };

    // Final extraction considers all complete eligible properties, including
    // extension-supplied initial image data. A missing resource binding is
    // already knowable here; do not discover it after the download mutates.
    for segment in image.segments() {
        if eligible_space(segment.location())
            && segment.location().offset == 0
            && segment.mask().iter().all(|mask| *mask == u8::MAX)
        {
            require_binding(segment.location(), segment.end_offset())?;
        }
    }

    // The parser already bound stamp reads. Only image-dependent geometry and
    // membership in the final output range remain to validate here.
    for step in &procedure.steps {
        if let ProcedureOperation::LoadImage { image_location, extent, alignment, .. } = &step.operation
            && matches!(&image_location.space, ImageSpace::Property {
                object: ObjectSelector::Index { .. },
                property_id: zweidraehte_proto::pid::MCB_TABLE
            })
            && extent.byte_length == 8
            && *alignment == 8
        {
            let segments: Vec<_> =
                image.ranges().filter(|range| range.location.space == image_location.space).collect();
            if !segments.is_empty()
                && !(segments.len() == 1
                    && segments[0].location == *image_location
                    && segments[0].length == extent.byte_length)
            {
                return Err(failure(format!(
                    "stamp read at {image_location:?} requires an absent or exact property image segment"
                )));
            }
            if eligible_space(image_location) {
                require_binding(image_location, extent.byte_length)?;
            }
        }
    }
    procedure.validate().map_err(|error| failure(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::catalog::profile::{ManagementModel, ResourceManagementStyle};
    use crate::commissioning::compiler::binding::tests::preparation_support::authorization_profile;
    use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections};
    use crate::commissioning::procedure::RestartKind;
    use zweidraehte_ets_files::product::ProductData;

    #[test]
    fn plain_system_b_program_restart_is_basic_unless_the_product_supports_data_secure() {
        let mut profile = authorization_profile("SystemB", None);
        profile.set_test_management_style(Some(ResourceManagementStyle::LoadStateMachine));

        for supports_data_secure in [false, true] {
            let product = ProductData::default().with_fixture_data_secure(supports_data_secure);
            let target = profile.network_restart_kind(
                profile.management_style().expect("fixture management style"),
                product.supports_data_secure(),
            );
            assert_eq!(target, RestartKind::Confirmed);

            for intent in [
                CommissioningIntent::Download(DownloadMode::Full),
                CommissioningIntent::Download(DownloadMode::Partial(ProgramSections::PARAMETERS)),
                CommissioningIntent::AssignAddressAndDownload(DownloadMode::Automatic),
            ] {
                assert_eq!(
                    profile.program_restart_kind(
                        matches!(
                            intent,
                            CommissioningIntent::Download(_) | CommissioningIntent::AssignAddressAndDownload(_)
                        ),
                        false,
                        product.supports_data_secure(),
                        target
                    ),
                    // A Data Secure product restarts with a confirmed master
                    // reset even while security is disabled.
                    if supports_data_secure { RestartKind::Confirmed } else { RestartKind::Basic }
                );
                assert_eq!(
                    profile.program_restart_kind(
                        matches!(
                            intent,
                            CommissioningIntent::Download(_) | CommissioningIntent::AssignAddressAndDownload(_)
                        ),
                        true,
                        product.supports_data_secure(),
                        target
                    ),
                    RestartKind::Confirmed
                );
            }
        }
    }

    #[test]
    fn plain_program_restart_override_preserves_network_unload_and_other_families() {
        let mut profile = authorization_profile("SystemB", None);
        profile.set_test_management_style(Some(ResourceManagementStyle::LoadStateMachine));
        let product = ProductData::default().with_fixture_data_secure(true);
        let target = profile.network_restart_kind(
            profile.management_style().expect("fixture management style"),
            product.supports_data_secure(),
        );

        for intent in [
            CommissioningIntent::AssignAddress,
            CommissioningIntent::Unload(UnloadMode::Application),
            CommissioningIntent::Unload(UnloadMode::AllConfiguration),
        ] {
            assert_eq!(
                profile.program_restart_kind(
                    matches!(
                        intent,
                        CommissioningIntent::Download(_) | CommissioningIntent::AssignAddressAndDownload(_)
                    ),
                    false,
                    product.supports_data_secure(),
                    target
                ),
                RestartKind::Confirmed
            );
        }

        profile.set_test_management_model(ManagementModel::System7);
        let target = profile.network_restart_kind(
            profile.management_style().expect("fixture management style"),
            product.supports_data_secure(),
        );
        assert_eq!(target, RestartKind::Confirmed);
        assert_eq!(profile.program_restart_kind(true, false, true, target), RestartKind::Confirmed);
    }
}
