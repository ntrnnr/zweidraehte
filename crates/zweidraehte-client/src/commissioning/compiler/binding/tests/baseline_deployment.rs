use super::preparation_support::deployment_record;
use crate::commissioning::catalog::profile::{ReadAccess, ResourceId};
use crate::commissioning::compiler::binding::tests::preparation_support::{
    add_resources, indexed_stamp_resource, observed_stamp_reads, partial_plan, stamp_profile,
};
use crate::commissioning::evidence::{DeviceStamp, DifferentialDecision, DifferentialFallback, DifferentialPolicy};
use crate::commissioning::image::{ImageLocation, fingerprint_image};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::runtime::prepare::installation::{finish_baseline, prepare_baseline, validate_baseline};
use crate::commissioning::runtime::prepared::ReadExpectation;

#[test]
fn live_probe_rejects_a_new_stamp_absent_from_persisted_evidence() {
    let mut profile = stamp_profile(&["required"]);
    add_resources(&mut profile, [indexed_stamp_resource("optional", 4, ReadAccess::Runtime, true)]);
    let product_fingerprint = [0; 32];
    let deployment = deployment_record(&profile, product_fingerprint, vec![DeviceStamp {
        resource: ResourceId("required".to_owned()),
        value: vec![0x44; 8],
    }]);
    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.full_image_stamp_coverage = true;
    let baseline = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("local history is valid")
        .0
        .expect("live probe required");
    let observed = [deployment.device_stamps[0].clone(), DeviceStamp {
        resource: ResourceId("optional".to_owned()),
        value: vec![0x55; 8],
    }];
    let reads = observed_stamp_reads(&plan, &observed);
    let (differential, _) = finish_baseline(&plan, baseline, &reads, DifferentialPolicy::FallBackToUndifferenced, 4)
        .expect("policy permits fallback");
    assert_eq!(differential, DifferentialDecision::FellBackToUndifferenced {
        reason: DifferentialFallback::MissingDeviceStamp,
    });
}

#[test]
fn direct_deployment_record_cannot_forge_its_image_fingerprint() {
    let profile = stamp_profile(&["application"]);
    let product_fingerprint = [0xA5; 32];
    let mut deployment = deployment_record(&profile, product_fingerprint, vec![DeviceStamp {
        resource: ResourceId("application".to_owned()),
        value: vec![0x11; 8],
    }]);
    deployment.image_fingerprint[0] ^= 1;

    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.product_fingerprint = product_fingerprint;
    let result = validate_baseline(&plan, &deployment);

    assert_eq!(result, Err(DifferentialFallback::ProfileChanged));
}

#[test]
fn direct_deployment_record_may_retain_the_physical_stamp_subset() {
    let profile = stamp_profile(&["group", "application"]);
    let product_fingerprint = [0xA5; 32];
    let deployment = deployment_record(&profile, product_fingerprint, vec![DeviceStamp {
        resource: ResourceId("group".to_owned()),
        value: vec![0x22; 8],
    }]);

    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.product_fingerprint = product_fingerprint;
    validate_baseline(&plan, &deployment).expect("the recorded subset was established by the preceding full download");
    assert_eq!(deployment.device_stamps.len(), 1);
    assert_eq!(deployment.device_stamps[0].resource.0, "group");
}

#[test]
fn direct_deployment_record_cannot_add_caller_selected_stamps() {
    let profile = stamp_profile(&["application"]);
    let product_fingerprint = [0xA5; 32];
    let deployment = deployment_record(&profile, product_fingerprint, vec![
        DeviceStamp { resource: ResourceId("application".to_owned()), value: vec![0x33; 8] },
        DeviceStamp { resource: ResourceId("unrelated".to_owned()), value: vec![0x44; 8] },
    ]);

    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.product_fingerprint = product_fingerprint;
    let result = validate_baseline(&plan, &deployment);

    assert_eq!(result, Err(DifferentialFallback::StampMismatch));
}

#[test]
fn direct_deployment_record_stamp_width_must_match_the_profile() {
    let profile = stamp_profile(&["application"]);
    let product_fingerprint = [0xA5; 32];
    let deployment = deployment_record(&profile, product_fingerprint, vec![DeviceStamp {
        resource: ResourceId("application".to_owned()),
        value: vec![0x55; 7],
    }]);

    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.product_fingerprint = product_fingerprint;
    let result = validate_baseline(&plan, &deployment);

    assert_eq!(result, Err(DifferentialFallback::StampMismatch));
}

#[test]
fn duplicate_persisted_stamp_ids_reject_before_live_observation() {
    let profile = stamp_profile(&["application"]);
    let stamp = DeviceStamp { resource: ResourceId("application".to_owned()), value: vec![0x11; 8] };
    let deployment = deployment_record(&profile, [0; 32], vec![stamp.clone(), stamp]);
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);
    let original = plan.clone();
    let error = prepare_baseline(&plan, DifferentialPolicy::RequireVerified, Some(&deployment))
        .expect_err("duplicate identity cannot authenticate a baseline");
    assert!(error.to_string().contains("StampMismatch"));
    assert_eq!(plan, original);
}

#[test]
fn incomplete_or_unobserved_stamp_reads_cannot_install_baseline_knowledge() {
    let profile = stamp_profile(&["application"]);
    let deployment = deployment_record(&profile, [0; 32], vec![DeviceStamp {
        resource: ResourceId("application".to_owned()),
        value: vec![0x11; 8],
    }]);
    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.full_image_stamp_coverage = true;
    let baseline = prepare_baseline(&plan, DifferentialPolicy::RequireVerified, Some(&deployment))
        .expect("local evidence is valid")
        .0
        .expect("stamps require observation");
    let mut unobserved = observed_stamp_reads(&plan, &deployment.device_stamps);
    unobserved[0].expected = ReadExpectation::Capture { optional: true };
    let original = plan.clone();
    for reads in [&[][..], unobserved.as_slice()] {
        finish_baseline(&plan, baseline, reads, DifferentialPolicy::RequireVerified, 1)
            .expect_err("a pending read is never evidence");
        assert_eq!(plan, original);
    }
}

#[test]
fn verified_undifferenced_execution_still_starts_from_observed_previous_bytes() {
    let profile = stamp_profile(&["application"]);
    let mut deployment = deployment_record(&profile, [0; 32], vec![DeviceStamp {
        resource: ResourceId("application".to_owned()),
        value: vec![0x11; 8],
    }]);
    let location = ImageLocation::standard_memory(0x200);
    deployment.image.apply_owned(location.clone(), vec![0x33]).expect("old image byte");
    deployment.image_fingerprint = fingerprint_image(&deployment.image);
    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.full_image_stamp_coverage = true;
    plan.image.apply_owned(location.clone(), vec![0x44]).expect("desired image byte");
    let baseline = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("local evidence is valid")
        .0
        .expect("stamps require observation");
    let reads = observed_stamp_reads(&plan, &deployment.device_stamps);
    let (differential, known) =
        finish_baseline(&plan, baseline, &reads, DifferentialPolicy::FallBackToUndifferenced, 1)
            .expect("no equal run retains a verified ordinary download");
    assert!(matches!(differential, DifferentialDecision::VerifiedUndifferenced { .. }));
    assert_eq!(known.as_ref().expect("verified contents remain known").byte(&location), Some((0x33, 255)));
}

#[cfg(feature = "project")]
mod persistence {
    use super::super::preparation_support::authorization_profile;
    use super::*;
    use crate::commissioning::error::MutationStatus;
    use crate::commissioning::image::SparseDeviceImage;
    use crate::commissioning::runtime::policy::successful_section_outcomes;

    #[test]
    fn project_persists_confirmed_sparse_bytes_and_preserved_security_observations() {
        use crate::commissioning::catalog::profile::AssociationTableEntrySize;
        use crate::commissioning::evidence::DiscoveredDevice;
        use crate::commissioning::input::security::{DesiredDataSecurity, ObservedDataSecurity};
        use crate::commissioning::report::ExecutionReport;

        for full in [false, true] {
            for mode in [ObservedDataSecurity::Enabled, ObservedDataSecurity::Unknown] {
                let mut plan = partial_plan(authorization_profile("Bcu2", None), ProgramSections::PARAMETERS);
                plan.full_program_scope = full;
                plan.desired_data_security = DesiredDataSecurity::Preserve;
                plan.facts.data_security = mode;
                plan.profile.association_entry_size = Some(AssociationTableEntrySize::FourBytes);
                let location = ImageLocation::standard_memory(0x200);
                plan.image.apply_owned(location.clone(), vec![0xAA, 0xBB]).expect("desired image bytes");
                let mut programmed_image = SparseDeviceImage::new();
                programmed_image.apply(
                    &crate::commissioning::ImageSegment::new(location, vec![0x0C], vec![0x0F]).expect("confirmed bits"),
                );
                let expected_fingerprint = fingerprint_image(&programmed_image);
                let report = ExecutionReport {
                    execution_address: plan.individual_address(),
                    differential: DifferentialDecision::Undifferenced,

                    discovered: DiscoveredDevice {
                        address: Some(plan.individual_address),
                        serial_number: None,
                        mask: plan.profile.mask().clone(),
                        interface_max_apdu: 15,
                        target_max_apdu: 15,
                        secure_management: false,
                        observed_management_style: None,
                    },
                    sections: successful_section_outcomes(&plan, &programmed_image, &Default::default()),
                    plan,
                    programmed_image,

                    procedure: None,

                    device_stamps: Vec::new(),
                    effects: crate::commissioning::ExecutionEffects::with_status(MutationStatus::Complete),
                };
                let record = crate::project::persistence::project_deployment_from_report(&report)
                    .expect("confirmed bytes serialize without interpreting controls")
                    .expect("download evidence remains available");
                assert_eq!(record.image_segments.len(), 1);
                assert_eq!(record.image_segments[0].data, [0x0C]);
                assert_eq!(record.image_segments[0].mask, [0x0F]);
                assert_eq!(record.image_fingerprint, expected_fingerprint);
                assert_eq!(record.data_security_enabled, (mode == ObservedDataSecurity::Enabled).then_some(true));
                assert_eq!(
                    record.association_table_entry_size,
                    Some(zweidraehte_project::CommissioningAssociationEntrySize::FourBytes)
                );
            }
        }
    }
}
