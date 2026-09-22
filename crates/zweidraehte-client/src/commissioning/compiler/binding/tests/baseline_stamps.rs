use super::preparation_support::deployment_record;
use crate::commissioning::catalog::profile::{ReadAccess, ResourceId};
use crate::commissioning::compiler::binding::tests::preparation_support::{
    authorization_profile, indexed_stamp_resource, observed_stamp_reads, partial_plan, partial_resource, set_feature,
    set_resources, stamp_profile,
};
use crate::commissioning::evidence::{DeviceStamp, DifferentialDecision, DifferentialFallback, DifferentialPolicy};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::runtime::policy::verified_undifferenced_fallback;
use crate::commissioning::runtime::prepare::installation::{finish_baseline, prepare_baseline};
use crate::commissioning::runtime::prepare::installed_contract::partial_installed_state_requirements;
use crate::commissioning::runtime::prepared::{PreparedEvidence, ReadExpectation};
use zweidraehte_ets_files::product::ProductData;

#[test]
fn preflight_binds_the_physically_present_stamp_subset_in_profile_order() {
    let profile = stamp_profile(&["required", "absent-advertised", "present-optional"]);
    let observed = [DeviceStamp { resource: ResourceId("required".to_owned()), value: vec![0x11; 8] }, DeviceStamp {
        resource: ResourceId("present-optional".to_owned()),
        value: vec![0x22; 8],
    }];

    let deployment = deployment_record(&profile, [0; 32], observed.to_vec());
    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.full_image_stamp_coverage = true;
    let baseline = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("local evidence is valid")
        .0
        .expect("recorded stamps need probing");
    let reads = observed_stamp_reads(&plan, &observed);
    let (differential, _) = finish_baseline(&plan, baseline, &reads, DifferentialPolicy::FallBackToUndifferenced, 1)
        .expect("physical absence is legal for an unrecorded candidate");

    assert_eq!(differential, DifferentialDecision::VerifiedUndifferenced {
        previous_image_fingerprint: deployment.image_fingerprint,
        device_stamps: observed.to_vec(),
    });
    assert_eq!(reads[1].expected, ReadExpectation::Exact(None));
}

#[test]
fn preflight_observes_missing_stamps_and_rejects_the_previous_baseline() {
    let profile = stamp_profile(&["required", "optional"]);
    let deployment = deployment_record(&profile, [0; 32], vec![DeviceStamp {
        resource: ResourceId("required".to_owned()),
        value: vec![0x11; 8],
    }]);
    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.full_image_stamp_coverage = true;
    let baseline = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("local evidence is valid")
        .0
        .expect("recorded stamps need probing");
    let reads = observed_stamp_reads(&plan, &[]);
    let (differential, known) =
        finish_baseline(&plan, baseline, &reads, DifferentialPolicy::FallBackToUndifferenced, 1)
            .expect("missing physical stamps select an ordinary fallback");
    assert!(reads.iter().all(|read| read.expected == ReadExpectation::Exact(None)));
    assert_eq!(differential, DifferentialDecision::FellBackToUndifferenced {
        reason: DifferentialFallback::StampMismatch,
    });
    assert!(known.is_none());
}

#[test]
fn missing_deployment_falls_back_without_requesting_a_stamp_probe() {
    let profile = stamp_profile(&["application"]);
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);

    let (probe, differential) = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, None)
        .expect("fallback policy accepts missing history");

    assert!(probe.is_none());
    assert_eq!(differential, DifferentialDecision::FellBackToUndifferenced {
        reason: DifferentialFallback::MissingDeploymentHistory,
    });
    assert_eq!(plan.program_sections, Some(ProgramSections::PARAMETERS));
    assert!(!plan.full_program_scope);
}

#[test]
fn profiles_without_download_stamps_use_the_undifferenced_selected_scope() {
    let profile = authorization_profile("Bcu2", None);
    let plan = partial_plan(profile, ProgramSections::GROUP_COMMUNICATION);

    let (probe, differential) = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, None)
        .expect("a stamp-less profile can execute its selected semantic procedure");

    assert!(probe.is_none());
    assert_eq!(differential, DifferentialDecision::Undifferenced);
    assert_eq!(plan.program_sections, Some(ProgramSections::GROUP_COMMUNICATION));
    assert!(!plan.full_program_scope);
}

#[test]
fn structurally_valid_evidence_requests_a_probe_for_its_recorded_subset() {
    // This tests the legacy proof path. System B flavour 1 must first
    // prove stamp-encoded previous-image coverage before reaching it.
    let mut profile = authorization_profile("System7", None);
    set_feature(&mut profile, "DownloadStamp", 1);
    set_resources(&mut profile, vec![
        indexed_stamp_resource("required", 3, ReadAccess::Runtime, false),
        indexed_stamp_resource("absent-advertised", 4, ReadAccess::Runtime, false),
    ]);
    let product_fingerprint = [0; 32];
    let deployment = deployment_record(&profile, product_fingerprint, vec![DeviceStamp {
        resource: ResourceId("required".to_owned()),
        value: vec![0x33; 8],
    }]);
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);

    let (probe, differential) = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("valid local evidence reaches live verification");

    assert!(probe.is_some());
    assert_eq!(differential, DifferentialDecision::Undifferenced);
}

#[test]
fn prepared_differential_retains_the_exact_stamp_set_for_execute_revalidation() {
    let profile = stamp_profile(&["group", "application"]);
    let stamps = [DeviceStamp { resource: ResourceId("group".to_owned()), value: vec![0x11; 8] }, DeviceStamp {
        resource: ResourceId("application".to_owned()),
        value: vec![0x22; 8],
    }];

    let deployment = deployment_record(&profile, [0; 32], stamps.to_vec());
    let mut plan = partial_plan(profile, ProgramSections::PARAMETERS);
    plan.full_image_stamp_coverage = true;
    let baseline = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("local evidence is valid")
        .0
        .expect("recorded stamps need probing");
    let reads = observed_stamp_reads(&plan, &stamps);
    let (differential, _) = finish_baseline(&plan, baseline, &reads, DifferentialPolicy::FallBackToUndifferenced, 1)
        .expect("the prepared set is exact");

    assert_eq!(differential, DifferentialDecision::VerifiedUndifferenced {
        previous_image_fingerprint: deployment.image_fingerprint,
        device_stamps: stamps.to_vec(),
    });
    for (read, stamp) in reads.iter().zip(stamps) {
        assert_eq!(read.resource, stamp.resource);
        assert_eq!(read.expected, ReadExpectation::Exact(Some(stamp.value)));
    }
}

#[test]
fn completed_download_rejects_a_wrong_width_stamp_response() {
    let plan = partial_plan(stamp_profile(&["application"]), ProgramSections::PARAMETERS);
    let evidence = PreparedEvidence {
        execution_address: plan.individual_address(),
        differential: DifferentialDecision::Undifferenced,
        baseline_known: None,
        interface_max_apdu: 15,
        target_max_apdu: 15,
        management_style: None,
        reads: Vec::new(),
    };
    let error = evidence
        .validate_captured_stamps(&plan, &[DeviceStamp {
            resource: ResourceId("application".to_owned()),
            value: vec![0x66; 7],
        }])
        .expect_err("short stamp response must fail publication");

    assert!(error.message.contains("invalid download-stamp binding"));
    assert_eq!(error.kind(), crate::commissioning::DiagnosticKind::Management);
}

#[test]
fn incomplete_secondary_metadata_cannot_enable_an_ap2_request() {
    let mut profile = authorization_profile("SystemB", None);
    set_resources(&mut profile, vec![
        partial_resource("ApplicationId", 5, ReadAccess::Runtime),
        partial_resource("ApplicationLoadStatus", 1, ReadAccess::Runtime),
        partial_resource("PeiprogId", 5, ReadAccess::Runtime),
    ]);

    let error = partial_installed_state_requirements(
        &partial_plan(profile, ProgramSections::APPLICATION_PROGRAM_2),
        &ProductData::default(),
    )
    .expect_err("secondary resource metadata cannot make AP2 executable");

    assert!(error.to_string().contains("AP2"));
}

#[test]
fn no_useful_difference_retains_verified_base_only_for_fallback_policy() {
    let profile = authorization_profile("SystemB", None);
    let fingerprint = [0xA5; 32];
    let stamps = vec![DeviceStamp { resource: ResourceId("application-stamp".to_owned()), value: vec![0x11; 8] }];
    let fallback_plan = partial_plan(profile.clone(), ProgramSections::PARAMETERS);

    let differential =
        verified_undifferenced_fallback(DifferentialPolicy::FallBackToUndifferenced, fingerprint, stamps.clone())
            .expect("fallback policy may retain the verified undifferenced base");
    assert_eq!(differential, DifferentialDecision::VerifiedUndifferenced {
        previous_image_fingerprint: fingerprint,
        device_stamps: stamps,
    });
    assert_eq!(fallback_plan.program_sections, Some(ProgramSections::PARAMETERS));

    let required_plan = partial_plan(profile, ProgramSections::PARAMETERS);
    let original = required_plan.clone();
    let error = verified_undifferenced_fallback(DifferentialPolicy::RequireVerified, fingerprint, Vec::new())
        .expect_err("RequireVerified still requires a useful sparse procedure");

    assert!(error.to_string().contains("NoUsefulDifference"));
    assert_eq!(required_plan, original);
    assert_eq!(required_plan.program_sections, Some(ProgramSections::PARAMETERS));
}
