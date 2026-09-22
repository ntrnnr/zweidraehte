use super::preparation_support::deployment_record;
use crate::commissioning::catalog::profile::{ObjectSelector, ResourceId};
use crate::commissioning::compiler::binding::tests::preparation_support::{
    partial_plan, stamp_profile, system_b_differential_fixture,
};
use crate::commissioning::evidence::{DeviceStamp, DifferentialDecision, DifferentialFallback, DifferentialPolicy};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::OperationTarget;
use crate::commissioning::procedure::operands::pure_property_address;
use crate::commissioning::runtime::prepare::installation::prepare_baseline;

#[test]
fn devices_observed_without_stamps_use_the_undifferenced_selected_scope() {
    let profile = stamp_profile(&["application"]);
    let product_fingerprint = [0; 32];
    let deployment = deployment_record(&profile, product_fingerprint, Vec::new());
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);

    let (probe, differential) = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("an observed stamp-less device can execute its selected semantic procedure");

    assert!(probe.is_none());
    assert_eq!(differential, DifferentialDecision::Undifferenced);
    assert_eq!(plan.program_sections, Some(ProgramSections::PARAMETERS));
    assert!(!plan.full_program_scope);
}

#[test]
fn devices_observed_without_stamps_cannot_satisfy_require_verified() {
    let profile = stamp_profile(&["application"]);
    let product_fingerprint = [0; 32];
    let deployment = deployment_record(&profile, product_fingerprint, Vec::new());
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);

    let original = plan.clone();
    let error = prepare_baseline(&plan, DifferentialPolicy::RequireVerified, Some(&deployment))
        .expect_err("a stamp-less device cannot prove a byte-level differential base");

    assert!(error.to_string().contains("MissingDeviceStamp"));
    assert_eq!(plan, original);
}

#[test]
fn require_verified_rejects_invalid_evidence_before_requesting_a_stamp_probe() {
    let profile = stamp_profile(&["group", "application"]);
    let product_fingerprint = [0; 32];
    let deployment = deployment_record(&profile, product_fingerprint, vec![DeviceStamp {
        resource: ResourceId("unrelated".to_owned()),
        value: vec![0x22; 8],
    }]);
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);

    let original = plan.clone();
    let error = prepare_baseline(&plan, DifferentialPolicy::RequireVerified, Some(&deployment))
        .expect_err("invalid persisted evidence must fail offline");

    assert!(error.to_string().contains("StampMismatch"));
    assert_eq!(plan, original);
}

#[test]
fn system_b_unproven_image_coverage_falls_back_before_requesting_live_stamps() {
    let (plan, deployment, _) = system_b_differential_fixture();
    let expected = plan.clone();
    let expected_decision =
        DifferentialDecision::FellBackToUndifferenced { reason: DifferentialFallback::UnprovenImageCoverage };

    let (probe, differential) = prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
        .expect("unproven coverage selects an ordinary fallback");

    assert!(probe.is_none());
    assert_eq!(plan, expected);
    assert_eq!(differential, expected_decision);
}

#[test]
fn equal_retained_system_b_stamps_cannot_authorize_omitting_other_table_bytes() {
    let (plan, deployment, candidates) = system_b_differential_fixture();
    let original = plan.clone();
    let expected: Vec<_> = [3, 4]
        .into_iter()
        .map(|index| OperationTarget::Property {
            address: pure_property_address(&ObjectSelector::Index { index }, 27).expect("indexed stamp"),
            start_element: 1,
        })
        .collect();
    assert_eq!(
        candidates.iter().map(|resource| &resource.read.target).collect::<Vec<_>>(),
        expected.iter().collect::<Vec<_>>()
    );

    // Matching stamps for indices 3/4 cannot establish bytes at 1/2.
    // Preparation must not install this unproven image as runtime knowledge.

    let (baseline, differential) =
        prepare_baseline(&plan, DifferentialPolicy::FallBackToUndifferenced, Some(&deployment))
            .expect("equal stamps still require proven image coverage");
    assert!(baseline.is_none(), "unproven contents never reach live baseline binding");

    let expected = original;
    let expected_decision =
        DifferentialDecision::FellBackToUndifferenced { reason: DifferentialFallback::UnprovenImageCoverage };
    assert_eq!(plan, expected);
    assert_eq!(differential, expected_decision);
}

#[test]
fn system_b_require_verified_rejects_unproven_coverage_without_a_previous_base_claim() {
    let (original, deployment, _) = system_b_differential_fixture();
    let preflight = original.clone();
    let error = prepare_baseline(&preflight, DifferentialPolicy::RequireVerified, Some(&deployment))
        .expect_err("unproven coverage rejects before live probing");
    assert!(error.to_string().contains("UnprovenImageCoverage"));
    assert_eq!(preflight, original);
}
