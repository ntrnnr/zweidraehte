use crate::commissioning::catalog::profile::ResourceManagementStyle;
use crate::commissioning::compiler::binding::tests::preparation_support::{authorization_profile, partial_plan};
use crate::commissioning::image::{ImageLocation, SparseDeviceImage};
use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections, UnloadMode};
use crate::commissioning::report::CommissioningSectionOutcome;
use crate::commissioning::runtime::policy::{
    operation_requires_installed_management_style, successful_section_outcomes, validate_partial_management_style,
};
use std::collections::BTreeMap;
use zweidraehte_project::ProgrammingSection;

#[test]
fn bcu2_automatic_full_widening_may_convert_the_installed_management_style() {
    let requested_sections = ProgramSections::APPLICATION_PROGRAM_1.union(ProgramSections::PARAMETERS);
    let mut profile = authorization_profile("Bcu2", Some(4));
    profile.set_test_management_style(Some(ResourceManagementStyle::LoadStateMachine));
    let mut plan = partial_plan(profile, requested_sections);

    // This is the semantic result when the exact BCU2 profile publishes
    // only `Load/all` for the requested automatic delta.
    plan.intent = CommissioningIntent::Download(DownloadMode::Automatic);
    plan.program_sections = Some(ProgramSections::all());
    plan.full_program_scope = true;

    assert!(!operation_requires_installed_management_style(&plan));
    validate_partial_management_style(Some(ResourceManagementStyle::Simple), &plan)
        .expect("semantic full replacement may convert Simple to load-state-machine management");
}

#[test]
fn successful_download_reports_only_selected_status_sections() {
    let sections = ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION);
    let mut plan = partial_plan(authorization_profile("Bcu2", None), sections);
    plan.intent = CommissioningIntent::AssignAddressAndDownload(DownloadMode::Partial(sections));
    let outcomes = successful_section_outcomes(&plan, &plan.image, &Default::default());
    assert_eq!(
        outcomes,
        BTreeMap::from([
            (ProgrammingSection::Address, CommissioningSectionOutcome::Programmed),
            (ProgrammingSection::Parameters, CommissioningSectionOutcome::Programmed),
            (ProgrammingSection::GroupCommunication, CommissioningSectionOutcome::Programmed),
        ])
    );
}

#[test]
fn application_unload_clears_application_sections_but_keeps_address() {
    let mut plan = partial_plan(authorization_profile("Bcu2", None), ProgramSections::empty());
    plan.intent = CommissioningIntent::Unload(UnloadMode::Application);
    let cleared = std::collections::BTreeSet::from([
        ProgrammingSection::ApplicationProgram1,
        ProgrammingSection::ApplicationProgram2,
        ProgrammingSection::Parameters,
        ProgrammingSection::GroupCommunication,
        ProgrammingSection::Configuration,
    ]);
    let outcomes = successful_section_outcomes(&plan, &plan.image, &cleared);
    assert!(!outcomes.contains_key(&ProgrammingSection::Address));
    assert_eq!(outcomes.len(), 5);
    assert!(outcomes.values().all(|outcome| *outcome == CommissioningSectionOutcome::Cleared));
}

#[test]
fn section_success_requires_every_owned_bit_but_ignores_unowned_bits() {
    use crate::commissioning::ImageSegment;
    let mut plan = partial_plan(authorization_profile("Bcu2", None), ProgramSections::PARAMETERS);
    let location = ImageLocation::standard_memory(0x400);
    plan.image.apply_section(
        ProgrammingSection::Parameters,
        &ImageSegment::new(location.clone(), vec![0xA5], vec![0xF0]).expect("desired bits"),
    );
    for (value, mask, expected) in [
        (0xAF, 0xF0, CommissioningSectionOutcome::Programmed),
        (0xAF, 0xE0, CommissioningSectionOutcome::Unverified),
        (0xBF, 0xF0, CommissioningSectionOutcome::Unverified),
    ] {
        let mut observed = SparseDeviceImage::new();
        observed.apply_section(
            ProgrammingSection::Parameters,
            &ImageSegment::new(location.clone(), vec![value], vec![mask]).expect("observed bits"),
        );
        assert_eq!(
            successful_section_outcomes(&plan, &observed, &Default::default())[&ProgrammingSection::Parameters],
            expected
        );
    }
    assert_eq!(
        successful_section_outcomes(&plan, &SparseDeviceImage::new(), &Default::default())
            [&ProgrammingSection::Parameters],
        CommissioningSectionOutcome::Unverified
    );
}
