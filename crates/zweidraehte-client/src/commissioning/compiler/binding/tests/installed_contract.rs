use crate::commissioning::catalog::profile::{ReadAccess, ResourceManagementStyle};
use crate::commissioning::compiler::binding::tests::preparation_support::{
    authorization_profile, partial_plan, partial_resource, set_resources,
};
use crate::commissioning::input::ProgramSections;
use crate::commissioning::runtime::policy::{
    operation_requires_installed_management_style, validate_partial_management_style,
};
use crate::commissioning::runtime::prepare::installed_contract::partial_installed_state_requirements;
use zweidraehte_ets_files::product::{ApplicationIdentity, LoadProcedureStyle, ProductData};
use zweidraehte_ets_files::schema::{LdCtrlConnect, LoadControl, LoadProcedure};

#[test]
fn bcu2_explicit_partial_still_requires_the_installed_management_style() {
    let mut profile = authorization_profile("Bcu2", Some(4));
    profile.set_test_management_style(Some(ResourceManagementStyle::LoadStateMachine));
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);

    assert!(operation_requires_installed_management_style(&plan));
    let error = validate_partial_management_style(Some(ResourceManagementStyle::Simple), &plan)
        .expect_err("an explicit partial reuses the installed application realization");

    assert!(error.to_string().contains("needs installed Simple management"));
}

#[test]
fn configuration_only_partial_does_not_require_application_state() {
    let mut profile = authorization_profile("SystemB", None);
    set_resources(&mut profile, vec![partial_resource("ApplicationId", 5, ReadAccess::Runtime)]);
    let plan = partial_plan(profile, ProgramSections::CONFIGURATION);

    let requirements = partial_installed_state_requirements(&plan, &ProductData::default())
        .expect("configuration-only partial has independent compatibility checks");

    assert!(requirements.is_empty());
}

#[test]
fn semantic_full_scope_does_not_depend_on_the_ap2_section_bit() {
    let mut profile = authorization_profile("SystemB", None);
    set_resources(&mut profile, vec![partial_resource("ApplicationId", 5, ReadAccess::Runtime)]);
    let sections = ProgramSections::APPLICATION_PROGRAM_1
        .union(ProgramSections::PARAMETERS)
        .union(ProgramSections::GROUP_COMMUNICATION)
        .union(ProgramSections::CONFIGURATION);
    let mut plan = partial_plan(profile, sections);
    plan.full_program_scope = true;

    let requirements = partial_installed_state_requirements(&plan, &ProductData::default())
        .expect("semantic full replacement does not reuse installed application state");

    assert!(requirements.is_empty());
    assert!(plan.is_full_program_scope());
}

#[test]
fn coupler_parameter_partial_without_application_semantics_skips_the_ap_gate() {
    let plan = partial_plan(authorization_profile("Coupler", None), ProgramSections::PARAMETERS);

    let requirements = partial_installed_state_requirements(&plan, &ProductData::default())
        .expect("a non-application procedure does not invent AP1 resources");

    assert!(requirements.is_empty());
}

#[test]
fn missing_procedure_cannot_be_used_as_proof_of_a_non_application_flow() {
    let mut plan = partial_plan(authorization_profile("Coupler", None), ProgramSections::PARAMETERS);
    plan.procedure = None;

    let error = partial_installed_state_requirements(&plan, &ProductData::default())
        .expect_err("an absent procedure cannot prove that a partial is coupler-only");

    assert!(error.to_string().contains("has no normalized procedure"));
}

#[test]
fn application_partial_requires_a_complete_runtime_readable_ap1_pair() {
    let mut profile = authorization_profile("SystemB", None);
    set_resources(&mut profile, vec![partial_resource("ApplicationId", 5, ReadAccess::Runtime)]);
    let plan = partial_plan(profile, ProgramSections::PARAMETERS);

    let error = partial_installed_state_requirements(&plan, &ProductData::default())
        .expect_err("a half-resolved AP1 contract must fail before a bus session opens");

    assert!(error.to_string().contains("only one of ApplicationLoadStatus and ApplicationId"));
}

#[test]
fn partial_identity_width_and_read_access_fail_closed() {
    let mut wrong_width = authorization_profile("SystemB", None);
    set_resources(&mut wrong_width, vec![
        partial_resource("ApplicationId", 6, ReadAccess::Runtime),
        partial_resource("ApplicationLoadStatus", 1, ReadAccess::Runtime),
    ]);
    let error = partial_installed_state_requirements(
        &partial_plan(wrong_width, ProgramSections::GROUP_COMMUNICATION),
        &ProductData::default(),
    )
    .expect_err("an invented identity width must fail");
    assert!(error.to_string().contains("has width 6"));

    let mut not_runtime = authorization_profile("SystemB", None);
    set_resources(&mut not_runtime, vec![
        partial_resource("ApplicationId", 5, ReadAccess::Configuration),
        partial_resource("ApplicationLoadStatus", 1, ReadAccess::Runtime),
    ]);
    let error = partial_installed_state_requirements(
        &partial_plan(not_runtime, ProgramSections::PARAMETERS),
        &ProductData::default(),
    )
    .expect_err("a configuration-only read right cannot prove installed identity");
    assert!(error.to_string().contains("is not runtime-readable"));

    let mut constant_identity = authorization_profile("SystemB", None);
    let mut identity = partial_resource("ApplicationId", 5, ReadAccess::Runtime);
    identity = identity.replace(
        "AddressSpace=\"StandardMemory\" StartAddress=\"512\"",
        "AddressSpace=\"Constant\" StartAddress=\"0\"",
    );
    set_resources(&mut constant_identity, vec![
        identity,
        partial_resource("ApplicationLoadStatus", 1, ReadAccess::Runtime),
    ]);
    let error = partial_installed_state_requirements(
        &partial_plan(constant_identity, ProgramSections::PARAMETERS),
        &ProductData::default(),
    )
    .expect_err("a constant is not device-resident installed state");
    assert!(error.to_string().contains("has no live readable online location"));
}

#[test]
fn legacy_four_byte_ap1_identity_drops_only_a_zero_manufacturer_octet() {
    let mut profile = authorization_profile("BCU1", None);
    set_resources(&mut profile, vec![
        partial_resource("ApplicationId", 4, ReadAccess::Runtime),
        partial_resource("ApplicationLoadStatus", 1, ReadAccess::Runtime),
    ]);
    let product = ProductData::default().with_fixture_application_identity(ApplicationIdentity {
        application_id: [0x00, 0xFA, 0x03, 0x06, 0x02],
        pei_type: 0,
    });
    let requirements =
        partial_installed_state_requirements(&partial_plan(profile.clone(), ProgramSections::PARAMETERS), &product)
            .expect("a legacy identity with an eight-bit manufacturer is representable");
    assert!(matches!(
        &requirements[1].expected,
        crate::commissioning::runtime::prepared::ReadExpectation::Exact(Some(expected))
            if expected == &[0xFA, 0x03, 0x06, 0x02]
    ));

    let product = ProductData::default().with_fixture_application_identity(ApplicationIdentity {
        application_id: [0x01, 0xFA, 0x03, 0x06, 0x02],
        pei_type: 0,
    });
    let error = partial_installed_state_requirements(&partial_plan(profile, ProgramSections::PARAMETERS), &product)
        .expect_err("a four-byte resource must not truncate a non-zero manufacturer octet");
    assert!(error.to_string().contains("has capacity 4, but its value has 5 bytes"));
}

#[test]
fn partial_preflight_ignores_secondary_metadata_and_rejects_an_ap2_scope() {
    let mut profile = authorization_profile("SystemB", None);
    set_resources(&mut profile, vec![
        partial_resource("ApplicationId", 5, ReadAccess::Runtime),
        partial_resource("ApplicationLoadStatus", 1, ReadAccess::Runtime),
        partial_resource("PeiprogId", 5, ReadAccess::Runtime),
        partial_resource("PeiprogLoadStatus", 1, ReadAccess::Runtime),
    ]);
    let parameters = partial_plan(profile.clone(), ProgramSections::PARAMETERS);

    let ordinary = partial_installed_state_requirements(&parameters, &ProductData::default())
        .expect("the fixed AP2 object is not product evidence");
    assert_eq!(ordinary.len(), 2);

    let mut fixed_object_only = profile.clone();
    set_resources(&mut fixed_object_only, vec![
        partial_resource("ApplicationId", 5, ReadAccess::Runtime),
        partial_resource("ApplicationLoadStatus", 1, ReadAccess::Runtime),
        partial_resource("PeiprogId", 5, ReadAccess::Runtime),
    ]);
    let ordinary = partial_installed_state_requirements(
        &partial_plan(fixed_object_only, ProgramSections::PARAMETERS),
        &ProductData::default(),
    )
    .expect("an AP1-only product does not inspect the fixed AP2 object");
    assert_eq!(ordinary.len(), 2);

    let explicit = partial_installed_state_requirements(
        &partial_plan(profile, ProgramSections::APPLICATION_PROGRAM_2),
        &ProductData::default(),
    )
    .expect_err("an explicit AP2 request remains unsupported");
    assert!(explicit.to_string().contains("AP2"));
}

#[test]
fn primary_merge_fragments_do_not_create_secondary_installed_state_requirements() {
    let mut profile = authorization_profile("SystemB", None);
    set_resources(&mut profile, vec![
        partial_resource("ApplicationId", 5, ReadAccess::Runtime),
        partial_resource("ApplicationLoadStatus", 1, ReadAccess::Runtime),
        partial_resource("PeiprogId", 5, ReadAccess::Runtime),
        partial_resource("PeiprogLoadStatus", 1, ReadAccess::Runtime),
    ]);
    let product = ProductData::default()
        .with_fixture_load_procedure_style(LoadProcedureStyle::Merged)
        .with_fixture_load_procedures(vec![LoadProcedure {
            merge_id: Some(3),
            controls: vec![LoadControl::LdCtrlConnect(LdCtrlConnect::default())],
        }]);

    let requirements =
        partial_installed_state_requirements(&partial_plan(profile, ProgramSections::PARAMETERS), &product)
            .expect("primary merges do not make secondary metadata reachable");

    assert_eq!(requirements.len(), 2);
}
