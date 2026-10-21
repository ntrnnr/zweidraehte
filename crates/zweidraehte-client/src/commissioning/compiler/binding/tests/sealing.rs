use crate::bus::access::ManagementCredential;
use crate::commissioning::compiler::binding::tests::preparation_support::{authorization_profile, partial_plan};
use crate::commissioning::compiler::credentials::CredentialTransition;
use crate::commissioning::error::{CleanupOperation, Diagnostic, MutationStatus, TransportCause};
use crate::commissioning::evidence::DifferentialDecision;
use crate::commissioning::image::ImageLocation;
use crate::commissioning::input::security::{DesiredDataSecurity, ObservedDataSecurity};
use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections, TargetSelection};
use crate::commissioning::procedure::{
    OperationData, OperationExtent, OperationTarget, ProcedureOperation, WriteIntent,
};
use crate::commissioning::runtime::AuthorizationPolicy;
use crate::commissioning::runtime::prepared::PreparedEvidence;
use zweidraehte_proto::address::IndividualAddress;

#[test]
fn sealing_rejects_an_image_operand_that_preparation_has_not_bound() {
    let mut plan = partial_plan(authorization_profile("SystemB", None), ProgramSections::PARAMETERS);
    let procedure = plan.procedure.as_mut().expect("fixture procedure");
    let mut write = procedure.steps[0].clone();
    write.operation = ProcedureOperation::Write {
        target: OperationTarget::ImageMemory(ImageLocation::standard_memory(0x200)),
        data: OperationData::Inline(vec![0x11]),
        extent: OperationExtent::bytes(1),
        policy: WriteIntent::Memory { verify: false },
    };
    procedure.steps.insert(1, write);
    assert!(
        crate::commissioning::compiler::ProgramCompiler::finish(plan)
            .expect_err("unresolved image operand cannot reach execution")
            .to_string()
            .contains("image memory operand has not been bound")
    );
}

#[test]
fn configuration_download_leaves_domain_assignment_to_address_programming() {
    // The open-medium domain address is loaded together with the individual
    // address. Selecting the medium-configuration section of an application
    // download must not schedule it, even for a serial-number target that
    // could address the domain write.
    let mut draft = partial_plan(authorization_profile("SystemB", None), ProgramSections::CONFIGURATION);
    let serial = [0x37; 6];
    draft.target = TargetSelection::SerialNumber(serial);
    draft.facts.target.as_mut().expect("fixture target").serial_number = Some(serial);
    draft.topology.domain_address = Some(zweidraehte_project::DomainAddress::Rf([0x31; 6]));
    draft.network = crate::commissioning::compiler::binding::network::compile(&draft);
    assert!(!draft.network.assign_domain);
    assert!(!draft.network.restart);

    // Sealing recomputes the network actions from the final intent, so an
    // address-programming operation on the same target carries the domain.
    draft.intent = CommissioningIntent::AssignAddressAndDownload(DownloadMode::Partial(ProgramSections::CONFIGURATION));
    let program = crate::commissioning::compiler::ProgramCompiler::finish(draft).expect("final network scope seals");
    assert!(program.network().assign_domain);
    assert!(program.network().restart);
    assert!(!program.network().advance_sending_sequence);
    assert!(program.apdu_requirements().network_configuration().is_some());
}

#[test]
fn sealing_rejects_identity_facts_that_disagree_with_the_request() {
    let draft = partial_plan(authorization_profile("SystemB", None), ProgramSections::PARAMETERS);
    let mut different_address = draft.clone();
    different_address.facts.target.as_mut().expect("fixture target").previous_address = IndividualAddress::new(1, 1, 2);
    assert!(
        crate::commissioning::compiler::ProgramCompiler::finish(different_address)
            .expect_err("address must match")
            .to_string()
            .contains("target address")
    );

    let mut different_serial = draft;
    different_serial.target = TargetSelection::SerialNumber([1; 6]);
    different_serial.facts.target.as_mut().expect("fixture target").serial_number = Some([2; 6]);
    assert!(
        crate::commissioning::compiler::ProgramCompiler::finish(different_serial)
            .expect_err("serial must match")
            .to_string()
            .contains("serial number")
    );
}

#[test]
fn bootstrap_requires_its_credential_and_complete_apdu_before_sealing() {
    let mut draft = partial_plan(authorization_profile("SystemB", None), ProgramSections::PARAMETERS);
    draft.intent = CommissioningIntent::AssignAddress;
    draft.procedure = None;
    draft.program_sections = None;
    draft.target = TargetSelection::SerialNumber([1; 6]);
    draft.facts.target.as_mut().expect("fixture target").serial_number = Some([1; 6]);
    draft.facts.target.as_mut().expect("fixture target").credential = ManagementCredential::Fdsk;
    draft.facts.data_security = crate::commissioning::input::security::ObservedDataSecurity::Disabled;
    draft.configured_max_apdu = Some(15);
    assert!(
        crate::commissioning::compiler::ProgramCompiler::finish(draft.clone())
            .expect_err("Tool-Key write does not fit")
            .to_string()
            .contains("APDU")
    );

    draft.configured_max_apdu = Some(55);
    let program = crate::commissioning::compiler::ProgramCompiler::finish(draft).expect("bootstrap fits");
    assert!(program.network().bootstrap_tool_key);
    assert_eq!(program.observed_target().credential, ManagementCredential::Fdsk);
}

#[test]
fn credential_transition_survives_later_failure_and_cleanup_without_losing_diagnostics() {
    let mut effects = crate::commissioning::ExecutionEffects::with_status(MutationStatus::PartiallyApplied);
    effects.record_credentials([CredentialTransition::IpBackboneKey]);
    let primary = Diagnostic::new("restart timed out")
        .with_transport(TransportCause::Timeout)
        .with_cleanup_failure(CleanupOperation::Disconnect, Diagnostic::new("close failed"));
    effects.record_credentials([CredentialTransition::ToolKey, CredentialTransition::ToolKey]);
    let error = crate::commissioning::CommissioningError::after_execution(primary, effects);
    assert_eq!(error.effects().credential_transitions(), [
        CredentialTransition::IpBackboneKey,
        CredentialTransition::ToolKey
    ]);
    assert_eq!(error.diagnostic().transport, Some(TransportCause::Timeout));
    assert_eq!(error.diagnostic().cleanup_failures.len(), 1);
    assert_eq!(error.effects().mutation_status(), MutationStatus::PartiallyApplied);
}

#[test]
fn credential_bootstrap_preserves_disabled_mode_unless_enabling_is_requested() {
    let mut draft = partial_plan(authorization_profile("SystemB", None), ProgramSections::PARAMETERS);
    draft.intent = CommissioningIntent::AssignAddress;
    draft.procedure = None;
    draft.program_sections = None;
    draft.target = TargetSelection::SerialNumber([1; 6]);
    draft.facts.target.as_mut().expect("fixture target").serial_number = Some([1; 6]);
    draft.facts.target.as_mut().expect("fixture target").credential = ManagementCredential::Fdsk;
    draft.facts.data_security = ObservedDataSecurity::Disabled;
    for desired in [DesiredDataSecurity::Preserve, DesiredDataSecurity::Disabled, DesiredDataSecurity::Enabled] {
        draft.desired_data_security = desired;
        let program = crate::commissioning::compiler::ProgramCompiler::finish(draft.clone())
            .expect("known mode permits credential bootstrap");
        assert!(program.network().bootstrap_tool_key);
        assert_eq!(program.network().enable_data_security, desired == DesiredDataSecurity::Enabled);
    }
    draft.facts.data_security = ObservedDataSecurity::Unknown;
    assert!(
        crate::commissioning::compiler::ProgramCompiler::finish(draft)
            .expect_err("unknown mode cannot authorize bootstrap")
            .to_string()
            .contains("observed Security Mode")
    );
}

#[test]
fn preparation_requires_replacement_material_for_fdsk_bootstrap() {
    use crate::commissioning::runtime::credentials::ManagementAccess;
    use crate::commissioning::runtime::prepared::PreparedProgram;
    let mut fixture = partial_plan(authorization_profile("SystemB", None), ProgramSections::PARAMETERS);
    fixture.intent = CommissioningIntent::AssignAddress;
    fixture.procedure = None;
    fixture.program_sections = None;
    fixture.target = TargetSelection::SerialNumber([1; 6]);
    fixture.facts.target.as_mut().expect("target").serial_number = Some([1; 6]);
    fixture.facts.target.as_mut().expect("target").credential = ManagementCredential::Fdsk;
    fixture.facts.data_security = ObservedDataSecurity::Disabled;
    let program = crate::commissioning::compiler::ProgramCompiler::finish(fixture).expect("bootstrap compiles");
    for replacement in [None, Some([0xA7; 16])] {
        let evidence = PreparedEvidence {
            execution_address: program.individual_address(),
            differential: DifferentialDecision::Undifferenced,
            baseline_known: None,
            interface_max_apdu: 64,
            target_max_apdu: 64,
            management_style: None,
            reads: Vec::new(),
        };
        let bound = PreparedProgram::new(
            1,
            program.clone(),
            evidence,
            ManagementAccess::Fdsk([0xF0; 16].into()),
            AuthorizationPolicy::None,
            replacement.map(Into::into),
        );
        assert_eq!(bound.is_ok(), replacement.is_some());
        if replacement.is_none() {
            assert!(bound.expect_err("bootstrap requires a replacement").message.contains("replacement credential"));
        }
    }
}
