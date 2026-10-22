//! Observed device evidence and immutable programs bound for execution.

use crate::commissioning::catalog::profile::{ResourceId, ResourceManagementStyle};
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::evidence::{DifferentialDecision, DiscoveredDevice};
use crate::commissioning::image::SparseDeviceImage;
use crate::commissioning::procedure::operands::ServiceRead;
use std::fmt;
use zweidraehte_proto::address::IndividualAddress;

use super::credentials::ManagementAccess;
use crate::commissioning::error::PreparationFailure;
use crate::commissioning::runtime::AuthorizationPolicy;
use zweidraehte_util::secret::SecretBytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundRead {
    pub(crate) resource: ResourceId,
    pub(crate) service: ServiceRead,
    pub(crate) expected: ReadExpectation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadExpectation {
    Capture { optional: bool },
    Exact(Option<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedEvidence {
    pub(crate) execution_address: IndividualAddress,
    pub(crate) differential: DifferentialDecision,
    pub(crate) baseline_known: Option<SparseDeviceImage>,
    pub(crate) interface_max_apdu: u16,
    pub(crate) target_max_apdu: u16,
    pub(crate) management_style: Option<(ServiceRead, ResourceManagementStyle)>,
    pub(crate) reads: Vec<BoundRead>,
}
/// Immutable plan bound to the device discovered during `prepare()`.
///
/// Construction is crate-private, so callers cannot pair a plan with a
/// different physical target or inject credentials after preflight.
/// An offline compiled program lacks the observed identity and bound
/// credentials required by execution:
///
/// ```compile_fail
/// use zweidraehte_client::commissioning::{Commissioner, CommissioningCancellation, CompiledProgram};
/// async fn execute_unprepared(commissioner: &Commissioner<'_>, program: CompiledProgram) {
///     let _result = commissioner.execute(program, &CommissioningCancellation::default(), |_| {}).await;
/// }
/// ```
pub struct PreparedProgram {
    pub(super) bus_instance_id: u64,
    pub(super) plan: CompiledProgram,
    pub(super) evidence: PreparedEvidence,
    pub(super) access: ManagementAccess,
    pub(super) authorization: AuthorizationPolicy,
    pub(super) replacement_tool_key: Option<SecretBytes>,
}

impl PreparedProgram {
    pub(in crate::commissioning) fn new(
        bus_instance_id: u64,
        plan: CompiledProgram,
        evidence: PreparedEvidence,
        access: ManagementAccess,
        authorization: AuthorizationPolicy,
        replacement_tool_key: Option<SecretBytes>,
    ) -> std::result::Result<Self, Diagnostic> {
        let observations = plan.observed_target();
        if access.credential() != observations.credential {
            return Err(Diagnostic::new("selected management credential differs from the compiled program"));
        }
        if plan.network().bootstrap_tool_key && replacement_tool_key.is_none() {
            return Err(Diagnostic::new("Tool-Key bootstrap has no replacement credential"));
        }
        Ok(Self { bus_instance_id, plan, evidence, access, authorization, replacement_tool_key })
    }

    pub fn plan(&self) -> &CompiledProgram {
        &self.plan
    }

    /// Address bound for execution; unloads can target a previous project address.
    pub fn execution_address(&self) -> IndividualAddress {
        self.evidence.execution_address
    }

    /// Differential choice established by live evidence, without changing the program.
    pub fn differential(&self) -> &DifferentialDecision {
        &self.evidence.differential
    }

    /// Compute the discovered-device summary from the same facts execution validates.
    pub fn discovered_device(&self) -> DiscoveredDevice {
        self.evidence.discovery(&self.plan)
    }

    pub(crate) const fn bus_instance_id(&self) -> u64 {
        self.bus_instance_id
    }
}

impl fmt::Debug for PreparedProgram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProgram")
            .field("plan", &self.plan)
            .field("evidence", &self.evidence)
            .field("access", &self.access)
            .field("authorization", &self.authorization)
            .field("replacement_tool_key", &self.replacement_tool_key)
            .finish()
    }
}

impl PreparedProgram {
    pub(in crate::commissioning) fn check_bus(
        prepared_bus_instance_id: u64,
        executing_bus_instance_id: u64,
    ) -> crate::commissioning::error::DiagnosticResult<()> {
        if prepared_bus_instance_id == executing_bus_instance_id {
            Ok(())
        } else {
            Err(Diagnostic::preparation(
                PreparationFailure::TargetChanged,
                "prepared commissioning belongs to a different KNX bus instance; prepare it again on this bus",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::commissioning::compiler::program::CommissioningApduRequirements;
    use crate::commissioning::input::ProgramSections;

    #[test]
    fn partial_section_sets_are_explicit() {
        let sections = ProgramSections::PARAMETERS.union(ProgramSections::GROUP_COMMUNICATION);

        assert!(sections.contains(ProgramSections::PARAMETERS));
        assert!(sections.contains(ProgramSections::GROUP_COMMUNICATION));
        assert!(!sections.contains(ProgramSections::APPLICATION_PROGRAM_1));
    }

    #[test]
    fn independent_phase_requirements_have_no_sentinel_value() {
        let procedure_only = CommissioningApduRequirements {
            address_assignment: None,
            network_configuration: None,
            procedure: Some(15),
        };
        let both = CommissioningApduRequirements {
            address_assignment: Some(6),
            network_configuration: Some(12),
            procedure: Some(15),
        };

        assert_eq!(CommissioningApduRequirements::default().maximum(), None);
        assert_eq!(procedure_only.maximum(), Some(15));
        assert_eq!(both.maximum(), Some(15));
    }

    #[test]
    fn prepared_commissioning_rejects_a_different_bus_instance() {
        assert!(crate::commissioning::runtime::prepared::PreparedProgram::check_bus(7, 7).is_ok());

        let error = crate::commissioning::runtime::prepared::PreparedProgram::check_bus(7, 8)
            .expect_err("a different bus must fail before execution");

        assert_eq!(
            error.kind(),
            crate::commissioning::DiagnosticKind::Preparation(crate::commissioning::PreparationFailure::TargetChanged)
        );
    }
}
