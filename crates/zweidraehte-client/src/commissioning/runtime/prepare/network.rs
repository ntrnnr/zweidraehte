//! Validate installed realization and network preconditions for the compiled plan.

use crate::commissioning::catalog::profile::ResourceManagementStyle;
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::error::PreparationFailure;
use crate::commissioning::input::{CommissioningIntent, ProgrammingInput, TargetSelection, UnloadMode};
use crate::commissioning::procedure::operands::ServiceRead;
use crate::commissioning::runtime::ExecutionSession;
use crate::commissioning::runtime::commissioner::Commissioner;
use crate::commissioning::runtime::identity::management_style_read;
use crate::commissioning::runtime::policy::{
    open_medium_domain, operation_requires_installed_management_style, validate_partial_management_style,
};
use crate::commissioning::runtime::prepare::profile::AcquiredTarget;

impl Commissioner<'_> {
    pub(in crate::commissioning) async fn validate_installed_realization(
        &self,
        plan: &CompiledProgram,
        target: AcquiredTarget,
        session: &mut ExecutionSession<'_>,
    ) -> Result<Option<(ServiceRead, ResourceManagementStyle)>> {
        // Automatic section selection is profile-aware and may widen a raw
        // project delta to a published semantic full procedure. Only the
        // compiled plan can therefore decide whether the installed
        // application realization must remain compatible.
        let management_style = if operation_requires_installed_management_style(plan) {
            match management_style_read(plan.profile())? {
                Some(probe) => {
                    let style = session.read_installed_management_style(target.address, &probe).await?;
                    Some((probe, style))
                }
                None => None,
            }
        } else {
            None
        };
        validate_partial_management_style(management_style.as_ref().map(|(_, style)| *style), plan)?;

        Ok(management_style)
    }
    pub(in crate::commissioning) async fn preflight_network_program(
        &self,
        plan: &CompiledProgram,
        input: &ProgrammingInput,
        target: AcquiredTarget,
    ) -> Result<zweidraehte_proto::address::IndividualAddress> {
        let execution_address = match input.intent {
            CommissioningIntent::Download(_) if target.address != plan.individual_address() => {
                return Err(Diagnostic::preparation(
                    PreparationFailure::AddressConflict,
                    format!(
                        "download target is at {0}, but the project address is {1}; assign the address before downloading",
                        target.address,
                        plan.individual_address()
                    ),
                ));
            }
            CommissioningIntent::Unload(_) => target.address,
            CommissioningIntent::AssignAddress
            | CommissioningIntent::AssignAddressAndDownload(_)
            | CommissioningIntent::Download(_) => plan.individual_address(),
        };

        if matches!(input.intent, CommissioningIntent::Unload(UnloadMode::AllConfiguration))
            && !plan.procedure().is_some_and(|procedure| {
                procedure.steps.iter().any(|step| {
                    matches!(step.operation, crate::commissioning::procedure::ProcedureOperation::MasterReset {
                        erase_code: 2,
                        channel: 0
                    })
                })
            })
            && target.serial_number.is_none()
        {
            return Err(Diagnostic::preparation(
                PreparationFailure::Unsupported,
                "complete unload on this profile requires a serial number for the scoped IA reset",
            ));
        }
        let network = plan.network();
        let address_change_expected = network.assign_address;

        if address_change_expected
            && self
                .bus
                .network_management()
                .is_device_present(plan.individual_address(), self.options.scan_window)
                .await
                .map_err(|error| {
                    Diagnostic::from(error).preparation_context(
                        PreparationFailure::Communication,
                        "checking the desired individual address",
                    )
                })?
        {
            return Err(Diagnostic::preparation(
                PreparationFailure::AddressConflict,
                format!("individual address {} is already occupied", plan.individual_address()),
            ));
        }

        if network.assign_domain
            && let Some(domain) = plan.topology().domain_address
        {
            if !self.options.caller_manages_open_medium_path {
                return Err(Diagnostic::preparation(
                    PreparationFailure::InvalidOptions,
                    "RF domain assignment requires the caller to configure and restore the open-medium path",
                ));
            }

            let domain = open_medium_domain(domain)?;
            let domain_serial_number = match &input.options.target {
                TargetSelection::SerialNumber(serial_number) => Some(*serial_number),
                TargetSelection::ProgrammingButton(_)
                | TargetSelection::KnownPreviousAddress(_)
                | TargetSelection::ExistingAddress(_) => None,
            };
            self.preflight_open_medium_domain(plan, target.address, domain_serial_number, domain).await?;
        }

        Ok(execution_address)
    }
}
