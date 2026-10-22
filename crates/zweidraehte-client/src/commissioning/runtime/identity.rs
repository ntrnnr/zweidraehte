//! Revalidate the prepared identity and security observation before mutation.
use crate::AddressTarget;
use crate::commissioning::runtime::TransferContext;

use crate::commissioning::catalog::profile::{
    ManagementModel, ResolvedProfile, ResourceFlavour, ResourceManagementStyle,
};
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::error::Diagnostic;
use crate::commissioning::error::DiagnosticResult as Result;
use crate::commissioning::error::PreparationFailure;
use crate::commissioning::input::security::ObservedDataSecurity;
use crate::commissioning::procedure::operands::{ServiceRead, StandardMemoryService};
use crate::commissioning::runtime::ExecutionSession;
use crate::commissioning::runtime::policy::unique_target;
use crate::commissioning::runtime::prepare::profile::read_data_security_mode;
use crate::commissioning::runtime::prepare::profile::{read_dd0, read_management_descriptor_01};
use crate::commissioning::runtime::prepared::PreparedEvidence;
use zweidraehte_proto::address::IndividualAddress;

pub(crate) fn management_style_read(profile: &ResolvedProfile) -> Result<Option<ServiceRead>> {
    let Some(resource) = profile
        .resource("ManagementStyle")
        .map_err(|error| Diagnostic::preparation(PreparationFailure::Profile, error.to_string()))?
    else {
        return if profile.management_model() == ManagementModel::Bcu2 {
            Err(Diagnostic::preparation(
                PreparationFailure::Profile,
                "BCU2 profile has no remote management-style probe",
            ))
        } else {
            Ok(None)
        };
    };
    let location = resource
        .source
        .location
        .as_ref()
        .ok_or_else(|| Diagnostic::preparation(PreparationFailure::Profile, "management-style probe has no location"))?
        .to_address_space()
        .map_err(|error| Diagnostic::preparation(PreparationFailure::Profile, error.to_string()))?;
    if matches!(location, zweidraehte_ets_files::schema::master_data::AddressSpaceLocation::Constant { .. }) {
        return Ok(None);
    }
    if resource.flavour().map_err(|error| Diagnostic::preparation(PreparationFailure::Profile, error.to_string()))?
        != Some(ResourceFlavour::ManagementStyleBcu2)
    {
        return Err(Diagnostic::preparation(
            PreparationFailure::Profile,
            "management-style resource has unsupported coding",
        ));
    }
    if !matches!(location, zweidraehte_ets_files::schema::master_data::AddressSpaceLocation::StandardMemory { .. }) {
        return Err(Diagnostic::preparation(
            PreparationFailure::Profile,
            "management-style probe has unsupported online location",
        ));
    }
    u8::try_from(resource.length()).map_err(|_| {
        Diagnostic::preparation(PreparationFailure::Profile, "management-style probe exceeds one transfer")
    })?;
    Ok(Some(resource.read(StandardMemoryService::Classic)?))
}

impl ExecutionSession<'_> {
    pub(crate) async fn read_installed_management_style(
        &mut self,
        address: IndividualAddress,
        probe: &ServiceRead,
    ) -> Result<ResourceManagementStyle> {
        self.connect_without_authorization_at(address).await?;
        let value = read_bound_management_style(self, probe).await;
        self.finish(value).await
    }
    pub(in crate::commissioning) async fn revalidate_binding(
        &mut self,
        address: IndividualAddress,
        plan: &CompiledProgram,
        evidence: &PreparedEvidence,
        require_prepared_address: bool,
    ) -> Result<()> {
        // These are the same profile-selection facts read before authorization
        // during preparation. Revalidate them in that state as well: legacy
        // authorization is neither needed for the reads nor observationally
        // neutral on every converted BCU1 application hosted by MV-0020.
        self.connect_without_authorization_at(address).await?;
        let observations = async {
            let observed = read_dd0(self).await?;
            let descriptor = if plan.profile().mask().management_descriptor_01.is_some() {
                Some(read_management_descriptor_01(self).await?)
            } else {
                None
            };
            let management_style = if let Some((probe, _)) = &evidence.management_style {
                Some(read_bound_management_style(self, probe).await?)
            } else {
                None
            };
            // Mode is a compilation fact only before the first mutation. A
            // later revalidation follows the explicit compiled mode transition.
            let expected = plan.observed_data_security();
            if require_prepared_address && expected != ObservedDataSecurity::Unknown {
                // Security Mode has configuration access. Identity probes above
                // intentionally retain their pre-authorization observation state.
                self.authorize().await?;
                let observed_mode = read_data_security_mode(self).await?;
                if observed_mode != expected {
                    return Err(Diagnostic::preparation(
                        PreparationFailure::TargetChanged,
                        "Security Mode changed after preparation; prepare commissioning again",
                    ));
                }
            }
            Ok((observed, descriptor, management_style))
        }
        .await;
        let (observed, observed_descriptor, observed_management_style) = self.finish(observations).await?;

        if observed != plan.profile().mask().dd0 {
            return Err(Diagnostic::preparation(
                PreparationFailure::TargetChanged,
                format!(
                    "the device at {address} changed after Diagnostic::preparation (expected DD0 {:04X}, observed {observed:04X})",
                    plan.profile().mask().dd0
                ),
            ));
        }
        if observed_descriptor != plan.profile().mask().management_descriptor_01 {
            return Err(Diagnostic::preparation(
                PreparationFailure::TargetChanged,
                format!(
                    "the device at {address} changed after Diagnostic::preparation (PID 72 no longer identifies {})",
                    plan.profile().mask()
                ),
            ));
        }
        let expected_style = evidence.management_style.as_ref().map(|(_, style)| *style);
        if observed_management_style != expected_style {
            return Err(Diagnostic::preparation(
                PreparationFailure::TargetChanged,
                format!(
                    "the installed management realization at {address} changed after preparation \
                 (expected {:?}, observed {observed_management_style:?})",
                    expected_style
                ),
            ));
        }

        if let Some(serial_number) = plan.observed_target().serial_number {
            let addresses = self
                .bus
                .network_management()
                .read_individual_addresses(AddressTarget::Serial(serial_number), self.config.scan_window)
                .await
                .map_err(|error| {
                    Diagnostic::from(error).preparation_context(
                        PreparationFailure::Communication,
                        "revalidating the selected serial number",
                    )
                })?;
            let serial_address = unique_target(addresses, "the prepared serial number")?;
            if serial_address != address {
                return Err(Diagnostic::preparation(
                    PreparationFailure::TargetChanged,
                    format!("the prepared serial number moved from {address} to {serial_address} before execution"),
                ));
            }
        }

        Ok(())
    }
}

pub(in crate::commissioning) async fn read_bound_management_style(
    session: &mut ExecutionSession<'_>,
    probe: &ServiceRead,
) -> Result<ResourceManagementStyle> {
    let value = session.read(&probe.target, probe.extent, TransferContext::Public).await?;
    let value = value.first().copied().ok_or_else(|| {
        Diagnostic::preparation(
            PreparationFailure::InvalidResponse,
            "management-style identity probe returned no bytes",
        )
    })?;
    Ok(if value == 0 { ResourceManagementStyle::LoadStateMachine } else { ResourceManagementStyle::Simple })
}
