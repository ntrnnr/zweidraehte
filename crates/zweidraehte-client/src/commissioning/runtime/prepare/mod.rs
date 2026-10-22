//! The live boundary reads identity, compiles once, then binds execution evidence.
use crate::commissioning::catalog::{bound_master_data, validate_for_live_commissioning};
use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::input::facts::{ObservedTarget, ProgrammingFacts};
use crate::commissioning::input::security::DesiredDataSecurity;
use crate::commissioning::input::{ProgrammingInput, TargetSelection};
use crate::commissioning::report::{CommissioningEvent, CommissioningStage};
use crate::commissioning::runtime::commissioner::{
    Commissioner, CommissioningObserver, DeviceObservation, PreparationOptions,
};
use crate::commissioning::runtime::policy::{
    requested_topology_network_configuration, validate_apdu_requirements, validate_credential_inputs,
    validate_differential_inputs, validate_options,
};
use crate::commissioning::runtime::prepare::profile::ProfileObservation;
use crate::commissioning::runtime::prepared::{PreparedEvidence, PreparedProgram};

impl Commissioner<'_> {
    /// Observe the target and bind this input for execution. Live observations
    /// replace supplied target facts; cancellation or failed preflight returns
    /// an error before configuration writes begin.
    ///
    /// The observer receives events and is polled for cancellation; it is
    /// never asked to approve, because the caller holds the prepared program.
    pub async fn prepare(
        &self,
        mut input: ProgrammingInput,
        options: PreparationOptions,
        observer: &mut impl CommissioningObserver,
    ) -> crate::commissioning::Result<PreparedProgram> {
        async {
            let PreparationOptions { access, variant_hint, differential_policy, deployment } = options;
            let product = input.device.product();
            let device = &input.device;
            let desired_data_security = input.desired_data_security;
            let observes_group_security =
                desired_data_security != DesiredDataSecurity::Preserve && input.intent.updates_group_communication();

            // Raw Master Data documents deliberately support offline inspection of
            // incomplete or newer XML. Live preparation is the mutation boundary:
            // reject unsupported schema provenance before target acquisition.
            // Exact resources and controls are validated when selected below.
            let master_data = std::sync::Arc::clone(bound_master_data(product)?);
            validate_for_live_commissioning(&master_data)?;
            let deployment = deployment.as_ref();
            validate_differential_inputs(input.intent, differential_policy, deployment.is_some())?;
            validate_options(&self.options, device.max_apdu())?;
            validate_credential_inputs(input.device.key_material())?;
            observer.checkpoint()?;

            observer.emit(CommissioningEvent::Stage(CommissioningStage::DiscoveringTarget));
            let open_medium =
                device.topology().domain_address.is_some() && requested_topology_network_configuration(input.intent);
            let mut target = self.acquire_target(&input.options.target, open_medium, &*observer).await?;
            let mut session = self.select_management_session(target, input.device.key_material(), &access).await?;

            observer.checkpoint()?;
            observer.emit(CommissioningEvent::Stage(CommissioningStage::IdentifyingProfile));
            let ProfileObservation { profile, target_max_apdu, data_security } = self
                .observe_profile(
                    &master_data,
                    &input,
                    variant_hint,
                    &mut target,
                    &mut session,
                    &access,
                    observes_group_security,
                )
                .await?;

            observer.emit(CommissioningEvent::TargetDiscovered {
                address: target.address,
                serial_number: target.serial_number,
            });

            let credential = session.selected_credential();
            observer.checkpoint()?;
            observer.emit(CommissioningEvent::Stage(CommissioningStage::CompilingPlan));
            input.facts = ProgrammingFacts {
                target: Some(ObservedTarget {
                    previous_address: target.address,
                    serial_number: target.serial_number,
                    credential,
                }),
                data_security,
            };
            // Discovery resolves this exact product against the validated catalog
            // and adds observed geometry. Reuse that selection, then apply the same
            // policy and module checks as offline compilation.
            let plan = ProgramCompiler::from_profile(&input, profile)?.compile()?;

            let device = &input.device;
            let secure_management = plan.management_secure();

            let management_style = self.validate_installed_realization(&plan, target, &mut session).await?;

            let execution_address = self.preflight_network_program(&plan, &input, target).await?;

            let (partial_installed_state, baseline_known, differential) = self
                .bind_installation_evidence(&plan, &mut session, &input, differential_policy, deployment, observer)
                .await?;

            validate_apdu_requirements(
                &plan,
                self.bus.max_apdu(),
                target_max_apdu,
                device.max_apdu(),
                secure_management,
                matches!(input.options.target, TargetSelection::SerialNumber(_)) && secure_management,
            )?;
            PreparedProgram::new(
                self.bus.instance_id(),
                plan,
                PreparedEvidence {
                    execution_address,
                    differential,
                    baseline_known,
                    interface_max_apdu: self.bus.max_apdu(),
                    target_max_apdu,
                    management_style,
                    reads: partial_installed_state,
                },
                session.access,
                session.config.authorization,
                session.replacement_tool_key,
            )
        }
        .await
        .map_err(crate::commissioning::CommissioningError::before_execution)
    }
}

pub(crate) mod capabilities;
pub(crate) mod installation;
pub(crate) mod installed_contract;
mod network;
pub(crate) mod profile;
pub(crate) mod reads;
pub(crate) mod revalidate;
pub(crate) mod target;
