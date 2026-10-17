//! Lowering in order: select a recipe, bind contributions, lower its controls,
//! then validate and seal the immutable program.

use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::error::CompileError;

use crate::commissioning::catalog::rules::lifecycle::{compile_confirmed_unload, validate_download_stamp_output};
use crate::commissioning::compiler::CompilationOutput;
use crate::commissioning::compiler::features::IP_SECURE_CONFIGURATION_CONTRIBUTION;
use crate::commissioning::compiler::image::ProgramImage;
use crate::commissioning::compiler::program::network::NetworkProgram;
use crate::commissioning::compiler::program::{CommissioningApduRequirements, CompiledProgram};
use crate::commissioning::compiler::secrets::validate_secret_bindings;
use crate::commissioning::input::security::DesiredDataSecurity;
use crate::commissioning::input::{CommissioningIntent, ProgramSections, ProgrammingInput, TargetSelection};
use crate::commissioning::procedure::operands::required_plaintext_apdu;
use crate::commissioning::procedure::{ProcedureOperation, ToolState};

use std::collections::BTreeSet;
use zweidraehte_project::IpServiceSecurity;

impl ProgramCompiler<'_> {
    pub(super) fn bind_operands(self) -> Result<CompilationOutput, CompileError> {
        let Self { image: compiled_image, profile, input, recipes, standard_memory_service, restart_kind, .. } = self;
        let ProgrammingInput { device, intent, options, facts, desired_data_security } = input;
        let (intent, facts, desired_data_security) = (*intent, *facts, *desired_data_security);
        let observed_target = facts.target.ok_or(CompileError::missing_evidence(
            "final lowering requires the target address and selected management credential",
        ))?;
        let credential = observed_target.credential;
        let product = device.product();
        let configuration = device.configuration();

        // Select once, after the desired image and target evidence are available.
        if matches!(recipes, crate::commissioning::compiler::selection::RecipeSet::Automatic) {
            return Err(CompileError::missing_evidence(
                "automatic download requires explicitly resolved program sections",
            ));
        }
        let procedure_request = recipes.request();
        let is_download = procedure_request.is_some_and(|request| request.procedure_type == "Load");

        // The full desired image is useful before automatic scope selection.
        // Network security transitions must follow the final selected scope.
        let desired_data_security = if procedure_request.is_some_and(|request| {
            request.procedure_type == "Load"
                && request.applicability.sections.contains(ProgramSections::GROUP_COMMUNICATION)
        }) {
            desired_data_security
        } else {
            DesiredDataSecurity::Preserve
        };

        let ProgramImage {
            image,
            mut manifest,
            regions: native_regions,
            secret_payload,
            product_fingerprint,
            table_spans,
            ..
        } = compiled_image;

        let address = configuration.individual_address.as_bytes();
        manifest.insert(
            zweidraehte_project::ProgrammingSection::Address,
            zweidraehte_project::semantic_fingerprint("individual-address", "desired", address),
        );

        if desired_data_security == DesiredDataSecurity::Disabled && product.supports_data_secure() {
            use crate::commissioning::input::security::ObservedDataSecurity;

            match facts.data_security {
                ObservedDataSecurity::Unknown => {
                    return Err(CompileError::missing_evidence(
                        "disabling Data Secure requires an observed device security mode",
                    ));
                }
                ObservedDataSecurity::Enabled => {
                    return Err(CompileError::unsupported(
                        "disabling Data Secure requires a supported reset and cleanup transition",
                    ));
                }
                ObservedDataSecurity::Disabled => {}
            }
        }

        // Resolve each service operand against the same image and management metadata.
        let mut procedure = match recipes {
            crate::commissioning::compiler::selection::RecipeSet::ConfirmedUnload(mode) => {
                Some(compile_confirmed_unload(&profile, mode, ToolState::default(), credential.is_secure())?)
            }
            crate::commissioning::compiler::selection::RecipeSet::AddressOnly => None,
            crate::commissioning::compiler::selection::RecipeSet::Automatic => {
                unreachable!("automatic scope checked above")
            }
            crate::commissioning::compiler::selection::RecipeSet::Exact { procedure, .. } => {
                Some(procedure.finish_with_tables(&profile, &image, &table_spans, is_download)?)
            }
        };

        // Finalize the selected lifecycle before validating sizes.
        if let Some(procedure) = &mut procedure {
            if is_download {
                validate_download_stamp_output(&profile, &image, procedure)?;
            }

            if matches!(intent, CommissioningIntent::Unload(crate::commissioning::input::UnloadMode::AllConfiguration))
            {
                let all_sections = BTreeSet::from([
                    zweidraehte_project::ProgrammingSection::Address,
                    zweidraehte_project::ProgrammingSection::ApplicationProgram1,
                    zweidraehte_project::ProgrammingSection::ApplicationProgram2,
                    zweidraehte_project::ProgrammingSection::Parameters,
                    zweidraehte_project::ProgrammingSection::GroupCommunication,
                    zweidraehte_project::ProgrammingSection::Configuration,
                ]);

                for step in &mut procedure.steps {
                    if matches!(&step.operation, ProcedureOperation::MasterReset { .. }) {
                        step.sections = all_sections.clone();
                    }
                }
            }
        }

        if let Some(procedure) = &mut procedure {
            // Plain management can compile public IP settings for a secure-
            // capable device. The reference retains its plain-service controls
            // as SecureOnly, so they stay dormant on that management path.
            // This permission does not cover credentials, secure IP services,
            // or the separate Data Secure contribution.
            let dormant_plain_ip_security = configuration.topology.ip.as_ref().is_some_and(|ip| {
                ip.password_users.is_empty()
                    && ip.security.as_ref().is_some_and(|security| {
                        security.routing == IpServiceSecurity::Plain
                            && security.device_management == IpServiceSecurity::Plain
                            && security.tunnelling == IpServiceSecurity::Plain
                            && security.tunnelling_users.is_empty()
                    })
            });
            if !credential.is_secure() && dormant_plain_ip_security {
                procedure.steps.retain(|step| {
                    !(step.secure_only && step.path.contribution == Some(IP_SECURE_CONFIGURATION_CONTRIBUTION))
                });
            }
            if !credential.is_secure()
                && procedure.steps.iter().any(|step| step.secure_only && step.source_control_code.is_none())
            {
                return Err(CompileError::invalid("Data Secure programming requires secure management access"));
            }
            validate_secret_bindings(procedure, Some(&secret_payload))?;
        }

        let verify_mode = match profile.feature("VerifyMode")? {
            None | Some(0) => false,
            Some(1) => true,
            Some(value) => {
                return Err(CompileError::unsupported(format!("unsupported VerifyMode feature {value}")));
            }
        };
        let plan = CompiledProgram {
            desired_data_security,
            full_image_stamp_coverage: profile.supports_full_image_stamp_coverage()?,
            facts,
            verify_mode,
            programming_mode: crate::commissioning::procedure::operands::programming_mode(
                &profile,
                standard_memory_service,
            )?,
            verification_reads: if is_download {
                verification::bind(&profile, standard_memory_service, &image)?
            } else {
                Vec::new()
            },
            native_regions,
            configured_max_apdu: configuration.configured_max_apdu,
            intent,
            target: options.target.clone(),
            individual_address: configuration.individual_address,
            network_restart_kind: profile
                .management_style()
                .map_or(restart_kind, |style| profile.network_restart_kind(style, product.supports_data_secure())),
            program_sections: procedure_request
                .filter(|request| request.procedure_type == "Load")
                .map(|request| request.applicability.sections),
            full_program_scope: procedure_request
                .is_some_and(|request| request.procedure_type == "Load" && request.applicability.full),
            topology: configuration.topology.clone(),
            profile,
            network: NetworkProgram::default(),
            image,
            manifest,
            procedure,
            apdu_requirements: CommissioningApduRequirements::default(),
            product_fingerprint,
        };

        Ok(CompilationOutput { program: Self::finish(plan)?, secret_payload })
    }

    pub(in crate::commissioning::compiler) fn finish(
        mut program: CompiledProgram,
    ) -> Result<CompiledProgram, CompileError> {
        let secure_access = program.management_secure();

        match program.target {
            TargetSelection::ExistingAddress(address) | TargetSelection::KnownPreviousAddress(address)
                if address != program.observed_target().previous_address =>
            {
                return Err(CompileError::invalid("observed target address differs from the requested target"));
            }
            TargetSelection::SerialNumber(serial) if Some(serial) != program.observed_target().serial_number => {
                return Err(CompileError::invalid("observed serial number differs from the requested target"));
            }
            _ => {}
        }

        // Network controls and APDU bounds depend only on compiled intent and facts.
        program.network = network::compile(&program);
        program.apdu_requirements = network::required_apdu(&program.network, &program)?;
        if let Some(procedure) = &program.procedure {
            procedure.validate()?;
            if !secure_access && procedure.steps.iter().any(|step| step.secure_only) {
                return Err(CompileError::invalid("secure-only procedure operations require secure management access"));
            }
            program.apdu_requirements.procedure = required_plaintext_apdu(procedure, program.verify_mode)?;
        }
        for (_, read) in &program.verification_reads {
            program.apdu_requirements.procedure =
                Some(program.apdu_requirements.procedure.unwrap_or(0).max(read.minimum_apdu()?));
        }
        if let (Some(required), Some(configured)) = (program.apdu_requirements.maximum(), program.configured_max_apdu)
            && required > configured
        {
            return Err(CompileError::invalid(format!(
                "plan requires plaintext APDU {required}, above configured target ceiling {configured}"
            )));
        }
        Ok(program)
    }
}
pub(crate) mod facts;
pub(crate) mod network;
mod verification;

pub(crate) mod procedure;

#[cfg(test)]
pub(in crate::commissioning) mod tests;
