//! Statically composed programming behavior independent of mask families.
//!
//! Each module reads the supplied configuration and observations, validates its
//! transition, and contributes image bytes and procedure operations. Discovery
//! belongs to preparation; modules never receive a bus handle.

#[cfg(test)]
use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::compiler::selection::RecipeSet;
#[cfg(test)]
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureRequest};
use crate::commissioning::error::CompileError;
#[cfg(test)]
use crate::commissioning::input::security::DesiredDataSecurity;
pub mod data_secure;
pub mod ip;
pub mod topology;

#[cfg(test)]
use zweidraehte_ets_files::product::ProductData;

#[cfg(test)]
use crate::commissioning::catalog::profile::ResolvedProfile;
#[cfg(test)]
use crate::configuration::LoweredDeviceConfiguration;
#[cfg(test)]
use crate::configuration::{ResolvedIpSecureConfiguration, ResolvedKeyMaterial};

#[cfg(test)]
use crate::commissioning::compiler::binding::procedure::ParsedProcedure;
#[cfg(test)]
use crate::commissioning::compiler::image::ProgramImage;
#[cfg(test)]
use crate::commissioning::input::ProgramSections;
use crate::commissioning::procedure::{ErrorHandler, ProcedureOperation};
use zweidraehte_project::ProgrammingSection;

/// Semantic boundaries resolved against the selected source procedure.
/// A missing boundary is an error; contributions never silently move elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ProcedureCompilationPhase {
    /// After leading unloads, immediately before ordinary loading starts.
    BeforeFirstStartLoading,
    /// After ordinary tables commit, so dependent objects can validate them.
    AfterLastCompleteLoading,
    /// Reference unload cursor, resolved before final source filtering.
    NativeSecurityUnload,
    /// Reference reload cursor, including the earlier unload insertion.
    NativeSecurityLoad,
    /// In the final management session, before its closing operation.
    BeforeSessionClose,
    /// After the last unload in the program as composed so far, including
    /// unloads inserted by earlier contributions.
    AfterLastUnload,
    /// Right after the last start-loading record of the router object.
    AfterLastRouterLoad,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleProcedureFragment {
    pub source: &'static str,
    pub section: zweidraehte_project::ProgrammingSection,
    pub phase: ProcedureCompilationPhase,
    pub operation: crate::commissioning::procedure::ProcedureOperation,
    pub secure_only: bool,
}

impl RecipeSet {
    pub(super) fn require_restart(&mut self, kind: crate::commissioning::RestartKind, section: ProgrammingSection) {
        if let RecipeSet::Exact { procedure, .. } = self {
            procedure.require_feature_restart(kind, section);
        }
    }

    pub(super) fn before_loading(&mut self, operation: ProcedureOperation) {
        self.emit(
            ProcedureCompilationPhase::BeforeFirstStartLoading,
            "standard-data-secure",
            ProgrammingSection::GroupCommunication,
            true,
            operation,
        );
    }
    pub(super) fn after_loading(&mut self, operation: ProcedureOperation) {
        self.emit(
            ProcedureCompilationPhase::AfterLastCompleteLoading,
            "standard-data-secure",
            ProgrammingSection::GroupCommunication,
            true,
            operation,
        );
    }
    pub(super) fn unload_disabled_security(&mut self, operation: ProcedureOperation) {
        self.emit(
            ProcedureCompilationPhase::NativeSecurityUnload,
            "standard-data-secure",
            ProgrammingSection::GroupCommunication,
            true,
            operation,
        );
    }
    pub(super) fn reload_disabled_security(&mut self, operation: ProcedureOperation, handlers: Vec<ErrorHandler>) {
        if let RecipeSet::Exact { procedure: program, .. } = self {
            program.insert_builtin_with_handlers(
                ProcedureCompilationPhase::NativeSecurityLoad,
                "standard-data-secure",
                ProgrammingSection::GroupCommunication,
                true,
                operation,
                handlers,
            );
        }
    }
    pub(super) fn before_close(&mut self, secure: bool, operation: ProcedureOperation) {
        self.emit(
            ProcedureCompilationPhase::BeforeSessionClose,
            if secure { "standard-ip-secure-configuration" } else { "standard-ip-configuration" },
            ProgrammingSection::Configuration,
            secure,
            operation,
        );
    }
    pub(super) fn rf_medium_configuration(&mut self, operation: ProcedureOperation, handlers: Vec<ErrorHandler>) {
        if let RecipeSet::Exact { procedure: program, .. } = self {
            program.insert_builtin_with_handlers(
                ProcedureCompilationPhase::AfterLastUnload,
                "standard-rf-configuration",
                ProgrammingSection::Configuration,
                false,
                operation,
                handlers,
            );
        }
    }
    pub(super) fn router_configuration(
        &mut self,
        operation: ProcedureOperation,
        handlers: Vec<ErrorHandler>,
    ) -> Result<(), CompileError> {
        if let RecipeSet::Exact { procedure: program, .. } = self {
            // Without a router load the reference appends its own router
            // unload/load/completion sequence, shaped by the product's coupler
            // capabilities. It fails natively for every witnessed product, whose
            // capabilities are absent, so no reference output exists to match.
            //
            // TODO: Compose that sequence once a product with coupler
            // capabilities witnesses it.
            if !program.has_router_load() {
                return Err(CompileError::unsupported(
                    "router configuration needs a procedure that loads the router object",
                ));
            }
            program.insert_builtin_with_handlers(
                ProcedureCompilationPhase::AfterLastRouterLoad,
                "standard-router-configuration",
                ProgrammingSection::Configuration,
                false,
                operation,
                handlers,
            );
        }
        Ok(())
    }
    fn emit(
        &mut self,
        phase: ProcedureCompilationPhase,
        source: &'static str,
        section: ProgrammingSection,
        secure: bool,
        operation: ProcedureOperation,
    ) {
        if let RecipeSet::Exact { procedure: program, .. } = self {
            program.insert_builtin(phase, source, section, secure, operation);
        }
    }
}

#[cfg(test)]
fn fixture_input(
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
    data_secure: Option<&crate::configuration::SecurityConfig>,
    ip_secure: Option<&ResolvedIpSecureConfiguration>,
) -> crate::commissioning::ProgrammingInput {
    use crate::commissioning::{CommissioningIntent, CompileOptions, DownloadMode, TargetSelection};
    let device = crate::configuration::MaterializedDevice::new(
        product.clone(),
        configuration.clone(),
        Vec::new(),
        ResolvedKeyMaterial::new(None)
            .with_application_security(data_secure.cloned())
            .with_ip_secure(ip_secure.cloned()),
    );
    crate::commissioning::ProgrammingInput::new(
        device,
        CommissioningIntent::Download(DownloadMode::Full),
        CompileOptions {
            target: TargetSelection::ExistingAddress(configuration.individual_address),
            automatic_sections: None,
            progress_messages_by_reference: Default::default(),
            progress_messages_by_id: Default::default(),
        },
    )
    .data_security(DesiredDataSecurity::Enabled)
}

#[cfg(test)]
fn fixture_compiler<'a>(
    input: &'a crate::commissioning::ProgrammingInput,
    profile: &ResolvedProfile,
) -> ProgramCompiler<'a> {
    ProgramCompiler {
        input,
        profile: profile.clone(),
        image: ProgramImage::new(input.device.product()),
        standard_memory_service: crate::commissioning::StandardMemoryService::Classic,
        restart_kind: crate::commissioning::RestartKind::Basic,
        unload_required_ranges: Vec::new(),
        feature_sections: ProgramSections::all(),
        recipes: RecipeSet::Exact {
            request: ProcedureRequest {
                procedure_type: "Load",
                subtype: "all",
                applicability: ProcedureApplicability::full(),
            },
            procedure: Box::new(ParsedProcedure::feature_fixture(profile)),
        },
    }
}

#[cfg(test)]
fn compile_fixture(
    profile: &ResolvedProfile,
    product: &ProductData,
    configuration: &LoweredDeviceConfiguration,
    data_secure: Option<&crate::configuration::SecurityConfig>,
    ip_secure: Option<&ResolvedIpSecureConfiguration>,
    emit: impl FnOnce(&mut ProgramCompiler<'_>) -> Result<(), CompileError>,
) -> (ProgramImage, Vec<crate::commissioning::procedure::ProcedureStep>) {
    let input = fixture_input(product, configuration, data_secure, ip_secure);
    let mut compiler = fixture_compiler(&input, profile);
    emit(&mut compiler).expect("feature compiles");
    let RecipeSet::Exact { procedure, .. } = compiler.recipes else { unreachable!("fixture has an exact recipe") };
    let procedure =
        procedure.finish(profile, &compiler.image.image, false).expect("canonical feature controls validate");
    let steps = procedure.steps.into_iter().filter(|step| step.path.contribution.is_some()).collect();
    (compiler.image, steps)
}
