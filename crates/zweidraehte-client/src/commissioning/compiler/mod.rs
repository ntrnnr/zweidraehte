//! One compiler owns the mutable image and procedure; its input is borrowed.
use crate::commissioning::catalog::ProgrammingCatalog;
use crate::commissioning::catalog::profile::ImageRequirement;
use crate::commissioning::catalog::profile::{ProfileRequest, ProfileSelection, ResolvedProfile};
use crate::commissioning::compiler::image::ProgramImage;
use crate::commissioning::compiler::program::CompiledProgram;
use crate::commissioning::compiler::selection::RecipeSet;
use crate::commissioning::error::CompileError;
use crate::commissioning::image::RequiredImageRange;
use crate::commissioning::input::security::{DesiredDataSecurity, ObservedDataSecurity};
use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections, ProgrammingInput};
use crate::commissioning::procedure::RestartKind;
use crate::commissioning::procedure::operands::StandardMemoryService;
use application_identity::validate_application_metadata;

/// Completed compilation retains secrets only for the private preparation path.
pub(in crate::commissioning) struct CompilationOutput {
    pub(in crate::commissioning) program: CompiledProgram,
    pub(in crate::commissioning) secret_payload: crate::commissioning::compiler::secrets::SecretCommissioningPayload,
}

pub(super) struct ProgramCompiler<'a> {
    input: &'a ProgrammingInput,
    profile: ResolvedProfile,
    standard_memory_service: StandardMemoryService,
    restart_kind: RestartKind,
    image: ProgramImage,
    recipes: RecipeSet,
    unload_required_ranges: Vec<RequiredImageRange>,
    feature_sections: ProgramSections,
}

impl<'a> ProgramCompiler<'a> {
    pub(crate) fn new(input: &'a ProgrammingInput, selection: &ProfileSelection) -> Result<Self, CompileError> {
        let catalog = ProgrammingCatalog::for_product(input.device.product())?;

        let mut profile = catalog.resolve(ProfileRequest {
            discovery: selection.discovery.clone(),
            product: Some(input.device.product()),
            variant_hint: selection.variant_hint,
        })?;

        if let Some(width) = selection.association_table_entry_size {
            profile = profile.with_association_table_entry_size(width)?;
        }

        Self::from_profile(input, profile)
    }

    pub(crate) fn from_profile(
        input: &'a ProgrammingInput,
        mut profile: ResolvedProfile,
    ) -> Result<Self, CompileError> {
        profile.validate_programming()?;

        // Geometry must exist even for unload probes whose modules perform no writes.
        crate::commissioning::catalog::rules::ip::prepare_classic_ip_profile(
            &mut profile,
            input.device.product(),
            input.device.configuration().topology.ip.as_ref(),
        )?;

        // The hardware relation determines application scope. Pure address
        // assignment leaves both applications untouched and needs no AP2 proof.
        let product = input.device.product();
        if input.intent != CommissioningIntent::AssignAddress {
            validate_application_metadata(&profile, product)?;
        }

        let secure = input.facts.target.is_some_and(|target| target.credential.is_secure());
        let standard_memory_service =
            if secure { StandardMemoryService::Extended } else { StandardMemoryService::Classic };
        let target_restart = profile
            .management_style()
            .map_or(RestartKind::Basic, |style| profile.network_restart_kind(style, product.supports_data_secure()));
        let restart_kind = profile.program_restart_kind(
            input.intent.download_mode().is_some(),
            secure,
            product.supports_data_secure(),
            target_restart,
        );
        Ok(Self {
            profile,
            input,
            standard_memory_service,
            restart_kind,
            image: ProgramImage::new(product),
            recipes: RecipeSet::Automatic,
            unload_required_ranges: Vec::new(),
            feature_sections: ProgramSections::empty(),
        })
    }

    pub(crate) fn compile_with_secrets(mut self) -> Result<CompilationOutput, CompileError> {
        self.select_controls()?;
        self.build_image()?;
        self.bind_operands()
    }

    pub(crate) fn compile(self) -> Result<CompiledProgram, CompileError> {
        let CompilationOutput { program, secret_payload } = self.compile_with_secrets()?;
        drop(secret_payload);
        Ok(program)
    }

    pub(crate) fn preview(mut self) -> Result<ProgramImage, CompileError> {
        let input = self.input;
        // Automatic preview computes the whole desired image before stamp-based
        // section selection. Other intents retain their selected control demand.
        if input.intent().download_mode() == Some(DownloadMode::Automatic)
            && input.options().automatic_sections.is_none()
        {
            let mut requirements = self.profile.image_requirements()?;
            if input.device().product().supports_data_secure()
                && input.desired_data_security() == DesiredDataSecurity::Disabled
                && input.observed_facts().data_security == ObservedDataSecurity::Unknown
            {
                requirements.push(ImageRequirement::DataSecurityMode);
            }
            if !requirements.is_empty() {
                let mut image = ProgramImage::new(input.device().product());
                image.requirements = requirements;
                return Ok(image);
            }
        }
        self.select_controls()?;
        self.build_image()?;
        self.image.secret_payload = Default::default();
        Ok(self.image)
    }
}

#[cfg(test)]
pub(crate) fn compile_fixture(
    input: ProgrammingInput,
    profile: ResolvedProfile,
) -> Result<CompiledProgram, CompileError> {
    ProgramCompiler::from_profile(&input, profile)?.compile()
}

pub(in crate::commissioning) mod application_identity;
pub(in crate::commissioning) mod binding;
pub(in crate::commissioning) mod image;
pub(in crate::commissioning) mod selection;

pub mod program;

pub(in crate::commissioning) mod features;

pub(crate) mod secrets;
