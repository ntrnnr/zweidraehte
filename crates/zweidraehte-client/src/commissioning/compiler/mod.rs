//! One compiler owns the mutable image and procedure; its input is borrowed.
use crate::commissioning::catalog::profile::ImageRequirement;
use crate::commissioning::catalog::profile::ResolvedProfile;
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
use zweidraehte_ets_files::product::NotLoadableBehavior;

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

/// The reference never downloads an application whose options set
/// `NotLoadable`: with `DisplayError` it reports the product's message (or a
/// generic one), with `SkipSilently` it records the device as loaded and sends
/// nothing. Either way no download exists to compile, before any profile or
/// image work. Address assignment and unloads are unaffected.
// TODO: `SkipSilently` also marks the project's programming state as loaded;
// commissioning has no project-state outcome for a skipped download yet.
fn refuse_not_loadable(input: &ProgrammingInput) -> Result<(), CompileError> {
    if input.intent.download_mode().is_none() {
        return Ok(());
    }
    match input.device.product().programming_options().not_loadable() {
        None => Ok(()),
        Some(NotLoadableBehavior::DisplayError) => {
            Err(CompileError::not_loadable("the application is not loadable over the bus (DisplayError)"))
        }
        Some(NotLoadableBehavior::SkipSilently) => {
            Err(CompileError::not_loadable("the application is not loadable over the bus (SkipSilently)"))
        }
        Some(NotLoadableBehavior::Unknown(value)) => {
            Err(CompileError::invalid(format!("unknown NotLoadable behavior {value:?}")))
        }
    }
}

/// Hardware without an individual address is never addressed on the bus. A
/// project cannot assign it one, so every commissioning intent targets a
/// device that cannot exist: passive power supplies such as the PS640 family
/// (M-0164_A-0004-11-5CC2) declare `HasIndividualAddress="false"`. Refuse
/// before the product's own download data is inspected, because none of it
/// applies. Loose application XML binds no hardware and is not refused.
fn refuse_unaddressable(input: &ProgrammingInput) -> Result<(), CompileError> {
    if input.device.product().hardware_has_individual_address() == Some(false) {
        return Err(CompileError::no_individual_address(
            "the selected hardware has no individual address and cannot be commissioned over the bus",
        ));
    }
    Ok(())
}

/// Refuse a download the product cannot support, from the one list in
/// [`crate::commissioning::programmability`]. The resolved profile supplies
/// the authored mask's Master Data definition.
fn refuse_unprogrammable(input: &ProgrammingInput, profile: &ResolvedProfile) -> Result<(), CompileError> {
    match crate::commissioning::unprogrammable(input.device.product(), Some(profile.mask_source()), input.intent) {
        Some(reason) => Err(CompileError::unprogrammable(reason)),
        None => Ok(()),
    }
}

impl<'a> ProgramCompiler<'a> {
    /// Compile against a profile the caller resolved for this exact product.
    ///
    /// The profile is the single resolution of this target: the compiler never
    /// resolves again, so the caller cannot audit one profile while compiling
    /// another. A profile resolved for another product or Master Data
    /// document is refused.
    pub(crate) fn new(input: &'a ProgrammingInput, profile: &ResolvedProfile) -> Result<Self, CompileError> {
        let product = input.device.product();
        if profile.product_id.as_deref() != Some(product.id()) {
            return Err(CompileError::invalid(format!(
                "profile {} was resolved for {}, not for product `{}`",
                profile.mask(),
                profile.product_id.as_deref().map_or("no product".to_owned(), |id| format!("product `{id}`")),
                product.id()
            )));
        }
        if product.master_data() != Some(&profile.master_data) {
            return Err(CompileError::invalid(format!(
                "profile {} was resolved from other Master Data than product `{}` is bound to",
                profile.mask(),
                product.id()
            )));
        }
        Self::from_profile(input, profile.clone())
    }

    pub(crate) fn from_profile(
        input: &'a ProgrammingInput,
        mut profile: ResolvedProfile,
    ) -> Result<Self, CompileError> {
        refuse_unaddressable(input)?;
        refuse_not_loadable(input)?;
        refuse_unprogrammable(input, &profile)?;
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

    pub(crate) fn compile(mut self) -> Result<CompiledProgram, CompileError> {
        self.select_controls()?;
        self.build_image()?;
        self.bind_operands()
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

pub(crate) mod credentials;
