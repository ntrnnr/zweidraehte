//! Select one source, resolve its static choices, and parse its typed controls.
//! Automatic preview can defer source selection while building the desired image.

use crate::commissioning::error::CompileError;
mod demand;
pub(crate) mod sources;
pub(in crate::commissioning) mod syntax;

use crate::commissioning::input::{CommissioningIntent, DownloadMode, ProgramSections, UnloadMode};
use crate::commissioning::procedure::RestartKind;

use crate::commissioning::compiler::ProgramCompiler;
use crate::commissioning::compiler::features::topology::validate_network_topology;
use demand::required_image_ranges;
use sources::select_procedure;

impl ProgramCompiler<'_> {
    pub(in crate::commissioning) fn select_controls(&mut self) -> Result<(), CompileError> {
        let resolved = &*self;
        let profile = &resolved.profile;
        let device = &resolved.input.device;
        let product = device.product();
        let configuration = device.configuration();
        let intent = resolved.input.intent;
        let options = &resolved.input.options;
        let automatic = intent.download_mode() == Some(DownloadMode::Automatic);
        if !automatic && options.automatic_sections.is_some() {
            return Err(CompileError::invalid("automatic sections were supplied for a non-automatic operation"));
        }
        let recipes = if automatic && options.automatic_sections.is_none() {
            // Preview can build the full desired image before stamp comparison
            // chooses scope. Executable compilation requires that later decision.
            RecipeSet::Automatic
        } else {
            match (intent, resolved.restart_kind) {
                (CommissioningIntent::AssignAddress, _) => RecipeSet::AddressOnly,
                (CommissioningIntent::Unload(mode), RestartKind::Confirmed) => RecipeSet::ConfirmedUnload(mode),
                _ => {
                    let (request, input) = select_procedure(resolved)?;
                    let mut procedure = crate::commissioning::compiler::binding::procedure::parse(&input)?;
                    if request.procedure_type == "Load" {
                        procedure.program.stamp_output =
                            crate::commissioning::catalog::rules::resolved_download_stamp_output(
                                profile,
                                input.download_stamps,
                            )?;
                    }
                    RecipeSet::Exact { request, procedure: Box::new(procedure) }
                }
            }
        };
        let unload_required_ranges = if let RecipeSet::Exact { procedure, .. } = &recipes
            && matches!(intent, CommissioningIntent::Unload(_))
        {
            required_image_ranges(procedure, product)?
        } else {
            Vec::new()
        };

        // Address assignment and application download both carry the line's
        // medium configuration. Validate it even when this intent deliberately
        // produces an empty application image; execution must never discover a
        // missing or incompatible domain only after assigning the IA.
        if matches!(intent, CommissioningIntent::AssignAddress) {
            validate_network_topology(profile, &configuration.topology)?;
        }

        let feature_sections = if automatic {
            ProgramSections::all()
        } else {
            recipes
                .request()
                .filter(|request| request.procedure_type == "Load")
                .map_or(ProgramSections::empty(), |request| request.applicability.sections)
        };
        self.recipes = recipes;
        self.unload_required_ranges = unload_required_ranges;
        self.feature_sections = feature_sections;
        Ok(())
    }
}

/// One selected program, or an intent which needs no authored program yet.
#[derive(Debug)]
pub(crate) enum RecipeSet {
    AddressOnly,
    ConfirmedUnload(UnloadMode),
    Exact {
        request: ProcedureRequest,
        procedure: Box<crate::commissioning::compiler::binding::procedure::ParsedProcedure>,
    },
    Automatic,
}

impl RecipeSet {
    pub(crate) fn request(&self) -> Option<ProcedureRequest> {
        match self {
            Self::Exact { request, .. } => Some(*request),
            Self::AddressOnly | Self::ConfirmedUnload(_) | Self::Automatic => None,
        }
    }
}

/// Requested source family and semantic applicability before source selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcedureRequest {
    pub(crate) procedure_type: &'static str,
    pub(crate) subtype: &'static str,
    pub(crate) applicability: ProcedureApplicability,
}

/// How the selected mask and product define one procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureComposition {
    /// The selected Master Data procedure is complete.
    Default,

    /// The product procedure replaces the Master Data procedure.
    ProductOwned,

    /// Product fragments are inserted at matching `LdCtrlMerge` controls.
    Merged,
}

/// Which semantic part of the application the selected procedure updates.
///
/// The caller supplies the selected sections and automatic-control policy.
/// Partial downloads transform automatic machine controls using the resolved
/// object type and the ordered segment-write setting during source parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcedureApplicability {
    pub full: bool,
    pub automatic: bool,
    pub sections: ProgramSections,
}

#[cfg(test)]
impl ProcedureApplicability {
    pub const fn full() -> Self {
        Self { full: true, automatic: true, sections: ProgramSections::all() }
    }

    pub const fn partial(sections: ProgramSections) -> Self {
        Self { full: false, automatic: true, sections }
    }
}
