//! Compile, preview, and execute KNX device configurations.
//!
//! [`ProgrammingInput::compile`] produces a validated program from supplied facts;
//! [`ProgrammingInput::preview`] builds its desired image without device I/O.
//! [`Commissioner::prepare`] observes the device and binds the program to a
//! bus. [`Commissioner::execute`] consumes that [`PreparedProgram`].

pub use input::facts::{ObservedTarget, ProgrammingFacts};
pub use input::security::{DesiredDataSecurity, ObservedDataSecurity};
/// Requested device configuration and target facts.
pub mod input;

/// Exact target capabilities and metadata.
mod catalog;

/// Internal procedure composition.
mod compiler;

/// Programs bound to live evidence and credentials.
pub(crate) mod runtime;

/// Read-only procedure vocabulary for diagnostics and compatibility tools.
pub mod inspection;

pub mod error;
pub(crate) mod evidence;
pub(crate) mod image;
pub(crate) mod procedure;
pub mod programmability;
pub(crate) mod report;

#[cfg(test)]
mod test_support;

pub use crate::commissioning::compiler::image::{CompiledTableKind, CompiledTableSpan, ProgramImage};
pub use crate::commissioning::error::ImageError;
pub use crate::commissioning::error::{CompileError, CompileErrorKind, OverflowedTable};
pub use crate::commissioning::evidence::{
    DeploymentRecord, DeviceStamp, DifferentialDecision, DifferentialFallback, DifferentialPolicy, DiscoveredDevice,
};
pub use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace, NativeImageRegion, SparseDeviceImage};
pub use crate::commissioning::programmability::{Unprogrammable, mask_unprogrammable, unprogrammable};
pub use runtime::credentials::ManagementAccessOptions;
pub use runtime::prepared::PreparedProgram;

pub use crate::commissioning::catalog::SelectedResource;
#[cfg(feature = "project")]
pub(crate) use crate::commissioning::catalog::validate_for_live_commissioning;
pub use crate::commissioning::compiler::program::{CommissioningApduRequirements, CompiledProgram, ProgramSummary};
pub use crate::commissioning::error::{AssociationTableEntrySizeError, UnknownProfileToken};
pub use crate::commissioning::input::CompileOptions;
pub use crate::commissioning::report::{AddressAssignment, CommissioningSectionOutcome, ExecutionReport};
pub use crate::commissioning::report::{CommissioningEvent, CommissioningStage, ProcedureReport};
pub use crate::commissioning::runtime::commissioner::{
    Commissioner, CommissionerOptions, CommissioningCancellation, CommissioningObserver, CommissioningVeto,
    PreparationOptions,
};
pub use catalog::profile::{
    AssociationTableEntrySize, ImageRequirement, ManagementModel, MaskIdentity, ObjectSelector, Occurrence,
    ProcedureId, ProfileDisposition, ProfileSelection, ProfileVariant, ReadAccess, ResolvedProfile,
    ResourceAccessRights, ResourceFlavour, ResourceId, ResourceManagementStyle, VariantHint, WriteAccess,
};
pub use compiler::credentials::{CredentialEffects, CredentialTransition};
pub use error::{
    CleanupFailure, CleanupOperation, CommissioningError, Diagnostic, DiagnosticKind, LearnedTarget, MutationStatus,
    Result, TransportCause,
};
pub use input::{
    CommissioningIntent, DownloadMode, ProgramSections, ProgrammingInput, ProgrammingModePolling, TargetSelection,
    UnloadMode,
};

pub use report::effects::ExecutionEffects;

/// Crate-internal resolution primitives for unit tests, which resolve
/// against loose fixture documents and unbound products.
#[cfg(test)]
pub(crate) mod catalog_testing {
    pub(crate) use super::catalog::profile::{ProfileDiscovery, ProfileSelection, VariantHint};
    pub(crate) use super::catalog::{requires_management_descriptor_01, resolve_profile as resolve_catalog_profile};
    pub(crate) use zweidraehte_ets_files::MasterData;

    /// Resolve a selection for the input's own product, then compile or
    /// preview against that one profile, as every non-test caller does.
    pub(crate) trait ResolveAndCompile {
        fn compile_selection(
            &self,
            selection: &ProfileSelection,
        ) -> Result<super::CompiledProgram, super::CompileError>;
        fn preview_selection(&self, selection: &ProfileSelection) -> Result<super::ProgramImage, super::CompileError>;
    }

    impl ResolveAndCompile for super::ProgrammingInput {
        fn compile_selection(
            &self,
            selection: &ProfileSelection,
        ) -> Result<super::CompiledProgram, super::CompileError> {
            self.compile(&self.device().resolve_profile(selection)?)
        }

        fn preview_selection(&self, selection: &ProfileSelection) -> Result<super::ProgramImage, super::CompileError> {
            self.preview(&self.device().resolve_profile(selection)?)
        }
    }

    /// Parse a fixture document as a shared handle.
    pub(crate) fn parse_master_data(
        xml: &str,
    ) -> Result<std::sync::Arc<MasterData>, zweidraehte_ets_files::MasterDataError> {
        xml.parse().map(std::sync::Arc::new)
    }
}
