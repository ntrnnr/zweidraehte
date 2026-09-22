//! Compile, preview, and execute KNX device configurations.
//!
//! [`ProgrammingInput::compile`] produces a validated program from supplied facts;
//! [`ProgrammingInput::preview`] builds its desired image without device I/O.
//! [`Commissioner::prepare`] observes the device and binds the program to a
//! bus. [`Commissioner::execute`] consumes that [`PreparedProgram`].

pub use crate::bus::access::ManagementCredential;
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
pub(crate) mod report;

#[cfg(test)]
mod test_support;

pub use crate::commissioning::compiler::image::{CompiledTableKind, CompiledTableSpan, ProgramImage};
pub use crate::commissioning::error::ImageError;
pub use crate::commissioning::error::{CompileError, CompileErrorKind};
pub use crate::commissioning::evidence::{
    DeploymentRecord, DeviceStamp, DifferentialDecision, DifferentialFallback, DifferentialPolicy, DiscoveredDevice,
};
pub use crate::commissioning::image::{ImageLocation, ImageSegment, ImageSpace, NativeImageRegion, SparseDeviceImage};
pub use crate::commissioning::procedure::RestartKind;
pub use crate::commissioning::procedure::operands::StandardMemoryService;
pub use runtime::credentials::ManagementAccessOptions;
pub use runtime::prepared::PreparedProgram;

pub use crate::commissioning::catalog::SelectedResource;
pub use crate::commissioning::compiler::program::{CommissioningApduRequirements, CompiledProgram, ProgramSummary};
pub use crate::commissioning::error::{AssociationTableEntrySizeError, UnknownProfileToken};
pub use crate::commissioning::input::CompileOptions;
pub use crate::commissioning::report::{AddressAssignment, CommissioningSectionOutcome, ExecutionReport};
pub use crate::commissioning::report::{CommissioningEvent, CommissioningStage, ProcedureReport};
pub use crate::commissioning::runtime::commissioner::{
    Commissioner, CommissionerOptions, CommissioningCancellation, PreparationOptions,
};
pub use catalog::profile::{
    AssociationTableEntrySize, ImageRequirement, ManagementModel, MaskIdentity, ObjectSelector, Occurrence,
    ProcedureId, ProfileDiscovery, ProfileDisposition, ProfileRequest, ProfileSelection, ProfileVariant, ReadAccess,
    ResolvedProfile, ResourceAccessRights, ResourceFlavour, ResourceId, ResourceManagementStyle, VariantHint,
    WriteAccess,
};
pub use catalog::{
    LoadedProgrammingCatalog, ProgrammingCatalog, ProgrammingCatalogLoadError, ProgrammingCatalogLoadRequest,
    ProgrammingCatalogProvenance, ProgrammingCatalogSource,
};
pub use compiler::secrets::{CredentialTransition, SecretPayloadReference};
pub use error::{
    CleanupFailure, CleanupOperation, CommissioningError, Diagnostic, DiagnosticKind, LearnedTarget, MutationStatus,
    Result, TransportCause,
};
pub use input::{
    CommissioningIntent, DownloadMode, ProgramSections, ProgrammingInput, ProgrammingModePolling, TargetSelection,
    UnloadMode,
};

pub use report::effects::ExecutionEffects;
