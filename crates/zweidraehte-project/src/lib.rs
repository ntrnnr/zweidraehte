//! Host-side representation of a KNX installation.
//!
//! Installation values, key metadata and commissioning evidence are available
//! without parsing or persistence. They keep one shared identity and encoding
//! across the compiler, project storage and frontends.
//!
//! - No default features: shared values and their serialization contracts.
//! - `syntax`: lossless `AuthoredProject` parsing, rendering and validation.
//! - `storage` (default, includes `syntax`): `ProjectKeyStore`, read-only
//!   `ProjectStore` snapshots and `ProjectWriter` exclusion for credential edits
//!   and durable state changed by secure telegrams and programming.
//!
//! For a consumer which only handles values:
//!
//! ```toml
//! [dependencies]
//! zweidraehte-project = { version = "0.1", default-features = false }
//! ```
//!
//! Firmware crates never depend on this crate.

// Compatibility path for existing project consumers; ownership lives below storage.
pub use zweidraehte_util::secret::{SecretBytes, SecretLengthError};

mod keys;
mod model;
mod state;

#[cfg(feature = "storage")]
mod storage;
#[cfg(feature = "syntax")]
mod syntax;

pub use keys::{
    KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMetadata, KeyOrigin, KeyRecord, KeyScope, KeyState, format_serial,
};
pub use model::{
    CouplerRole, CouplerRoutingPolicy, DataSecureMode, Diagnostic, DiagnosticLevel, DomainAddress, ExternalSender,
    IpAssignment, IpDeviceConfiguration, IpLineConfiguration, IpSecurityIntent, IpServiceSecurity,
    IpTunnellingUserBinding, LineTopology, Medium, MembershipRole, Net, NetId, NetSecurityPolicy, ObjectFlagOverrides,
    ObjectMembership, ObjectPriority, ParamValue, ParameterAssignment, ProductReference, ProjectDevice,
    ProjectDeviceId, ProjectInstallationId, ProjectObjectConfiguration, ProjectPackageId, ProjectPackageIdError,
    RfDeviceMode, SourceSpan, TopologyError,
};
pub use state::{
    COMMISSIONING_DEPLOYMENT_RECORD_VERSION, CommissioningAssociationEntrySize, CommissioningDeploymentRecord,
    CommissioningImageSegment, CommissioningOutcome, CommissioningProfileVariant, CredentialCommitment,
    DesiredProgrammingManifest, DeviceDeploymentEvidence, DeviceProgrammingStatus, DeviceSequenceObservation,
    DeviceStamp, ImageSpace, MaskIdentity, MutableProjectState, ObjectSelector, ObservedPropertyType, Occurrence,
    ProgrammingManifest, ProgrammingSection, ProjectEvent, ResourceId, SenderIdentity, semantic_fingerprint,
};
#[cfg(feature = "storage")]
pub use storage::{
    DecodedFdsk, KeyMaterialSource, KeyMaterialStore, KeyMaterialTransaction, KeyStoreError, ProjectKeyStore,
    ProjectKeys, ProjectStore, ProjectStoreError, ProjectWriter, parse_fdsk, parse_key16, parse_serial,
};
#[cfg(feature = "syntax")]
pub use syntax::{
    AuthoredProject, Download, DraftNet, ParseError, ProjectDeviceDraft, RenderError, ValidatedProject,
    ValidationError, render_single_device_project,
};
