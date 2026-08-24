//! Host-side representation of a KNX installation.
//!
//! [`AuthoredProject`] is the human-owned desired state. [`ProjectKeyStore`]
//! keeps secret material out of that document, while [`ProjectStore`] owns the
//! mutable state which changes when secure telegrams are sent or devices are
//! programmed. Firmware crates never depend on this crate.

mod impact;
mod keys;
mod model;
mod parser;
mod render;
mod state;
mod store;
mod validate;

pub use impact::{ImpactReason, ProjectCommand, ProjectImpact};
pub use keys::{
    DecodedFdsk, KeyEncoding, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyMaterialStore, KeyMaterialTransaction,
    KeyMetadata, KeyOrigin, KeyRecord, KeyScope, KeyState, KeyStoreError, ProjectKeyStore, SecretBytes, format_serial,
    parse_fdsk, parse_key16, parse_serial,
};
pub use model::{
    AuthoredProject, Diagnostic, DiagnosticLevel, ExternalSender, Medium, MembershipRole, Net, NetId,
    NetSecurityPolicy, ObjectFlagOverrides, ObjectMembership, ObjectPriority, ParamValue, ParameterAssignment,
    ProductReference, ProjectDevice, ProjectDeviceId, ProjectObjectConfiguration, SourceSpan,
};
pub use parser::ParseError;
pub use render::{DraftNet, ProjectDeviceDraft, RenderError, render_single_device_project};
pub use state::{DeploymentFingerprints, DeviceSequenceObservation, MutableProjectState, ProjectEvent, SenderIdentity};
pub use store::{ProjectLock, ProjectStore, ProjectStoreError};
pub use validate::{Download, ValidatedProject, ValidationError};
