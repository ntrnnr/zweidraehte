use std::collections::BTreeMap;
use std::path::PathBuf;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::parser::{ParseError, parse_project};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectDeviceId(pub String);

impl std::fmt::Display for ProjectDeviceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetId(pub String);

impl std::fmt::Display for NetId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Medium {
    Tp1,
    Rf,
    Ip,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetSecurityPolicy {
    Plain,
    #[default]
    Automatic,
    Authentication,
    AuthenticationConfidentiality,
}

/// Desired KNX Data Secure application state for one device.
///
/// Product capability is deliberately not authored here: the referenced
/// MTXML is authoritative for whether the application supports Security IO.
/// This value records whether that capability is enabled in this project.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DataSecureMode {
    #[default]
    Disabled,
    Enabled,
}

impl DataSecureMode {
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectPriority {
    System,
    High,
    Alarm,
    Low,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectFlagOverrides {
    pub communication: Option<bool>,
    pub read: Option<bool>,
    pub write: Option<bool>,
    pub transmit: Option<bool>,
    pub update: Option<bool>,
    pub read_on_init: Option<bool>,
    pub priority: Option<ObjectPriority>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRole {
    Primary,
    Additional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMembership {
    pub net: NetId,
    pub role: MembershipRole,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectObjectConfiguration {
    pub com_object: u16,
    pub memberships: Vec<ObjectMembership>,
    pub flags: ObjectFlagOverrides,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    Integer(i64),
    Float(f64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParameterAssignment {
    pub id: String,
    pub value: ParamValue,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductReference {
    Local(PathBuf),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectDevice {
    pub id: ProjectDeviceId,
    pub name: Option<String>,
    pub area: u8,
    pub line: u8,
    pub medium: Medium,
    pub product: ProductReference,
    /// Catalogue product selected inside a `.knxprod`, when available.
    pub catalog_product: Option<String>,
    /// Application program selected inside a multi-program `.knxprod`.
    /// Loose MTXML files and single-program archives leave this unset.
    pub application_program: Option<String>,
    /// Preferred product-editor translation. This is host presentation state
    /// and has no effect on the bytes compiled for the device.
    pub language: Option<String>,
    pub address: IndividualAddress,
    pub serial: Option<[u8; 6]>,
    pub max_apdu: Option<u16>,
    pub data_secure: DataSecureMode,
    pub parameters: Vec<ParameterAssignment>,
    pub objects: BTreeMap<u16, ProjectObjectConfiguration>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Net {
    pub id: NetId,
    /// Human-readable label. The stable identifier remains the key and
    /// mutable-state namespace, so changing this does not orphan security
    /// material or rewrite memberships.
    pub name: Option<String>,
    pub address: GroupAddress,
    /// Canonical main/sub DPT spelling, for example `1.001`.
    pub dpt: String,
    pub security: NetSecurityPolicy,
    /// Exact policy token, retained so an editor can change security without
    /// normalising the declaration or discarding its comments.
    pub security_span: SourceSpan,
    /// Complete `security ...` declaration, used as the insertion anchor for
    /// a name added to an existing losslessly parsed net.
    pub(crate) security_decl_span: SourceSpan,
    /// Quoted name token, when authored, so a rename changes no surrounding
    /// comments or formatting.
    pub(crate) name_span: Option<SourceSpan>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSender {
    pub id: String,
    pub address: IndividualAddress,
    /// For unmanaged devices this is an operator assertion: `enabled`
    /// states that the sender both supports and currently uses Data Secure.
    pub data_secure: DataSecureMode,
    pub nets: Vec<NetId>,
    pub span: SourceSpan,
}

/// Parsed desired state plus its unchanged source text.
///
/// Keeping the source is intentional: parsing and checking a project is
/// byte-for-byte lossless. Focused editor commands can later replace the
/// recorded spans without normalising unrelated comments or whitespace.
#[derive(Debug, Clone)]
pub struct AuthoredProject {
    pub(crate) source: String,
    pub(crate) project_path: Option<PathBuf>,
    pub nets: BTreeMap<NetId, Net>,
    pub devices: BTreeMap<ProjectDeviceId, ProjectDevice>,
    pub external_senders: BTreeMap<String, ExternalSender>,
    pub(crate) areas: Vec<AuthoredArea>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthoredArea {
    pub number: u8,
    pub span: SourceSpan,
    pub lines: Vec<AuthoredLine>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthoredLine {
    pub number: u8,
    pub medium: Medium,
    pub span: SourceSpan,
}

impl AuthoredProject {
    pub fn parse(source: impl Into<String>) -> Result<Self, ParseError> {
        parse_project(source.into(), None)
    }

    pub(crate) fn parse_at(source: String, path: PathBuf) -> Result<Self, ParseError> {
        parse_project(source, Some(path))
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn project_path(&self) -> Option<&std::path::Path> {
        self.project_path.as_deref()
    }

    pub fn project_directory(&self) -> Option<&std::path::Path> {
        self.project_path.as_deref().and_then(std::path::Path::parent)
    }

    pub fn resolve_product_path(&self, device: &ProjectDevice) -> Option<PathBuf> {
        let directory = self.project_directory()?;
        match &device.product {
            ProductReference::Local(path) => Some(directory.join(path)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub message: String,
    pub span: SourceSpan,
}
