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
    pub address: IndividualAddress,
    pub serial: Option<[u8; 6]>,
    pub max_apdu: Option<u16>,
    pub parameters: Vec<ParameterAssignment>,
    pub objects: BTreeMap<u16, ProjectObjectConfiguration>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Net {
    pub id: NetId,
    pub address: GroupAddress,
    /// Canonical main/sub DPT spelling, for example `1.001`.
    pub dpt: String,
    pub security: NetSecurityPolicy,
    /// Exact policy token, retained so an editor can change security without
    /// normalising the declaration or discarding its comments.
    pub security_span: SourceSpan,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSender {
    pub id: String,
    pub address: IndividualAddress,
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
