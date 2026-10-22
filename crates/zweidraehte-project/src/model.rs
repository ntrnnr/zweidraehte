//! Semantic model of the human-authored project document.
//!
//! These types retain source spans for diagnostics while expressing topology,
//! products, parameters, group memberships, and security intent independently
//! of product XML and mutable commissioning state.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::num::NonZeroU8;
use std::str::FromStr;

use thiserror::Error;
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

/// The authored name of one device, unique within a project.
///
/// The field is private so every identifier satisfies the project grammar's
/// `identifier` rule: an ASCII letter or `_`, followed by ASCII letters,
/// digits, `_` or `-`. An identifier that renders into a project document
/// therefore parses back to the same device.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectDeviceId(String);

/// A device name that the project grammar cannot express.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("`{0}` is not a project identifier (start with a letter or `_`, then letters, digits, `_` or `-`)")]
pub struct InvalidDeviceId(String);

impl ProjectDeviceId {
    pub fn new(id: impl Into<String>) -> Result<Self, InvalidDeviceId> {
        let id = id.into();
        let mut characters = id.chars();
        let starts = characters.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_');
        if starts && characters.all(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '-')) {
            Ok(Self(id))
        } else {
            Err(InvalidDeviceId(id))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl FromStr for ProjectDeviceId {
    type Err = InvalidDeviceId;

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Self::new(id)
    }
}

impl std::fmt::Display for ProjectDeviceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for ProjectDeviceId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// Ordering and hashing are those of the wrapped string, so maps keyed by
// device id can be queried with a borrowed name.
impl std::borrow::Borrow<str> for ProjectDeviceId {
    fn borrow(&self) -> &str {
        &self.0
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

/// Open-medium or routing domain shared by one authored line.
///
/// Keeping the medium in the type prevents the commissioning compiler from
/// confusing the six-octet RF domain with the four-octet KNX/IP multicast
/// address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DomainAddress {
    Rf([u8; 6]),
    /// KNX/IP routing multicast address (the four-octet IP domain).
    Ip([u8; 4]),
}

impl std::fmt::Display for DomainAddress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rf(value) => {
                for (index, byte) in value.iter().enumerate() {
                    if index != 0 {
                        formatter.write_char(':')?;
                    }
                    write!(formatter, "{byte:02X}")?;
                }
                Ok(())
            }
            Self::Ip(value) => write!(formatter, "{}.{}.{}.{}", value[0], value[1], value[2], value[3]),
        }
    }
}

/// KNX/IP PID 51, split into its two semantic fields instead of exposing the
/// packed wire integer to project authors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectInstallationId {
    project: u16,
    installation: u8,
}

impl ProjectInstallationId {
    pub const fn new(project: u16, installation: u8) -> Option<Self> {
        if project <= 0x0fff && installation <= 0x0f { Some(Self { project, installation }) } else { None }
    }

    pub const fn encode(self) -> u16 {
        (self.project << 4) | self.installation as u16
    }

    pub const fn project(self) -> u16 {
        self.project
    }

    pub const fn installation(self) -> u8 {
        self.installation
    }
}

impl std::fmt::Display for ProjectInstallationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}", self.project, self.installation)
    }
}

/// Shared values of one authored KNX/IP routing backbone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpLineConfiguration {
    pub project_installation_id: ProjectInstallationId,
    pub multicast_latency_tolerance_ms: Option<u16>,
    pub sync_latency_fraction: Option<u8>,
}

/// Desired configured IP assignment method (PID 55).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAssignment {
    AutomaticDhcp,
    Fixed { address: [u8; 4], subnet_mask: [u8; 4], default_gateway: [u8; 4] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpServiceSecurity {
    Plain,
    Secure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpTunnellingUserBinding {
    pub user_id: NonZeroU8,
    pub address_index: u8,
}

/// Public IP Secure policy. Key bytes and password hashes deliberately live
/// in the project key store and never enter this inspectable topology value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSecurityIntent {
    pub routing: IpServiceSecurity,
    pub device_management: IpServiceSecurity,
    pub tunnelling: IpServiceSecurity,
    pub multicast_latency_tolerance_ms: u16,
    pub sync_latency_fraction: u8,
    pub tunnelling_users: Vec<IpTunnellingUserBinding>,
}

/// Device-local portion of tool-managed KNX/IP configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpDeviceConfiguration {
    pub assignment: IpAssignment,
    pub multicast_ttl: u8,
    pub friendly_name: String,
    pub additional_individual_addresses: Vec<IndividualAddress>,
    pub security: Option<IpSecurityIntent>,
    /// User IDs whose pre-derived 16-byte password hashes must be resolved
    /// from the private project key store.
    pub password_users: Vec<NonZeroU8>,
}

/// RF link-layer mode selected for one device.
///
/// This is the typed project value written to RF Medium Object PID 51. It is
/// a physical-device property, independent of the domain address shared by the
/// authored RF line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RfDeviceMode {
    Ready,
    Multi,
}

/// Routing behavior configured on an address-zero topology coupler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CouplerRoutingPolicy {
    Filter,
    RouteAll,
    BlockAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CouplerRole {
    Line,
    Backbone,
}

/// Public, span-free view of one authored topology line.
///
/// Parser spans remain private editor state. Commissioning consumers receive
/// only the values which can affect a device image or procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineTopology {
    pub area: u8,
    pub line: u8,
    pub medium: Medium,
    pub domain: Option<DomainAddress>,
    pub ip: Option<IpLineConfiguration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TopologyError {
    #[error("the project has no device `{0}`")]
    UnknownDevice(ProjectDeviceId),
    #[error("area {area} is missing from the authored topology")]
    MissingArea { area: u8 },
    #[error("area {area} is declared more than once")]
    AmbiguousArea { area: u8 },
    #[error("area {area}, line {line} is missing from the authored topology")]
    MissingLine { area: u8, line: u8 },
    #[error("area {area}, line {line} is declared more than once")]
    AmbiguousLine { area: u8, line: u8 },
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

const SHA256_BYTES: usize = 32;
const PACKAGE_DIGEST_PREFIX: &str = "sha256:";

/// SHA-256 identity of the exact `.knxprod` bytes in the project-local store.
///
/// Project source accepts only the canonical text form. Store directory names
/// are a persistence detail and therefore cannot leak into the authored
/// selector.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectPackageId([u8; SHA256_BYTES]);

impl ProjectPackageId {
    pub const fn from_bytes(bytes: [u8; SHA256_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SHA256_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for ProjectPackageId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::fmt::Display for ProjectPackageId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(PACKAGE_DIGEST_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ProjectPackageId {
    type Err = ProjectPackageIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hexadecimal =
            value.strip_prefix(PACKAGE_DIGEST_PREFIX).ok_or_else(|| ProjectPackageIdError(value.to_owned()))?;
        if hexadecimal.len() != SHA256_BYTES * 2
            || !hexadecimal.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ProjectPackageIdError(value.to_owned()));
        }

        let mut digest = [0; SHA256_BYTES];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hexadecimal[index * 2..index * 2 + 2], 16).expect("validated hexadecimal byte");
        }
        Ok(Self(digest))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid project package ID {0:?}; expected canonical sha256:<64 lowercase hexadecimal digits>")]
pub struct ProjectPackageIdError(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProductReference {
    /// One exact catalogue leaf from one immutable package revision.
    Package { package: ProjectPackageId, catalog_item: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProjectDevice {
    pub id: ProjectDeviceId,
    pub name: Option<String>,
    /// Whether automatic project operations and topology derivation include
    /// this device. Explicit single-device operations may still select it.
    pub active: bool,
    pub area: u8,
    pub line: u8,
    pub medium: Medium,
    pub product: ProductReference,
    pub address: IndividualAddress,
    /// Desired RF Medium Object PID 51 value for this physical device.
    ///
    /// Some RF profiles do not expose that property, so project parsing keeps
    /// this optional and profile-aware compilation decides when it is required.
    pub rf_mode: Option<RfDeviceMode>,
    /// Tool-owned KNX/IP configuration. Product-aware lowering decides from
    /// `ApplicationProgram/@IPConfig` whether this standard state is used.
    pub ip: Option<IpDeviceConfiguration>,
    /// Explicit routing behavior for a line or backbone coupler. Ordinary
    /// devices leave this absent; address-zero devices must declare it.
    pub routing: Option<CouplerRoutingPolicy>,
    pub serial: Option<[u8; 6]>,
    pub(crate) address_decl_span: SourceSpan,
    pub(crate) rf_mode_span: Option<SourceSpan>,
    pub(crate) serial_decl_span: Option<SourceSpan>,
    pub(crate) serial_value_span: Option<SourceSpan>,
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

impl ProjectDevice {
    /// Topology role implied by the standardized address-zero convention.
    pub fn coupler_role(&self) -> Option<CouplerRole> {
        if self.address.device() != 0 {
            return None;
        }

        if self.address.line() == 0 { Some(CouplerRole::Backbone) } else { Some(CouplerRole::Line) }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_ids_follow_the_grammar_identifier_rule() {
        for valid in ["button", "_spare", "ta-10-2", "Relay_2"] {
            assert_eq!(valid.parse::<ProjectDeviceId>().expect("grammar identifier").as_str(), valid);
        }
        for invalid in ["", "2nd-button", "-button", "living room", "küche"] {
            assert!(ProjectDeviceId::new(invalid).is_err(), "{invalid:?} must be rejected");
        }
    }

    #[test]
    fn package_ids_round_trip_through_the_canonical_project_spelling() {
        let bytes = std::array::from_fn(|index| index as u8);
        let id = ProjectPackageId::from_bytes(bytes);
        let rendered = id.to_string();

        assert_eq!(rendered, "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        assert_eq!(rendered.parse::<ProjectPackageId>().expect("canonical digest parses"), id);
        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(format!("{id:?}"), rendered);
    }

    #[test]
    fn package_ids_reject_noncanonical_source_spellings() {
        for value in [
            "sha256:00",
            "sha256-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "SHA256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "sha256:000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ] {
            assert!(value.parse::<ProjectPackageId>().is_err(), "{value:?} must be rejected");
        }
    }
}
