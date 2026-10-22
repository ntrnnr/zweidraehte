//! Target-independent desired configuration for one device.
//!
//! Product-specific parsing resolves into this model. Key bytes and
//! mask-specific table positions deliberately do not: the host project store
//! and future installation frontends can feed the same compiler boundary
//! without learning either concern.

use std::collections::{BTreeMap, BTreeSet};

use zweidraehte_project::{
    CouplerRoutingPolicy, DomainAddress, IpAssignment, IpSecurityIntent, ProjectInstallationId, RfDeviceMode,
};
use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use zweidraehte_ets_files::product::ComObjectDef;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRole {
    Primary,
    Additional,
}

/// One group address linked to one group object.
///
/// A device's memberships list every primary link before any additional one.
/// [`super::MaterializedDevice`] establishes that order on construction; the
/// association table encodes links in exactly this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMembership {
    pub group_address: GroupAddress,
    /// The group object number (ASAP) as the product database numbers it.
    /// The selected association-table codec checks its wire width.
    pub com_object: u16,
    pub role: MembershipRole,
}

impl ObjectMembership {
    /// The link that defines the object's sending group address.
    pub fn primary(group_address: GroupAddress, com_object: u16) -> Self {
        Self { group_address, com_object, role: MembershipRole::Primary }
    }

    /// A further group address the object listens to.
    pub fn additional(group_address: GroupAddress, com_object: u16) -> Self {
        Self { group_address, com_object, role: MembershipRole::Additional }
    }
}

/// Installation intent for one group address. `Automatic` is resolved
/// only after the selected key sources are available.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NetSecurityPolicy {
    Plain,
    #[default]
    Automatic,
    Authentication,
    AuthenticationConfidentiality,
}

/// Effective typed value consumed by a product load-procedure `choose`.
///
/// These values remain distinct from [`EncodedParameter`], which is already
/// encoded for its target storage. A procedure branches on the semantic value
/// of the referenced ETS control, including a ref-specific default, rather
/// than on the bytes eventually patched into a base parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcedureParameterValue {
    Signed(i64),
    Unsigned(u64),
    Boolean(bool),
    Text(String),
    Bytes(Vec<u8>),
}

/// Post-evaluation state of one parameter referenced by a product load
/// procedure.
///
/// Activity is explicit because an inactive selector has no value and skips
/// the whole `choose`. Omitting a selector and falling
/// back to its product default would therefore compile a different procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureParameter {
    pub active: bool,
    pub value: ProcedureParameterValue,
}

pub use zweidraehte_ets_files::product::{MaterializedModule, MaterializedModuleArgument};

/// Exact group-routing image requested for one line or backbone coupler.
///
/// Filter addresses are derived from the complete active project topology,
/// not copied from one device's application program. Route-all and block-all
/// policies deliberately retain an empty set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupFilterConfiguration {
    pub policy: CouplerRoutingPolicy,
    pub addresses: BTreeSet<GroupAddress>,
}

/// Complete non-secret standard KNX/IP Parameter Object intent for a product
/// whose `ApplicationProgram/@IPConfig` is `Tool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolManagedIpConfiguration {
    pub project_installation_id: ProjectInstallationId,
    pub assignment: IpAssignment,
    pub routing_multicast_address: [u8; 4],
    pub multicast_ttl: u8,
    pub friendly_name: String,
    pub additional_individual_addresses: Vec<IndividualAddress>,
    pub security: Option<IpSecurityIntent>,
    pub password_users: Vec<std::num::NonZeroU8>,
}

/// Non-secret topology and device-medium values required by medium and router masks.
///
/// The open-medium domain belongs to the authored RF line, while RF device
/// mode belongs to the physical device. KNX/IP values use the distinct `ip`
/// aggregate. Keeping these values beside the structural configuration lets the
/// generic image compiler use project topology without leaking it into the
/// compiler input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopologyConfiguration {
    pub domain_address: Option<DomainAddress>,
    pub rf_device_mode: Option<RfDeviceMode>,
    pub group_filter: Option<GroupFilterConfiguration>,
    pub ip: Option<ToolManagedIpConfiguration>,
}

/// Authored security choices, before key sources are consulted.
///
/// Resolving key material consumes this intent: a
/// [`super::MaterializedDevice<super::Keyed>`] holds the resolved
/// [`super::ResolvedKeyMaterial`] instead, so the two cannot disagree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityIntent {
    /// Serial number that binds the device's FDSK and serial-number addressing.
    pub serial_number: Option<[u8; 6]>,
    /// Project-selected application-security state. Product capability is
    /// checked separately before lowering or touching the bus.
    pub data_secure_enabled: bool,
    pub net_security: BTreeMap<GroupAddress, NetSecurityPolicy>,
}

/// Installation choices supplied alongside checked product evaluation.
///
/// Encoded parameters and effective objects come exclusively from that
/// evaluation ([`EncodedConfiguration`]); callers cannot inject a second
/// product image through this input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationConfiguration {
    pub individual_address: IndividualAddress,
    /// Group links in any order; primary links are encoded first.
    pub object_memberships: Vec<ObjectMembership>,
    pub topology: TopologyConfiguration,
    /// Optional project-authored ceiling applied after live interface and
    /// target capability discovery. It can reduce chunks for a problematic
    /// target but cannot enable long frames. `None` leaves capability
    /// negotiation authoritative instead of silently forcing standard frames.
    pub max_apdu: Option<u16>,
    pub security: SecurityIntent,
}

impl InstallationConfiguration {
    /// An installation at `individual_address` with no links, topology,
    /// APDU ceiling or security choices.
    pub fn new(individual_address: IndividualAddress) -> Self {
        Self {
            individual_address,
            object_memberships: Vec::new(),
            topology: TopologyConfiguration::default(),
            max_apdu: None,
            security: SecurityIntent::default(),
        }
    }
}

/// The product-side result of evaluating one configured device.
///
/// [`super::MaterializedDevice::from_evaluated`] encodes these from a checked
/// product evaluation. Expert adapters holding an evaluation made elsewhere
/// supply them to [`super::MaterializedDevice::from_parts`] instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncodedConfiguration {
    /// Stored parameter values in write order; a later entry for the same
    /// storage overwrites an earlier one.
    pub parameters: Vec<EncodedParameter>,
    /// The effective group-object roster.
    pub com_objects: Vec<ComObjectDef>,
    /// Typed values for the product parameters referenced by load-procedure
    /// choices. Storage bytes alone cannot preserve a `ParameterRef` override
    /// or distinguish numeric, text, Boolean, and opaque comparisons.
    pub procedure_parameters: BTreeMap<String, ProcedureParameter>,
}

/// A parameter value encoded for its target storage.
///
/// Distinct from the typed `zweidraehte_ets_files::runtime::model::ParameterValue`
/// an editor holds: this is the byte image the compiler patches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedParameter {
    /// The parameter's full MTXML identifier.
    pub id: String,
    /// Raw bytes in device-memory order. For a `BinaryValue` restriction,
    /// an empty vector denotes native null: own the declared bytes while
    /// retaining their seed. An explicitly empty binary payload is padded
    /// to the declared width during product evaluation instead.
    pub value: Vec<u8>,
}
