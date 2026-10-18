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

use super::ConfigurationResult as Result;
use zweidraehte_ets_files::product::ComObjectDef;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub desired_address: IndividualAddress,
    pub serial_number: Option<[u8; 6]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRole {
    Primary,
    Additional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMembership {
    pub group_address: GroupAddress,
    pub com_object: u16,
    pub role: MembershipRole,
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
/// These values remain distinct from [`ParameterValue`], which is already
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

/// Download-relevant desired state, before a mask backend lays it out.
#[derive(Debug, Clone)]
pub struct DeviceConfiguration {
    pub identity: DeviceIdentity,
    /// Project-selected application-security state. Product capability is
    /// checked separately before lowering or touching the bus.
    pub data_secure_enabled: bool,
    pub parameters: Vec<ParameterValue>,
    pub object_memberships: Vec<ObjectMembership>,
    pub objects: Vec<ComObjectDef>,
    pub net_security: BTreeMap<GroupAddress, NetSecurityPolicy>,
    pub topology: TopologyConfiguration,
    /// Optional upper bound on the detected PID-56 wire capability. This can
    /// reduce chunks for a problematic target but cannot enable long frames.
    pub max_apdu: Option<u16>,
}

/// Installation choices supplied alongside checked product evaluation.
/// Encoded parameters and effective objects come exclusively from that
/// evaluation; callers cannot inject a second product image through this input.
#[derive(Debug, Clone)]
pub struct InstallationConfiguration {
    pub identity: DeviceIdentity,
    pub data_secure_enabled: bool,
    pub object_memberships: Vec<ObjectMembership>,
    pub net_security: BTreeMap<GroupAddress, NetSecurityPolicy>,
    pub topology: TopologyConfiguration,
    pub max_apdu: Option<u16>,
}

impl From<InstallationConfiguration> for DeviceConfiguration {
    fn from(installation: InstallationConfiguration) -> Self {
        Self {
            identity: installation.identity,
            data_secure_enabled: installation.data_secure_enabled,
            object_memberships: installation.object_memberships,
            net_security: installation.net_security,
            topology: installation.topology,
            max_apdu: installation.max_apdu,
            parameters: Vec::new(),
            objects: Vec::new(),
        }
    }
}

/// Existing compiler input plus the effective object roster it must use.
#[derive(Debug, Clone)]
pub struct LoweredDeviceConfiguration {
    pub individual_address: IndividualAddress,
    pub parameters: Vec<ParameterValue>,
    pub links: Vec<GroupLink>,
    pub com_objects: Vec<ComObjectDef>,
    pub topology: TopologyConfiguration,
    /// Typed values for the product parameters referenced by load-procedure
    /// choices. Storage bytes alone cannot preserve a `ParameterRef` override
    /// or distinguish numeric, text, Boolean, and opaque comparisons.
    pub procedure_parameters: BTreeMap<String, ProcedureParameter>,
    /// Optional project-authored ceiling applied after live interface and
    /// target capability discovery. `None` leaves capability negotiation
    /// authoritative instead of silently forcing standard frames.
    pub configured_max_apdu: Option<u16>,
}

impl LoweredDeviceConfiguration {
    pub fn new(individual_address: IndividualAddress, configured_max_apdu: Option<u16>) -> Self {
        Self {
            individual_address,
            parameters: Vec::new(),
            links: Vec::new(),
            com_objects: Vec::new(),
            topology: TopologyConfiguration::default(),
            procedure_parameters: BTreeMap::new(),
            configured_max_apdu,
        }
    }

    pub fn with_com_objects(mut self, com_objects: Vec<ComObjectDef>) -> Self {
        self.com_objects = com_objects;
        self
    }

    pub fn with_topology(mut self, topology: TopologyConfiguration) -> Self {
        self.topology = topology;
        self
    }

    pub fn with_procedure_parameters(mut self, parameters: BTreeMap<String, ProcedureParameter>) -> Self {
        self.procedure_parameters = parameters;
        self
    }
}

impl DeviceConfiguration {
    /// Product resolution happens before key sources are consulted. It needs
    /// the structural project form before key resolution, but must not
    /// pretend that the final security tables have already been resolved.
    pub(crate) fn into_product_structure(mut self) -> Result<LoweredDeviceConfiguration> {
        let mut configuration = LoweredDeviceConfiguration::new(self.identity.desired_address, self.max_apdu);
        configuration.parameters = self.parameters;
        let memberships = &mut self.object_memberships;
        memberships.sort_by_key(|membership| match membership.role {
            MembershipRole::Primary => 0,
            MembershipRole::Additional => 1,
        });
        configuration.links = memberships
            .iter()
            .map(|membership| GroupLink { group_address: membership.group_address, com_object: membership.com_object })
            .collect();

        configuration.com_objects = self.objects;
        configuration.topology = self.topology;
        Ok(configuration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_associations_are_lowered_before_additional_ones() {
        let primary = GroupAddress::from_three_level(1, 0, 1);
        let additional = GroupAddress::from_three_level(1, 0, 2);
        let configuration = DeviceConfiguration {
            identity: DeviceIdentity { desired_address: IndividualAddress::new(1, 1, 1), serial_number: None },
            data_secure_enabled: false,
            parameters: Vec::new(),
            object_memberships: vec![
                ObjectMembership { group_address: additional, com_object: 971, role: MembershipRole::Additional },
                ObjectMembership { group_address: primary, com_object: 971, role: MembershipRole::Primary },
            ],
            objects: Vec::new(),
            net_security: BTreeMap::new(),
            topology: TopologyConfiguration::default(),
            max_apdu: None,
        };
        let lowered = configuration.into_product_structure().expect("configuration lowers");
        assert_eq!(lowered.links[0].group_address, primary);
        assert_eq!(lowered.links[1].group_address, additional);
        assert!(lowered.links.iter().all(|link| link.com_object == 971));
    }
}

/// A group address ↔ group object link (one association).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupLink {
    pub group_address: GroupAddress,
    /// The group object number (ASAP) as the product database numbers it.
    /// The selected association-table codec checks its wire width.
    pub com_object: u16,
}

/// A parameter value that differs from the product default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterValue {
    /// The parameter's full MTXML identifier.
    pub id: String,
    /// Raw bytes in device-memory order. For a `BinaryValue` restriction,
    /// an empty vector denotes native null: own the declared bytes while
    /// retaining their seed. An explicitly empty binary payload is padded
    /// to the declared width during product evaluation instead.
    pub value: Vec<u8>,
}
