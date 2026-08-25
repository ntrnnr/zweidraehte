//! Target-independent desired configuration for one device.
//!
//! Product-specific parsing resolves into this model. Key bytes and
//! mask-specific table positions deliberately do not: the host project store
//! and future installation frontends can feed the same compiler boundary
//! without learning either concern.

use std::collections::BTreeMap;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use super::product::ComObjectDef;
use super::project::{GroupLink, ParameterValue, ProjectConfig, SecurityConfig};
use crate::error::{Error, Result};

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
    /// Optional upper bound on the detected PID-56 wire capability. This can
    /// reduce chunks for a problematic target but cannot enable long frames.
    pub max_apdu: Option<u16>,
}

/// Existing compiler input plus the effective object roster it must use.
#[derive(Debug, Clone)]
pub struct LoweredDeviceConfiguration {
    pub project: ProjectConfig,
    pub com_objects: Vec<ComObjectDef>,
}

impl DeviceConfiguration {
    /// Lower the target-independent values into the existing compiler's
    /// project layer. Security has already been resolved from logical net
    /// policies and key sources, but remains free of physical offsets.
    pub fn lower(&self, security: Option<SecurityConfig>) -> Result<LoweredDeviceConfiguration> {
        match (self.data_secure_enabled, security.is_some()) {
            (true, false) => {
                return Err(Error::DeviceConfiguration(
                    "Data Secure is enabled but no application-security configuration was supplied".to_string(),
                ));
            }
            (false, true) => {
                return Err(Error::DeviceConfiguration(
                    "application-security configuration was supplied while Data Secure is disabled".to_string(),
                ));
            }
            _ => {}
        }
        self.lower_with_security(security)
    }

    /// Product resolution happens before key sources are consulted. It needs
    /// the structural project form for compatibility callers, but must not
    /// pretend that the final security tables have already been resolved.
    pub(crate) fn lower_product_structure(&self) -> Result<LoweredDeviceConfiguration> {
        self.lower_with_security(None)
    }

    fn lower_with_security(&self, security: Option<SecurityConfig>) -> Result<LoweredDeviceConfiguration> {
        let mut project = ProjectConfig::new(self.identity.desired_address);
        project.parameters = self.parameters.clone();
        project.security = security;
        if let Some(max_apdu) = self.max_apdu {
            project.max_apdu = max_apdu;
        }
        let mut memberships: Vec<_> = self.object_memberships.iter().collect();
        memberships.sort_by_key(|membership| match membership.role {
            MembershipRole::Primary => 0,
            MembershipRole::Additional => 1,
        });
        project.links = memberships
            .into_iter()
            .map(|membership| {
                let com_object = u8::try_from(membership.com_object).map_err(|_| {
                    Error::DeviceConfiguration(format!(
                        "group link names communication object {} above 255",
                        membership.com_object
                    ))
                })?;
                Ok(GroupLink { group_address: membership.group_address, com_object })
            })
            .collect::<Result<_>>()?;

        Ok(LoweredDeviceConfiguration { project, com_objects: self.objects.clone() })
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
                ObjectMembership { group_address: additional, com_object: 0, role: MembershipRole::Additional },
                ObjectMembership { group_address: primary, com_object: 0, role: MembershipRole::Primary },
            ],
            objects: Vec::new(),
            net_security: BTreeMap::new(),
            max_apdu: None,
        };
        let lowered = configuration.lower(None).expect("configuration lowers");
        assert_eq!(lowered.project.links[0].group_address, primary);
        assert_eq!(lowered.project.links[1].group_address, additional);
    }

    #[test]
    fn data_secure_enablement_and_tables_must_agree() {
        let mut configuration = DeviceConfiguration {
            identity: DeviceIdentity { desired_address: IndividualAddress::new(1, 1, 1), serial_number: None },
            data_secure_enabled: false,
            parameters: Vec::new(),
            object_memberships: Vec::new(),
            objects: Vec::new(),
            net_security: BTreeMap::new(),
            max_apdu: None,
        };
        assert!(configuration.lower(Some(SecurityConfig::default())).is_err());
        configuration.data_secure_enabled = true;
        assert!(configuration.lower(None).is_err());
        assert!(configuration.lower(Some(SecurityConfig::default())).is_ok());
    }
}
