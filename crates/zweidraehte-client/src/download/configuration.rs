//! Target-independent desired configuration for one device.
//!
//! Product-specific parsing resolves into this model. Key bytes and
//! mask-specific table positions deliberately do not: a mods file today,
//! and the planned installation DSL later, can feed the same compiler
//! boundary without learning either concern.

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
pub struct ObjectMembership {
    pub group_address: GroupAddress,
    pub com_object: u16,
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
    pub parameters: Vec<ParameterValue>,
    pub object_memberships: Vec<ObjectMembership>,
    pub objects: Vec<ComObjectDef>,
    pub net_security: BTreeMap<GroupAddress, NetSecurityPolicy>,
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
        let mut project = ProjectConfig::new(self.identity.desired_address);
        project.parameters = self.parameters.clone();
        project.security = security;
        if let Some(max_apdu) = self.max_apdu {
            project.max_apdu = max_apdu;
        }
        project.links = self
            .object_memberships
            .iter()
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
